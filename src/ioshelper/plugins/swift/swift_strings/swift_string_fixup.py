__all__ = ["SwiftStringsHook"]

import re

import ida_bytes
import ida_hexrays
import ida_lines
import idaapi
from ida_hexrays import (
    cexpr_t,
    cfuncptr_t,
    cinsn_t,
    citem_t,
    cot_num,
    ctree_parentee_t,
)
from ida_typeinf import tinfo_t
from idahelper import tif
from idahelper.ast import cexpr

# ---------- Config ----------
MAX_READ = 1024
OBJECT_OFFSET = 0x20
TAG = "[swift-string]"
# ----------------------------


def _log(message: str) -> None:
    print(f"[swift-strings] {message}")


# --------- Low-level helpers: reading/decoding ---------
def _read_cstring_from(addr: int, max_read: int = MAX_READ):
    if not addr:
        return "", b""
    raw = ida_bytes.get_bytes(addr, max_read) or b""
    if not raw:
        return "", b""
    z = raw.find(b"\x00")
    if z >= 0:
        raw = raw[:z]
    try:
        s = raw.decode("utf-8")
    except UnicodeDecodeError:
        s = raw.decode("latin-1", errors="replace")
    return s, raw


def _decode_string_d(obj_addr: int):
    base = obj_addr & 0x7FFFFFFFFFFFFFFF
    s, _ = _read_cstring_from(base + OBJECT_OFFSET)
    return s


def _decode_string_e(bits_val: int, obj_addr: int) -> str:
    top_nib = (obj_addr >> 60) & 0xF
    if top_nib != 0xE:
        return ""
    length = (obj_addr >> 56) & 0xF
    if length == 0:
        return ""
    cf = bits_val.to_bytes(8, byteorder="little", signed=False)
    oa = obj_addr.to_bytes(8, byteorder="little", signed=False)
    data = cf[:length]
    if len(data) < length:
        data += oa[: length - len(data)]
    try:
        return data.decode("utf-8", errors="strict")
    except Exception:
        return data.decode("latin-1", errors="replace")


# -------------------------------------------------------


# --------- C-tree utilities ----------
def from_string(s: str, ea: int = idaapi.BADADDR) -> cexpr_t:
    e = cexpr_t()
    e.ea = ea
    e.op = ida_hexrays.cot_str
    e.type = tif.from_c_type("char*")
    e.string = s
    return e


def _is_mem_asg_num(e: cexpr_t, var_x: cexpr_t, wanted_off: int) -> int | None:
    if e is None or e.op != ida_hexrays.cot_asg:
        return None
    lhs, rhs = e.x, e.y
    if lhs is None or rhs is None:
        return None
    if lhs.op != ida_hexrays.cot_memref or rhs.op != cot_num:
        return None
    if lhs.m != wanted_off:
        return None
    try:
        if lhs.x != var_x:
            return None
    except Exception:
        return None
    return rhs.numval()


def _safe_get_specific(node):
    if node is None:
        return None
    try:
        return node.to_specific_type
    except Exception:
        return None


def _find_prior_complementary_assignment(
    parents: list[citem_t], current: cexpr_t | cinsn_t, var_x: cexpr_t, wanted_off: int
):
    """
    Walk up parent chain. If inside a comma (we're its 'y'), scan the left spine.
    If inside a block, scan earlier statements. Never mutates the tree.
    Returns prior cexpr_t or None.
    """
    cur = current

    for raw_parent in reversed(parents or []):
        parent = _safe_get_specific(raw_parent)
        if parent is None:
            continue

        # promote cexpr -> cinsn wrapper when we pass through a statement
        if parent.op == ida_hexrays.cit_expr:
            try:
                if isinstance(cur, cexpr_t) and parent.cexpr == cur:
                    cur = parent
            except Exception:
                _log("Error in cit_expr")
            continue

        if parent.op == ida_hexrays.cot_comma:
            try:
                if isinstance(cur, cexpr_t) and cur == parent.y:
                    stack = [parent.x]
                    while stack:
                        node = stack.pop()
                        if node.op == ida_hexrays.cot_asg:
                            val = _is_mem_asg_num(node, var_x, wanted_off)
                            if val is not None:
                                return node
                        elif node.op == ida_hexrays.cot_comma:
                            stack.append(node.x)  # walk earlier-left only
                cur = parent
            except Exception:
                cur = parent
            continue

        if parent.op == ida_hexrays.cit_block:
            block = parent.cblock
            try:
                for i, insn in enumerate(block):
                    if insn == cur:
                        for j in range(i - 1, -1, -1):
                            pj = block[j]
                            if pj.op == ida_hexrays.cit_expr:
                                cand = pj.cexpr
                                val = _is_mem_asg_num(cand, var_x, wanted_off)
                                if val is not None:
                                    return cand
                        break
            except Exception:
                _log("Error in cit_block")
            cur = parent
            continue

        cur = parent

    return None


def _no_op_prior_assignment(prior_expr: cexpr_t) -> bool:
    """
    Make '<memref> = <num>' into '<memref> = <memref>' (safe no-op).
    """
    try:
        if prior_expr is None or prior_expr.op != ida_hexrays.cot_asg:
            return False
        lhs = prior_expr.x
        if lhs is None or lhs.op != ida_hexrays.cot_memref:
            return False
        rhs_copy = cexpr_t(lhs)
        prior_expr.y.swap(rhs_copy)
        return True
    except Exception:
        _log("Error in _no_op_prior_assignment")
    else:
        return False


# -------------------------------------


class SwiftStringsHook(ida_hexrays.Hexrays_Hooks):
    """
    Phase 1 (AST): rewrite the second assignment to __SwiftStr("…") and
    convert the earlier write into a self-assignment no-op (never delete nodes).

    Phase 2 (print): remove the self-assignment lines from pseudocode output.
    """

    # --- phase 1 ---
    def maturity(self, func: cfuncptr_t, new_maturity: int) -> int:
        if new_maturity < ida_hexrays.CMAT_CPA:
            return 0

        swift_str_type = tif.from_c_type("Swift::String")
        if swift_str_type is None:
            return 0

        try:
            SwiftStringVisitor(swift_str_type).apply_to(func.body, None)  # pyright: ignore[reportArgumentType]
        except Exception:
            _log("Error in SwiftStringVisitor")
        return 0

    # --- phase 2 ---
    # Remove the exact self-assignments our AST pass creates.
    _RE_SELF_NOP_PLAIN = re.compile(
        r"^(?P<indent>\s*)(?P<lhs>.+?)\.(?P<field>_countAndFlagsBits|_object)\s*=\s*(?P=lhs)\.(?P=field)\s*;\s*$"
    )

    def func_printed(self, cfunc: cfuncptr_t) -> int:
        try:
            sv = cfunc.get_pseudocode()
        except Exception:
            return 0

        changed = False
        for tl in sv:
            raw = tl.line
            plain = ida_lines.tag_remove(raw)  # <-- strip color tags
            m = self._RE_SELF_NOP_PLAIN.match(plain)
            if not m:
                continue

            # keep just the visual indent (spaces/tabs), drop the self-assignment
            indent = m.group("indent")
            tl.line = indent
            changed = True

        return 1 if changed else 0


class SwiftStringVisitor(ctree_parentee_t):
    """
    Finds pairs of assignments to Swift::String fields (offsets 0 & 8)
    in either order, possibly non-adjacent; decodes and rewrites the
    second write to construct the Swift::String.
    """

    def __init__(self, swift_str_type: tinfo_t):
        super().__init__()
        self.swift_str_type = swift_str_type

    def visit_expr(self, expr: cexpr_t) -> int:
        if expr is None or expr.op != ida_hexrays.cot_asg:
            return 0

        lhs: cexpr_t = expr.x
        rhs: cexpr_t = expr.y
        if lhs is None or rhs is None:
            return 0
        if lhs.op != ida_hexrays.cot_memref or rhs.op != cot_num:
            return 0

        # Ensure it's Swift::String
        try:
            if lhs.x.type != self.swift_str_type:
                return 0
        except Exception:
            return 0

        # Only offsets 0 & 8
        if lhs.m not in (0, 8):
            return 0

        var_x = lhs.x
        cur_off = lhs.m
        need_off = 0 if cur_off == 8 else 8

        # Look backwards for complementary write
        prior_expr = _find_prior_complementary_assignment(self.parents, expr, var_x, need_off)
        if prior_expr is None:
            return 0

        # Get numeric pair (bits@0, obj@8)
        if cur_off == 8:
            bits_val = _is_mem_asg_num(prior_expr, var_x, 0)
            obj_val = rhs.numval()
        else:  # cur_off == 0
            bits_val = rhs.numval()
            obj_val = _is_mem_asg_num(prior_expr, var_x, 8)

        if bits_val is None or obj_val is None:
            return 0

        # Decode
        try:
            s = _decode_string_e(bits_val, obj_val) or _decode_string_d(obj_val)
        except Exception:
            return 0
        if not s:
            return 0

        # Build helper call returning Swift::String
        try:
            call = cexpr.call_helper_from_sig(
                "__SwiftStr",
                self.swift_str_type,
                [from_string(s)],
            )
        except Exception:
            return 0

        # Replace RHS with call
        try:
            expr.y.swap(call)
        except Exception:
            return 0

        # Assign directly to the aggregate (remove field)
        try:
            lhs_parent = cexpr_t(expr.x.x)
            expr.x.swap(lhs_parent)
        except Exception:
            return 0

        # Mark older line as safe no-op (will be hidden in func_printed)
        _no_op_prior_assignment(prior_expr)
        return 0
