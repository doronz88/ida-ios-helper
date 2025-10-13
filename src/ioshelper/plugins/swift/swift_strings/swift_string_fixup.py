__all__ = ["SwiftStringsHook"]

import ida_bytes
import ida_hexrays
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
# ----------------------------


def _log_error(message: str) -> None:
    print(f'[SwiftStringsHook] [ERROR] {message}')


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
    """
    Pointer-backed Swift::String ('D' layout):
    actual base is masked with 0x7FFF..., string is at (base + OBJECT_OFFSET)
    """
    base = obj_addr & 0x7FFFFFFFFFFFFFFF
    s, _ = _read_cstring_from(base + OBJECT_OFFSET)
    return s, OBJECT_OFFSET


def _decode_string_e(bits_val: int, obj_addr: int) -> str:
    """
    Immediate small string when top nibble of _object is 0xE.
    Length is (object >> 56) & 0xF.
    Bytes come from bits_val first (LE), then _object if needed.
    """
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
    """
    If 'e' is '<var_x>.<mem at wanted_off> = <const number>', return the number; else None.
    """
    if e.op != ida_hexrays.cot_asg:
        return None
    lhs, rhs = e.x, e.y
    if lhs.op != ida_hexrays.cot_memref or rhs.op != cot_num:
        return None
    if lhs.m != wanted_off:
        return None
    if lhs.x != var_x:
        return None
    return rhs.numval()


def _find_prior_complementary_assignment(
    parents: list[citem_t], current: cexpr_t | cinsn_t, var_x: cexpr_t, wanted_off: int
):
    """
    Walk up the parent chain. If inside a comma-expr (we are 'y'), scan the left spine for a match.
    If inside a block, scan earlier statements in the block for a match.
    Also, if we enter a cit_expr that wraps our current cexpr_t, promote `current` to that cinsn_t
    so that the next cit_block step can locate the statement.
    Returns (expr, ctx) where ctx describes how to neutralize the prior:
        ("comma", comma_parent)
        ("block", block_parent, victim_index)
    If not found, return (None, None).
    """
    # We'll mutate this as we climb so that when we hit cit_block we point at the cinsn_t
    cur = current

    for _parent in reversed(parents):
        if _parent is None:
            continue
        try:
            parent = _parent.to_specific_type
        except Exception:
            # Some parents can be null/invalid in edge cases
            _log_error('Failed to get parent')
            continue

        # If we're entering a statement wrapper for our expression, promote it to cinsn_t
        if parent.op == ida_hexrays.cit_expr:
            try:
                if isinstance(cur, cexpr_t) and parent.cexpr == cur:
                    cur = parent  # promote to cinsn_t
            except Exception:
                _log_error('Failed in cit_expr')
            # Keep walking up
            continue

        # Comma-expression: (... , cur). We're the right side iff cur is exactly parent.y
        if parent.op == ida_hexrays.cot_comma:
            try:
                if isinstance(cur, cexpr_t) and cur == parent.y:
                    # Scan the left spine (depth-first on left links only)
                    stack = [parent.x]
                    while stack:
                        node = stack.pop()
                        if node.op == ida_hexrays.cot_asg:
                            val = _is_mem_asg_num(node, var_x, wanted_off)
                            if val is not None:
                                return node, ("comma", parent)
                        elif node.op == ida_hexrays.cot_comma:
                            stack.append(node.x)  # only walk leftwards
                # Move up
                cur = parent
            except Exception:
                cur = parent
                _log_error('Failed in cot_comma')
            continue

        # Block: scan earlier statements
        if parent.op == ida_hexrays.cit_block:
            block = parent.cblock
            try:
                # Find our index as a statement (cur must be a cinsn_t by now in normal cases)
                for i, insn in enumerate(block):
                    if insn == cur:
                        # Look backwards for a candidate
                        for j in range(i - 1, -1, -1):
                            pj = block[j]
                            if pj.op == ida_hexrays.cit_expr:
                                cand = pj.cexpr
                                val = _is_mem_asg_num(cand, var_x, wanted_off)
                                if val is not None:
                                    return cand, ("block", parent, j)
                        break
            except Exception:
                _log_error('Failed in cit_block')
            cur = parent
            continue

        # Default: just keep walking up
        cur = parent

    return None, None


def _remove_prior_with_ctx(ctx, current: cexpr_t):
    """
    Neutralize the earlier complementary assignment.
    - In comma-exprs: replace '(left, current)' with 'current'.
    - In blocks: turn the victim instruction into an empty statement (';').
    """
    if ctx is None:
        return
    kind = ctx[0]
    if kind == "comma":
        comma_parent = ctx[1]
        current_copy = cexpr_t(current)
        comma_parent.swap(current_copy)
        return
    if kind == "block":
        block_parent, idx = ctx[1], ctx[2]
        victim = block_parent.cblock[idx]
        empty = cinsn_t()
        empty.op = ida_hexrays.cit_empty
        victim.swap(empty)
        return


# -------------------------------------


class SwiftStringsHook(ida_hexrays.Hexrays_Hooks):
    def maturity(self, func: cfuncptr_t, new_maturity: int) -> int:
        # Run once the function has a reasonably stable AST
        if new_maturity < ida_hexrays.CMAT_CPA:
            return 0

        swift_str_type = tif.from_c_type("Swift::String")
        if swift_str_type is None:
            return 0

        SwiftStringVisitor(swift_str_type).apply_to(func.body, None)  # pyright: ignore[reportArgumentType]
        return 0


class SwiftStringVisitor(ctree_parentee_t):
    """
    Finds pairs of assignments to Swift::String.{_countAndFlagsBits (off 0), _object (off 8)}
    in either order, possibly separated by other statements, decodes the string,
    and rewrites the second assignment to construct the Swift::String directly.
    """

    def __init__(self, swift_str_type: tinfo_t):
        super().__init__()
        self.swift_str_type = swift_str_type

    def visit_expr(self, expr: cexpr_t) -> int:
        # Only process assignments
        if expr.op != ida_hexrays.cot_asg:
            return 0

        lhs: cexpr_t = expr.x
        rhs: cexpr_t = expr.y

        # Must be a member assignment with an immediate numeric RHS
        if lhs.op != ida_hexrays.cot_memref or rhs.op != cot_num:
            return 0

        # Only on Swift::String
        if lhs.x.type != self.swift_str_type:
            return 0

        # Only offsets 0 (countAndFlagsBits) & 8 (_object)
        if lhs.m not in (0, 8):
            return 0

        var_x = lhs.x
        cur_off = lhs.m
        need_off = 0 if cur_off == 8 else 8

        # Find the complementary assignment earlier in the same block/comma
        prior_expr, ctx = _find_prior_complementary_assignment(self.parents, expr, var_x, need_off)
        if prior_expr is None:
            return 0

        # Extract values (bits @ off 0, object @ off 8)
        if cur_off == 8:
            bits_val = _is_mem_asg_num(prior_expr, var_x, 0)
            obj_val = rhs.numval()
        else:  # cur_off == 0
            bits_val = rhs.numval()
            obj_val = _is_mem_asg_num(prior_expr, var_x, 8)

        if bits_val is None or obj_val is None:
            return 0

        # Decode
        s = ""
        if ((obj_val >> 60) & 0xF) == 0xE:
            s = _decode_string_e(bits_val, obj_val)
        if not s:
            s, _ = _decode_string_d(obj_val)
        if not s:
            return 0

        # Build a helper-call that returns Swift::String from a C string
        call = cexpr.call_helper_from_sig(
            "__SwiftStr",
            self.swift_str_type,
            [from_string(s)],
        )

        # Replace RHS with the call
        expr.y.swap(call)

        # Assign directly to the struct/object (remove '._object'/'._countAndFlagsBits')
        lhs_parent = cexpr_t(expr.x.x)
        expr.x.swap(lhs_parent)

        # Neutralize the older complementary assignment
        _remove_prior_with_ctx(ctx, expr)
        return 0
