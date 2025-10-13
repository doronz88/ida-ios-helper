# Rewrites:
#   v4._countAndFlagsBits = 0xD000...;
#   v4._object = (void *)0x8000...;
# and:
#   v16->qword20._countAndFlagsBits = 0x7474...;
#   v16->qword20._object = (void *)0xEA00...;
# into:
#   v4 = S"...";
#   v16->qword20 = S"...";
#
# Keeps full LHS token (e.g., v16->qword20). If raw token extraction fails due to
# coloring quirks, falls back to plain text so it still replaces.

import re

import ida_bytes
import ida_hexrays
import ida_lines
import idaapi

MAX_READ = 1024
OBJECT_OFFSET = 0x20
TAG = "[swift-string]"

# Tokens
NUM = r"(?P<bitsval>(?:0x[0-9A-Fa-f]+|\d+))"
HEX = r"(0x[0-9A-Fa-f]+)"
# C-ish dotted/arrow path: ident, *ident, ident->ident, obj.field, *p->x.y, etc.
VAR = r"(?P<var>(?:\*?[\w$]+(?:(?:->|\.)\*?[\w$]+)*))"

# Accept both hex & decimal addresses; allow optional (void *) cast, tolerant spaces, optional LL, and trailing , ); or EoL
RE_BITS = re.compile(rf"{VAR}\s*\.\s*_countAndFlagsBits\s*=\s*{NUM}\s*(?:LL)?(?=(?:\s*[),;]|$))")
RE_OBJ = re.compile(
    rf"{VAR}\s*\.\s*_object\s*=\s*(?:\(\s*void\s*\*\s*\))?\s*(?P<addr>{HEX}|\d+)\s*(?:LL)?(?=(?:\s*[),;]|$))"
)


def _log_error(msg: str) -> None:
    idaapi.msg(f"{TAG} [error] {msg}\n")


def _escape_for_c(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")


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
    return s, OBJECT_OFFSET


def _iter_raw_plain_indices(raw: str):
    pi = 0
    ri = 0
    n = len(raw)
    while ri < n:
        c = raw[ri]
        if c == ida_lines.COLOR_ON:
            ri += 2 if ri + 1 < n else 1
            continue
        if c == ida_lines.COLOR_OFF:
            ri += 1
            continue
        yield ri, pi
        pi += 1
        ri += 1


def _plain_to_raw_span(raw: str, plain: str, span: tuple[int, int]):
    ps, pe = span
    raw_start = None
    raw_end = None
    last_ri = None
    for ri, pi in _iter_raw_plain_indices(raw):
        if pi == ps and raw_start is None:
            raw_start = ri
        if ps <= pi < pe:
            last_ri = ri
        if pi >= pe:
            raw_end = ri
            break
    if raw_start is None:
        return None, None
    if raw_end is None:
        raw_end = (last_ri + 1) if last_ri is not None else raw_start
    return raw_start, raw_end


def _parse_int(val: str) -> int:
    try:
        return int(val, 0)
    except Exception:
        _log_error(f"Failed to parse integer: {val}")
        return 0


def _extract_var_raw_exact(raw: str, start_raw_idx: int, var_plain: str) -> str | None:
    """
    Collect raw chars (skipping color codes) until the assembled plain text equals var_plain.
    Return raw slice with colors; None if it couldn't be reconstructed.
    """
    n = len(raw)
    i = start_raw_idx
    collected_plain: list[str] = []
    raw_start = start_raw_idx

    while i < n and len(collected_plain) < len(var_plain):
        c = raw[i]
        if c == ida_lines.COLOR_ON:
            i += 2 if i + 1 < n else 1
            continue
        if c == ida_lines.COLOR_OFF:
            i += 1
            continue
        collected_plain.append(c)
        i += 1
        if "".join(collected_plain) == var_plain:
            j = i
            while j < n and raw[j] == ida_lines.COLOR_OFF:
                j += 1
            return raw[raw_start:j]
    return None


def _leading_indent_plain(plain_line: str) -> str:
    m = re.match(r"^\s*", plain_line)
    return m.group(0) if m else ""


def _collect(lines: list[str]):
    """
    Return:
      bits: {var_plain: [(idx, var_span_plain, var_raw_or_plain, prefix_raw_or_plain, bits_value_int)]}
      objs: {var_plain: [(idx, addr, var_span_plain, var_raw_or_plain, prefix_raw_or_plain)]}
    """
    bits: dict[str, list[tuple]] = {}
    objs: dict[str, list[tuple]] = {}

    for idx, raw in enumerate(lines):
        plain = ida_lines.tag_remove(raw)
        indent_plain = _leading_indent_plain(plain)

        for m in RE_BITS.finditer(plain):
            var_span = m.span("var")
            # Try to map to raw; if fails, fall back to plain
            rs, _ = _plain_to_raw_span(raw, plain, var_span)
            var_plain = m.group("var").strip()
            var_raw = _extract_var_raw_exact(raw, rs, var_plain) if rs is not None else None
            prefix = raw[:rs] if rs is not None and var_raw else indent_plain
            bits_val = _parse_int(m.group("bitsval"))
            bits.setdefault(var_plain, []).append((idx, var_span, var_raw if var_raw else var_plain, prefix, bits_val))

        for m in RE_OBJ.finditer(plain):
            var_span = m.span("var")
            rs, _ = _plain_to_raw_span(raw, plain, var_span)
            var_plain = m.group("var").strip()
            var_raw = _extract_var_raw_exact(raw, rs, var_plain) if rs is not None else None
            prefix = raw[:rs] if rs is not None and var_raw else indent_plain
            addr = _parse_int(m.group("addr"))
            objs.setdefault(var_plain, []).append((idx, addr, var_span, var_raw if var_raw else var_plain, prefix))

    return bits, objs


def _nearest(bits_idx: int, obj_list: list[tuple]):
    best = None
    best_key = None
    for oi, addr, _ospan, var_tok, prefix in obj_list:
        key = (abs(oi - bits_idx), 0 if oi >= bits_idx else 1)
        if best is None or key < best_key:
            best = (oi, addr, var_tok, prefix)
            best_key = key
    return best


def _find_pairs(lines: list[str]):
    bits, objs = _collect(lines)
    spans = []
    claimed = set()
    cands = []
    for var_plain, blist in bits.items():
        olist = objs.get(var_plain, [])
        if not olist:
            continue
        for bi, _bspan, bvar_tok, bprefix, bval in blist:
            near = _nearest(bi, olist)
            if not near:
                continue
            oi, addr, ovar_tok, oprefix = near
            lo, hi = (bi, oi) if bi <= oi else (oi, bi)
            # Prefer left token/prefix
            if bi <= oi:
                prefix, var_tok = bprefix, bvar_tok
            else:
                prefix, var_tok = oprefix, ovar_tok
            cands.append((hi - lo, lo, hi, addr, prefix, var_tok, bval))

    cands.sort(key=lambda t: (t[0], t[1], t[2]))
    for _, lo, hi, addr, prefix, var_tok, bval in cands:
        if any(i in claimed for i in range(lo, hi + 1)):
            continue
        spans.append((lo, hi, addr, prefix, var_tok, bval))
        claimed.update(range(lo, hi + 1))

    spans.sort(key=lambda t: t[0], reverse=True)
    return spans


def _decode_string_e(bits_val: int, obj_addr: int) -> str:
    # Immediate small string when top nibble is 0xE
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


def _rewrite(lines: list[str]) -> list[str]:
    out = list(lines)
    spans = _find_pairs(lines)
    changed = False

    for start, end, obj_addr, prefix_tok, var_tok, bits_val in spans:
        s = ""
        if ((obj_addr >> 60) & 0xF) == 0xE:
            s = _decode_string_e(bits_val, obj_addr)
        if not s:
            s, _ = _decode_string_d(obj_addr)

        if s:
            shown = _escape_for_c(s)
            repl = (
                f"{prefix_tok}{var_tok} = "
                f"{ida_lines.COLOR_ON}{ida_lines.SCOLOR_MACRO}S"
                f'{ida_lines.COLOR_ON}{ida_lines.SCOLOR_STRING}"{shown}"'
                f"{ida_lines.COLOR_OFF};"
            )
        else:
            base = (obj_addr & 0x7FFFFFFFFFFFFFFF) + OBJECT_OFFSET
            repl = f"{prefix_tok}// {TAG}: undecodable at {hex(base)}"

        out[start : end + 1] = [repl]
        changed = True

    return out if changed else lines


class SwiftStringsHook(ida_hexrays.Hexrays_Hooks):
    def func_printed(self, cfunc: "ida_hexrays.cfunc_t") -> int:
        try:
            sv = cfunc.get_pseudocode()
            lines = [sv[k].line for k in range(len(sv))]
            new_lines = _rewrite(lines)
            if new_lines == lines:
                return 0
            if len(new_lines) <= len(sv):
                for i, t in enumerate(new_lines):
                    sv[i].line = t
                while len(sv) > len(new_lines):
                    sv.pop_back()
            else:
                for i in range(len(sv)):
                    sv[i].line = new_lines[i]
                for i in range(len(sv), len(new_lines)):
                    tl = ida_hexrays.ctext_line_t()
                    tl.line = new_lines[i]
                    sv.push_back(tl)
        except Exception as e:
            _log_error(f"func_printed error: {e}")
            return 0
        else:
            return 1
