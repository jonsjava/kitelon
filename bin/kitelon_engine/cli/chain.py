"""Shell-style command chaining (`;` and `&&`)."""



def tokenize_chain(line: str) -> list[str]:
    """Split a line on ``;`` and ``&&`` outside quotes."""
    parts: list[str] = []
    buf: list[str] = []
    in_quote: str | None = None
    i = 0
    while i < len(line):
        ch = line[i]
        if in_quote:
            buf.append(ch)
            if ch == in_quote and (i == 0 or line[i - 1] != "\\"):
                in_quote = None
            i += 1
            continue
        if ch in "\"'":
            in_quote = ch
            buf.append(ch)
            i += 1
            continue
        if line[i : i + 2] == "&&":
            segment = "".join(buf).strip()
            if segment:
                parts.append(segment)
            parts.append("&&")
            buf = []
            i += 2
            continue
        if ch == ";":
            segment = "".join(buf).strip()
            if segment:
                parts.append(segment)
            parts.append(";")
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    segment = "".join(buf).strip()
    if segment:
        parts.append(segment)
    return parts


def has_chain(line: str) -> bool:
    return ";" in line or "&&" in line
