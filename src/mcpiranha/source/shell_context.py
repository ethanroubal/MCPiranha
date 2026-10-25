"""Track literal shell quotes around interpolation; not a full shell parser."""


def advance(text: str, quote: str = "", escaped: bool = False) -> tuple[str, bool]:
    for char in text:
        if escaped:
            escaped = False
        elif char == "\\" and quote != "'":
            escaped = True
        elif char in {"'", '"'}:
            if quote == char:
                quote = ""
            elif not quote:
                quote = char
    return quote, escaped
