def parse(frame: bytes, offset: int = 0) -> dict:
    with ParseContext(frame, offset) as ctx:
        insert_item(ctx.result, "rt_hdr", radiotap_header.parser())

        rt_hdr = ctx.result.get("rt_hdr")

        if not rt_hdr:
            return ctx.result

        rt_flags = rt_hdr.get("parsed", {}).get("flags", {})

        if rt_flags.get("bad_fcs"):
            return ctx.result

        dot11.parse()

        return ctx.result

def make_config(assume_fcs: bool = True)
    return {
        "assume_fcs": True,
    }

