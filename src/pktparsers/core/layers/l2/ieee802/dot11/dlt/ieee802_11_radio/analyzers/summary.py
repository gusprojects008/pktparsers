# dlt/ieee802_11_radio/analyzers/summary.py
from pktparsers.core.analyzers.traffic.context import TrafficContext

def summarize(parsed: dict): # recebe "result" de ParseContext para gerar summary.
    rt_hdr = parsed.get(RT_HEADER)
    rt_hdr_summary = "radiotap header"
    dot11 = parsed.get(DOT11)
    dot11_summary = dot11.analyzers.summary.summarize(dot11)
    return summary

def analyzer(parsed: dict, parser_summary: dict): # Analisa o summary do frame dot11 por exemplo, e obtém as informações necessárias para criar ou atualizar as variáveis de TrafficSummary, muitas vezes, ela analisará as próprias variáveis de TrafficSummary antes de criar ou atualizar as variáveis de TrafficSummary.
    traffic_ctx = TrafficContext.current()
    if traffic_ctx is None:
        return          # parse chamado sem Dissector

    traffic = traffic_ctx.summary

    # ... lógica de criar/atualizar DeviceEntry em traffic

    rt_hdr = parsed.get(RT_HDR)
    rt_hdr_summary = parser_summary.get(RT_HDR)

    dot11 = parsed.get(DOT11)
    dot11_summary = parser_summary.get(DOT11)

    dot11_device = {}

    pass
