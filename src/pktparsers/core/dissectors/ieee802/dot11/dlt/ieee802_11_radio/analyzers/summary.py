# dlt/ieee802_11_radio/analyzers/summary.py
from pktparsers.core.traffic.context import TrafficContext
from pktparsers.core.dissectors.ieee802.dot11.dlt.ieee802_11_radio.definitions import RT_HDR
from pktparsers.core.dissectors.definitions.parsing import SUMMARY

def summarize(parsed: dict): # recebe ctx.result[RT_HDR] de ParseContext para gerar summary.
    rt_hdr_summary = "radiotap header summary"
    summary = {} 
    return summary

def analyzer(parsed: dict, summary: dict): # Analisa o resultado de parse e o summary, chama a função analyzer: e obtém as informações necessárias para criar ou atualizar as variáveis de TrafficSummary, muitas vezes, ela analisará as próprias variáveis de TrafficSummary antes de criar ou atualizar as variáveis de TrafficSummary.
    # ... lógica de criar/atualizar DeviceEntry em traffic
    traffic_ctx = TrafficContext.current()
    traffic_summary = traffic_ctx.summary
    summary = summary or dot11.get(SUMMARY)
    rt_hdr_summary = summary or summarizer.get(RT_HDR)
    pass
