from pktparsers.common.definitions import (DissectContext, DissectionResult, TrafficContext)
from contextvars import ContextVar
from dataclasses import dataclass, field

_dissect_context = ContextVar("_dissect_context")

@dataclass
class DissectContext:
    summaries: dict[str, list] = field(default_factory=dict)
    result: dict | None = None

    def __enter__(self):
        self._token = _dissect_context.set(self)
        return self

    def __exit__(self, *args):
        _dissect_context.reset(self._token)

    def add_summary(self, protocol: str, summary):
        self.summaries.setdefault(protocol, []).append(summary)

    @classmethod
    def current(cls):
        return _dissect_context.get(None)

@dataclass
class DissectionResult:
    parsed: dict
    summaries: dict,
    traffic: TrafficSummary

class Dissector:
    def __init__(self, dlt: str | int): 
        self.dlt = dlt 
        self.traffic_ctx = TrafficContext(dlt=dlt) 
        self.parser = get_parser(dlt)

    def dissect(self, packet: bytes, offset: int = 0, dlt: str | int = None):
        with DissectContext() as dissect_ctx:

            parsed = self.parser(packet, offset)

            dissect_ctx.result = parsed

            traffic_summary = self.traffic_ctx.update(
                dissect_ctx.summaries
            )

            return DissectionResult(
                parsed=parsed,
                summaries=dissect_ctx.summaries,
                traffic=traffic_summary
            )

"""
Seguir a lógica?:
ParseContext:
summary

Funções de parse chamadas dentro de ParseContext, alimentar o summary de ParseContext.

No fim do bloco código de ParseContext, é chamada a função de summarize relacionada específica do padrão ou protocolo do parse.
Essa função irá consumir 


Assim, irá evitar com que a função de summarize do parse do padrão ou protocolo específico, tenha que navegar pelo result de ParseContext, utilizando as chaves do próprio conteúdo parseado, que podem mudar, ou seja, a própria função de summarize nesse caso, iria depender do conhecimento das chaves de dicionário do conteúdo parseado gerados por outras funções, eu sinto que isso pode ser fragil a longo prazo, pois por exemplo:
parse mac header define no seu resultado parseado:
      return {
            "fc": {
                "protocol_version": protocol_version,
                "type": f_type,
                "type_name": type_name,
                "subtype": f_subtype,
                "subtype_name": subtype_name,
                "tods": to_ds,
                "fromds": from_ds,
                "protected": protected,
            },
            "duration_id": duration,
            "ra": ra, "ta": ta, "sa": sa, "da": da, "bssid": bssid,
            "sequence_number": seq,
            "qos_control": qos
        }

Se eu mudo uma chaves nesse resultado, vou ter que atualizar o analisador de summary que se baseia no result parsed do frame de ParseContext.


Mas isso cria um suposto problema que não sei bem como resolver, w

"""
