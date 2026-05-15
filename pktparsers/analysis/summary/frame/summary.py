@dataclass 
class Dot11Device: 
    ssids: set[str] 
    channels_seen: set[int] 
    role: str # diz se é AP ou STA
    # relationships: dict[str, dict # como eu já disse, tenho que decidir se ela vai ser aqui ou não.

"""
irá ser definida se eu escolher a forma:
receber "result" de ParseContext para gerar summary.
def summarize():
    pass

Caso contrario, ou seja, usar a outra forma:
sub-parsers a partir da função principal de parse, alimentam o summary de ParseContext.
Então não será necessário uma função de summarize, pois o summary de ParseContext, gerado dinâmicamente através de sub-parsers chamados a partir da função principal de parse, já conseguem gerar uma estrutura suficientemente boa para uma função de analyzer de summary pode gerar entries para alimentar/atualizar TrafficSummary.
"""

def analyzer(summary, traffic_summary: TrafficSummary): # Analisa o summary do frame dot11, cria/atualiza DeviceEntry global e outras entries caso seja necessário, e adiciona elas no traffic_summary. Talvez seja possível/necessário que essa função acesse a estrutura "devices" de traffic_summary, para acessar a entrada de um dispositivo específico, e realizar comparações e outras operações. 
    pass
