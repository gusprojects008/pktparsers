@dataclass 
class Dot11Device: 
    ssids: set[str] 
    channels_seen: set[int] 
    role: str # diz se é AP ou STA
    relationships: dict[str, dict]
    relationships: dict[str, dict[str, dict]] = None # exemplo: {"mac": {"recv": int, "sent": int, "retry": int}, "mac": {"recv": int, "sent": int, "retry": int}}
    entries: Any # Variável para adicionar outras informações variável sobre o dispositivo.


def analyzer(summary, traffic_summary: TrafficSummary): # Analisa o summary do frame dot11 por exemplo, e obtém as informações necessárias para criar ou atualizar as variáveis de TrafficSummary, muitas vezes, ela analisará as próprias variáveis de TrafficSummary antes de criar ou atualizar as variáveis de TrafficSummary.
    pass

# Não irá ser necessária, pois atualmente, os subparsers de um parse principal, alimentam dinâmicamente a variável summary de ParseContext do parse principal.
def summarize(parse_result: dict): # recebe "result" de ParseContext para gerar summary.
    pass
