@dataclass 
class TrafficSummary: 
    devices: set[str, DeviceEntry]
    entries: set | list

@dataclass
class DeviceEntry:
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    protocol_data: dict[str, Any] = field(default_factory=dict)

"""
Exemplo de como a TUI irá ficar:
Traffic Summary:
    iface/ifname/interface: None ou wlp0s20f3 é opcional/complementar

    Date: 2026-05-15 hora

    DLT (Data Link Type): DLT_IEEE802_11_RADIO

    Devices:
        ID (hash(mac ou ip, depende do endereço relacionado à PDU da DLT principal de captura)) -> DeviceEntry ficando como: {
            first seen: 12.00
            last seen: 20:00
            protocol data: {}
        }
    Others:
        Diferentes tipos de entries indicando outras informações a partir da analise de tráfego.

"""

"""
E se summaries de DissectContext e protocol_data de DeviceEntry, forem estruturados assim?:

summaries ficaria assim:
{
    "l2": {
        "dot11": {},
        "dot3": {},
    },
    "l3": {
        "ip": {},
        "arp": {},
    },
    "l4": {
        "tcp": {},
        "udp: {}
    },
}

protocol_data ficaria assim:
{
    "l2": {
        "dot11": {"device": {}, "outras entries": {}},
        "dot3": {"device": {}, "outras entries": {}},
    },
    "l3": {
        "ip": {"device": {}, "outras entries": {}},
        "arp": {"device": {}, "outras entries": {}},
    },
    "l4": {
        "tcp": {"device": {}, "outras entries": {}},
        "udp: {"device": {}, "outras entries": {}},
    },
}

Sugeri essa estrutura novamente pois tenho resseio de futuramente os nomes de protocolos colidirem, por mais improvável que seja, além de que mantém a ideia do projeto de implementar/seguir o modelo OSI. Mas talvez isso seja verboso de mais, além de que isso parece implicar de que devo aplicar essa estrutura em camadas para tudo, exemplo:
Pensei incialmente nesse estrutura:
[gus@voidlinux ~/Documents/pktparsers/pktparsers/analysis (development)]$ ls
definitions.py  summary  traffic
[gus@voidlinux ~/Documents/pktparsers/pktparsers/analysis (development)]$ ls summary/
data  frame  packet  segment


Mas agora, parece que vou ter implementar esse para seguir o modelo OSI:
[gus@voidlinux ~/Documents/pktparsers/pktparsers/analysis (development)]$ ls
definitions.py  summary  traffic
[gus@voidlinux ~/Documents/pktparsers/pktparsers/analysis (development)]$ ls summary/
l2  l3  l4  l5 
[gus@voidlinux ~/Documents/pktparsers/pktparsers/analysis (development)]$ ls summary/l2/
frame/
[gus@voidlinux ~/Documents/pktparsers/pktparsers/analysis (development)]$ ls summary/l2/frame/
[gus@voidlinux ~/Documents/pktparsers/pktparsers/analysis (development)]$ ls summary/l2/frame/

Isso me leva a concluir que é melhor centralizar tudo em um diretório como core/, criar traffic/ dentro de core/, summary/ ou analysis/ dentro de dot11/.
Talvez abandonando a ideia de um diretório "analysis".

"""

"""
E se eu criasse uma DISSECT_TABLE, uma tabela de dispatch que associa DLTs e nomes de camadas à parsers? ou melhor e mais correto ser apenas por DLT?
dot11/ é diretório de padrão de comunicação, ele possui um diretório chamada radio/ só por causa da DLT_IEEE802_11_RADIO.
l3/ é diretório de camada, então faz sentido ter um diretório ip/ com o seus parsers, só por causa da DLT_RAW? ou ainda é melhor continuar com a ideia de chamar l3.parse("ip") para obter o parse de ip que será associado à DLT_RAW?
"""

"""
Provavelmente irei ter que transformar todos os dataclasses em dicts, pois quero permitir o usuário acessar qualquer estrutura de dados.
"""

"""
Preciso planejar toda essa engenharia e arquitetura para que em um futuro próximo, já estar pronto para resolver esses problemas:
Como futuramente irei possibilitar o usuário escolher o que não parsear, ou seja, quais protocolo não analisar?
Ver como futuramente irei fazer para implementar um módulo que gera um gráfico com base em estruturas de summary?
"""

"""
read_pcap() e read_pcapng() do pktparsers:
irá utilizar o dpkt ou outro módulo (talvez até mesmo custom do próprio pktparsers se for necessário ou interessante criar) para ler o pcap ou pcapng, e irá chamar o dissector de acordo com a DLT obtida do pcap ou pcapng, e assim, irá instanciar Dissect uma vez caso seja pcap, mas caso for pcapng, irei instanciar Dissect para cada dlt relacionada a uma interface, e assim fazer a dissecação completa gerando até mesmo traffic summary para cada uma.


Pensei também em uma própria implementação de funcionalidade de parse manual pelo usuário, exemplo:
O ifname é opcional, mas também estou em dúvida entre as chaves: "ifname", "iface" ou "interface".
pktparser_pcap_format:
{
    "ifname": "wlp0s20f3",
    "dlt": "DLT_IEEE802_11_RADIO ou inteiro",
    "raw": ["00038...", "00038..."]
    
}

pktparsers_pcapng_format:
{
    "wlp0s20f3": {
        "dlt": DLT_IEEE802_11_RADIO,
        "raw": [00038..., "00038..."]
    },
}
"""
