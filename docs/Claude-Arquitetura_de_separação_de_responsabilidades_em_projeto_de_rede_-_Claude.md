## Prompt:
O prompt está no arquivo criptografia-e-descriptografia.md

## Response:
Lendo o repomix para ter contexto completo antes de responder.

Done

Contexto suficiente. Respondendo diretamente.

* * *

### Estrutura de credentials — decisão

A questão central é: **onde vive a lógica de descriptografia e onde ficam as credenciais?**

**`encryptor`/`decryptor` ficam em `DltEntry`/`ProtocolEntry`, não em `ProtocolConfig`.** A razão: `ProtocolConfig` armazena *estado* (credenciais, opções), callables de criptografia são *comportamento*. Misturar os dois em `ProtocolConfig` torna o dataclass mais difícil de serializar e inspecionar.

python

```
# core/registry.py
@dataclass
class DltEntry:
    value:      int
    parser:     Callable
    summarizer: Callable | None = None
    analyzer:   Callable | None = None
    encryptor:  Callable | None = None   # callable(payload, credentials) → bytes
    decryptor:  Callable | None = None   # callable(payload, credentials) → bytes
    config:     "DltConfig | None" = None

@dataclass
class DltConfig:
    credentials: dict = field(default_factory=dict)
    parse:       dict = field(default_factory=dict)   # ex: {"assume_fcs": False}
```

* * *

### Estrutura de credentials para dot11

A estrutura hierárquica que você propôs está correta na direção, mas pode ser simplificada. O problema das suas formas 1 e 2 é que misturam "contexto de qual AP" com "qual protocolo de autenticação". A separação mais limpa:

python

```
# Estrutura de credentials para dot11
# Passada em DltConfig.credentials ou DissectConfig.credentials

credentials = {
    "dot11": {
        # keyed por BSSID — identificador natural do AP em 802.11
        "aa:bb:cc:dd:ee:ff": {
            "ssid": "MinhaRede",
            
            # WPA2/WPA3 Personal
            "psk": "senha123",          # string → deriva PMK internamente
            # OU diretamente se já derivado:
            "pmk": "hex_do_pmk_aqui",   # 32 bytes hex
            
            # WPA Enterprise
            "eap": {
                "method":   "PEAP",
                "identity": "usuario",
                "password": "senha",
                # ou certificado
                "ca_cert":  "/path/to/ca.pem",
            },

            # RADIUS (para descriptografar EAP dentro de RADIUS)
            "radius": {
                "secret": "radius_shared_secret",
            },

            # WEP
            "wep": {
                "key_index": 0,
                "key":       "hex_da_chave_wep",
            },

            # Clientes — opcional, otimiza derivação de PTK sem reprocessar handshake
            "clients": {
                "11:22:33:44:55:66": {
                    "ptk": "hex_ptk_já_derivado",   # pula derivação se já conhecido
                },
            },
        },
    }
}
```

**Por que não aninhar por protocolo dentro do BSSID?** Porque um dado BSSID usa *um* protocolo de autenticação por vez. Ter `"eapol": {...}`, `"eap": {...}`, `"radius": {...}` como chaves paralelas dentro do BSSID é correto — cada uma é independente e o parse sabe qual usar pela análise do frame.

* * *

### Como o parse acessa credentials

Não passa credentials por parâmetro em cada função de parse — isso quebraria a assinatura de tudo. O caminho é via `DissectContext`, que já é um `ContextVar`:

python

```
# core/dissect.py
@dataclass
class DissectConfig:
    credentials: dict = field(default_factory=dict)
    parse:       dict = field(default_factory=dict)
    analysis:    dict = field(default_factory=dict)

class DissectContext:
    def __init__(self, config: DissectConfig = None):
        self.config = config or DissectConfig()
        self.result = None

    # ... __enter__, __exit__, current() via ContextVar

    @classmethod
    def get_credentials(cls, protocol: str, key: str = None) -> dict | None:
        ctx = cls.current()
        if not ctx:
            return None
        creds = ctx.config.credentials.get(protocol, {})
        return creds.get(key) if key else creds
```

O `decryptor` de dot11 chama:

python

```
# dot11/dlt/ieee802_11_radio/crypt.py
from pktparsers.core.dissect import DissectContext

def decrypt_ccmp(payload: bytes, bssid: str, sta: str) -> bytes | None:
    creds_bssid = DissectContext.get_credentials("dot11", bssid)
    if not creds_bssid:
        return None

    ptk = creds_bssid.get("clients", {}).get(sta, {}).get("ptk")
    if not ptk:
        # tenta derivar PTK a partir do handshake + PMK/PSK
        ptk = _derive_ptk(creds_bssid, bssid, sta)

    if not ptk:
        return None

    return _ccmp_decrypt(payload, bytes.fromhex(ptk))
```

* * *

### Onde fica `crypt.py`

Segue o mesmo padrão do resto do projeto: **criptografia específica de protocolo fica junto ao protocolo**:

```
dot11/
  crypt.py          # funções: derive_pmk(), derive_ptk(), decrypt_ccmp(), decrypt_tkip()
  dlt/
    ieee802_11_radio/
      crypt.py      # wrapper DLT-específico — chama dot11/crypt.py com contexto radiotap
```

`core/crypt.py` que já existe no seu projeto fica para utilitários **genéricos** de criptografia (AES-CCM, RC4, SHA1-HMAC) que `dot11/crypt.py` importa. Nunca lógica de protocolo em `core/crypt.py`.

* * *

### L3+ — como credentials funcionariam

Para DLT\_EN10MB a estrutura espelha dot11 mas keyed por IP ou par IP+porta:

python

```
credentials = {
    "dot11": { ... },  # como acima
    "tls": {
        # keylog format (NSS Key Log) — suporta Wireshark e outros
        "keylog_file": "/path/to/sslkeylog.log",
        # ou inline:
        "session_keys": {
            "CLIENT_RANDOM hex": "master_secret hex",
        },
    },
    "ipsec": {
        "spi_hex": {
            "esp_key":  "hex",
            "auth_key": "hex",
        },
    },
}
```

A lógica de L3+ de autenticação (EAP, RADIUS) é identificada pelo contexto do frame — se veio de um BSSID específico, as credentials do dot11 já têm o `radius.secret` necessário para descriptografar EAP dentro de RADIUS.

## Prompt:
mas assim não estaria acoplando funções de criptografia no protocolo dot11? além disso, a estrutura credentials de dot11, não estaria acoplando de forma hardcode esruturas como "eap" "radius" e "wep" ? elas não deveriam está no padrão/protocolo específico relacionado a elas? Esse protocolos e funções de criptografia são exclusivos do dot11?

## Response:
Você está certo nos dois pontos. Vou ser direto.

* * *

### Acoplamento de criptografia

`dot11/crypt.py` com `decrypt_ccmp()` e `derive_ptk()` não é acoplamento ruim — CCMP e PTK são **definidos pela spec 802.11**, não pelo pktparsers. A derivação de PTK usa endereços MAC 802.11 (ANonce, SNonce, BSSID, STA MAC) que são conceitos intrínsecos ao protocolo. Isso pertence ao dot11.

O que **seria** acoplamento ruim: colocar lógica de CCMP dentro do parse de mac\_header, ou chamar decrypt dentro de body.py. A separação correta é:

```
parse.py    → parseia estrutura do frame (stateless, sem side-effects)
crypt.py    → descriptografa payload (chamado pelo parse de DLT, não pelo protocolo)
analyzers/  → análise semântica
```

O parse de DLT chama `crypt.py` apenas quando o frame tem o flag `protected=True` e há credenciais disponíveis. O protocolo `dot11/parse.py` nunca toca em criptografia.

* * *

### Acoplamento de `eap`, `radius`, `wep` em credentials do dot11

Você está certo — essas chaves não pertencem ao dot11. O dot11 é a camada de transporte. O que acontece dentro do payload protegido é:

*   EAPOL é um protocolo do `dot1x`
*   EAP é um protocolo do `dot1x`
*   RADIUS é um protocolo separado
*   WEP é um mecanismo de criptografia da camada dot11 mesmo — esse fica

A estrutura correta separa por **quem precisa da credential para descriptografar**:

python

```
credentials = {
    # dot11 precisa para descriptografar o payload CCMP/TKIP/WEP
    "dot11": {
        "aa:bb:cc:dd:ee:ff": {          # BSSID
            "ssid":    "MinhaRede",
            "psk":     "senha123",      # WPA2/WPA3 Personal → deriva PMK
            "pmk":     "hex...",        # ou direto se já derivado
            "wep":     {"key_index": 0, "key": "hex..."},
            "clients": {
                "11:22:33:44:55:66": {
                    "ptk": "hex...",    # pula derivação de PTK se já conhecido
                },
            },
        },
    },

    # dot1x/eapol precisa para processar handshakes EAP Enterprise
    # (o payload já foi descriptografado pelo dot11 antes de chegar aqui)
    "eap": {
        "aa:bb:cc:dd:ee:ff": {          # BSSID do AP associado
            "method":   "PEAP",
            "identity": "usuario",
            "password": "senha",
            "ca_cert":  "/path/to/ca.pem",
        },
    },

    # radius precisa do shared secret para verificar/descriptografar atributos
    "radius": {
        "192.168.1.100": {              # IP do servidor RADIUS
            "secret": "shared_secret",
        },
    },

    # tls — futuramente, para descriptografar TLS em L4/L7
    "tls": {
        "keylog_file": "/path/sslkeylog.log",
    },
}
```

Cada protocolo acessa só o que é seu via `DissectContext.get_credentials("dot11", bssid)`, `DissectContext.get_credentials("eap", bssid)`, etc.

* * *

### CCMP/TKIP/WEP são exclusivos do dot11?

CCMP (AES-CCM) e TKIP (RC4+MIC) como **algoritmos criptográficos** não são exclusivos — TLS usa AES-CCM também. Mas a **derivação de chaves PTK/GTK** usando ANonce + SNonce + PRF-SHA1 + endereços MAC 802.11 **é exclusiva do 802.11**. Essa lógica fica em `dot11/crypt.py`.

Os algoritmos primitivos (AES-CCM, RC4, SHA1-HMAC) ficam em `core/crypt.py` e são importados por `dot11/crypt.py`:

```
core/crypt.py           → AES_CCM_decrypt(), RC4(), HMAC_SHA1(), PBKDF2()
dot11/crypt.py          → derive_pmk(psk, ssid), derive_ptk(pmk, anonce, snonce, bssid, sta)
                          decrypt_ccmp(payload, ptk), decrypt_tkip(payload, ptk)
dot1x/eapol/crypt.py    → verify_mic(eapol_frame, ptk, kck)
                          clear_mic(eapol_frame) → bytes para hashcat
```

`dot1x/eapol/crypt.py` existe porque a verificação de MIC e a limpeza de campos para gerar o hash 22000 são operações específicas do protocolo EAPOL, não do 802.11.

## Prompt:
Ótimo, mas como vou gerar automaticamente um DissectConfig? provavelmente irei me basear justamente nas tabelas "DLT" e "PROTOCOL" em registry. Então quero adiante o trabalho para mim, crie os arquivos ou defina as estruturas de dados que você propôs, em formato de dict, provavelmente utilizando a funções como make\_ para gerar a estrutura dinâmicamente. Crie os módulos de crypt no formato em que você sugeriu, mas com alguns possíveis ajustes de acordo com o contexto e funcionamento de parsers internos que vou passar através do arquivo repomix.

## Response:
Contexto suficiente. Criando os arquivos.

Done

## Response:
pktparsers

