Na tui irei permitir o usuário inserir as chaves manualmente ou editar as que foram carregadas no momento em que o usuário escolheu carregar um arquivo de captura (qualquer um dos formatos suportados) para gerar a estrutura de credentials para aquele protocolo ou DLT específica. Então vou precisar dessa função analisadora de captura, e geradora de dicts credentials para o protocolo ou DLT sendo configurada no momento.

Dependendo do protocolo ou DLT, irei ter que pedir algumas informações como PSK, SSID, etc... antes ou obrigar o usuário a por elas depois que ele já carregou, para poder por exemplo, analisar os frames eapol do arquivo de captura, e assim ir alimentando o credentials de ieee802_11.

Existe um problema arquitetural na estrutura do dict "crypt" dentro do dict config de uma dlt ou protocolo.
Atualmente, "credentials" de "crypt" é preparada para receber apenas um entry de credentials de um dispositivo específico, sendo que na verdade, esse estrutura "credentials" deveria estar preparada para ter vários dicts com a estrutura "credentials" para cada dispositivo, ou seja, para cada mac ou ip, dependendo do protocolo de autenticação. Mas na verdade, não irei impedir o usuário de por o que quiser para identificar um dispositivo à uma estrutura credentials de um protocolo de autenticação específico.

A função de parse no body.py dentro de parsers/ do protocolo ou dlt específica, provavelmente será responsável por:
Verificar se o pacote é protegido, através de protected de mac_header por exemplo.
Se for protegido, obtém a função de decrypt do protocolo ou dlt específica, essa decrypt está nas tabelas de dispatch PROTOCOL ou DLT em registry.py. Após isso, a função de decrypt ou a funçao em body.py (ainda tenho que decidir), através do dict de config do protocolo ou DLT específica, obtido através de dissect config que foi obtido através do contexto do app/framework ou passado diretamente para DissectContext, obtém o dict "credentials" específico do dispositivo através do id que o usuário definiu para a estrutura "credentials" dentro de "crypt" do config do protocolo ou DLT específica. 

Lembrando que o idenficador do dispositivo não deve ficar acoplado ao protocolo, e onde ele geralmente é utilizado, quero dar a liberdade ao usuário permitindo que ele defina um ip, mac ou qualquer coisa para idenficar as credenticiais específicas do dispositivo em um protocolo específico.

Futuramente, provavelmente irei ter que disponibilizar um função de merge de diferentes arquivos de ssl key log, para juntar todos em um só, e dessa forma, manter com ideia de que "credentials" de TLS irá manter apenas o fullpath do arquivo de ssl key log, e todas as session keys derivadas a partir do fullpath. 

Ficando assim exemplo:
    # ieee802_11 precisa para descriptografar o payload CCMP/TKIP/WEP
    "ieee802_11": {
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
    # (o payload já foi descriptografado pelo ieee802_11 antes de chegar aqui)
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

    "ipsec": {
        "spi_hex": {
            "esp_key":  "hex",
            "auth_key": "hex",
        },
    },
    "tls": {
        # keylog format (NSS Key Log) — suporta Wireshark e outros
        "keylog_file": "/path/to/sslkeylog.log",
        # ou inline:
        "session_keys": {
            "CLIENT_RANDOM hex": "master_secret hex",
        },
    },
}

Mas nesse exemplo, como o WEP é um protocolo que faz parte do padrão ieee802_11, então faz sentido criar um diretório protocol/ dentro de dot11/ , e dentro dele conter a mesma estrutura de arquivos e diretórios do diretório dot11/ . 
Dessa forma, o mais provável é que quem vai ter a estrutura de credentials geralmente vai ser apenas protocolos de segurança em si, e não protocolos de comunicação que utilizam protocolos de segurança.
get_credentials(protocol, address) essa função vai obter a estrutura credentials do protocolo e dispositivo correto.


Lembrando que por criar o diretório protocol/ dentro de dot11/ , isso significa que futuros parsers de outros protocolos ou outros padrões, podem criar um diretório protocol/ caso possua protocolos relacionados a ele.
