Forma 1:

A estrutura "credentials" deve estar preparada para ter várias dicts com a estrutura "credentials" para cada dispositivo, ou seja, para cada mac ou ip, dependendo do protocolo de autenticação. Mas não irei impedir o usuário de por o que quiser para identificar um dispositivo à uma estrutura credentials de um protocolo de autenticação ou DLT específica.

A função de parse no body.py dentro de parsers/ do protocolo ou dlt específica, provavelmente será responsável por:
Verificar se o pacote é protegido, através de protected de mac_header por exemplo.
Se for protegido, obtém a função de decrypt do protocolo ou dlt específica, essa decrypt está nas tabelas de dispatch PROTOCOL ou DLT em dissectors/registry.py. Após isso, a função de decrypt ou a funçao em body.py (ainda tenho que decidir), através do dict de config do protocolo ou DLT específica, obtido através de dissect config que foi obtido através do contexto do app/framework ou passado diretamente para DissectContext, obtém o dict "credentials" específico do dispositivo através do id que o usuário definiu para a estrutura "credentials" dentro de "crypt" do config do protocolo ou DLT específica. 

Lembrando que o idenficador do dispositivo não deve ficar acoplado ao protocolo, e onde ele geralmente é utilizado, quero dar a liberdade ao usuário permitindo que ele defina um ip, mac ou qualquer coisa para idenficar as credenticiais específicas do dispositivo em um protocolo específico.

Na prática, provavelmente poderá haver uma pequena força bruta inicial, pois irei ter que obter as credentials de cada protocolo de autenticação que o ieee802.11 pode utilizar, e nisso pode acontecer de que dois protocolo de autenticação diferentes contenham uma entry de credentials para o mesmo dispositivo (identificado através do mac, ip ou qualquer coisa), e caso isso aconteça, terei que testar as chaves de ambos os credentials, e depois fazer o cache das ou da chave correta para o dispositivo.

Futuramente, provavelmente irei ter que disponibilizar um função de merge de diferentes arquivos de ssl key log, para juntar todos em um só, e dessa forma, manter com ideia de que "credentials" de TLS irá manter apenas o fullpath do arquivo de ssl key log, e todas as session keys serão obtidas a partir do fullpath. 

Ficando assim exemplo:
    "eap": {
        "aa:bb:cc:dd:ee:ff": {          # BSSID do AP associado
            "msk": "",
        },
    },

    # radius precisa do shared secret para verificar/descriptografar atributos
    "radius": {
        "192.168.1.100": {              # IP do servidor RADIUS
            "msk": "",
        },
        "00:00:00:00:00:00": {              # IP do servidor RADIUS
            "msk": "",
        },
    },

    "esp": {},
    "tls": {
        # keylog format (NSS Key Log) — suporta Wireshark e outros
        "keylog_file": "/path/to/sslkeylog.log",
    },
}

Mas nesse exemplo, como o WEP é um protocolo que faz parte do padrão ieee802_11, então faz sentido criar um diretório protocol/ dentro de dot11/ , e dentro dele conter a mesma estrutura de arquivos e diretórios do diretório dot11/ . 
Dessa forma, o mais provável é que quem vai ter a estrutura de credentials geralmente vai ser apenas protocolos de segurança em si, e não protocolos de comunicação que utilizam protocolos de segurança.
get_credentials(protocol, address) essa função vai obter a estrutura credentials do protocolo e dispositivo correto.


Lembrando que por criar o diretório protocol/ dentro de dot11/ , isso significa que futuros parsers de outros protocolos ou outros padrões, podem criar um diretório protocol/ caso possua protocolos relacionados a ele.


Como cada protocolo ou DLT específica irá ter a estrutura de config: {"parse": {}, "analysis": {}, "crypt": {"credentials": {}, "config": {}}}
Na TUI irei permitir o usuário inserir entry(s) de credentials de cada dispositivo manualmente ou editar as credentials que foram carregadas no momento em que o usuário escolheu carregar um arquivo de captura (qualquer um dos formatos suportados) para gerar a estrutura de credentials para aquele protocolo ou DLT específica. Então vou precisar de uma função analisadora de captura, e geradora de dicts credentials para o protocolo ou DLT sendo configurada no momento, vou ter que exigir alguma chave antes, no caso exemplo: eapol.

Prós:
Evitar ter que realizar muita tentativa e erro inicial para realizar caching.
Se fizer dessa forma, então acho que poderei seguir com esse padrão para todos os outros protocolos. Esse padrão é fácil de lembrar/entender.
Facilita o usuário escolher chaves de criptografia/descriptografia específicas de dispositivo, para a funcionalidade que permite o usuário criptografar/descriptografar o campo específico de um pacote/frame.

Contras:
Um pouco menos simples e prático em relação à forma 2.
Está sujeito a erros humanos, como no momento da digitação do endereço mac e a inserção da sua chave.
E se o usuário conhecer a chave mas não conhecer o mac ou ip do dispositivo?



Forma 2:
Forma utilizada pelo wireshark:
Apenas alguns protocolos de comunicação específicos como ieee802.11 utilizam realmente uma estrutura de "credentials", essa estrutura de credentials será própria para o ieee802.11, permitindo adicionar apenas as chaves de descriptografia de protcolos de segurança utilizados/suportados por ele, como:
wpa-psk
wpa-pwd
wep
tk
msk

Prós:
Muito mais simples e prático.
É importante lembrar que quero permitir o usuário carregar previamente arquivo de captura com handshakes, e assim, popular previamente credentials com as TKs derivadas.
Essa forma irá manter as chaves de criptografia e descriptografia de forma "solta", pois o mapeamento/caching delas será feito internamente, testando e associando elas aos dispositivos corretos através de tentativa e erro inicial.

Forma 3:
Utilizar uma forma parecida com a do wireshark, ou seja, sem obrigar o usuário a definir uma credentials para um cliente especifico (mac, ip etc...), pois esse mapeamente será interno.
A diferença será que as chaves de credentials serão criadas/inseridas dentro da própria estrutura de credentials do protocolo de autênticação em si, não no protocolo de comunicaçõo que utilizar o protocolo de autênticação. Isso fara com que o próprio 

Prós:
Didático, fará com que o usuário entenda os diferentes tipos de chaves de cada protocolo de autênticação, e entender a diferença entre protocolos.
O mapeamento de chave para dispositivo é feito internamente, para evitar erros de mapeamento feitos pelo usuário.

Contras:
Sei que protocolo wep irá ter uma estrutura de credentials suportando uma chave "wep", EAPOL provavelmente irá abrigar:
wpa-psk
wpa-pwd
tk

Mas provavelmente, a credentials de eap e radius irá se repetir, sendo basicamente apenas algo como:
{
    "credentials": 
         "msk": ,
}

A forma 2 e 3, indicam uma flexibilidade na estrutura de credentials e na forma como descriptografia é feita de acordo com o protocolo de comunicação, essa flexibilidade serve também para manter uma maior facilidade/simplicidade/praticidade para com o usuário.
A forma 2 e 3 possui um contra em comum, mas acho que pode não ser tão ruim assim:
Fica complicado quando o usuário quiser criptografar ou descriptografar um campo específico do pacote ou frame manualmente. Mas talvez isso possa ser resolvido através da amostragem do mapeamento/caching interno de chaves que o pktparsers fez, caso houver.

Entre a forma 1, 2 e 3, qual é a melhor? 
