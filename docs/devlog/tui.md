Vou utiliza textual. E módulos auxiliares que facilitem caso necessário.

Algumas questões e problemas:

Atualmente, estou com a ideia de fazer com pktparsers disponibilize alguns módulos auxiliares, como:
Além de fornecer uma interface TUI básica para interpretar todo o resultado de dissect, e exibi-los em uma interface semelhante ao do termshark, mas voltada apenas para analise de pacotes. Dessa forma, um sniffer poderia utilizar esses módulos de interface TUI de pktparsers, como componentes/adapters/widgets da sua interface de sniff.

Ou seja, pktparsers iria fornecer módulos auxiliares para interfaces TUI.
Exemplo:

Componente de interface de sniff
┌─ toolbar ──────────────────────────────────────────────────────┐
│ Interface: wlan0 | [▶ Capture] [■ Stop] | Ch: 6 (2.4GHz) | Hop│
│ Store filter: [___________________] Display: [________________]│
└────────────────────────────────────────────────────────────────┘

Componente de interface de pktparsers:
Obs: ainda iria ter uma outras partes, tudo o que permite configurar ou manipular me relação à dissecação, parsing e analise.
[File] [Options] [Misc]
[Filter: ]
┌─ packet list (70% da tela) ────────────────────────────────────┐
│ # │ Time  │ Src          │ Dst          │ Proto │ Info         │
│ 1 │ 0.000 │ aa:bb:...    │ ff:ff:...    │ Beacon│ SSID="X" ch6 │
│ 2 │ 0.001 │ ...          │ ...          │ EAPOL │ Msg 1 of 4   │
└────────────────────────────────────────────────────────────────┘
┌─ tree view (30% esquerda) ────┐ ┌─ hexdump (30% direita) ──────┐
│ ▼ Radiotap Header             │ │ 0000  00 00 1a 00 2f 48 00  │
│   ├ Signal: -31 dBm           │ │ 0007  00 1b 64 14 18 00 00  │
│   └ Channel: 2412 MHz         │ │ [campo selecionado destacado]│
│ ▼ MAC Header                  │ │                              │
│   ├ Type: Data (QoS)          │ └──────────────────────────────┘
│   └ BSSID: 2e:c9:fb:6b:0c:d1 │
└───────────────────────────────┘

Detalhes de funcionamento: 
[File]:
    [Open file]: (todos os formatos suportados pelo pktparsers)
    [Export]: (todos os formatos suportados pelo pktparsers)
    [Merge]: (todos os formatos suportados pelo pktparsers)
    [Load config]: Salva em json ou jsonl (se o usuário quiser) e atualiza AppConfig/PktparsersConfig (ainda tenho que decidir o nome) que atualiza dissect config internamente, reiniciando o dissector.
    [Close]: Fecha arquivo sendo analisando no momento.

[Options]:
   Hexdump view (Enable/Disable) []
   Tree View (Enable/Disable) []
   Edit (Enable/Disable) []
   [Config]:
       [Dissect config]:
           [parse]:
               Lista de todos os protocolos suportados pelo pktparsers, cada um é entrypoint para suas opções.
           [crypt]: Lista de todos os protocolos suportados pelo pktparser, cada um é entrypoint para suas opções, ainda estou pensando na estrutura.
           [analysis]: Configurações de funções ou operações relacionadas à analysis ou analyzers.
       [Output config]:
            Ainda estou pensando na estrutura.
       [Save config]: Salva em json ou jsonl (se o usuário quiser) e atualiza AppConfig/PktparsersConfig (ainda tenho que decidir o nome) que atualiza dissect config internamente, reiniciando o dissector.

[Misc]: terá opções como Dark/Light theme, provavelmente não será necessário no momento, pois o próprio textual já implementa toggle theme.

Se Edit setá Enabled, um widget/interface ao lado de Hexdump view ou em algum bom lugar que faça bom uso da resolução da tela, irá ser aberto para permitir o usuário editar o pacote.
O widget de edição de pacote será algo assim:
[File]: Mesmas opções do [File] que descrevi anteriormente.
O usuário altera __metadata__ e fmt do 

O usuário sempre poderá redmimensionar os componentes/widgets como Hexdump viwer, PacketTree etc.. 

Tudo o que minha interface de PacketTree irá precisar ter para bater de frente com o wireshark:
Clicar direito ou teclar alguma tecla ou atalho para abrir menu para opções do campo:
    Copy:
        All visible items
        All visible selected Tree items
        Description
        Summary
        Field name
        Value
        As filter
        As Hexstream

Clicar direito ou teclar alguma tecla ou atalho para abrir menu para opções do pacote:
    Copy:
        As Hexstream
    Export:
        As pcap
        As pcapng
        Todos os formatos suportados pela a aplicação.

Exemplo de como o widget/tela de Traffic summary irá ficar:

Traffic Summary:
    iface/ifname/interface: None ou wlp0s20f3 é opcional/complementar

    Date: 2026-05-15 hora

    DLT (Data Link Type): DLT_IEEE802_11_RADIO

    Devices:
        ID (hash(mac ou ip, depende do endereço relacionado à PDU da DLT principal de captura)) -> DeviceEntry ficando como: {
            first seen: 12.00
            last seen: 20:00
            protocols data:  
            annotations: 
        }
    Annotations:
        Diferentes tipos de entries indicando outras informações a partir da analise de tráfego.

Exemplo de estrutura que o wireshark fornece:

===============================================================================================================================================
Wireless LAN Statistics - wlp0s20f3:
Address  Channel  SSID  Percent Packets  Percent Retry  Retry  Pkts Sent  Pkts Received  Probe Reqs  Probe Resp  Auths  Deauths  Other  Comment
-----------------------------------------------------------------------------------------------------------------------------------------------
28:87:2e:9f:f6:85        0  <Broadcast>         0.061805       0.000000      0          0              1           0           0      0        0      0  Unknown
28:87:ba:9f:f6:85        1  404wi-fi indisponível        98.269468       0.125786      2       1360            188           0          42      0        0      0  Unknown
48:22:54:7e:69:48        1  Gisele Matos         0.185414       0.000000      0          3              0           0           0      0        0      0         
4a:22:54:4e:69:48        1  <Broadcast>         0.432633       0.000000      0          7              0           0           0      0        0      0         
4a:22:54:5e:69:48        1  <Broadcast>         0.309023       0.000000      0          5              0           0           0      0        0      0         
80:1f:65:5a:67:95        0  <Broadcast>         0.061805       0.000000      0          0              1           0           0      0        0      0  Unknown
ee:81:9c:85:b0:dc        0  <Broadcast>         0.185414       0.000000      0          0              3           0           0      0        0      0  Unknown
ee:81:9c:85:b0:df        0  <Broadcast>         0.309023       0.000000      0          0              5           0           0      0        0      0  Unknown
ff:ff:ff:ff:ff:ff        1  <Broadcast>         0.185414       0.000000      0          0              0           3           0      0        0      0         
-----------------------------------------------------------------------------------------------------------------------------------------------


Sobre interface de build de pacotes brutos (tem haver com as próprias interfaces de Hexdump, PacketsList e ProtocolTree):

Quero utilizar essa forma:
Utilizar tamplates de frames/pacotes brutos de diferentes tipos de acordo com o protocolo ou DLT. Para obter o resultado "parsed" através do próprio resultado de do Dissector.

Pois o resultado de parsed de Dissector ou diretamente de um parse protocolo, já contém __metadata__ mais do que o suficiente para criar um TUI completa para a visualização binária, construação e reconstrução do frame/pacote bruto, a partir do próprio dict parsed ou json com os pacotes/frame parseados.

Utilizar a própria função que já tenho "iter_from_json" ou outras no arquivo files.py do módulo cli-core (o contexto dele está no arquivo cli-core-repomix.md) e passar uma callback para ele ler cada entry dict do json, e fazer a mesma analise que é feita nos dict "parsed". O detalhe de funcionamento é:

Se fmt for menor que um value específico sendo editado, então automaticamente o fmt desse value vira f"{len(value)s". Cada value analisado será adicionado em uma lista, e cada fmt analisado será adicionado em outra lista, ou algo assim, pois talvez não seja necessário ser realmente em lista. Mas no fim, só será necessário utilizar a função struct.pack. Se fmt for maior que o prório value, então é adicionado um padding até o dar tamanho total do fmt.

O ponto-chave é a ideia de que as chaves do json/dict serão usadas apenas para o usuário ter um ponto de referencia sobre onde ou o qual valor está alterando no frame/pacote bruto, essas chaves são usadas para fornecer um interface legivel para auxiliar o usuário a modificar os campos e valores, e até adicionar outras chaves e valores, mas internamente ele vai estar modificando de forma bruta o frame/pacote, pois internamente iremos apenas fazer struct.pack() para todos os valores através dos fmts.

Template raw bytes
        ↓
  Dissector.dissect()
        ↓
  parsed result (com _metadata_ em cada campo)
        ↓
  TUI itera a árvore — gera widgets a partir de _metadata_.tokens + value
        ↓
  Usuário edita values na TUI
        ↓
  build_from_parsed(edited_parsed) → struct.pack por token
        ↓
  raw bytes


Como vou implementar os tamplates:
Cada DLT ou protocolo, irá ter seu arquivo .json com vários pacotes/frames brutos, esse mesmo arquivo é usado para fazer testes automatizado de Dissect e filter engine, por isso ele sempre será bem rico e com vários tipos de pacotes/frames brutos.
Quando o usuário abrir ele, ele poderá utilizar o próprio filter da TUI para filtrar o tipo de pacote/frame específico que ele quer editar, e assim ele pode começar a edição e salvar em um json ou qualquer outro formato suportado.

É importante lembrar:
Se o usuário mudar para o widget/componente de edição de frame, o packet tree e hexdump viwer focam no pacote sendo editado.

Vou ter que de alguma forma, permitir o app principal, como o framesniff, adicionar um widget ou algo assim na tela de edição de pacotes, para assim, permitir o usuário utilizar uma função como send_raw de framesniff para enviar o pacote bruto editado, pela rede. 

Vou ter que pensar no(s) mecanismos que vou ter que utilizar para permitir com que funções como [Save Config] salvem o arquivo json de configuração em path específico.
pois caso o contrário, uma aplicação como framesniff que utiliza o pktparsers como engine de análise, irá ter incosistências como:
geração de framesniff-config.json e criação de pktparsers-config.json o que pode confundir o usuário, e fazer com que framesniff dependa do conhecimento do filename "pktparsers" para carregar ele caso precise. Tudo isso porque pktparsers poderá ser executado tanto como cli como tui. Além disso vem outro problema, uma aplicação como framesniff que depende de pktparsers, não deve deixar com que pktparsers crie seus próprios arquivos e diretórios no sistema do usuário, como se fosse a aplicação principal sendo executada.


Analise o arquivo de contexto repomix, ele contém o contexto mais atualizado do projeto, analise principalmente os arquivos corep/parsing.py .
Analise também o arquivo ARCHITECTURE.md, pode estar um pouco desatualizado, então se baseie mais no arquivo repomix .

O chatgpt sugeriu:
Sua arquitetura está ficando MUITO sólida.
E depois de analisar seu utils.py, _metadata_, tokens, sizes, unpack() e a estrutura do ParseContext, sinceramente:

você já possui quase toda a infraestrutura necessária para:

visualização binária;
edição semântica;
reconstrução;
highlighting por offset;
hexdump interativo;
builders reversíveis;
traffic analysis;
export/import;
packet crafting.

O ponto mais forte da sua arquitetura atual é este:

_metadata_ = {
    "start": start_offset,
    "end": end_offset,
    "length": length,
    "raw": raw_hex,
    "fmt": fmt,
    "tokens": tokens,
    "sizes": sizes,
    "size": size
}

Isso é EXTREMAMENTE poderoso.

Porque isso transforma qualquer parse em:

AST binária;
mapa de offsets;
mapa de tokens struct;
mapa de ranges;
fonte para TUI;
fonte para builders.

Você praticamente criou uma IR (Intermediate Representation) para protocolos.

Sobre sua ideia de usar parsed/json como backend

Isso está corretíssimo.

Você NÃO deveria editar bytes diretamente.

Você deveria editar:

{
    "field_name": {
        "value": ...,
        "_metadata_": ...
    }
}

E depois:

packet
