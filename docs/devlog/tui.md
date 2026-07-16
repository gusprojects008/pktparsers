Utilizar textual e outro módulos auxiliares para desenvolver a TUI.

pktparsers irá disponibilizar módulos auxiliares que vão poder ser reutilizados em diferentes aplicações, para montar diferentes interfaces.
pktparsers irá fornecer uma interface TUI básica para interpretar todo o resultado de dissect, e irá exibi-los em uma interface semelhante ao do termshark, mas voltada apenas para análise de pacotes. Dessa forma, uma outra aplicação como um sniffer, poderá utilizar esses módulos que compõem a interface TUI principal de pktparsers, como componentes/widgets para a interface de sniff da aplicação principal, que no caso seria a aplicação "framesniff" por exemplo.

Ou seja, pktparsers iria fornecer módulos auxiliares para interfaces TUI.

Exemplo:
Widget de interface de sniff (próprio da aplicação principal "framesniff")
┌─ toolbar ────────────────────────────────────────────────────── ┐
│ Interface: wlan0 | [▶ Capture] [■ Stop] | Ch: 6 (2.4GHz) | Hop  │
└──────────────────────────────────────────────────────────────── ┘

Widgets de interface de pktparsers:
Obs: ainda iria ter uma outras partes, tudo o que permite configurar ou manipular em relação à dissecação, parsing e análise.
Os widgets estão enumaerados (1, 2, 3 ...).
1: File/Ops/Misc [[File] [Options] [Misc]]
2: Filter [Filter: store: [] display: []]
3: packet list
┌─ packet list (70% da tela) ────────────────────────────────────┐
│ # │ Time  │ Src          │ Dst          │ Proto │ Info         │
│ 1 │ 0.000 │ aa:bb:...    │ ff:ff:...    │ Beacon│ SSID="X" ch6 │
│ 2 │ 0.001 │ ...          │ ...          │ EAPOL │ Msg 1 of 4   │
└────────────────────────────────────────────────────────────────┘
4: tree view                      5: hexdump viwer/navigator
┌─ tree view (30% esquerda) ────┐ ┌─ hexdump (30% direita) ──────┐
│ ▼ Radiotap Header             │ │ 0000  00 00 1a 00 2f 48 00  │
│   ├ Signal: -31 dBm           │ │ 0007  00 1b 64 14 18 00 00  │
│   └ Channel: 2412 MHz         │ │ [campo selecionado destacado]│
│ ▼ MAC Header                  │ │                              │
│   ├ Type: Data (QoS)          │ └──────────────────────────────┘
│   └ BSSID: 2e:c9:fb:6b:0c:d1  │
└───────────────────────────────┘

Acho que será possível que framesniff possa importar a interface padrão de pktparsers, e assim, precisará apenas implementar algumas lógicas de funcionamento entre as duas aplicações, como:
Não permitir que o usuário salve o arquivo (utilizando as opções em [File]) enquanto a captura estiver em andamente, será necessário encerrar a captura para poder salvar o arquivo.

Acho que o widget de "Filter" ficará na própria interface de pktparsers, e assim, a instância da interface de pktparsers fornecer métodos como update_filters para permitir com que aplicações como framesniff possam atualizar os filtros de pktparsers. O problema é que acho que o componente de "Filter" talvez tenha que ser um widget para ser utilizado de forma independente, pois ele possui um "store" filter, que está relacionado à IO, dessa forma, talvez faça mais sentido com que 
Ou será que posso resolver isso implementando uma classe utilitária chamada "FilterEngine" que internamente cria uma instância PacketsWriter que lida com store filter ou algo assim. 
Dessa forma, o widget de Filter cria uma instância ou consome (não sei) a classe FilterEngine. Lembrando que não precisamos nos preucupar com configurações de output para PacketsWriter, pois PacketsWriter já obtém e consome OutputConfig de AppConfig.
Preciso de ajuda pois não entendo sobre interfaces TUI, quero implemntar isso da forma mais profissional, modular e escalável.

Detalhes de funcionamento:
[File]:
    [Open file]: (todos os formatos suportados pelo pktparsers)
    [Export]: (todos os formatos suportados pelo pktparsers)
    [Merge]: (todos os formatos suportados pelo pktparsers)
    [Load config]: Salva em json ou jsonl (se o usuário quiser) e atualiza AppConfig (ainda tenho que decidir o nome) que atualiza dissect config internamente, reiniciando o Dissector.
    [Close]: Fecha arquivo sendo analisando no momento (pergunta se o usuário não quer salvar antes).

[Options]:
   [Reload all]: irá reiniciar/atualizar a interface e re-processar todos os pacotes novamente utilizando a nova config de dissector.
   Hexdump view (Enable/Disable) []
   Tree View (Enable/Disable) []
   Packet edition (Enable/Disable) []
   [Config]:
       [Dissect config]:
           [global]: Configurações globais relacionadas à parse, crypt e analysis.
               [parse]
               [crypt]: 
                   [opção aleatória exemplo]
                   [credentials]
               [analysis]: Configurações de funções ou operações relacionadas à analysis ou analyzers.
           [Protocols]: Editar configurações de protocolos
               [Exemplo: para IEEE802.1X]:
                   [parse]
                   [crypt]:
                       [Enable decryption] (Enable/Disable)
                       [credentials]:
                           [Add key]: Permite o usuário adicionar as chaves de criptografia e descriptografia. Poderá receber um arquivo de captura (em qualquer formato suportado) com pacotes ou frames de handshake, e irá criar automaticamente uma entrada de credentials para cada dispositivo identificado em cached, para isso, geralmente será necessário passar a chaves de descriptografia desses handshakes ou algo assim (se necessário), como uma PSK.
                           O usuário irá adicionar quantas chaves de descriptografia ele quiser, pois internamente o pktparsers irá manter em cache, o mapeamente de cada chave de descriptografia associada a um dispositivo/station/ap.
                       [Config]: Configurações específicas que serão aplicadas em funções de crypt relacionadas à ieee802.11 ou ieee802.1x
                   [analysis]: Configurações de funções ou operações relacionadas à analysis ou analyzers.
           [DLTs]: Editar configurações de DLTs
       [Output config]:
            Ainda estou pensando na estrutura.
       [Save config]: Salva em json ou jsonl (se o usuário quiser) e atualiza AppConfig, e assim reiniciando o dissector config quando o dissector for reiniciado.

[Misc]: terá opções como Dark/Light theme, provavelmente não será necessário no momento, pois o próprio textual já implementa toggle theme.

Se packet edition estiver Enabled, um widget/interface ao lado de Hexdump view ou em algum bom lugar que faça bom uso da resolução da tela, irá ser aberto para permitir o usuário editar o pacote. Se definir disabled ela irá fechar.
O widget de edição de pacote será algo assim:
[File]: Mesmas opções do [File] que descrevi anteriormente.
O usuário altera __metadata__ e fmt do 
O usuário sempre poderá redmimensionar os componentes/widgets como Hexdump viwer, PacketTree etc.. 

O widget de hexdump view, PacketTree etc...  irá ser atualizado de acordo com o campo selecionado do pacote específico, por exemplo: se o usuário clicou em um campo do widget de edição de pacote, então hexdump view e PacketTree irão ser atualizados para interpretar aquele pacote específico sendo editado. etc...

Todos os widgets poderão ser extendidos por interfaces/aplicações TUI principais, só não sei qual é a melhor forma de fazer isso, não sei se com herança de classe ou hooks de extensão, ou alguma outra forma melhor, quero uma forma profissional de resolver isso.

Vou ter que de alguma forma, permitir o app principal, como o framesniff, adicionar um widget para funções como "send-raw" que permite razer um resend daquele de um pacote específico selecionado atualmente em PacketList/PacketTree, dessa forma, permitindo reenviar um pacote editado ou apenas capturado. E permitir o usuário passar um arquivo de captura (em qualquer um dos formatos suportados), passar os parâmetros que send-raw aceita, e fazer o reenvio desses pacotes.

Tudo o que minha interface de PacketTree irá precisar ter:
Clicar direito ou teclar alguma tecla ou atalho para abrir menu para opções do campo:
    crypt/decrypt: Permite o usuário escolher manualmente uma chave de criptografia ou descriptografia. Se o usuário realizar crypt, então automaticamente irá abrir ao lado, um widget de edição de pacote/frame com o a parte específica criptografada. 
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
        Todos os formatos suportados por pktparsers.

Exemplo de como o widget/tela de Traffic summary irá ficar algo como:
Traffic Summary:
    iface/ifname/interface: None ou wlp0s20f3 é opcional/complementar

    Date: 2026-05-15 hora

    Dissector ID: DLT_IEEE802_11_RADIO

    Devices:
        ID (mac ou ip, depende do dissector_id inicial) 
            first seen: 12.00
            last seen: 20:00
            protocols data:  
            annotations: 
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


Quero utilizar essa forma:
Utilizar tamplates de frames/pacotes brutos de diferentes tipos de acordo com o protocolo ou DLT. Para obter o resultado "parsed" através do próprio resultado de do Dissector.

Pois o resultado de parsed de Dissector ou diretamente de um parse protocolo, já contém __metadata__ mais do que o suficiente para criar um TUI completa para a visualização binária, construação e reconstrução do frame/pacote bruto, a partir do próprio dict parsed ou json com os pacotes/frame parseados.

Utilizar a própria função que já tenho "iter_from_json" ou outras no arquivo files.py do módulo cli-core (o contexto dele está no arquivo cli-core-repomix.md) e passar uma callback para ele ler cada entry dict do json, e fazer a mesma análise que é feita nos dict "parsed". 

O detalhe de funcionamento é:
Se fmt for menor que um value específico sendo editado, então automaticamente o fmt desse value vira f"{len(value)s". Cada value analisado será adicionado em uma lista, e cada fmt analisado será adicionado em outra lista, ou algo assim, pois talvez não seja necessário ser realmente em lista. Mas no fim, só será necessário utilizar a função struct.pack. Se fmt for maior que o prório value, então é adicionado um padding até o dar tamanho total do fmt.

O ponto-chave é a ideia de que as chaves do json/dict serão usadas apenas para o usuário ter um ponto de referencia sobre onde ou o qual valor está alterando no frame/pacote bruto, essas chaves são usadas para fornecer um interface legivel para auxiliar o usuário a modificar os campos e valores, e até adicionar outras chaves e valores, mas internamente ele vai estar modificando de forma bruta o frame/pacote, pois internamente iremos apenas fazer struct.pack() para todos os valores através dos fmts.

Clicar direito ou teclar alguma tecla ou atalho para abrir menu para opções do campo:
    crypt/decrypt: Permite o usuário escolher manualmente uma chave de criptografia ou descriptografia.

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
