## Ideias e implementações futuras 
Esta seção contém percepções coletadas durante o desenvolvimento; nenhuma está garantida para ser implementada. Elas exigem revisão e pesquisa adicional.

* Ao implementar a função de signal_analyzer, ela deve receber ParseContext.result para extrair o máximo de valores e campos possíveis e necessários para fazer uma boa estimativa da distância aproximada com o alvo.
* Basear no código fonte de parsers do wireshark para melhorar meus parsers.
* Provavelmente irei ter reestruturar toda essa estrutura de diretórios em layers/ voltada para para parsers de protocolos, que está orientada à camadas do modelo OSI, pois está limitando a escalabilidade do projeto, que pode se tornar um dissector de vários protocolo e DLTs independentes, pois nem toda DLT está relacionada à um protocolo específico. Então preciso definir a estrutura mais profissional e escalável. 
* Provavelmente irei ter que um classe Context maior para todo o módulo, ela conterá uma lista ou dict com todos os contextos abertos a partir dela, era manterá do pktparsers config.
* Opção para os usuários enviarem pacotes devidamente criptografados para que os APs os aceitem.
* Permitir que os usuários forneçam um arquivo JSON com as informações necessárias para descriptografar frames protegidos.
* Adicionar suporte a parse de: FTP, SSH,
* Desenvolver uma TUI para sniffing (semelhante ao termshark).
* Desenvolver uma TUI para edição de frames de forma semelhante ao mitmproxy.
* Implementar um módulo para geração/edição de frames/pacotes.
* implementar editor de conteúdo de pacotes e frames assim como o mitmproxy, usar "select-editor" abrir o editor com o conteúdo do frame, quando o usuário salvar alterar o conteúdo e permitir ele realizar o replay.
* Se inspirar no mitmproxy para permitir o usuário desenvolver seus próprio plugins/scripts para manipular a captura e comportamento da interface e trafégo.
* Permitir o usuário cerregar arquivo com padrões de filtro de frames.
* Para geração de gráficos e análises com base nos resultados de Dissect. 
* Documentação para expressões de filtro; recomendar que os usuários capturem frames com `sniff` e analisem a saída JSON.
* Utilizar GitHub Docs.

## O que está faltando? para corrigir / adicionar
* Corrigir como registry vai definir config de ProtocolEntry: ou DltEntry.
* Substituir todos os hardcodes de tamanhos, struct formats e nomes de chaves de resultado de parsers, por constantes. Atualizar todos os formats de struct, para utilizarem valores de constantes definidas, dessa forma irá eliminar boa parte dos hardcodes, irá melhorar a legibilidade, e significativamente a escalabilidade.
* A estrutura de dissect config será: {"global": {"crypt": {}, "parse": {}, "analysis": {}}, nome_do_protocolo_ou_dlt: {"crypt": {}, "parse": {}, "analysis": {}}}
* Ajustar funções para irem de acordo com dissect config.
* Testar criptografia de payloads funciona.
* Testar descriptografia de payloads funciona.
* Revisar os resultados dos parsers, comparar com o resultado do wireshark, e corrigir os parsers se necessário.
* Analisar módelo de desenvolvimento de dissector/parser de wireshark, e ver como ele compara ao meu, e ver no que posso melhorar.
* adicionar funções/cache de filtros, exemplo: permitir o usuário filtrar por frame ou device (AP WPA2.

## Melhorias e correções durante o projeto (pode ser utilizado no release)
* Exemplo

## Referências

## Desabafos durante todo o projeto kkkkkkk
* Estou tentando ao máximo remover hardcodes, mas em protocolos de padrões de comunicação, muitas vezes não dá para fugir de formatos e números arbitrários.
* Percebi que aprendi na prática como a visão de projeto muda de acordo com novos conhecimentos, acabei de entender o porque não vai ser possível continuar com a ideia de tentar desenvolver todo projeto com uma arquitetura voltada ao modelo OSI, o que era algo que eu mais admirava no projeto, pois assim ele se mantia mais didático. Mas percebo que meu módulo/framework está limitado à ideia de apenas parsers de rede organizados de acordo com o modelo OSI em core/layers , e que ele pode crescer e escalar muito mais, então irei ter mudar a ideia de ter layers/ dentro de core/ .
