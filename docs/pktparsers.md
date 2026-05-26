## Ideias e implementações futuras 
Esta seção contém percepções coletadas durante o desenvolvimento; nenhuma está garantida para ser implementada. Elas exigem revisão e pesquisa adicional.

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
* Substituir todos os hardcodes de tamanhos, struct formats e nomes de chaves de resultado de parsers, por constantes. Atualizar todos os formats de struct, para utilizarem valores de constantes definidas, dessa forma irá eliminar boa parte dos hardcodes, irá melhorar a legibilidade, e significativamente a escalabilidade.
* A estrutura de dissect config será: {"global": {"crypt": {}, "parse": {}, "analysis": {}}, nome_do_protocolo_ou_dlt: {"crypt": {}, "parse": {], "analysis": {}} }}
* Ajustar funções para irem de acordo com dissect config.
* Testar criptografia de payloads funciona.
* Testar descriptografia de payloads funciona.
* Revisar os resultados dos parsers, comparar com o resultado do wireshark, e corrigir os parsers se necessário.
* Analisar módelo de desenvolvimento de dissector/parser de wireshark, e ver como ele compara ao meu, e ver no que posso melhorar.
* adicionar funções/cache de filtros, exemplo: permitir o usuário filtrar por frame ou device (AP WPA2.

* pktparsers irá fornecer manter uma forte separação de responsabilidades. 
Dissect lida apenas com packet, offset e DissectConfig, DissectConfig irá ter apenas variáveis e dados relacionados à parse, analise de parse e preferencias de protocolo, como o que e o que não parsear ou analisar, etc...
Por isso, ele fornece módulos auxiliares relacionado ao projeto, que podem ser utilizados por outros programas e módulos, como:
io.py: que fornece funções de leitura ou escrita em arquivos, de acordo com os formatos suportado:
pcap
pcapng
erf
json
jsonl

* Como vai funciona DissectConfig:
DissectConfig é passado para a classe Dissec ou é gerado automaticamente por ela.
Essa config é passada para TrafficContext e ParseContext.
Provavelmente as funções de parse e subparse irão acessar o objeto ParseContext.config para verificar se alguma configuração/preferencia de protocolo específica está configurada. Algo como:
Possível estrutura de DissectConfig:

```python
if get_nested(f"{IEE802_11_RADIO}.assume_fcs", ctx.config):
   detect_fcs()
```

## Melhorias e correções durante o projeto (pode ser utilizado no release)
* Exemplo

## Referências

## Desabafos durante todo o projeto kkkkkkk
* Todo esse projeto tenta replicar ao máximo o modelo OSI, para deixar o mais didático possível.
* Estou tentando ao máximo remover hardcodes, mas em protocolos de padrões de comunicação, muitas vezes não dá para fugir de formatos e números arbitrários.
