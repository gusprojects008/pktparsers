## Ideias e implementações futuras 
Esta seção contém percepções coletadas durante o desenvolvimento; nenhuma está garantida para ser implementada. Elas exigem revisão e pesquisa adicional.

* Exemplo

## O que está faltando? para corrigir / adicionar
* Revisar os resultados dos parsers, comparar com o resultado do wireshark, e corrigir os parsers se necessário.
* Melhorar nomes de variáveis e strings
* Atualizar todos os formats de struct, para utilizarem valores de constantes definidas, dessa forma irá eliminar boa parte dos hardcodes, irá melhorar a legibilidade, e significativamente a escalabilidade.
* Adicionar verificações adicionais de detecção de erros.
* Adicionar uma seção de todos os artigos e manuais que explicam e definem os padrões dos frames, incluindo seus campos valores etc...
* Melhorar filtro, permitir com que o usuário possa passar diretamente o nome de um tipo de frame, e assim obter o filtro que corresponde a ele.
* Substituir todos os hardcodes de tamanhos, struct formats e nomes de chaves de resultado de parsers, por constantes.

## Local para anotar as melhorias e correções durante o projeto (pode ser utilizado no release)
* Exemplo

## Padrões do projeto que é aconselhavel/recomendável serem seguidos
* Utilizar a função "fail" apenas quando for realmente um erro que pode afetar todo restante do parse.
* Para nomes de chaves de valores em dicionários como "parsed", é recomendado que sigam o mesmo padrão de outros analisadores/sniffers de rede como scapy e wireshark, abreviados sempre que possível para facilitar o filtro do usuário, a documentação de filtro irá ser criada justamente para evitar confusões.
* Em funções utilitárias que utilizam um parser diretamente, utilizar get_nested sempre que precisar obter valores em parsed.
* Sempre montar dict ou fazer operações com valores, em memória, armazenando em variáveis antes de seres passada para o dict final, ou seja, não realizar lógica inline no dict. Isso se aplica principalmente para parsers internos usados como argumento de callback para a função unpack.
* Seguir padrão da função unpack, ou seja, sempre que precisar interpretar um valor desempacotado por struct.unpack ou struct.unpack_from passar o parser interno que irá receber os valores binários desempacotados, e irá retornar o dict com resultado interpretador por ele.
* Não realizar conversões ou transformações hexadecimais nos resultados de parsed, só _add_metadata faz isso. O encoder json em finish_capture já faz esse trabalho, e filter_engine detecta se o valor é bytes, se for, faz apenas uma conversão local para ser utilizada em operações de comparação. Com exceção de conversão bytes_for_mac ou bytes_for_oui.

## Explicações e esclarecimentos
* Todo esse projeto tenta replicar ao máximo o modelo OSI, para deixar o mais didático possível.
* Estou tentando ao máximo remover hardcodes, mas em protocolos de padrões de comunicação, muitas vezes não dá para fugir de formatos e números arbitrários.
* namespaces do próprio programa: parsed, _metadata_, raw, summary, counter.

* diretórios como: traffic/ analyses/ e summary/, contém módulos e estruturas usadas para gerar estruturas de dados que descrevem semanticamente os resultados de parsers. Cada DLT conterá um diretório de summary/.

* O módulo parse.py contém a função de parse principal de uma DLT ou camada específica de rede específica, exemplo: dot11/ é diretório que representa o padrão ieee80211. Dentro dele contém "parse.py", pois ele está relacionado à DLT_IEEE802_11. Mas existe a DLT_IEEE802_11_RADIO, por isso, existe: "dot11/radio/", esse diretório "radio/" está relacionado à DLT_IEEE802_11_RADIO, dentro dele existe: "parse.py" pois é o parse de uma outra DLT. Outro exemplo: "l3/" representa a camada 3 do modelo OSI, nessa camada existe os protocolos arp, ip etc..., então dentro de "l3/" tem parse.py, que contém a função de parse principal relacionada à todos os protocolos da camada 3. A função ficaria parse(protocol: str | int) protocol pode ser "ip", ethertype ou dsap. Ou seja, quando me refiro a parse principal, me refiro a um parse relacionado a uma DLT ou camada de rede específica, esse parse irá abrir um ParseContext, ter uma função de summarize o summary de ParseContext, e ter uma função que irá analisar todos os summary(s) acumulados na variável "summaries" de DissectContext, esse summary(s) os próprios summarys criados em cada função de parse principal, ou seja, baseada na DLT ou camada de rede específica.

* Poderia extender unpack para suportar callback "descriptor", que recebe os próprios values desempacotados, para interpretar e retornarum dict de description, ou uma estrutura de summary. Mas acho que não é necessário, pois "summary" de ParseContext já pode manter esses/descriptions/resumos.

* subparsers alimentam "ctx.summary" de "ParseContext" dinamicamente. A razão prática mais importante: cada subparser já tem os dados em mãos no momento certo, sem precisar renavegar o parsed depois.

* Dict para summaries internos, não dataclass. Summaries de subparsers são estruturas abertas que variam. Dataclass aqui seria rigidez desnecessária. Mas esses dicts de summary irão manter o mesmo nome de chaves do result do subparser específico naquele momento, para mnater compatibilidade entre filtros.

* relationships pertence ao protocolo, não ao DeviceEntry global.

* Se por exemplo, um frame tiver dois mac headers, não será possível adicionar o outro mac header no summary de parse context, até mesmo porque a função de parse de dot11 quebraria antes disso.

* Criar módulos através de critérios como: common/ contém diretórios e módulos com constantes, funções e estruturas globais, que são usadas durante todo o projeto.

# Decisões de arquitetura pendentes:

## Referências

## Desabafos durante todo o projeto kkkkkkk
