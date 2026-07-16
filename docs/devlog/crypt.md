Utilizar uma forma parecida com a do wireshark, ou seja, sem obrigar o usuário a definir uma credentials para um cliente especifico (mac, ip etc...), pois esse mapeamente será interno.
A diferença será que as cifras de credentials serão criadas/inseridas dentro da própria estrutura de credentials do protocolo de autenticação em si, não no protocolo de comunicação que utiliza esse protocolo de autenticação.

Prós:
Didático, fará com que o usuário entenda os diferentes tipos de chaves de cada protocolo de autenticação, e entender a diferença entre protocolos.
Desacopla estruturas conceitualmente pertencentes à protocolos de autenticação, de protocolos de comunicação.                          
O mapeamento de chave para dispositivo é feito internamente, para evitar erros de mapeamento pelo usuário.
Passa a ideia de que os mecanismos de crypt e estruturas de credentials são flexiveis, essa flexibilidade serve também para manter uma maior facilidade/simplicidade/praticidade para com o usuário.

Contras:
Um pouco menos simples e prático em comparação com a forma que o wireshark utiliza, o wireshark acopla configuração de cifras de diferentes protocolo de autenticação, à protocolos de comunicação como ieee802.11.

Explicações:
O que o usuário sabe e o que o engine precisa são coisas diferentes. O usuário sabe a chave (psk, tk, msk). O engine precisa mapeá-la a um dispositivo. Essa distinção é o critério correto para decidir.
