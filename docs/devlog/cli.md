Preciso criar uma CLI básica, baseando-se na próprio arquivo tests.py.
Anexei o arquivo repomix com o contexto atualizado do projeto.

Minha estrutura está assim agora:
[gus@voidlinux ~/Documents/pktparsers/src/pktparsers (development)]$ ls
__init__.py  __main__.py  __pycache__  app  cli  common  core  tui
[gus@voidlinux ~/Documents/pktparsers/src/pktparsers (development)]$ ls app/
app.py  bootstrap.py  context.py  services
[gus@voidlinux ~/Documents/pktparsers/src/pktparsers (development)]$ ls app/services/
dissect.py  io.py

A ideia é que tui e cli possam consumir a mesma interface "app.py" chamar as operações disponíveis em services/ .
services/ possui módulos com as funções que aplicação fornece, construidas através de módulos que o sistema fornece, exemplo:
services/io.py utiliza funções de common/io.py para criar suas funcionalidades.
app.py importa os módulos de domínio/recurso dentro de services/ e vai adicionando eles em Operations de app.py.
