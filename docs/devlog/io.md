OutputConfig vai o ser dataclass que mantém as configurações de output padrão que o usuário definiu ou não.

Preciso implementar:
Permitir definir compressão de arquivos para todos os formatos suportados.
Em PacketWriter, permitir parar a escrita de pacotes após processar uma certa quantidade de pacotes.
Em PacketWriter, permitir criar um novo arquivo em um formato específico e com um padrão de filepath específico, a cada quantidade de tempo específico, ou a cada quantidade específica de bytes que um arquivo de saída atingir.
