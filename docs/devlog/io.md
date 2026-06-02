Provavelmente irei ter que criar um dataclass PktparsersConfig, ele irá manter um dissect config e OutputConfig.
OutputConfig vai o ser dataclass que mantém as configurações de output padrão que o usuário definiu ou não.

Preciso implementar:
Permitir definir compressão de arquivos para todos os formatos suportados.
Em PacketWriter, permitir parar a escrita de pacotes após processar uma certa quantidade de pacotes.
Em PacketWriter, permitir criar um novo arquivo em um formato específico e com um padrão de filepath específico, a cada quantidade de tempo específico, ou a cada quantidade de bytes específica que um arquivo de saída atingir.
