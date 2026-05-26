Analise o arquivo pktparsers-repomix.md que anexei. Para obter todo o contexto do projeto.

Como lidar com a criação e carregamento de PktparsersConfig/AppConfig (ainda tenho que decidir o nome), mas por enquanto vou chamar de AppConfig pois remete ao ponto de vista do módulo/framework.
A estrutura de dissect config será: {"global": {"crypt": {}, "parse": {}, "analysis": {}}, nome_do_protocolo_ou_dlt: {"crypt": {}, "parse": {], "analysis": {}} }}
Não vou utilizar dataclasses em nenhuma estrutura, talvez apenas para AppConfig.
Atualizei o nome da variável "frame" para "buffer" em ParseContext.
Ao gerar código lembre:
Não defina nomes de chaves de forma hardcoded em dicts, defina elas antes em definitions.py específico daquele protocolo ou DLT, caso ela não exista em algum outro definitions.py anterior.
Siga a estrutura de arquivos que defini, apenas ajuste complete/desenvolva as funções que estão incompletas, de acordo com a ideia.
Atualmente estou seguindo a ideia de que cada definitions de protocolo ou DLT específica, irá ter uma variável "CONFIG" que utilizará suas funções de make_ para gerar a CONFIG que será atribuida à estrutura de entry de protocolo ou DLT. Ou seja, fazendo com que o regsitry.py faça por exemplo: make_dlt_entry(todos os outro argumentos padrões da estrutura DltEntry (que será convertida para uma função make_), config=dot11_radio.definitions.CONFIG).
Logo logo vou ter que criar uma função em core/crypt.py que lê qualquer arquivo dentro dos formatos suportados em io/, e gerar um AppConfig com credentials de cada protocolo ou DLT. Não estou dizendo que vai ser exatamente assim, mas a ideia é essa.


Forma 1:
return {
    GLOBAL: make_config(), # utiliza make_ de core/crypt.py core/parsing.py e core/analysis.py
    dlt: registry.DLT,
    protocol: registry.PROTOCOL
}

Forma 1.1:
A forma 3.1 faz sentido pois segue uma ideia:
utiliza registry.py como referencia para gerar e expor globalmente as entry(s) de configurações de cada DLT e PROTOCOLO. E forneceria apenas as dicts de configs, ao contrário da forma 3 que iria fazer particamente um dump completo de registry.py, incluindo dados desncessários.
Com a forma 3.1 posso definit alguma funções em dissect context, para auxiliar obter dados específicos da estrutura dissect config.

dlts_configs = {k: v.get(CONFIG) for k, v in registry.DLT.items() if CONFIG in v} 
protocols_configs = {k: v.get(CONFIG) for k, v in registry.DLT.items() if CONFIG in v}

return {
    GLOBAL: make_config(), # utiliza make_ de core/crypt.py core/parsing.py e core/analysis.py
    dlt: dlts_config,
    protocol: protocols_config
}


Logo log vou ter que lidar com:
Otimização: Cache de Chaves.

A derivação de chaves criptográficas (como calcular a PTK a partir de uma PSK de WPA2 e o handshake do EAPOL) é extremamente custosa para a CPU. Executar operações de força bruta ou cálculos complexos repetidamente em um sistema Void Linux dedicado a ferramentas de rede vai gerar gargalos severos durante a captura ao vivo.

A lista de crypt em dissect config guarda os segredos estáticos (senhas do usuário, PMKs conhecidas). No entanto, as chaves de sessão derivadas (PTK, GTK) devem viver de forma efêmera.

No seu analisador (dot11/dlt/ieee802_11_radio/analyzers/summary.py), quando um 4-way handshake for parseado, você utiliza a senha plana do DissectConfig.crypt, deriva a chave e a salva nas anotações do dispositivo alvo dentro de credentials:
