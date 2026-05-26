Existe um possível problema relacionado a análise de pacotes e gerenciamento de estruturas de dados que utilizam um endereço mac, ip ou qualquer outro endereço utilizado para identificar um dispositivo na rede, o problema é justamente a possibilidade de dois ou mais dispositivos terem o mesmo endereço (ip ou mac ou qualquer outro na rede), isso pode atrapalhar muito a descriptografia de pacotes através da obtenção da chave de descriptografia de um dispositivo, através do endereço dele. Isso também se aplica aos devices dentro de cada protocolo em protocols_data, preciso saber como vou lidar com isso. Isso pode ser usado até mesmo como ataque, caso o atacante saiba que há alguém está utilizando um software que utiliza o pktparsers como módulo de dissecação.

Por isso as funções insert_item() e get_nested() são necessárias. Mas acho que o problema continua, principalmente quando se trata de funções analyzer de um protocolo ou DLT específica, que gerencias a estrutura Device específica do protocolo, dentro de protocols_data que está dentro de device entry, que está dentro de devices em traffic summary.


Na verdade, o traffic summary retornado pela função "dissect" serve justamente como um log que cada dispositivo detectado na rede no momento da analise. Então mesmo que surja um dispositivo malicioso na rede tentando falsificar ou manipular os resultados de traffic summary, ele irá conseguir, mas antes, houve um resultado de traffic summary com o dispositivo original. Exemplo:
AP detectado, bssid usado como chave para dict da entry dele.
Após isso surge um dispositivo malicioso com o mesmo BSSID mas inserindo informações falsas, como ssid etc...
isso irá adicicionar mais um ssid na lista de ssids nas esrutura dot11 device.
