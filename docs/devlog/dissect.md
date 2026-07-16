Criar ParseContext dentro da função dissect() de Dissector.
O resultado de parse de protocolo irá se alocado em ParseContext.result utilizando sua chave de dicionário relacionado ao seu protocolo específico do resultado. 
Função de parse de protocolo e função de parse DLT, irão verificar se TrafficContext existe antes de tentar chamar função "summarizer" e "analyzer". Isso permitirá com que as funções parse de protocolo e até mesmo de DLT possam continuar sendo utilizadas de forma independente de DissectContext ou TrafficContext, dependendo apenas de ParseContext.

Exemplo de ParseContext.result de um parse de DLT:
{
    "rt_hdr": {
        "_metadata_": {"start": 0, "end": 26, "raw": "00001b64..."},
        "parsed": {"version": 0, "flags": {"bad_fcs": False}, "channel": 6}
    },
    "ieee802_11": {
        "mac_hdr": {"parsed": {"addr2": {"addr": "aa:bb:cc:dd:ee:ff"}}},
        "body": {"llc": {"parsed": {"protocol_type": 0x888e, "name": "eapol"}}}
    }
}

Exemplo para DLT_IEEE802_11_RADIO de dict "devices" em TrafficContext.summary:
{
    "devices": { # aqui ainda é TrafficContext.summary
        "aa:bb:cc:dd:ee:ff": { # aqui é device_entry
            "first_seen": 1234567890.123,
            "protocols_data": {"ieee802_11": {"role": "STA", "frames_sent": 542}, "ip": {}, "tcp": {}, "tls": {}, "http": {}},
            "annotations": {"security": "WPA2/PSK"}
        }
    }
}

Analyzers de protocolos ou DLTs alimentam protocols_data de um device_entry específico obtido através do método get_addresses de ParseContext, que retorna os endereços raizes do pacote sendo parseado no momento. Esses endereços identificam os dispositivos sendo analisados no momento, e permitem atualizar a entrada de cada um deles em TrafficContext.summary.get("devices"). A função get_addresses obtém a função address_extractor do dissector raiz, que pode ser um dissector de DLT ou de protocolo. 
ParseContext.get_addresses retorna {"sa": , "da": , "ta": , "ra": ,}

dissector_id permite que o Dissector possa utilizar tanto um dissector de protocolo quanto um dissector de DLT como raiz do processo de dissecação/parse e analysis.

Em vez de ParseContext depender de Dissector.current() diretamente — o que criaria acoplamento entre parsing.py e dissect.py —, a solução mais limpa é ParseContext aceitar um dissector_id que pode ser por exemplo: ieee802_11, DLT_IEEE802_11 ou 127.
