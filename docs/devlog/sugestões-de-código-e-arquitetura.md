## Caso PROTOCOL de regsitry.py seja: {"família/domínio": {"proto1": DissectorEntry}} ou {"protocolo sem domínio/família": DissectorEntry}
```python
def _resolve(registry_dict: dict, key: str):
    if "." in key:
        domain, name = key.split(".", 1)
        domain_entry = registry_dict.get(domain)
        if isinstance(domain_entry, dict):
            return domain_entry.get(name)
        return None
    return registry_dict.get(key)  # protocolo solto (arp, wapi...)

def get_protocol(key: str) -> DissectorEntry | None:
    return _resolve(PROTOCOL, key)

def get_protocol_parser(key: str):
    entry = get_protocol(key)
    return entry.parser if entry else None
```
