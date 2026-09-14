"""Explicit opt-in provider boundary. No remote provider ships enabled."""
from typing import Protocol
class HashLookupProvider(Protocol):
    name: str
    def lookup(self,value:str)->dict: ...
providers:dict[str,HashLookupProvider]={}
def lookup(name,value,confirmed):
    if not confirmed:raise ValueError('联网前必须明确确认允许发送当前 Hash')
    if name not in providers:raise ValueError('未配置联网查询服务；没有发送任何数据')
    return providers[name].lookup(value)
