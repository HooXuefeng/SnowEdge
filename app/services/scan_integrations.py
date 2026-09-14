import base64
import json
import httpx
from urllib.parse import urlsplit
from ..models import AppPreference
from .secret_store import encrypt_json, decrypt_json
from .network_routes import httpx_proxy_url
from .utility_tools import parse_target
from ..scope import target_in_scope

PROVIDERS={'fofa':'https://fofa.info/api/v1/search/all','hunter':'https://hunter.qianxin.com/openApi/search',
           'quake':'https://quake.360.net/api/v3/search/quake_service','shodan':'https://api.shodan.io/shodan/host/search'}


def pref(db,key):
    row=db.query(AppPreference).filter_by(key=key).first()
    if not row:row=AppPreference(key=key,value_json='{}');db.add(row);db.flush()
    return row


def secret_config(db,key):
    row=db.query(AppPreference).filter_by(key=key).first()
    return decrypt_json(row.secret_encrypted,{}) if row else {}


def save_config(db,key,data):
    row=pref(db,key);row.secret_encrypted=encrypt_json(data);db.commit()


async def mapping_search(db,project,provider,query,page=1):
    if provider not in PROVIDERS:raise ValueError('未知测绘平台。')
    config=secret_config(db,'mapping:'+provider)
    key=config.get('api_key','')
    if not key:raise ValueError('请先配置该平台 API Key。')
    if not query or len(query)>2000 or not 1<=page<=20:raise ValueError('查询或页码无效。')
    params={};headers={};body=None
    if provider=='fofa':params={'key':key,'email':config.get('email',''),'qbase64':base64.b64encode(query.encode()).decode(),'fields':'host,ip,port,protocol,title','size':100,'page':page}
    elif provider=='hunter':params={'api-key':key,'search':base64.urlsafe_b64encode(query.encode()).decode(),'page':page,'page_size':100,'is_web':3}
    elif provider=='quake':headers={'X-QuakeToken':key};body={'query':query,'start':(page-1)*100,'size':100}
    else:params={'key':key,'query':query,'page':page,'minify':'true'}
    async with httpx.AsyncClient(timeout=20,proxy=httpx_proxy_url(db,project.id),trust_env=False,follow_redirects=False) as client:
        try:
            async with client.stream('POST' if body else 'GET',PROVIDERS[provider],params=params,headers=headers,json=body) as response:
                if response.status_code!=200:raise ValueError(f'平台返回 HTTP {response.status_code}，请检查权限或额度。')
                content=bytearray()
                async for chunk in response.aiter_bytes():
                    content.extend(chunk)
                    if len(content)>5000000:raise ValueError('平台响应超过 5 MB。')
                try:data=json.loads(content)
                except ValueError:raise ValueError('平台返回的内容不是有效 JSON。') from None
        except httpx.HTTPError as exc:raise ValueError(f'平台连接失败：{type(exc).__name__}') from None
    if not isinstance(data,dict):raise ValueError('平台响应格式不正确。')
    if data.get('error') or (provider=='hunter' and data.get('code')!=200) or (provider=='quake' and str(data.get('code')) not in {'0','200'}):
        raise ValueError('平台拒绝查询，请检查语法、API 权限和额度。')
    if provider=='fofa':
        results=data.get('results') or []
        if not isinstance(results,list):raise ValueError('平台资产列表格式不正确。')
        raw=[dict(zip(['host','ip','port','protocol','title'],r)) for r in results if isinstance(r,list)]
    elif provider=='hunter':
        container=data.get('data') or {}
        if not isinstance(container,dict):raise ValueError('平台资产列表格式不正确。')
        raw=container.get('arr') or []
    elif provider=='quake':raw=data.get('data',[])
    else:raw=data.get('matches',[])
    rows=[]
    if not isinstance(raw,list):raise ValueError('平台资产列表格式不正确。')
    scope=project.scope_text.splitlines()
    for row in raw[:100]:
        if not isinstance(row,dict):continue
        service=row.get('service') if isinstance(row.get('service'),dict) else {}
        web=service.get('http') if isinstance(service.get('http'),dict) else row.get('http') if isinstance(row.get('http'),dict) else {}
        host=row.get('url') or row.get('host') or web.get('host') or row.get('ip_str') or row.get('ip')
        if not host:continue
        try:name,_,url=parse_target(str(host))
        except ValueError:continue
        title=row.get('title') or row.get('web_title') or web.get('title','')
        port=row.get('port') or urlsplit(url).port
        try:port=int(port) if port else None
        except (ValueError,TypeError):continue
        if port and not 1<=port<=65535:continue
        if '://' not in str(host):
            protocol=service.get('name') or row.get('protocol')
            scheme='http' if protocol=='http' or port in {80,8080,8000,8888} else 'https'
            authority=f'[{name}]' if ':' in name else name
            url=f'{scheme}://{authority}'+(f':{port}' if port else '')+'/'
        rows.append({'target':url[:1000],'host':name,'port':port,'title':str(title)[:200],'in_scope':target_in_scope(name,scope)})
    return {'provider':provider,'page':page,'items':rows,'note':'仅查询平台已有数据；结果不会自动扫描。范围外目标禁止导入扫描。'}
