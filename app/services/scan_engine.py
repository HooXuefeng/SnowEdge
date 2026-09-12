"""Checkpointed bounded scan stages sharing the persistent job queue."""
import asyncio
import base64
import ipaddress
import json
import re
import socket
import hashlib
import secrets
from urllib.parse import urlsplit, urljoin, unquote
import httpx
from ..models import Asset, Endpoint, Evidence, Service, TechnologyFingerprint
from ..scope import target_in_scope
from .utility_tools import parse_target
from .network_routes import httpx_proxy_url, record_route_use
from .evidence_safety import redact_object, redact_url
from .evidence_chain import ensure_evidence_integrity
from .fingerprint_engine import analyze_http_observation
from .finding_service import create_finding
from .scan_rules import project_rules, matches
from ..scanners.web_discovery import DiscoveryParser, _extract_routes

DEFAULT_PORTS='21,22,25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443'
STAGES={'ports','http','rules','discovery','subdomains'}


def parse_ports(text):
    ports=set()
    for token in text.split(','):
        if '-' in token:
            a,b=map(int,token.strip().split('-'))
            if not 1<=a<=b<=65535 or b-a>1023:raise ValueError('端口范围无效或超过 1024 个。')
            ports.update(range(a,b+1))
        else:ports.add(int(token))
    if not ports or len(ports)>1024 or min(ports)<1 or max(ports)>65535:raise ValueError('请选择 1–1024 个有效端口。')
    return sorted(ports)


def parse_targets(text, rules):
    targets=[]
    for line in text.splitlines():
        line=line.strip()
        if not line:continue
        values=[line]
        if '/' in line and '://' not in line:
            try:
                net=ipaddress.ip_network(line,strict=False)
                if net.num_addresses>256:raise ValueError('单个网段最多 256 个地址。')
                values=[str(ip) for ip in net.hosts()]
            except ValueError as exc:
                raise ValueError(f'网段无效：{line}') from exc
        for value in values:
            host,_,url=parse_target(value)
            if not re.fullmatch(r'[A-Za-z0-9.\-:]+',host):raise ValueError('目标主机无效。')
            if not target_in_scope(host,rules):raise ValueError(f'目标不在授权范围：{host}')
            if urlsplit(url).query:raise ValueError('扫描入口不接收查询参数；请在请求工作台处理。')
            normalized=url if '://' in value or urlsplit(url).port is not None else host
            if normalized not in targets:targets.append(normalized)
            if len(targets)>256:raise ValueError('单次最多 256 个目标。')
    if not targets:raise ValueError('请提供至少一个目标。')
    return targets


async def open_tunnel(host, port, proxy=None):
    if not proxy:return await asyncio.open_connection(host,port)
    p=urlsplit(proxy)
    reader,writer=await asyncio.open_connection(p.hostname,p.port)
    try:
        if p.scheme=='http':
            authority=f'[{host}]:{port}' if ':' in host else f'{host}:{port}'
            auth=''
            if p.username:
                token=base64.b64encode(f'{unquote(p.username)}:{unquote(p.password or "")}'.encode()).decode()
                auth=f'Proxy-Authorization: Basic {token}\r\n'
            writer.write(f'CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n{auth}\r\n'.encode());await writer.drain()
            header=await reader.readuntil(b'\r\n\r\n')
            if header.split(b' ',2)[1]!=b'200':raise OSError('代理拒绝 CONNECT')
        elif p.scheme=='socks5':
            writer.write(b'\x05\x02\x00\x02' if p.username else b'\x05\x01\x00');await writer.drain()
            version,method=await reader.readexactly(2)
            if version!=5 or method not in (0,2):raise OSError('SOCKS5 协商失败')
            if method==2:
                user=unquote(p.username or '').encode();password=unquote(p.password or '').encode()
                if len(user)>255 or len(password)>255:raise ValueError('代理凭据过长')
                writer.write(b'\x01'+bytes([len(user)])+user+bytes([len(password)])+password);await writer.drain()
                if await reader.readexactly(2)!=b'\x01\x00':raise OSError('代理认证失败')
            name=host.encode('idna')
            if len(name)>255:raise ValueError('主机名过长')
            writer.write(b'\x05\x01\x00\x03'+bytes([len(name)])+name+port.to_bytes(2,'big'));await writer.drain()
            ver,rep,_,kind=await reader.readexactly(4)
            if ver!=5 or rep:raise OSError('SOCKS5 连接失败')
            length=4 if kind==1 else 16 if kind==4 else (await reader.readexactly(1))[0] if kind==3 else 0
            if not length:raise OSError('SOCKS5 响应无效')
            await reader.readexactly(length+2)
        else:raise ValueError('不支持的代理类型')
        return reader,writer
    except BaseException:
        writer.close()
        raise


async def tcp_probe(host, port, proxy):
    writer=None
    try:
        reader,writer=await asyncio.wait_for(open_tunnel(host,port,proxy),3)
        banner=b''
        try:banner=await asyncio.wait_for(reader.read(512),.4)
        except asyncio.TimeoutError:pass
        text=banner.decode('utf-8','replace')
        name='unknown'
        for prefix,service in [('SSH-','ssh'),('220','smtp/ftp'),('+OK','pop3'),('* OK','imap')]:
            if text.startswith(prefix):name=service;break
        if name=='smtp/ftp':
            if 'smtp' in text.lower():name='smtp'
            elif 'ftp' in text.lower():name='ftp'
        if len(banner)>5 and banner[3:5]==b'\x00\x0a':name='mysql'
        if not banner and port==6379:
            writer.write(b'*1\r\n$4\r\nPING\r\n');await writer.drain()
            try:
                banner=await asyncio.wait_for(reader.read(512),1)
                text=banner.decode('utf-8','replace')
                if text.startswith(('+PONG','-NOAUTH','-DENIED')):name='redis'
            except asyncio.TimeoutError:pass
        hint={80:'http',443:'https',22:'ssh',21:'ftp',25:'smtp',3306:'mysql',5432:'postgresql',6379:'redis',3389:'rdp',8080:'http',8443:'https'}.get(port,'unknown')
        return {'port':port,'state':'open','service':name,'port_hint':hint,'banner':text[:300],'identification':'banner' if name!='unknown' else 'port-hint-only'}
    except (OSError,asyncio.TimeoutError):return {'port':port,'state':'closed_or_filtered'}
    finally:
        if writer:
            writer.close()


async def http_probe(url, scope, proxy=None, method='GET', auth=None):
    parsed=urlsplit(url)
    if parsed.scheme not in {'http','https'} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('只接受不含凭据的 HTTP / HTTPS 地址。')
    if not target_in_scope(url,scope):raise ValueError('请求地址不在当前授权范围。')
    result={'url':url,'final_url':url,'ok':False}
    try:
        async with httpx.AsyncClient(proxy=proxy,trust_env=False,timeout=8,follow_redirects=False,verify=auth is not None) as client:
            async with client.stream(method,url,headers={'User-Agent':'SnowEdge/1.0 Authorized-Assessment'},auth=auth) as response:
                body=bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk[:max(0,200000-len(body))])
                    if len(body)>=200000:break
                text=body.decode('utf-8','replace')
                title=re.search(r'<title[^>]*>(.*?)</title>',text,re.I|re.S)
                result.update(ok=True,status_code=response.status_code,headers=dict(response.headers),body=text,title=re.sub(r'\s+',' ',title[1]).strip()[:200] if title else '',truncated=len(body)>=200000)
    except httpx.HTTPError as exc:result['error']=type(exc).__name__
    return result


def save_evidence(db,job,kind,data,parent=None):
    content=json.dumps(redact_object(data)[0],ensure_ascii=False)
    existing=db.query(Evidence).filter_by(job_id=job.id,kind=kind,content=content,parent_evidence_id=parent).first()
    if existing:return existing
    row=Evidence(project_id=job.project_id,job_id=job.id,source_type='scan_engine',source_id=job.id,kind=kind,
                 parent_evidence_id=parent,content=content,redaction_state='redacted')
    db.add(row);db.commit();ensure_evidence_integrity(db,row);return row


async def run_scan(db,job,project,payload):
    state=json.loads(job.result_json or '{}')
    state.setdefault('items',[]);state.setdefault('cursor',0)
    scope=lambda:[r.strip() for r in project.scope_text.splitlines() if r.strip()]
    targets=payload['targets'];ports=payload['ports'];stages=set(payload['stages'])
    lease=job.lease_token
    current_host=None
    async def boundary():
        db.refresh(job);db.refresh(project)
        if job.lease_token!=lease:raise RuntimeError('执行租约已失效。')
        if job.status in {'pause_requested','cancel_requested'}:return False
        if job.status!='running':raise RuntimeError('执行租约已失效。')
        if current_host and not target_in_scope(current_host,scope()):raise ValueError('授权范围已变化，扫描停止。')
        return True
    for index in range(state['cursor'],len(targets)):
        if not await boundary():return state
        target=targets[index];host,input_port,input_url=parse_target(target)
        current_host=host
        if not target_in_scope(host,scope()):raise ValueError('授权范围已变化，扫描停止。')
        proxy=httpx_proxy_url(db,project.id)
        record_route_use(db,project.id)
        asset=db.query(Asset).filter_by(project_id=project.id,target=host).first()
        if not asset:asset=Asset(project_id=project.id,target=host,kind='host');db.add(asset);db.commit()
        item={'target':target,'services':[],'http':[],'findings':[],'discoveries':[],'status':'done'}
        if 'ports' in stages:
            target_ports=sorted(set(ports+[input_port])) if '://' in target else ports
            for offset in range(0,len(target_ports),16):
                if not await boundary():return state
                probes=await asyncio.gather(*(tcp_probe(host,p,proxy) for p in target_ports[offset:offset+16]))
                for probe in probes:
                    if probe['state']!='open':continue
                    item['services'].append(probe)
                    row=db.query(Service).filter_by(asset_id=asset.id,port=probe['port'],protocol='tcp').first()
                    if not row:row=Service(asset_id=asset.id,port=probe['port'],protocol='tcp');db.add(row)
                    row.name=probe['service'];row.banner=probe['banner']
                db.commit()
            save_evidence(db,job,'scan_ports',{'target':host,'services':item['services'],'tested_ports':target_ports})
        urls=[input_url] if '://' in target else [f'{scheme}://'+(f'[{host}]' if ':' in host else host)+f':{port}/' for port,scheme in [(80,'http'),(443,'https')]]
        for service in item['services']:
            p=service['port']
            schemes=[service['port_hint']] if service['port_hint'] in {'http','https'} else ['http','https'] if service['service']=='unknown' else []
            for scheme in schemes:
                url=f'{scheme}://'+(f'[{host}]' if ':' in host else host)+f':{p}/'
                if url not in urls:urls.append(url)
        if stages & {'http','rules','discovery'}:
            item['http_candidates_skipped']=max(0,len(urls)-64)
            for url in urls[:64]:
                if not await boundary():return state
                obs=await http_probe(url,scope(),proxy)
                if not obs['ok']:
                    item['http'].append({'url':redact_url(url),'error':obs.get('error','未响应')});continue
                safe={k:v for k,v in obs.items() if k!='body'}
                evidence=save_evidence(db,job,'scan_http',safe)
                endpoint=db.query(Endpoint).filter_by(asset_id=asset.id,url=url,method='GET').first()
                if not endpoint:endpoint=Endpoint(asset_id=asset.id,url=url,method='GET',source='scan_engine');db.add(endpoint)
                endpoint.status_code=obs['status_code'];db.commit()
                parsed_url=urlsplit(url);observed_port=parsed_url.port or (443 if parsed_url.scheme=='https' else 80)
                service=db.query(Service).filter_by(asset_id=asset.id,port=observed_port,protocol='tcp').first()
                if not service:service=Service(asset_id=asset.id,port=observed_port,protocol='tcp');db.add(service)
                service.name=parsed_url.scheme;service.banner=obs['headers'].get('server','')[:300];db.commit()
                for entry in item['services']:
                    if entry['port']==observed_port:entry.update(service=parsed_url.scheme,identification='http-response')
                analyze_http_observation(db,project,obs,evidence_source=f'evidence:{evidence.id}')
                products=sorted({r.product for r in db.query(TechnologyFingerprint).filter_by(project_id=project.id,asset_id=asset.id,evidence_source=f'evidence:{evidence.id}').all()})
                item['http'].append({'url':redact_url(url),'status':obs['status_code'],'title':obs['title'],'products':products,'evidence_id':evidence.id})
                if 'rules' in stages:
                    for rule in project_rules(db,project.id):
                        if rule.get('products') and not set(rule['products']) & set(products):continue
                        for path in rule['paths']:
                            if not await boundary():return state
                            check_url=(url.rstrip('/')+path) if rule.get('path-base')=='base' else urljoin(url,path)
                            check=await http_probe(check_url,scope(),proxy,rule.get('method','GET'))
                            record=save_evidence(db,job,'poc_check',{'rule':rule['id'],'url':check_url,'matched':matches(rule,check),'status':check.get('status_code'),'products':products,'conditions':rule['matchers'],'response_sha256':hashlib.sha256(check.get('body','').encode()).hexdigest(),'error':check.get('error')},evidence.id)
                            if matches(rule,check):
                                if record.finding_id:
                                    item['findings'].append(record.finding_id);continue
                                finding=create_finding(db,project.id,rule.get('name',rule['id']),rule.get('severity','info'),check_url,
                                  '声明式规则匹配成功，需结合业务语义复核。','核对是否应向匿名用户开放，限制不必要的访问。','scan_rule',
                                  'poc_match',{'rule':rule['id'],'evidence_id':record.id,'status':check.get('status_code'),'matchers':rule['matchers']},finding_state='candidate')
                                record.finding_id=finding.id;db.commit();ensure_evidence_integrity(db,record)
                                item['findings'].append(finding.id)
                if 'discovery' in stages:
                    parser=DiscoveryParser();parser.feed(obs['body'])
                    discovered=[urljoin(url,p) for p in parser.links+parser.scripts]
                    for script in list(dict.fromkeys(urljoin(url,p) for p in parser.scripts))[:10]:
                        if not await boundary():return state
                        if not target_in_scope(script,scope()):continue
                        js=await http_probe(script,scope(),proxy)
                        if js.get('ok'):discovered.extend(urljoin(url,r['path']) for r in _extract_routes(js['body'],script,scope()))
                    baseline=None
                    if payload.get('paths'):
                        if not await boundary():return state
                        baseline=await http_probe(urljoin(url,'/__snowedge_missing_'+secrets.token_hex(8)),scope(),proxy)
                    for path in payload.get('paths',[]):
                        if not await boundary():return state
                        probe=await http_probe(urljoin(url,path),scope(),proxy)
                        soft404=baseline and baseline.get('ok') and (probe.get('status_code'),probe.get('body'))==(baseline.get('status_code'),baseline.get('body'))
                        if probe.get('ok') and probe['status_code'] not in {404,410} and not soft404:discovered.append(urljoin(url,path))
                    for candidate in list(dict.fromkeys(discovered))[:200]:
                        parsed=urlsplit(candidate)
                        if parsed.scheme not in {'http','https'} or parsed.username or parsed.password or not target_in_scope(candidate,scope()):continue
                        candidate=redact_url(candidate)
                        if not db.query(Endpoint).filter_by(asset_id=asset.id,url=candidate,method='GET').first():db.add(Endpoint(asset_id=asset.id,url=candidate,method='GET',source='scan_discovery'))
                        item['discoveries'].append(redact_url(candidate))
                    db.commit();save_evidence(db,job,'scan_discovery',{'url':url,'candidates':item['discoveries'],'note':'发现候选不等于漏洞；目录状态可能来自统一错误页。'},evidence.id)
        if 'subdomains' in stages:
            item['subdomains']=[]
            if proxy:raise ValueError('DNS 子域名解析使用系统解析器，代理模式下不会静默直连，请单独使用直连项目。')
            wildcard=set()
            wildcard_name=f'snowedge-{secrets.token_hex(8)}.{host}'
            if target_in_scope(wildcard_name,scope()):
                if not await boundary():return state
                try:
                    records=await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(wildcard_name,None,type=socket.SOCK_STREAM),3)
                    wildcard={r[4][0] for r in records}
                except (OSError,asyncio.TimeoutError):pass
            for prefix in payload.get('prefixes',[]):
                if not await boundary():return state
                name=f'{prefix}.{host}'
                if not target_in_scope(name,scope()):continue
                try:
                    addresses=await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(name,None,type=socket.SOCK_STREAM),3)
                    resolved={r[4][0] for r in addresses}
                    item['subdomains'].append({'host':name,'addresses':sorted(resolved),'wildcard_candidate':bool(wildcard & resolved)})
                    if wildcard & resolved:continue
                    if not db.query(Asset).filter_by(project_id=project.id,target=name).first():db.add(Asset(project_id=project.id,target=name,kind='domain'));db.commit()
                except (OSError,asyncio.TimeoutError):pass
            save_evidence(db,job,'scan_subdomains',item['subdomains'])
        if not item['services'] and not any('status' in h for h in item['http']) and not item.get('subdomains'):
            item['status']='unreachable';item['note']='已完成探测，未获得响应；不能据此断言主机离线。'
        state['items'].append(item);state['cursor']=index+1;state['total']=len(targets)
        item['findings']=list(dict.fromkeys(item['findings']))
        job.result_json=json.dumps(redact_object(state)[0],ensure_ascii=False);db.commit()
    return state
