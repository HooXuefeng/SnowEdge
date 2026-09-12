"""Declarative HTTP checks with an explicitly validated Nuclei HTTP subset."""
import json
import re
import yaml
from ..models import AppPreference

BUILTINS = [
    {'id':'directory-listing','name':'目录索引公开','severity':'medium','products':[],
     'paths':['/'],'matchers':[{'type':'status','status':[200]},{'type':'word','words':['Index of /'],'part':'body'}]},
    {'id':'nginx-status','name':'Nginx 状态页面公开','severity':'low','products':['Nginx'],
     'paths':['/nginx_status'],'matchers':[{'type':'status','status':[200]},{'type':'word','words':['Active connections:','server accepts handled requests'],'condition':'and'}]},
    {'id':'prometheus-metrics','name':'监控指标公开','severity':'medium','products':[],
     'paths':['/metrics'],'matchers':[{'type':'status','status':[200]},{'type':'word','words':['# HELP ','# TYPE '],'condition':'and'}]},
]


def validate_rule(rule):
    if not isinstance(rule,dict): raise ValueError('规则必须是对象。')
    if set(rule)-{'id','name','severity','products','paths','method','matchers','matchers-condition','path-base'}:
        raise ValueError('规则包含不支持的字段。')
    if not isinstance(rule.get('id'),str) or not re.fullmatch(r'[a-zA-Z0-9_\-]{1,80}',rule['id']): raise ValueError('规则 id 无效。')
    if not isinstance(rule.get('name',''),str) or len(rule.get('name',''))>200:raise ValueError('规则名称无效。')
    if rule.get('path-base','root') not in {'root','base'}:raise ValueError('路径基准无效。')
    if rule.get('method','GET') not in {'GET','HEAD'}: raise ValueError('此规则引擎支持 GET / HEAD。')
    if rule.get('severity','info') not in {'info','low','medium','high','critical'}: raise ValueError('风险级别无效。')
    paths=rule.get('paths',[])
    if not isinstance(paths,list) or not 1<=len(paths)<=20: raise ValueError('每条规则需要 1–20 个路径。')
    for path in paths:
        if not isinstance(path,str) or len(path)>500 or not path.startswith('/') or path.startswith('//') or '\\' in path or '..' in path:
            raise ValueError('规则路径必须是站内绝对路径。')
        if '{{' in path: raise ValueError('不支持此模板变量；OOB 请使用独立的带外验证入口。')
    matchers=rule.get('matchers',[])
    if not isinstance(matchers,list) or not 1<=len(matchers)<=12: raise ValueError('规则需要 1–12 个匹配条件。')
    for item in matchers:
        if not isinstance(item,dict) or set(item)-{'type','part','words','status','condition','negative','case-insensitive'}: raise ValueError('不支持此匹配条件。')
        if any(type(item[k]) is not bool for k in ('negative','case-insensitive') if k in item):raise ValueError('匹配开关必须是布尔值。')
        if item.get('type') not in {'word','status'} or item.get('part','body') not in {'body','header','all'}: raise ValueError('只支持 status / word 及 body / header / all。')
        values=item.get('words' if item['type']=='word' else 'status',[])
        if not isinstance(values,list) or not 1<=len(values)<=20: raise ValueError('匹配值无效。')
        if item['type']=='word' and any(not isinstance(v,str) or not v or len(v)>500 for v in values): raise ValueError('词匹配值无效。')
        if item['type']=='status' and any(type(v)!=int or not 100<=v<=599 for v in values): raise ValueError('状态码无效。')
        if item.get('condition','or') not in {'and','or'}: raise ValueError('匹配逻辑无效。')
    if rule.get('matchers-condition','and') not in {'and','or'}: raise ValueError('规则逻辑无效。')
    products=rule.get('products',[])
    if not isinstance(products,list) or any(not isinstance(p,str) or len(p)>100 for p in products): raise ValueError('指纹列表无效。')
    return rule


def import_rules(text):
    if len(text)>100000: raise ValueError('规则文件最多 100 KB。')
    if any(isinstance(token,(yaml.tokens.AliasToken,yaml.tokens.AnchorToken)) for token in yaml.scan(text)):
        raise ValueError('规则不支持 YAML 锚点与别名。')
    raw=yaml.safe_load(text)
    if isinstance(raw,dict) and ('http' in raw or 'requests' in raw):
        if set(raw)-{'id','info','http','requests'}: raise ValueError('此模板使用了未支持的协议或顶层字段。')
        blocks=raw.get('http',raw.get('requests'))
        if not isinstance(blocks,list) or len(blocks)!=1: raise ValueError('当前兼容单个 HTTP 请求块；多块模板请拆分。')
        block=blocks[0]
        if not isinstance(block,dict):raise ValueError('HTTP 请求块必须是对象。')
        if set(block)-{'method','path','matchers','matchers-condition','redirects','max-redirects'}: raise ValueError('不支持 raw、payload、DSL、代码或提取器模板；不会静默忽略。')
        if block.get('redirects'): raise ValueError('规则请求不自动跟随重定向。')
        paths=[];bases=set()
        for path in block.get('path',[]):
            if not isinstance(path,str) or not path.startswith(('{{BaseURL}}/','{{RootURL}}/')): raise ValueError('Nuclei 路径必须以 {{BaseURL}}/ 或 {{RootURL}}/ 开头。')
            bases.add('base' if path.startswith('{{BaseURL}}') else 'root')
            paths.append(path.replace('{{BaseURL}}','').replace('{{RootURL}}',''))
        if len(bases)>1:raise ValueError('同一请求块请使用一致的路径基准。')
        info=raw.get('info',{})
        if not isinstance(info,dict):raise ValueError('模板信息必须是对象。')
        raw=[{'id':raw.get('id'),'name':info.get('name',raw.get('id')),'severity':info.get('severity','info'),
              'paths':paths,'path-base':next(iter(bases),'root'),'method':block.get('method','GET'),'products':[],
              'matchers':block.get('matchers',[]),'matchers-condition':block.get('matchers-condition','or')}]
    elif isinstance(raw,dict):raw=[raw]
    if not isinstance(raw,list) or len(raw)>100: raise ValueError('需要规则对象或最多 100 条规则的数组。')
    rules=[validate_rule(r) for r in raw]
    if len({r['id'] for r in rules})!=len(rules):raise ValueError('规则 id 不能重复。')
    return rules


def project_rules(db, project_id):
    row=db.query(AppPreference).filter_by(key=f'scan_rules:{project_id}').first()
    return BUILTINS+(json.loads(row.value_json) if row else [])


def matches(rule, observation):
    if not observation.get('ok'):return False
    outcomes=[]
    for matcher in rule['matchers']:
        if matcher['type']=='status':hit=observation.get('status_code') in matcher['status']
        else:
            header='\n'.join(f'{k}: {v}' for k,v in observation.get('headers',{}).items())
            part=matcher.get('part','body')
            text=header if part=='header' else observation.get('body','') if part=='body' else header+'\n'+observation.get('body','')
            values=[word.lower() in text.lower() if matcher.get('case-insensitive',False) else word in text for word in matcher['words']]
            hit=all(values) if matcher.get('condition')=='and' else any(values)
        outcomes.append(not hit if matcher.get('negative') else hit)
    return all(outcomes) if rule.get('matchers-condition','and')=='and' else any(outcomes)
