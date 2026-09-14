from __future__ import annotations
from urllib.parse import quote
import ipaddress
import re
from sqlalchemy.orm import Session
from ..models import NetworkRouteProfile, Project, AppPreference, _utcnow
import json
from .secret_store import decrypt_json, encrypt_json

ROUTE_TYPES={"direct","http","socks5","burp"}


def create_route_profile(db: Session, *, name: str, route_type: str, host: str="", port: int=0, username: str="", password: str="", notes: str="") -> NetworkRouteProfile:
    name=(name or "").strip()[:200]; route_type=(route_type or "direct").lower().strip()
    if not name: raise ValueError("Route profile name is required.")
    if route_type not in ROUTE_TYPES: raise ValueError("Unsupported route type.")
    if db.query(NetworkRouteProfile).filter(NetworkRouteProfile.name==name).first(): raise ValueError("Route profile name already exists.")
    if route_type != "direct":
        if not host.strip(): raise ValueError("Proxy host is required.")
        host=host.strip().strip('[]')
        try:ipaddress.ip_address(host)
        except ValueError:
            if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?',host):raise ValueError("Proxy host must be an IP or hostname, without a URL or credentials.")
        if not (1 <= int(port) <= 65535): raise ValueError("Proxy port must be 1-65535.")
    row=NetworkRouteProfile(name=name,route_type=route_type,host=host.strip()[:240],port=int(port or 0),username=username.strip()[:240],
        secret_encrypted=encrypt_json({"password":password}) if password else "",notes=(notes or "")[:5000])
    db.add(row);db.commit();db.refresh(row);return row


def route_payload(row: NetworkRouteProfile | None, *, reveal_runtime: bool=False) -> dict:
    if not row or not row.enabled: return {"id":None,"name":"Direct","route_type":"direct","active":False}
    result={"id":row.id,"name":row.name,"route_type":row.route_type,"host":row.host,"port":row.port,"username":row.username,"active":row.route_type!="direct","notes":row.notes}
    if reveal_runtime:
        secret=decrypt_json(row.secret_encrypted,{})
        result["password"]=str(secret.get("password") or "") if isinstance(secret,dict) else ""
    return result


def active_route(db: Session, project_id: int) -> NetworkRouteProfile | None:
    project=db.get(Project,project_id) if project_id else None
    route_id=project.network_route_profile_id if project else None
    if not route_id:
        preference=db.query(AppPreference).filter_by(key='global_network_route').first()
        if preference:
            route_id=json.loads(preference.value_json).get('route_id')
    if not route_id:return None
    row=db.get(NetworkRouteProfile,route_id)
    if not row or not row.enabled:raise ValueError('所选代理已失效或停用，请重新选择代理；不会自动改为直连。')
    return row


def record_route_use(db, project_id):
    row=active_route(db,project_id)
    if not row:return
    key=f'route_usage:{row.id}'
    usage=db.query(AppPreference).filter_by(key=key).first()
    if not usage:usage=AppPreference(key=key);db.add(usage)
    usage.value_json=json.dumps({'last_used':str(_utcnow()),'last_result':'用于扫描任务'})
    db.commit()


def httpx_proxy_url(db: Session, project_id: int) -> str | None:
    row=active_route(db,project_id)
    return proxy_url_for_route(row)


def proxy_url_for_route(row) -> str | None:
    if not row or row.route_type=="direct": return None
    scheme="http" if row.route_type in {"http","burp"} else "socks5"
    auth=""
    if row.username:
        pwd=route_payload(row,reveal_runtime=True).get("password","")
        auth=quote(row.username,safe="")+(":"+quote(pwd,safe="") if pwd else "")+"@"
    host=f'[{row.host}]' if ':' in row.host else row.host
    return f"{scheme}://{auth}{host}:{row.port}"


def playwright_proxy(db: Session, project_id: int) -> dict | None:
    row=active_route(db,project_id)
    if not row or row.route_type=="direct": return None
    scheme="http" if row.route_type in {"http","burp"} else "socks5"
    payload=route_payload(row,reveal_runtime=True)
    host=f'[{row.host}]' if ':' in row.host else row.host
    result={"server":f"{scheme}://{host}:{row.port}"}
    if row.username: result["username"]=row.username
    if payload.get("password"): result["password"]=payload["password"]
    return result


def select_route(db: Session, project: Project, route_id: int | None) -> None:
    if route_id is None:
        project.network_route_profile_id=None;db.commit();return
    row=db.get(NetworkRouteProfile,route_id)
    if not row or not row.enabled: raise ValueError("Route profile not found or disabled.")
    project.network_route_profile_id=row.id;db.commit()
