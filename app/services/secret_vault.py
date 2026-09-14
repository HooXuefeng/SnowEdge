from __future__ import annotations

import json
import os
from datetime import datetime

from sqlalchemy.orm import Session

from ..models import Identity, SecretVaultItem, _utcnow
from .secret_store import decrypt_json, encrypt_json, mask_secret

ALLOWED_TYPES={"http_identity","bearer_token","api_key","cookie_jar","login_credential","client_certificate","custom"}


def _expired(item: SecretVaultItem) -> bool:
    return bool(item.expires_at and item.expires_at <= _utcnow())


def create_vault_item(db:Session,*,label:str,secret_type:str,value:dict,project_id:int|None=None,username:str="",expires_at:datetime|None=None,notes:str="") -> SecretVaultItem:
    if secret_type not in ALLOWED_TYPES: raise ValueError("Unsupported secret type.")
    row=SecretVaultItem(project_id=project_id,label=label[:240],secret_type=secret_type,username=username[:240],value_encrypted=encrypt_json(value),expires_at=expires_at,notes=notes)
    db.add(row);db.commit();db.refresh(row);return row


def vault_value(item:SecretVaultItem) -> dict:
    data=decrypt_json(item.value_encrypted,{})
    return data if isinstance(data,dict) else {}


def item_summary(item:SecretVaultItem) -> dict:
    data=vault_value(item)
    fields=[]
    if item.secret_type=="http_identity":
        fields=[f"Header:{k}" for k in (data.get("headers") or {})]+[f"Cookie:{k}" for k in (data.get("cookies") or {})]
    else:
        for k,v in data.items():
            if isinstance(v,(str,int,float)): fields.append(f"{k}: {mask_secret(str(v))}")
    return {"item":item,"fields":fields[:30],"expired":_expired(item),"usable":not item.disabled and not item.deleted and not _expired(item)}


def identity_material(db:Session,identity:Identity|None) -> tuple[dict[str,str],dict[str,str]]:
    if not identity: return {},{}
    if identity.vault_item_id:
        item=db.get(SecretVaultItem,identity.vault_item_id)
        if item and not item.disabled and not item.deleted and not _expired(item):
            data=vault_value(item); item.last_used_at=_utcnow(); item.updated_at=_utcnow(); db.commit()
            headers=data.get("headers") if isinstance(data.get("headers"),dict) else {}
            cookies=data.get("cookies") if isinstance(data.get("cookies"),dict) else {}
            return {str(k):str(v) for k,v in headers.items()},{str(k):str(v) for k,v in cookies.items()}
    from .secret_store import decrypt_json as dec
    h=dec(identity.headers_encrypted,{}); c=dec(identity.cookies_encrypted,{})
    return ({str(k):str(v) for k,v in h.items()} if isinstance(h,dict) else {}, {str(k):str(v) for k,v in c.items()} if isinstance(c,dict) else {})


def rotate_vault_item(db:Session,item:SecretVaultItem,value:dict) -> SecretVaultItem:
    item.value_encrypted=encrypt_json(value); item.deleted=0; item.disabled=0; item.updated_at=_utcnow();db.commit();db.refresh(item);return item


def purge_vault_item(db:Session,item:SecretVaultItem) -> None:
    # Logical/cryptographic purge only. SQLite free pages may retain historical bytes until VACUUM/secure-delete maintenance.
    item.value_encrypted=encrypt_json({"purged":True,"nonce":os.urandom(24).hex()}); item.deleted=1; item.disabled=1; item.updated_at=_utcnow();db.commit()
