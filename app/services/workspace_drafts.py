from __future__ import annotations
import json
from sqlalchemy.orm import Session
from ..models import WorkspaceDraft,_utcnow
from .secret_store import decrypt_json,encrypt_json

def save_draft(db:Session,project_id:int,entity_type:str,entity_id:int,content:dict)->WorkspaceDraft:
    row=db.query(WorkspaceDraft).filter(WorkspaceDraft.project_id==project_id,WorkspaceDraft.entity_type==entity_type,WorkspaceDraft.entity_id==entity_id).first()
    if not row:
        row=WorkspaceDraft(project_id=project_id,entity_type=entity_type[:80],entity_id=entity_id);db.add(row)
    row.content_json=encrypt_json(content);row.updated_at=_utcnow();db.commit();db.refresh(row);return row

def load_draft(db:Session,project_id:int,entity_type:str,entity_id:int)->dict|None:
    row=db.query(WorkspaceDraft).filter(WorkspaceDraft.project_id==project_id,WorkspaceDraft.entity_type==entity_type,WorkspaceDraft.entity_id==entity_id).first()
    if not row:return None
    data=decrypt_json(row.content_json,{})
    return {"id":row.id,"content":data if isinstance(data,dict) else {},"updated_at":row.updated_at.isoformat() if row.updated_at else ""}

def delete_draft(db:Session,project_id:int,entity_type:str,entity_id:int)->bool:
    row=db.query(WorkspaceDraft).filter(WorkspaceDraft.project_id==project_id,WorkspaceDraft.entity_type==entity_type,WorkspaceDraft.entity_id==entity_id).first()
    if not row:return False
    db.delete(row);db.commit();return True
