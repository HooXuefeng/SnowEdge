from __future__ import annotations
import json
from sqlalchemy.orm import Session
from ..models import Project, ProjectSkill, ScanProfile, SkillDefinition, _utcnow
from ..skills.registry import ensure_project_skill_rows, seed_builtin_skills


def _slugs(raw: str) -> list[str]:
    try: data=json.loads(raw or "[]")
    except Exception: data=[]
    return [str(x) for x in data if str(x).strip()]


def capture_profile(db: Session, project: Project, name: str, description: str="", batch_target_limit: int=20) -> ScanProfile:
    name=(name or "").strip()[:200]
    if not name: raise ValueError("Profile name is required.")
    if db.query(ScanProfile).filter(ScanProfile.name==name).first(): raise ValueError("A profile with this name already exists.")
    ensure_project_skill_rows(db, project.id)
    rows=(db.query(SkillDefinition.slug).join(ProjectSkill,ProjectSkill.skill_id==SkillDefinition.id)
          .filter(ProjectSkill.project_id==project.id,ProjectSkill.enabled==1).all())
    profile=ScanProfile(name=name,description=(description or "")[:5000],enabled_skill_slugs_json=json.dumps([x[0] for x in rows],ensure_ascii=False),
        batch_target_limit=max(1,min(int(batch_target_limit),50)))
    db.add(profile);db.commit();db.refresh(profile);return profile


def apply_profile(db: Session, project: Project, profile: ScanProfile) -> dict:
    seed_builtin_skills(db); ensure_project_skill_rows(db,project.id)
    allowed=set(_slugs(profile.enabled_skill_slugs_json))
    skills=db.query(SkillDefinition).all(); rows={r.skill_id:r for r in db.query(ProjectSkill).filter(ProjectSkill.project_id==project.id).all()}
    enabled=[]
    for skill in skills:
        row=rows.get(skill.id)
        if not row: continue
        state=1 if skill.builtin and skill.slug in allowed else 0
        row.enabled=state
        if state: enabled.append(skill.slug)
    project.scan_profile_id=profile.id
    db.commit()
    return {"profile_id":profile.id,"enabled":enabled}


def profile_payload(profile: ScanProfile) -> dict:
    return {"id":profile.id,"name":profile.name,"description":profile.description,"skills":_slugs(profile.enabled_skill_slugs_json),"batch_target_limit":profile.batch_target_limit}
