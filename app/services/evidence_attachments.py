from __future__ import annotations
import hashlib, io, json, math
from pathlib import Path

from PIL import Image, ImageDraw
from sqlalchemy.orm import Session
from ..config import settings
from ..models import Evidence, EvidenceAttachment, Finding
from .evidence_chain import ensure_evidence_integrity
MAX_SCREENSHOT_BYTES=8*1024*1024
MIME_EXT={"image/png":".png","image/jpeg":".jpg","image/webp":".webp"}
def _valid_magic(raw,mime):
    if mime=="image/png": return raw.startswith(b"\x89PNG\r\n\x1a\n")
    if mime=="image/jpeg": return raw.startswith(b"\xff\xd8\xff")
    if mime=="image/webp": return len(raw)>=12 and raw[:4]==b"RIFF" and raw[8:12]==b"WEBP"
    return False

def save_finding_screenshot(db:Session,finding:Finding,label:str,mime_type:str,raw:bytes)->EvidenceAttachment:
    if mime_type not in MIME_EXT: raise ValueError("仅支持 PNG / JPEG / WebP 截图。")
    if not raw or len(raw)>MAX_SCREENSHOT_BYTES: raise ValueError("截图不能为空且最大 8 MB。")
    if not _valid_magic(raw,mime_type): raise ValueError("截图文件签名与 MIME 类型不匹配。")
    digest=hashlib.sha256(raw).hexdigest(); root=Path(settings.evidence_artifact_dir).expanduser(); directory=root/str(finding.project_id)/str(finding.id); directory.mkdir(parents=True,exist_ok=True); path=directory/f"{digest}{MIME_EXT[mime_type]}"
    if not path.exists(): path.write_bytes(raw)
    evidence=Evidence(project_id=finding.project_id,finding_id=finding.id,source_type="EvidenceAttachment",redaction_state="clean",kind="screenshot_evidence",content=json.dumps({"label":(label or "漏洞验证截图")[:300],"mime_type":mime_type,"file_sha256":digest,"size_bytes":len(raw),"binary_content_not_stored_in_evidence":True},ensure_ascii=False))
    db.add(evidence); db.flush(); ensure_evidence_integrity(db,evidence)
    row=EvidenceAttachment(project_id=finding.project_id,finding_id=finding.id,evidence_id=evidence.id,attachment_type="screenshot",label=(label or "漏洞验证截图")[:300],file_path=str(path.resolve()),mime_type=mime_type,file_sha256=digest,size_bytes=len(raw)); db.add(row); db.commit(); db.refresh(row); return row

def finding_attachments(db:Session,finding_id:int): return db.query(EvidenceAttachment).filter(EvidenceAttachment.finding_id==finding_id).order_by(EvidenceAttachment.id.asc()).all()


def _normalized_annotations(raw_json: str) -> list[dict]:
    try:
        data = json.loads(raw_json or "[]")
    except Exception:
        raise ValueError("标注数据不是有效 JSON。")
    if not isinstance(data, list):
        raise ValueError("标注数据必须是数组。")
    result = []
    for item in data[:50]:
        if not isinstance(item, dict):
            continue
        kind = str(item.get("type") or "").lower()
        if kind not in {"box", "redact", "arrow"}:
            continue
        try:
            x = min(1.0, max(0.0, float(item.get("x", 0))))
            y = min(1.0, max(0.0, float(item.get("y", 0))))
            raw_w = float(item.get("w", 0))
            raw_h = float(item.get("h", 0))
        except Exception:
            continue

        if kind == "arrow":
            # Arrow vectors are signed: left/up arrows legitimately have
            # negative width/height. Clamp the endpoint, not the vector sign.
            end_x = min(1.0, max(0.0, x + raw_w))
            end_y = min(1.0, max(0.0, y + raw_h))
            w = end_x - x
            h = end_y - y
            if abs(w) < 0.005 and abs(h) < 0.005:
                continue
        else:
            # Box/redact are stored as a positive normalized rectangle.
            end_x = min(1.0, max(0.0, x + raw_w))
            end_y = min(1.0, max(0.0, y + raw_h))
            x, end_x = sorted((x, end_x))
            y, end_y = sorted((y, end_y))
            w = end_x - x
            h = end_y - y
            if w < 0.005 or h < 0.005:
                continue
        result.append({
            "type": kind,
            "x": x, "y": y, "w": w, "h": h,
        })
    return result


def save_attachment_annotations(
    db: Session,
    attachment: EvidenceAttachment,
    *,
    label: str,
    annotation_json: str,
    sort_order: int | None = None,
) -> EvidenceAttachment:
    annotations = _normalized_annotations(annotation_json)
    attachment.label = (label or attachment.label or "漏洞验证截图")[:300]
    attachment.annotation_json = json.dumps(annotations, ensure_ascii=False)
    if sort_order is not None:
        attachment.sort_order = max(0, min(int(sort_order), 10000))
    db.commit()
    db.refresh(attachment)
    return attachment


def render_annotated_image_bytes(attachment: EvidenceAttachment) -> bytes:
    path = Path(attachment.file_path)
    if not path.exists():
        raise FileNotFoundError(path)
    raw = path.read_bytes()
    try:
        annotations = json.loads(attachment.annotation_json or "[]")
    except Exception:
        annotations = []
    # Preserve exact original bytes when there is nothing to annotate. This
    # keeps backward compatibility with screenshots that python-docx can embed
    # even if Pillow is stricter about decoding them.
    if not annotations:
        return raw
    image = Image.open(io.BytesIO(raw)).convert("RGB")
    draw = ImageDraw.Draw(image)

    width, height = image.size
    stroke = max(2, round(min(width, height) / 250))

    for item in annotations:
        if not isinstance(item, dict):
            continue
        kind = str(item.get("type") or "")
        x1 = round(float(item.get("x", 0)) * width)
        y1 = round(float(item.get("y", 0)) * height)
        x2 = round((float(item.get("x", 0)) + float(item.get("w", 0))) * width)
        y2 = round((float(item.get("y", 0)) + float(item.get("h", 0))) * height)
        x1, x2 = sorted((max(0, x1), min(width - 1, x2)))
        y1, y2 = sorted((max(0, y1), min(height - 1, y2)))
        if x2 <= x1 or y2 <= y1:
            continue

        if kind == "redact":
            draw.rectangle((x1, y1, x2, y2), fill=(20, 20, 20))
        elif kind == "box":
            draw.rectangle((x1, y1, x2, y2), outline=(220, 55, 65), width=stroke)
        elif kind == "arrow":
            draw.line((x1, y1, x2, y2), fill=(220, 55, 65), width=stroke)
            angle = math.atan2(y2 - y1, x2 - x1)
            head = max(10, stroke * 5)
            a1 = angle + math.pi * 0.82
            a2 = angle - math.pi * 0.82
            p1 = (x2 + head * math.cos(a1), y2 + head * math.sin(a1))
            p2 = (x2 + head * math.cos(a2), y2 + head * math.sin(a2))
            draw.polygon([(x2, y2), p1, p2], fill=(220, 55, 65))

    out = io.BytesIO()
    image.save(out, format="PNG")
    return out.getvalue()
