from __future__ import annotations

import base64
import hashlib
import json
import xml.etree.ElementTree as ET
from urllib.parse import urlencode, urljoin, urlparse

import yaml

from sqlalchemy.orm import Session

from ..models import Asset, ImportBatch, ImportRecord, Project, Service
from ..scope import target_in_scope
from .finding_service import create_finding
from .request_workspace import create_stored_request, parse_raw_http_request
from .endpoint_inventory import sync_stored_request_endpoint, _upsert_parameter

MAX_IMPORT_BYTES = 25 * 1024 * 1024
MAX_IMPORT_RECORDS = 20_000


def _scope_rules(project: Project) -> list[str]:
    return [x.strip() for x in project.scope_text.splitlines() if x.strip()]


def _safe_text(node, name: str, default: str = "") -> str:
    child = node.find(name)
    return (child.text or default).strip() if child is not None and child.text else default


def _record(
    db: Session,
    batch: ImportBatch,
    record_type: str,
    source_ref: str,
    status: str,
    entity_type: str = "",
    entity_id: int | None = None,
    detail: dict | None = None,
) -> None:
    db.add(ImportRecord(
        batch_id=batch.id,
        record_type=record_type[:80],
        source_ref=source_ref[:500],
        status=status[:60],
        entity_type=entity_type[:80],
        entity_id=entity_id,
        detail_json=json.dumps(detail or {}, ensure_ascii=False),
    ))


def _new_batch(
    db: Session,
    project: Project,
    import_type: str,
    filename: str,
    raw: bytes,
) -> ImportBatch:
    if len(raw) > MAX_IMPORT_BYTES:
        raise ValueError("Import file exceeds 25 MB limit.")
    batch = ImportBatch(
        project_id=project.id,
        import_type=import_type[:80],
        filename=(filename or "upload")[:300],
        file_sha256=hashlib.sha256(raw).hexdigest(),
        status="running",
    )
    db.add(batch)
    db.commit()
    db.refresh(batch)
    return batch


def _finish_batch(db: Session, batch: ImportBatch, summary: dict) -> ImportBatch:
    batch.status = "done"
    batch.summary_json = json.dumps(summary, ensure_ascii=False)
    db.commit()
    db.refresh(batch)
    return batch


def _fail_batch(db: Session, batch: ImportBatch, exc: Exception) -> ImportBatch:
    batch.status = "error"
    batch.error = f"{type(exc).__name__}: {exc}"[:8000]
    db.commit()
    return batch


def _asset(db: Session, project_id: int, target: str, kind: str = "host") -> Asset:
    row = db.query(Asset).filter(Asset.project_id == project_id, Asset.target == target).first()
    if row:
        return row
    row = Asset(project_id=project_id, target=target[:500], kind=kind[:50])
    db.add(row)
    db.flush()
    return row


def import_nmap_xml(db: Session, project: Project, filename: str, raw: bytes) -> ImportBatch:
    batch = _new_batch(db, project, "nmap_xml", filename, raw)
    try:
        root = ET.fromstring(raw)
        seen = imported = skipped = 0
        for host in root.findall("host")[:MAX_IMPORT_RECORDS]:
            address_node = host.find("address")
            if address_node is None:
                continue
            address = (address_node.attrib.get("addr") or "").strip()
            if not address:
                continue
            seen += 1
            if not target_in_scope(address, _scope_rules(project)):
                skipped += 1
                _record(db, batch, "host", address, "out_of_scope")
                continue
            asset = _asset(db, project.id, address, address_node.attrib.get("addrtype", "host"))
            open_ports = 0
            for port in host.findall("./ports/port"):
                state = port.find("state")
                if state is None or state.attrib.get("state") != "open":
                    continue
                try:
                    port_no = int(port.attrib.get("portid", "0"))
                except ValueError:
                    continue
                protocol = port.attrib.get("protocol", "tcp")
                service_node = port.find("service")
                name = service_node.attrib.get("name", "") if service_node is not None else ""
                banner_parts = []
                if service_node is not None:
                    for key in ("product", "version", "extrainfo"):
                        if service_node.attrib.get(key):
                            banner_parts.append(service_node.attrib[key])
                existing = (
                    db.query(Service)
                    .filter(Service.asset_id == asset.id, Service.port == port_no, Service.protocol == protocol)
                    .first()
                )
                if not existing:
                    db.add(Service(
                        asset_id=asset.id,
                        port=port_no,
                        protocol=protocol[:20],
                        name=name[:100],
                        banner=" ".join(banner_parts)[:1000],
                    ))
                open_ports += 1
            imported += 1
            _record(
                db, batch, "host", address, "imported", "Asset", asset.id,
                {"open_ports": open_ports},
            )
            if seen >= MAX_IMPORT_RECORDS:
                break
        batch.records_seen = seen
        batch.records_imported = imported
        batch.records_skipped = skipped
        db.commit()
        return _finish_batch(db, batch, {
            "assets_imported": imported,
            "records_skipped": skipped,
            "passive_only": True,
        })
    except Exception as exc:
        _fail_batch(db, batch, exc)
        raise


def _decode_burp_field(node, tag: str) -> bytes:
    child = node.find(tag)
    if child is None or child.text is None:
        return b""
    text = child.text
    if child.attrib.get("base64", "").lower() == "true":
        try:
            return base64.b64decode(text)
        except Exception:
            return b""
    return text.encode("utf-8", errors="replace")


def import_burp_xml(db: Session, project: Project, filename: str, raw: bytes) -> ImportBatch:
    batch = _new_batch(db, project, "burp_xml", filename, raw)
    try:
        root = ET.fromstring(raw)
        seen = imported = skipped = 0
        items = root.findall(".//item")
        for item in items[:MAX_IMPORT_RECORDS]:
            seen += 1
            host = _safe_text(item, "host")
            path = _safe_text(item, "path", "/")
            protocol = _safe_text(item, "protocol", "https")
            port = _safe_text(item, "port")
            if host:
                netloc = host if not port or port in {"80", "443"} else f"{host}:{port}"
                fallback_url = f"{protocol}://{netloc}{path or '/'}"
            else:
                fallback_url = ""
            url = _safe_text(item, "url", fallback_url)
            if not url or not target_in_scope(url, _scope_rules(project)):
                skipped += 1
                _record(db, batch, "burp_item", url or host, "out_of_scope")
                continue

            entity_type = ""
            entity_id = None
            request_bytes = _decode_burp_field(item, "request")
            if request_bytes:
                raw_request = request_bytes.decode("utf-8", errors="replace")
                try:
                    parsed = parse_raw_http_request(raw_request, protocol)
                    stored = create_stored_request(
                        db,
                        project.id,
                        _safe_text(item, "name", f"Burp {parsed.method} {url}")[:240],
                        parsed.method,
                        parsed.url,
                        headers=parsed.headers,
                        body=parsed.body,
                        source="burp_import",
                        explicit_read_only=parsed.method in {"GET", "HEAD"},
                    )
                    entity_type = "StoredRequest"
                    entity_id = stored.id
                except Exception:
                    pass

            issue_name = _safe_text(item, "name")
            severity = _safe_text(item, "severity", "info").lower()
            if issue_name and issue_name.lower() not in {"", "information"}:
                severity_map = {
                    "high": "high", "medium": "medium", "low": "low",
                    "information": "info", "info": "info",
                }
                detail = _safe_text(item, "issueDetail") or _safe_text(item, "issueBackground")
                finding = create_finding(
                    db=db,
                    project_id=project.id,
                    title=issue_name,
                    severity=severity_map.get(severity, "info"),
                    target=url,
                    description=detail[:12000] or "Imported from Burp XML for analyst review.",
                    recommendation=_safe_text(item, "remediationDetail")[:8000],
                    source="burp_import",
                    evidence_kind="burp_passive_import",
                    evidence_content={
                        "source": "Burp XML",
                        "serialNumber": _safe_text(item, "serialNumber"),
                        "type": _safe_text(item, "type"),
                        "confidence": _safe_text(item, "confidence"),
                        "request_response_omitted_from_evidence": True,
                    },
                )
                entity_type = "Finding"
                entity_id = finding.id

            imported += 1
            _record(db, batch, "burp_item", url, "imported", entity_type, entity_id)
        batch.records_seen = seen
        batch.records_imported = imported
        batch.records_skipped = skipped
        db.commit()
        return _finish_batch(db, batch, {
            "items_imported": imported,
            "records_skipped": skipped,
            "passive_only": True,
            "network_execution": False,
        })
    except Exception as exc:
        _fail_batch(db, batch, exc)
        raise


def import_nuclei_jsonl(db: Session, project: Project, filename: str, raw: bytes) -> ImportBatch:
    batch = _new_batch(db, project, "nuclei_jsonl", filename, raw)
    try:
        seen = imported = skipped = 0
        for line in raw.decode("utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            if seen >= MAX_IMPORT_RECORDS:
                break
            seen += 1
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                skipped += 1
                _record(db, batch, "nuclei_result", f"line:{seen}", "invalid_json")
                continue

            target = str(item.get("matched-at") or item.get("host") or "").strip()
            if not target or not target_in_scope(target, _scope_rules(project)):
                skipped += 1
                _record(db, batch, "nuclei_result", target or f"line:{seen}", "out_of_scope")
                continue

            info = item.get("info") or {}
            classification = info.get("classification") or {}
            cwe = classification.get("cwe-id") or classification.get("cwe_id") or ""
            if isinstance(cwe, list):
                cwe = ",".join(str(x) for x in cwe)
            title = str(info.get("name") or item.get("template-id") or "Nuclei finding")
            severity = str(info.get("severity") or "info").lower()
            if severity not in {"high", "medium", "low", "info"}:
                severity = "info"

            finding = create_finding(
                db=db,
                project_id=project.id,
                title=title,
                severity=severity,
                target=target,
                description=str(info.get("description") or "Imported Nuclei result for analyst review.")[:12000],
                recommendation=str(info.get("remediation") or "")[:8000],
                source="nuclei_import",
                evidence_kind="nuclei_passive_import",
                evidence_content={
                    "template_id": item.get("template-id"),
                    "matcher_name": item.get("matcher-name"),
                    "type": item.get("type"),
                    "timestamp": item.get("timestamp"),
                    "raw_request_response_omitted": True,
                },
                cwe_id=str(cwe)[:32],
            )
            imported += 1
            _record(
                db, batch, "nuclei_result",
                str(item.get("template-id") or target),
                "imported", "Finding", finding.id,
            )

        batch.records_seen = seen
        batch.records_imported = imported
        batch.records_skipped = skipped
        db.commit()
        return _finish_batch(db, batch, {
            "findings_imported": imported,
            "records_skipped": skipped,
            "passive_only": True,
            "network_execution": False,
        })
    except Exception as exc:
        _fail_batch(db, batch, exc)
        raise

def _json_or_yaml(raw: bytes):
    text = raw.decode("utf-8", errors="replace")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        try:
            return yaml.safe_load(text)
        except Exception as exc:
            raise ValueError(f"文件不是有效 JSON/YAML：{exc}")


def import_har(db: Session, project: Project, filename: str, raw: bytes) -> ImportBatch:
    batch = _new_batch(db, project, "har", filename, raw)
    try:
        data = json.loads(raw.decode("utf-8", errors="replace")); entries = (((data or {}).get("log") or {}).get("entries") or []); seen=imported=skipped=0
        for entry in entries[:MAX_IMPORT_RECORDS]:
            seen+=1; request=entry.get("request") or {}; method=str(request.get("method") or "GET").upper(); url=str(request.get("url") or "").strip()
            if not url or not target_in_scope(url,_scope_rules(project)):
                skipped+=1; _record(db,batch,"har_request",url or f"entry:{seen}","out_of_scope"); continue
            headers={}
            for h in request.get("headers") or []:
                name=str(h.get("name") or "").strip()
                if name: headers[name]=str(h.get("value") or "")
            post_data=request.get("postData") or {}; body=str(post_data.get("text") or "")
            stored=create_stored_request(db,project.id,f"HAR {method} {urlparse(url).path or '/'}"[:240],method,url,headers=headers,body=body,source="har_import",explicit_read_only=method in {"GET","HEAD"}); endpoint=sync_stored_request_endpoint(db,stored); imported+=1; _record(db,batch,"har_request",url,"imported","Endpoint",endpoint.id,{"stored_request_id":stored.id})
        batch.records_seen,batch.records_imported,batch.records_skipped=seen,imported,skipped; db.commit(); return _finish_batch(db,batch,{"requests_imported":imported,"records_skipped":skipped,"passive_only":True,"network_execution":False})
    except Exception as exc: _fail_batch(db,batch,exc); raise


def _postman_items(items):
    for item in items or []:
        if isinstance(item,dict) and isinstance(item.get("item"),list): yield from _postman_items(item["item"])
        elif isinstance(item,dict) and item.get("request"): yield item


def _postman_url(raw_url, variables: dict[str,str]) -> str:
    if isinstance(raw_url,str): value=raw_url
    elif isinstance(raw_url,dict):
        value=str(raw_url.get("raw") or "")
        if not value:
            protocol=str(raw_url.get("protocol") or "https");host=raw_url.get("host") or [];path=raw_url.get("path") or [];host_text=".".join(host) if isinstance(host,list) else str(host);path_text="/".join(path) if isinstance(path,list) else str(path);value=f"{protocol}://{host_text}/{path_text}"
    else: value=""
    for key,val in variables.items(): value=value.replace("{{"+key+"}}",val)
    return value


def import_postman_collection(db: Session, project: Project, filename: str, raw: bytes) -> ImportBatch:
    batch=_new_batch(db,project,"postman_collection",filename,raw)
    try:
        data=json.loads(raw.decode("utf-8",errors="replace")); variables={str(x.get("key")):str(x.get("value") or "") for x in (data.get("variable") or []) if isinstance(x,dict) and x.get("key")};seen=imported=skipped=0
        for item in list(_postman_items(data.get("item") or []))[:MAX_IMPORT_RECORDS]:
            seen+=1; req=item.get("request") or {};method=str(req.get("method") or "GET").upper();url=_postman_url(req.get("url"),variables).strip()
            if "{{" in url or not url or not target_in_scope(url,_scope_rules(project)):
                skipped+=1;_record(db,batch,"postman_request",url or str(item.get("name") or seen),"unresolved_or_out_of_scope");continue
            headers={}
            for h in req.get("header") or []:
                if isinstance(h,dict) and not h.get("disabled") and h.get("key"): headers[str(h["key"])]=str(h.get("value") or "")
            body_obj=req.get("body") or {};body="";mode=body_obj.get("mode")
            if mode=="raw": body=str(body_obj.get("raw") or "")
            elif mode=="urlencoded": body=urlencode([(str(x.get("key")),str(x.get("value") or "")) for x in body_obj.get("urlencoded") or [] if isinstance(x,dict) and x.get("key") and not x.get("disabled")])
            stored=create_stored_request(db,project.id,str(item.get("name") or f"Postman {method}")[:240],method,url,headers=headers,body=body,source="postman_import",explicit_read_only=method in {"GET","HEAD"});endpoint=sync_stored_request_endpoint(db,stored);imported+=1;_record(db,batch,"postman_request",url,"imported","Endpoint",endpoint.id,{"stored_request_id":stored.id})
        batch.records_seen,batch.records_imported,batch.records_skipped=seen,imported,skipped;db.commit();return _finish_batch(db,batch,{"requests_imported":imported,"records_skipped":skipped,"passive_only":True,"network_execution":False})
    except Exception as exc:_fail_batch(db,batch,exc);raise


def _openapi_base(project:Project,data:dict)->str:
    servers=data.get("servers") or []
    if servers and isinstance(servers[0],dict) and servers[0].get("url"): return str(servers[0]["url"]).rstrip("/")+"/"
    host=str(data.get("host") or "").strip();base_path=str(data.get("basePath") or "/")
    if host:
        schemes=data.get("schemes") or ["https"];return f"{schemes[0]}://{host}{base_path.rstrip('/')}/"
    rules=_scope_rules(project);candidate=next((x for x in rules if "*" not in x and "/" not in x),"");return f"https://{candidate}/" if candidate else ""


def _schema_example(schema):
    if not isinstance(schema,dict): return None
    if "example" in schema:return schema["example"]
    if "default" in schema:return schema["default"]
    typ=schema.get("type")
    if typ=="object" or schema.get("properties"): return {key:(_schema_example(value) if _schema_example(value) is not None else "") for key,value in list((schema.get("properties") or {}).items())[:50]}
    if typ=="array":
        item=_schema_example(schema.get("items") or {});return [item] if item is not None else []
    if typ=="integer":return 0
    if typ=="number":return 0
    if typ=="boolean":return False
    return ""


def import_openapi(db:Session,project:Project,filename:str,raw:bytes)->ImportBatch:
    batch=_new_batch(db,project,"openapi",filename,raw)
    try:
        data=_json_or_yaml(raw)
        if not isinstance(data,dict) or not (data.get("openapi") or data.get("swagger")): raise ValueError("不是 OpenAPI / Swagger 文档。")
        base=_openapi_base(project,data)
        if not base: raise ValueError("无法确定 API Base URL；请在 OpenAPI servers/Swagger host 中提供，或使用单一明确 Scope。")
        seen=imported=skipped=0
        for path,path_item in list((data.get("paths") or {}).items())[:5000]:
            if not isinstance(path_item,dict):continue
            path_params=path_item.get("parameters") or []
            for method,operation in path_item.items():
                if method.upper() not in {"GET","HEAD","POST","PUT","PATCH","DELETE","OPTIONS"} or not isinstance(operation,dict):continue
                seen+=1
                if seen>MAX_IMPORT_RECORDS:break
                method_upper=method.upper();url=urljoin(base,str(path).lstrip("/"))
                if not target_in_scope(url,_scope_rules(project)):skipped+=1;_record(db,batch,"openapi_operation",f"{method_upper} {url}","out_of_scope");continue
                params=list(path_params)+list(operation.get("parameters") or []);query=[];headers={};body_value=None
                for param in params:
                    if not isinstance(param,dict):continue
                    name=str(param.get("name") or "");location=str(param.get("in") or "");schema=param.get("schema") or {};example=param.get("example")
                    if example is None:example=_schema_example(schema)
                    if location=="query" and name:query.append((name,str(example if example not in (None,"") else "{"+name+"}")))
                    elif location=="header" and name:headers[name]=str(example if example not in (None,"") else "{"+name+"}")
                    elif location=="body":body_value=_schema_example(schema)
                request_body=operation.get("requestBody") or {}
                if isinstance(request_body,dict):
                    for media_type,media in (request_body.get("content") or {}).items():
                        if not isinstance(media,dict):continue
                        schema=media.get("schema") or {};body_value=media.get("example")
                        if body_value is None:body_value=_schema_example(schema)
                        headers.setdefault("Content-Type",media_type);break
                if query:url=url+("&" if "?" in url else "?")+urlencode(query)
                body=json.dumps(body_value,ensure_ascii=False) if body_value is not None else ""
                stored=create_stored_request(db,project.id,str(operation.get("summary") or operation.get("operationId") or f"{method_upper} {path}")[:240],method_upper,url,headers=headers,body=body,source="openapi_import",explicit_read_only=method_upper in {"GET","HEAD"});endpoint=sync_stored_request_endpoint(db,stored)
                from ..models import EndpointParameter
                for param in params:
                    if not isinstance(param,dict) or not param.get("name"):continue
                    loc=str(param.get("in") or "")
                    if loc not in {"query","header","path"}:continue
                    pname=str(param["name"])
                    schema=param.get("schema") or {}
                    example=param.get("example")
                    if example is None: example=_schema_example(schema)
                    if example in (None, ""): example="{"+pname+"}"
                    row=_upsert_parameter(db,endpoint,loc,pname,example,"openapi_import")
                    if param.get("required"):
                        row.required=1
                imported+=1;_record(db,batch,"openapi_operation",f"{method_upper} {url}","imported","Endpoint",endpoint.id,{"stored_request_id":stored.id})
        batch.records_seen,batch.records_imported,batch.records_skipped=seen,imported,skipped;db.commit();return _finish_batch(db,batch,{"operations_imported":imported,"records_skipped":skipped,"passive_only":True,"network_execution":False,"format":str(data.get("openapi") or data.get("swagger"))})
    except Exception as exc:_fail_batch(db,batch,exc);raise


def _snowforge_text(record: dict, key: str, limit: int) -> str:
    value = record.get(key, "")
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False)
    return str(value or "").strip()[:limit]


def import_snowforge_json(db: Session, project: Project, filename: str, raw: bytes) -> ImportBatch:
    """Import SnowRelay's passive, password-free interchange package."""
    batch = _new_batch(db, project, "snowforge_json", filename, raw)
    try:
        package = json.loads(raw.decode("utf-8"))
        if not isinstance(package, dict) or package.get("schema") != "snowedge-import/1":
            raise ValueError("不是受支持的 SnowRelay / SnowEdge 联动包。")
        producer = package.get("producer") or {}
        if not isinstance(producer, dict) or producer.get("name") not in {"SnowRelay", "SnowForge"}:
            raise ValueError("联动包生产者标识无效。")
        producer_name = producer["name"]
        import_source = "snowrelay_import" if producer_name == "SnowRelay" else "snowforge_import"
        evidence_kind = "snowrelay_normalized_record" if producer_name == "SnowRelay" else "snowforge_normalized_record"
        records = package.get("records")
        if not isinstance(records, list):
            raise ValueError("联动包 records 必须是数组。")
        if len(records) > MAX_IMPORT_RECORDS:
            raise ValueError(f"联动包超过 {MAX_IMPORT_RECORDS:,} 条记录限制。")
        declared = package.get("record_count")
        if declared is not None and declared != len(records):
            raise ValueError("联动包记录数量与声明不一致。")
        if any(isinstance(row, dict) and str(row.get("password") or "").strip() for row in records):
            raise ValueError("联动包包含口令明文，已拒绝导入。请使用 SnowRelay v0.5.0 或更高版本重新导出。")

        seen = imported = skipped = assets_imported = services_imported = findings_imported = 0
        severity_map = {
            "严重": "high", "高危": "high", "中危": "medium",
            "低危": "low", "信息": "info", "critical": "high",
            "high": "high", "medium": "medium", "low": "low", "info": "info",
        }
        safe_inputs = []
        for item in (package.get("inputs") or [])[:100]:
            if not isinstance(item, dict):
                continue
            safe_inputs.append({
                "name": str(item.get("name") or "")[:300],
                "sha256": str(item.get("sha256") or "")[:64],
                "size": int(item.get("size") or 0) if str(item.get("size") or "0").isdigit() else 0,
            })
        rules = _scope_rules(project)
        for index, record in enumerate(records, start=1):
            seen += 1
            if not isinstance(record, dict):
                skipped += 1
                _record(db, batch, "snowforge_record", f"record:{index}", "invalid_record")
                continue
            asset_target = _snowforge_text(record, "asset", 500) or _snowforge_text(record, "hostname", 500)
            source = record.get("source") if isinstance(record.get("source"), dict) else {}
            source_ref = f"{source.get('file') or filename}:{source.get('sheet') or '-'}:{source.get('row') or index}"
            if not asset_target or not target_in_scope(asset_target, rules):
                skipped += 1
                _record(db, batch, "snowforge_record", source_ref, "out_of_scope", detail={"target": asset_target})
                continue

            asset = _asset(db, project.id, asset_target, "host")
            assets_imported += 1
            entity_type, entity_id = "Asset", asset.id
            port_text = _snowforge_text(record, "port", 8)
            if port_text.isdigit() and 0 < int(port_text) <= 65535:
                port_no = int(port_text)
                protocol = (_snowforge_text(record, "protocol", 20) or "tcp").lower()
                existing = db.query(Service).filter(
                    Service.asset_id == asset.id,
                    Service.port == port_no,
                    Service.protocol == protocol,
                ).first()
                if not existing:
                    db.add(Service(
                        asset_id=asset.id,
                        port=port_no,
                        protocol=protocol,
                        name=_snowforge_text(record, "service", 100) or "unknown",
                        banner="",
                    ))
                    services_imported += 1

            title = _snowforge_text(record, "title", 300)
            has_finding_data = bool(title and (
                _snowforge_text(record, "severity", 30)
                or _snowforge_text(record, "description", 12000)
                or _snowforge_text(record, "evidence", 12000)
                or _snowforge_text(record, "risk_type", 160)
            ))
            if has_finding_data:
                severity_raw = _snowforge_text(record, "severity", 30).lower()
                evidence_content = {
                    "source": f"{producer_name} interchange",
                    "source_platform": str(source.get("platform") or "")[:120],
                    "source_file": str(source.get("file") or "")[:300],
                    "source_sheet": str(source.get("sheet") or "")[:200],
                    "source_row": str(source.get("row") or "")[:20],
                    "file_manifest": safe_inputs,
                    "evidence": _snowforge_text(record, "evidence", 12000),
                    "cve": _snowforge_text(record, "cve", 200),
                    "cvss": _snowforge_text(record, "cvss", 16),
                    "risk_type": _snowforge_text(record, "risk_type", 160),
                    "match_reason": _snowforge_text(record, "match_reason", 1000),
                    "credential_status": _snowforge_text(record, "credential_status", 80),
                    "username": _snowforge_text(record, "username", 200),
                    "password_included": False,
                }
                finding = create_finding(
                    db=db,
                    project_id=project.id,
                    title=title,
                    severity=severity_map.get(severity_raw, "info"),
                    target=asset_target,
                    description=_snowforge_text(record, "description", 12000) or "由 SnowRelay 标准化结果导入，等待分析人员复核。",
                    recommendation=_snowforge_text(record, "recommendation", 8000),
                    source=import_source,
                    evidence_kind=evidence_kind,
                    evidence_content=evidence_content,
                    vuln_type=_snowforge_text(record, "risk_type", 160),
                    finding_state="candidate",
                )
                entity_type, entity_id = "Finding", finding.id
                findings_imported += 1

            imported += 1
            _record(
                db, batch, "snowforge_record", source_ref, "imported",
                entity_type, entity_id,
                {"asset_id": asset.id, "candidate_finding": entity_type == "Finding"},
            )

        batch.records_seen = seen
        batch.records_imported = imported
        batch.records_skipped = skipped
        db.commit()
        return _finish_batch(db, batch, {
            "assets_seen": assets_imported,
            "services_created": services_imported,
            "candidate_findings": findings_imported,
            "records_skipped": skipped,
            "producer_version": str(producer.get("version") or ""),
            "passive_only": True,
            "network_execution": False,
            "password_included": False,
        })
    except Exception as exc:
        _fail_batch(db, batch, exc)
        raise


IMPORTERS = {
    "nmap_xml": import_nmap_xml,
    "burp_xml": import_burp_xml,
    "nuclei_jsonl": import_nuclei_jsonl,
    "har": import_har,
    "postman_collection": import_postman_collection,
    "openapi": import_openapi,
    "snowforge_json": import_snowforge_json,
}


def import_passive_file(
    db: Session,
    project: Project,
    import_type: str,
    filename: str,
    raw: bytes,
) -> ImportBatch:
    importer = IMPORTERS.get(import_type)
    if not importer:
        raise ValueError("Unsupported passive import type.")
    return importer(db, project, filename, raw)
