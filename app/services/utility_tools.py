"""Small, bounded diagnostics. Network operations require project scope."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import ipaddress
import json
import socket
import time
from urllib.parse import urlsplit, parse_qsl, urlencode, quote, unquote

import httpx

from ..scope import target_in_scope
from ..scanners.tls import analyze_tls
from .evidence_safety import redact_url

TOOLS = [
    {"id": "dns", "name": "DNS 解析", "group": "信息搜集", "description": "查看域名的 IPv4 / IPv6 地址", "placeholder": "example.com", "network": True},
    {"id": "http", "name": "HTTP 响应头", "group": "信息搜集", "description": "查看状态码、服务器信息和安全响应头", "placeholder": "https://example.com", "network": True},
    {"id": "tls", "name": "TLS 证书", "group": "运维诊断", "description": "检查证书有效性、到期时间和协议", "placeholder": "example.com:443", "network": True},
    {"id": "tcp", "name": "端口连通性", "group": "运维诊断", "description": "检查一个服务端口能否建立连接", "placeholder": "example.com:443", "network": True},
    {"id": "ip", "name": "IP / 网段计算", "group": "本地处理", "description": "查看地址类型、网络范围和地址数量", "placeholder": "192.168.1.0/24", "network": False},
    {"id": "url", "name": "URL 解析", "group": "本地处理", "description": "拆解地址和参数名称，隐藏参数值", "placeholder": "https://example.com/api?page=1", "network": False},
    {"id": "json", "name": "JSON 格式化", "group": "本地处理", "description": "校验并整理 JSON 缩进", "placeholder": '{"name":"example","enabled":true}', "network": False},
    {"id": "base64", "name": "Base64 解码", "group": "本地处理", "description": "将 Base64 文本还原为 UTF-8", "placeholder": "SGVsbG8=", "network": False},
    {"id": "sha256", "name": "SHA-256 摘要", "group": "本地处理", "description": "计算文本摘要，便于核对内容一致性", "placeholder": "输入需要计算摘要的文本", "network": False},
    {"id": "jwt", "name": "JWT 查看", "group": "本地处理", "description": "查看头部和声明；不验证签名", "placeholder": "粘贴三段式 JWT", "network": False},
    {"id": "base64_encode", "name": "Base64 编码", "group": "本地处理", "description": "将 UTF-8 文本转为 Base64", "placeholder": "输入要编码的文本", "network": False},
    {"id": "url_encode", "name": "URL 编码", "group": "本地处理", "description": "编码 URL 参数文本", "placeholder": "例如：搜索关键词", "network": False},
    {"id": "url_decode", "name": "URL 解码", "group": "本地处理", "description": "还原百分号编码的 UTF-8 文本", "placeholder": "%E6%B5%8B%E8%AF%95", "network": False},
    {"id": "targets", "name": "目标清单整理", "group": "本地处理", "description": "逐行提取主机、去重并标出无效行", "placeholder": "https://example.com/a\nexample.com\n192.0.2.1", "network": False},
]
TOOL_MAP = {tool["id"]: tool for tool in TOOLS}


def parse_target(value: str) -> tuple[str, int, str]:
    value = value.strip()
    if not value or len(value) > 2000 or any(c.isspace() for c in value):
        raise ValueError("请输入有效域名、IP 或 HTTP(S) 地址。")
    try:
        # Bare IPv6 literals need brackets for URL parsing.
        ip = ipaddress.ip_address(value)
        value = f"[{ip}]" if ip.version == 6 else str(ip)
    except ValueError:
        pass
    parsed = urlsplit(value if "://" in value else f"https://{value}")
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise ValueError("仅支持 HTTP(S) 地址，地址中不能包含用户名或密码。")
    try:
        port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
        host = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    except (ValueError, UnicodeError) as exc:
        raise ValueError("域名或端口格式不正确。") from exc
    if not 1 <= port <= 65535:
        raise ValueError("端口应在 1–65535 之间。")
    return host, port, parsed._replace(fragment="").geturl()


def local_tool(kind: str, value: str) -> dict:
    if kind == "base64_encode":
        return {"编码结果": base64.b64encode(value.encode('utf-8')).decode('ascii')}
    if kind == "url_encode":
        return {"编码结果": quote(value, safe='')}
    if kind == "url_decode":
        return {"解码结果": unquote(value, errors='strict')}
    if kind == "jwt":
        parts = value.strip().split('.')
        if len(parts) != 3:
            raise ValueError('JWT 应包含三段。')
        def decode(part):
            data = json.loads(base64.b64decode(part + '=' * (-len(part) % 4), altchars=b'-_', validate=True))
            if not isinstance(data, dict):
                raise ValueError('JWT 头部与声明必须是对象。')
            return data
        return {"签名状态":"未验证；解码内容不能证明令牌真实或有效", "头部":decode(parts[0]), "声明":decode(parts[1])}
    if kind == "targets":
        hosts, invalid = [], []
        for number, line in enumerate(value.splitlines(), 1):
            if not line.strip():
                continue
            try:
                host, _, _ = parse_target(line)
                if not host or not all(c.isalnum() or c in '.-:' for c in host):
                    raise ValueError('Invalid hostname')
                if host not in hosts:
                    hosts.append(host)
            except ValueError:
                invalid.append(number)
        return {"主机清单":hosts, "去重后数量":len(hosts), "无效行号":invalid, "说明":"仅整理输入，不发送网络请求，也不自动扩大项目范围。"}
    if kind == "ip":
        net = ipaddress.ip_network(value.strip(), strict=False)
        return {"网络": str(net), "版本": f"IPv{net.version}", "起始地址": str(net.network_address), "结束地址": str(net.broadcast_address), "地址总数": net.num_addresses, "私有地址段": net.is_private}
    if kind == "url":
        host, port, url = parse_target(value)
        parsed = urlsplit(url)
        keys = list(dict.fromkeys(k for k, _ in parse_qsl(parsed.query, keep_blank_values=True)))
        safe_url = parsed._replace(query=urlencode([(key, "[隐藏]") for key in keys])).geturl()
        return {"地址": safe_url, "协议": parsed.scheme, "主机": host, "端口": port, "路径": parsed.path or "/", "参数名称": keys}
    if kind == "json":
        return {"格式化结果": json.dumps(json.loads(value), ensure_ascii=False, indent=2)}
    if kind == "base64":
        return {"解码结果": base64.b64decode(value.strip(), validate=True).decode("utf-8")}
    if kind == "sha256":
        return {"SHA-256": hashlib.sha256(value.encode("utf-8")).hexdigest(), "UTF-8 字节数": len(value.encode("utf-8"))}
    raise ValueError("不支持的工具。")


async def network_tool(kind: str, value: str, rules: list[str], proxy: str | None = None) -> dict:
    host, port, url = parse_target(value)
    scope_target = f"https://[{host}]" if ":" in host else host
    if not target_in_scope(scope_target, rules):
        raise ValueError("目标不在当前项目授权范围内，请先到项目设置核对范围。")
    if proxy and kind != "http":
        raise ValueError("当前项目启用了代理；DNS、TCP 和 TLS 诊断需要直连，请先在项目设置中选择直连。")
    start = time.monotonic()
    async with asyncio.timeout(12):
        if kind == "dns":
            records = await asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM)
            result = {"域名": host, "IPv4": sorted({r[4][0] for r in records if r[0] == socket.AF_INET}), "IPv6": sorted({r[4][0] for r in records if r[0] == socket.AF_INET6})}
        elif kind == "tcp":
            _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), 6)
            writer.close()
            await writer.wait_closed()
            result = {"主机": host, "端口": port, "连接": "成功"}
        elif kind == "tls":
            data = await analyze_tls(host, port, timeout=6)
            if not data.get("ok"):
                raise ValueError("TLS 校验未通过，请检查证书有效期、域名匹配及服务端配置。")
            result = {"主机": host, "端口": port, "协议": data["protocol"], "加密套件": data["cipher"], "生效时间": data["notBefore"], "到期时间": data["notAfter"], "颁发者": data["issuer"], "覆盖域名": data["subjectAltName"], "证书校验": "通过"}
        elif kind == "http":
            async with httpx.AsyncClient(timeout=8, follow_redirects=False, verify=True, trust_env=False, proxy=proxy) as client:
                # HEAD and streaming avoid downloading a potentially unbounded response body.
                async with client.stream("HEAD", url, headers={"User-Agent": "SnowEdge-Diagnostics"}) as response:
                    allowed = {"server", "content-type", "content-length", "date", "cache-control", "strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy"}
                    headers = {k: v[:2000] for k, v in response.headers.items() if k in allowed}
                    result = {"地址": redact_url(url), "HTTP 状态": response.status_code, "响应头": headers, "重定向": "未跟随" if response.is_redirect else "无", "说明": "仅发送 HEAD 请求；405 表示服务不支持 HEAD，并不代表站点离线。"}
        else:
            raise ValueError("不支持的网络工具。")
    result["耗时（毫秒）"] = round((time.monotonic() - start) * 1000)
    return result
