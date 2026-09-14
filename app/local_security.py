"""Reject browser-origin mutations and DNS rebinding against the local UI."""
from urllib.parse import urlsplit
import re
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

class LocalOriginMiddleware(BaseHTTPMiddleware):
    def __init__(self,app,allowed_hosts):
        super().__init__(app)
        self.allowed_hosts={host.strip().lower() for host in allowed_hosts.split(',') if host.strip()}

    async def dispatch(self,request,call_next):
        try:
            raw_host=request.headers.get('host','')
            if any(c in raw_host for c in '@ /\\\t\r\n'):raise ValueError('Invalid host')
            parsed_host=urlsplit('//'+raw_host)
            host=parsed_host.hostname
            parsed_host.port
        except ValueError:host=None
        if not host or host.lower() not in self.allowed_hosts:
            return JSONResponse({'detail':'不受信任的工作台地址'},status_code=400)
        if request.method not in {'GET','HEAD','OPTIONS'}:
            # Public correlation endpoint has its own expiring, unguessable capability token.
            callback=bool(re.fullmatch(r'/api/oob/callback/[A-Za-z0-9_-]{32}',request.url.path))
            if not callback:
                origin=request.headers.get('origin')
                site=request.headers.get('sec-fetch-site')
                if origin:
                    try:parsed=urlsplit(origin)
                    except ValueError:return JSONResponse({'detail':'来源地址无效'},status_code=403)
                    expected=urlsplit(str(request.url))
                    if origin=='null' or parsed.scheme!=expected.scheme or parsed.netloc.lower()!=expected.netloc.lower() or parsed.path not in {'','/'} or parsed.query or parsed.fragment:
                        return JSONResponse({'detail':'已拒绝跨来源修改请求，请在工作台页面内操作。'},status_code=403)
                elif site and site!='same-origin':
                    return JSONResponse({'detail':'修改请求缺少可信来源'},status_code=403)
                elif 'mozilla/' in request.headers.get('user-agent','').lower() and site!='same-origin':
                    return JSONResponse({'detail':'浏览器修改请求缺少来源信息'},status_code=403)
        response=await call_next(request)
        if request.url.path.startswith('/api/hash') or request.url.path in ('/decoder','/api/decoder'):
            response.headers['Cache-Control']='no-store'
        response.headers.setdefault('X-Content-Type-Options','nosniff')
        response.headers.setdefault('X-Frame-Options','DENY')
        response.headers.setdefault('Referrer-Policy','same-origin')
        return response
