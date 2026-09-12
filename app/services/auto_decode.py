"""Conservative text decoder: bounded, reversible transformations, no execution."""
import base64
import html
import json
import re
from urllib.parse import unquote


def readable(raw):
    text = raw.decode('utf-8', errors='strict')
    if not text or sum(c.isprintable() or c in '\r\n\t' for c in text) / len(text) < .95:
        raise ValueError('解码结果不是可读 UTF-8 文本。')
    return text


def candidates(value):
    result = []
    def attempt(kind, fn):
        try:
            decoded = fn()
            if decoded != value and len(decoded) <= 128000:
                result.append({'type': kind, 'text': decoded})
        except (ValueError, UnicodeError, TypeError, json.JSONDecodeError):
            pass
    clean = value.strip()
    if re.search(r'%[0-9a-fA-F]{2}', value):
        attempt('URL', lambda: unquote(value, errors='strict'))
    if re.search(r'&(?:#[xX]?[0-9a-fA-F]+|[A-Za-z]+);', value):
        attempt('HTML 实体', lambda: html.unescape(value))
    if re.search(r'\\(?:u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2})', value):
        def escapes():
            text = re.sub(r'\\u([0-9a-fA-F]{4})', lambda m: chr(int(m[1],16)), value)
            text = re.sub(r'(?:\\x[0-9a-fA-F]{2})+', lambda m: readable(bytes.fromhex(m[0].replace('\\x',''))), text)
            return text.encode('utf-16', 'surrogatepass').decode('utf-16')
        attempt('Unicode / Hex 转义', escapes)
    if clean.count('.') == 2:
        def jwt():
            a,b,_ = clean.split('.')
            parts = [json.loads(base64.urlsafe_b64decode(p+'='*(-len(p)%4))) for p in (a,b)]
            if not all(isinstance(p,dict) for p in parts): raise ValueError()
            return json.dumps({'签名':'未验证','头部':parts[0],'声明':parts[1]},ensure_ascii=False,indent=2)
        attempt('JWT（不验证签名）', jwt)
    if len(clean) >= 4 and re.fullmatch(r'(?:[0-9a-fA-F]{2}[ :\-]?)+',clean):
        attempt('十六进制', lambda: readable(bytes.fromhex(re.sub(r'[ :\-]','',clean))))
    if len(clean) >= 4 and re.fullmatch(r'[A-Za-z0-9+/_\-]+={0,2}',clean):
        attempt('Base64 / Base64URL', lambda: readable(base64.b64decode(clean+'='*(-len(clean)%4),altchars=b'-_',validate=True)))
    return result


def decode(value, layers=1):
    if not value or len(value)>32000: raise ValueError('请输入 1–32000 字符。')
    choices = candidates(value)
    chain, current, seen = [], value, {value}
    for _ in range(max(1,min(layers,5))):
        options = candidates(current)
        if len(options) != 1: break
        step = options[0]
        if step['text'] in seen: break
        chain.append(step); current=step['text']; seen.add(current)
    return {'candidates':choices,'steps':chain,'result':current,
            'message':'存在多种可能，请选择解码方式。' if len(choices)>1 else ('已解码' if chain else '未发现可靠的文本编码；哈希和加密内容不能直接解码。')}
