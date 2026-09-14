"""Format evidence suggests candidates, never proves an unlabelled digest algorithm."""
import base64
import json
import re

SIZES={16:['MySQL 旧密码','LM（半段）'],32:['MD5','NTLM','MD4','LM'],40:['SHA-1'],56:['SHA-224','SHA3-224'],64:['SHA-256','SHA3-256'],96:['SHA-384','SHA3-384'],128:['SHA-512','SHA3-512']}
FORMATS=[
 (r'\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}', ['bcrypt']),
 (r'\$argon2(?:id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[^$]+\$[^$]+',['Argon2']),
 (r'\$(?:scrypt|7)\$.+',['scrypt']),
 (r'\$pbkdf2(?:-sha\d+)?\$.+',['PBKDF2']),
 (r'pbkdf2_(?:sha256|sha1)\$\d+\$[^$]+\$[^$]+',['Django PBKDF2']),
 (r'(?:bcrypt_sha256|bcrypt|argon2|scrypt)\$.+',['Django 密码 Hash']),
 (r'\$apr1\$[^$]{1,8}\$[./A-Za-z0-9]{22}',['APR1']),
 (r'\$[PH]\$[./A-Za-z0-9]{31}',['phpass','WordPress（历史格式）']),
 (r'\$wp\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}',['WordPress bcrypt']),
 (r'\$(?:1|5|6|y)\$.+',['Unix crypt']),
 (r'(?:sha1|md5)\$[^$]+\$[a-fA-F0-9]+',['Django 旧密码 Hash']),
 (r'\*[0-9A-Fa-f]{40}',['MySQL 4.1+']),
 (r'[^:\r\n]+::[^:\r\n]*:[0-9a-fA-F]{48}:[0-9a-fA-F]{48}:[0-9a-fA-F]{16}',['NetNTLMv1']),
 (r'[^:\r\n]+::[^:\r\n]*:[0-9a-fA-F]{16}:[0-9a-fA-F]{32}:[0-9a-fA-F]{32,}',['NetNTLMv2']),
]
def analyze(value):
    if not value or len(value)>32000:raise ValueError('请输入 1–32000 字符')
    clean=value.strip()
    result={'kind':'unknown','label':'无法确定类型','confidence':'低','candidates':[], 'length':len(clean),'bits':None,'representation':'文本','reason':'缺少可靠格式特征；不能仅凭随机外观断定为加密数据。','normalized':clean}
    for pattern,names in FORMATS:
        if re.fullmatch(pattern,clean):
            result.update(kind='hash',label='密码 Hash 格式',confidence='高',candidates=names,reason='匹配固定前缀与字段结构；尚未验证摘要内容。');return result
    if clean.count('.') in (2,4):
        try:
            parts=clean.split('.')
            header=json.loads(base64.urlsafe_b64decode(parts[0]+'='*(-len(parts[0])%4)))
            if not isinstance(header,dict) or not header.get('alg'):raise ValueError()
            if len(parts)==5 and header.get('enc'):
                result.update(kind='encrypted',label='JWE 加密 Token',confidence='高',reason='需要相应算法与密钥，不能直接解码声明。');return result
            payload=json.loads(base64.urlsafe_b64decode(parts[1]+'='*(-len(parts[1])%4)))
            if not isinstance(payload,dict):raise ValueError()
            result.update(kind='token',label='JWT',confidence='高',reason='仅解析头部与声明，不验证签名或可信性。');return result
        except (ValueError,TypeError,UnicodeError):pass
    compact=re.sub(r'\s+','',clean)
    if re.fullmatch('[0-9a-fA-F]+',compact) and len(compact)%2==0:
        raw=bytes.fromhex(compact)
        result.update(representation='Hex 表示形式',length=len(compact),bits=len(raw)*8,normalized=compact)
        try:
            decoded=raw.decode('utf-8')
            # Only clear text is automatically reversible; do not output control bytes.
            if decoded and all(c.isprintable() or c in '\n\r\t' for c in decoded):
                result.update(kind='encoding',label='Hex 文本',confidence='中',reason='可还原为可打印 UTF-8 文本；可打印性不证明来源。',decoded=decoded,candidates=SIZES.get(len(compact),[]));return result
        except UnicodeError:pass
        if len(compact) in SIZES:
            result.update(kind='hash',label='疑似 Hash',confidence='中',candidates=SIZES[len(compact)],reason='长度和字符集匹配摘要；同长度算法无法唯一确认，也可能是随机数据。');return result
    if re.fullmatch('[./A-Za-z0-9]{13}',clean):
        result.update(kind='hash',label='疑似 Unix crypt',candidates=['Unix DES crypt'],reason='仅长度和字符集匹配，可能是普通文本。');return result
    try:
        raw=base64.b64decode(clean+'='*(-len(clean)%4),altchars=b'-_',validate=True)
        if raw.startswith(b'Salted__'):
            result.update(kind='encrypted',label='疑似 OpenSSL 加盐加密数据',confidence='中',reason='检测到 Salted__ 标记，需要算法、口令或密钥。');return result
        try:
            decoded=raw.decode('utf-8')
            printable=all(c.isprintable() or c in '\r\n\t' for c in decoded)
        except UnicodeError:printable=False
        if not printable and len(raw)*2 in SIZES:
            result.update(kind='hash',label='疑似 Hash / 二进制数据',confidence='低',representation='Base64 表示形式',bits=len(raw)*8,candidates=SIZES[len(raw)*2],normalized=raw.hex(),reason='Base64 还原为摘要长度的二进制数据，也可能是密文或随机字节；不能唯一判断。')
    except ValueError:pass
    return result
