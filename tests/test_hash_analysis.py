import hashlib
import io
import time
import pytest
from app.services.hash_analysis.detector import analyze
from app.services.hash_analysis.algorithms import md4,digest
from app.services.hash_analysis.dictionary import DictionaryManager
from app.services.hash_analysis.matcher import HashMatcher
from app.services.auto_decode import decode

@pytest.mark.parametrize('value,names',[('e10adc3949ba59abbe56e057f20f883e',['MD5','NTLM','MD4']),('8846f7eaee8fb117ad06bdd830b7586c',['NTLM']),('da39a3ee5e6b4b0d3255bfef95601890afd80709',['SHA-1']),('e3b0c44298fc1c149afbf4c8996fb924\n27ae41e4649b934ca495991b7852b855',['SHA-256']),('a0'*16,['MD5','NTLM'])])
def test_ambiguous(value,names):
    a=analyze(value);assert a['kind']=='hash' and a['confidence']!='高'
    assert set(names)<=set(a['candidates']);assert not decode(value,5)['steps']
@pytest.mark.parametrize('value',['U25vd0VkZ2U=','536e6f7745646765','NTM2ZTZmNzc0NTY0Njc2NQ=='])
def test_decode(value):assert decode(value,5)['result']=='SnowEdge'
def test_wrapped_hash():
    import base64
    target='e10adc3949ba59abbe56e057f20f883e';r=decode(base64.b64encode(target.encode()).decode(),5)
    assert r['result']==target and r['analysis']['kind']=='hash' and len(r['steps'])==1
@pytest.mark.parametrize('raw,expected',[(b'','31d6cfe0d16ae931b73c59d7e0c089c0'),(b'a','bde52cb31de33e46245e05fbdbd6fb24'),(b'abc','a448017aaf21d8525fc10ae87aa6729d'),(b'1234567890'*8,'e33b4ddc9c38f2199c3e7b164fcc0536')])
def test_md4(raw,expected):assert md4(raw)==expected
def test_ntlm():assert digest('password','NTLM')=='8846f7eaee8fb117ad06bdd830b7586c'
@pytest.mark.parametrize('value,kind',[('$2b$12$'+'a'*53,'hash'),('$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA','hash'),('$P$'+'a'*31,'hash'),('*'+'A'*40,'hash'),('pbkdf2_sha256$600000$salt$aGFzaA==','hash'),('U2FsdGVkX18xMjM0NTY3OA==','encrypted'),('plain text','unknown')])
def test_formats(value,kind):assert analyze(value)['kind']==kind

def wait(m,key):
    deadline=time.monotonic()+5
    while time.monotonic()<deadline:
        r=m.get(key)
        if r['status'] not in ('queued','running'):return r
        time.sleep(.01)
    raise AssertionError('timeout')
@pytest.mark.parametrize('algorithm,password',[('MD5','123456'),('MD5','password'),('NTLM','password'),('SHA-1','admin'),('SHA-256','admin'),('SHA-512','admin')])
def test_match(algorithm,password):
    m=HashMatcher()
    try:
        r=wait(m,m.start(digest(password,algorithm),[algorithm])['id']);assert r['status']=='matched' and r['result']['plaintext']==password
        m.clear(r['id'])
        with pytest.raises(ValueError):m.get(r['id'])
    finally:m.pool.shutdown()
def test_dictionary(tmp_path):
    d=DictionaryManager(tmp_path);item=d.import_file(io.BytesIO(b'one\ntwo\n'),'../../custom.txt')
    assert item['entries']==2 and not item['enabled'] and item['name']=='custom.txt'
    with pytest.raises(ValueError):d.selected(item['id'])
    d.update(item['id'],True);assert d.selected(item['id'])[1].is_file()
    d.update(item['id'],delete=True)
    with pytest.raises(ValueError):d.path('../other')
    with pytest.raises(ValueError):d.update('common',delete=True)
    with pytest.raises(ValueError):d.import_file(io.BytesIO(b'\xff'),'bad.txt')
def test_cancel(monkeypatch,tmp_path):
    from app.services.hash_analysis import matcher as module
    path=tmp_path/'large.txt';path.write_text('no\n'*100000)
    monkeypatch.setattr(module.manager,'selected',lambda key:({'entries':100000,'name':'test'},path))
    m=HashMatcher()
    try:
        job=m.start('e10adc3949ba59abbe56e057f20f883e',['MD5']);m.cancel(job['id']);assert wait(m,job['id'])['status']=='cancelled'
    finally:m.pool.shutdown()
def test_provider():
    from app.services.hash_analysis.providers import lookup,providers
    calls=[]
    class Fake:
        def lookup(self,value):calls.append(value);return {'found':False}
    providers['test']=Fake()
    try:
        with pytest.raises(ValueError):lookup('test','secret',False)
        assert not calls;assert lookup('test','secret',True)=={'found':False}
    finally:providers.clear()
def test_api():
    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app) as c:
        r=c.post('/api/hash/jobs',json={'value':hashlib.md5(b'password').hexdigest(),'algorithms':['MD5']})
        assert r.status_code==200 and r.headers['cache-control']=='no-store'
        key=r.json()['id'];assert c.get('/api/hash/jobs/'+key).headers['cache-control']=='no-store'
        assert c.delete('/api/hash/jobs/'+key).status_code==200
        assert c.post('/api/hash/lookup',json={'value':'abc','provider':'none','confirmed':True}).status_code==400
        assert c.get('/decoder').status_code==200

@pytest.mark.parametrize('value,name',[
 ('$scrypt$ln=16,r=8,p=1$c2FsdA$aGFzaA','scrypt'),
 ('$pbkdf2-sha256$10000$c2FsdA$aGFzaA','PBKDF2'),
 ('$apr1$salt$'+'a'*22,'APR1'),
 ('$6$salt$hash','Unix crypt'),
 ('$wp$2y$12$'+'a'*53,'WordPress bcrypt'),
 ('user::DOMAIN:'+'a'*48+':'+'b'*48+':'+'c'*16,'NetNTLMv1'),
 ('user::DOMAIN:'+'a'*16+':'+'b'*32+':'+'c'*64,'NetNTLMv2'),
 ('ad'*28,'SHA3-224'),('ad'*32,'SHA3-256'),('ad'*48,'SHA3-384'),('ad'*64,'SHA3-512'),
])
def test_additional_formats(value,name):assert name in analyze(value)['candidates']
def test_jwt_and_jwe():
    import base64,json
    enc=lambda v:base64.urlsafe_b64encode(json.dumps(v).encode()).decode().rstrip('=')
    jwt=enc({'alg':'HS256'})+'.'+enc({'sub':'test'})+'.signature'
    assert decode(jwt,5)['analysis']['kind']=='token'
    assert analyze(enc({'alg':'RSA-OAEP','enc':'A256GCM'})+'.a.b.c.d')['kind']=='encrypted'
def test_not_found():
    m=HashMatcher()
    try:assert wait(m,m.start(digest('not-in-common-fixture','SHA-256'),['SHA-256'])['id'])['status']=='not_found'
    finally:m.pool.shutdown()
def test_hashcat_configuration(monkeypatch):
    from app.services.hash_analysis import hashcat
    monkeypatch.setattr(hashcat.shutil,'which',lambda value:None)
    assert not hashcat.available()['available']
    with pytest.raises(ValueError):hashcat.runner('MD5','dictionary')
    monkeypatch.setattr(hashcat.shutil,'which',lambda value:'C:/fixture/hashcat.exe')
    with pytest.raises(ValueError):hashcat.runner('MD5','bruteforce')
    assert callable(hashcat.runner('NTLM','dictionary'))
def test_hashcat_process_adapter(monkeypatch,tmp_path):
    from app.services.hash_analysis import hashcat
    import threading
    monkeypatch.setattr(hashcat.shutil,'which',lambda name:'hashcat-fixture')
    seen=[]
    class Process:
        returncode=0
        def __init__(self,args,**kwargs):
            seen.append(args)
            from pathlib import Path
            Path(args[args.index('--outfile')+1]).write_text('password\n',encoding='utf-8')
        def poll(self):return 0
    monkeypatch.setattr(hashcat.subprocess,'Popen',Process)
    job={'cancel':threading.Event()};dictionary=tmp_path/'dict.txt';dictionary.write_text('password')
    hashcat.runner('MD5','dictionary')(job,'5f4dcc3b5aa765d61d8327deb882cf99',['MD5'],dictionary)
    assert job['result']['plaintext']=='password'
    assert '--potfile-disable' in seen[0] and '--restore-disable' in seen[0]
    assert '5f4dcc3b5aa765d61d8327deb882cf99' not in seen[0]

def test_binary_base64_is_ambiguous():
    import base64
    value=base64.b64encode(bytes.fromhex('e10adc3949ba59abbe56e057f20f883e')).decode()
    result=decode(value,5)
    assert result['analysis']['confidence']=='低' and 'MD5' in result['analysis']['candidates']
    assert not result['steps']
