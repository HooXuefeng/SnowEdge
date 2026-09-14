"""Small offline digest implementations; no network or password logging."""
import hashlib
import struct

def md4(data):
    size=len(data)*8;data+=b'\x80';data+=b'\0'*((56-len(data)%64)%64)+struct.pack('<Q',size)
    state=[0x67452301,0xefcdab89,0x98badcfe,0x10325476]
    def rol(x,n):x&=0xffffffff;return ((x<<n)|(x>>(32-n)))&0xffffffff
    for offset in range(0,len(data),64):
        words=struct.unpack('<16I',data[offset:offset+64]);v=state[:]
        for rnd in range(3):
            order=range(16) if rnd==0 else [i+4*j for i in range(4) for j in range(4)] if rnd==1 else [0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15]
            for j,k in enumerate(order):
                a=(-j)%4;b=(a+1)%4;c=(a+2)%4;d=(a+3)%4
                f=(v[b]&v[c])|(~v[b]&v[d]) if rnd==0 else (v[b]&v[c])|(v[b]&v[d])|(v[c]&v[d]) if rnd==1 else v[b]^v[c]^v[d]
                v[a]=rol(v[a]+f+words[k]+[0,0x5a827999,0x6ed9eba1][rnd],[(3,7,11,19),(3,5,9,13),(3,9,11,15)][rnd][j%4])
        state=[(x+y)&0xffffffff for x,y in zip(state,v)]
    return struct.pack('<4I',*state).hex()

SUPPORTED=['MD5','NTLM','MD4','SHA-1','SHA-224','SHA-256','SHA-384','SHA-512','SHA3-224','SHA3-256','SHA3-384','SHA3-512']
def digest(password,algorithm):
    if algorithm=='NTLM':return md4(password.encode('utf-16le'))
    if algorithm=='MD4':return md4(password.encode('utf-8'))
    if algorithm not in SUPPORTED:raise ValueError('该格式目前仅支持识别，不支持内置匹配')
    name=algorithm.lower().replace('sha3-','sha3_').replace('-','')
    return hashlib.new(name,password.encode('utf-8')).hexdigest()
