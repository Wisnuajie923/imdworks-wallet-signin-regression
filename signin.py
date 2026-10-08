"""Local-only Ethereum-style personal_sign verifier regression lab."""
from __future__ import annotations
import hashlib, re, threading
from dataclasses import dataclass

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (55066263022277343669578718895168534326250603453777594175500187360389116729240,
     32670510020758816978083085130507043184471273380659243275938904335757337482424)

# Small Keccak-256 implementation (Ethereum uses Keccak, not standardized SHA3 padding).
_RC = [1,0x8082,0x800000000000808A,0x8000000080008000,0x808B,0x80000001,0x8000000080008081,0x8000000000008009,0x8A,0x88,0x80008009,0x8000000A,0x8000808B,0x800000000000008B,0x8000000000008089,0x8000000000008003,0x8000000000008002,0x8000000000000080,0x800A,0x800000008000000A,0x8000000080008081,0x8000000000008080,0x80000001,0x8000000080008008]
_ROT = [[0,36,3,41,18],[1,44,10,45,2],[62,6,43,15,61],[28,55,25,21,56],[27,20,39,8,14]]
_MASK=(1<<64)-1

def _rol(x,n): return ((x<<n)|(x>>(64-n)))&_MASK if n else x

def keccak256(data: bytes) -> bytes:
    rate=136; a=[0]*25; padded=bytearray(data); padded.append(1)
    while len(padded)%rate != rate-1: padded.append(0)
    padded.append(0x80)
    for off in range(0,len(padded),rate):
        block=padded[off:off+rate]
        for i in range(rate//8): a[i]^=int.from_bytes(block[8*i:8*i+8],'little')
        for rc in _RC:
            c=[a[x]^a[x+5]^a[x+10]^a[x+15]^a[x+20] for x in range(5)]
            d=[c[(x-1)%5]^_rol(c[(x+1)%5],1) for x in range(5)]
            for x in range(5):
                for y in range(5): a[x+5*y]^=d[x]
            b=[0]*25
            for x in range(5):
                for y in range(5): b[y+5*((2*x+3*y)%5)] = _rol(a[x+5*y],_ROT[x][y])
            for x in range(5):
                for y in range(5): a[x+5*y]=b[x+5*y]^((~b[(x+1)%5+5*y])&b[(x+2)%5+5*y])
            a[0]^=rc
    return b''.join(x.to_bytes(8,'little') for x in a)[:32]

def inv(x, m=P): return pow(x, m-2, m)
def point_add(a,b):
    if a is None: return b
    if b is None: return a
    if a[0]==b[0] and (a[1]+b[1])%P==0: return None
    if a==b: lam=(3*a[0]*a[0])*inv(2*a[1])%P
    else: lam=(b[1]-a[1])*inv((b[0]-a[0])%P)%P
    x=(lam*lam-a[0]-b[0])%P; return x,(lam*(a[0]-x)-a[1])%P
def point_mul(k,p=G):
    out=None
    while k:
        if k&1: out=point_add(out,p)
        p=point_add(p,p); k>>=1
    return out

def _rfc6979(priv, digest):
    x=priv.to_bytes(32,'big'); h=digest
    v=b'\x01'*32; k=b'\x00'*32
    k=hmac(k,v+b'\x00'+x+h); v=hmac(k,v); k=hmac(k,v+b'\x01'+x+h); v=hmac(k,v)
    while True:
        v=hmac(k,v)
        z=int.from_bytes(v,'big')
        if 1<=z<N: return z
        k=hmac(k,v+b'\x00'); v=hmac(k,v)
def hmac(k,d): return hashlib.hmac.new(k,d,hashlib.sha256).digest() if hasattr(hashlib,'hmac') else __import__('hmac').new(k,d,hashlib.sha256).digest()

def personal_digest(message):
    raw=message.encode(); return keccak256(b'\x19Ethereum Signed Message:\n'+str(len(raw)).encode()+raw)
def recover(digest,r,s,v):
    if not (1<=r<N and 1<=s<N and v in (27,28)): raise VerifyError('malformed-signature')
    x=r; alpha=(pow(x,3,P)+7)%P; beta=pow(alpha,(P+1)//4,P); y=beta if beta%2==(v-27) else P-beta
    R=(x,y)
    if point_mul(N,R) is not None: raise VerifyError('malformed-signature')
    z=int.from_bytes(digest,'big'); return point_mul(inv(r,N), point_add(point_mul(s,R), point_mul((-z)%N,G)))
def address_for(pub): return '0x'+keccak256(pub[0].to_bytes(32,'big')+pub[1].to_bytes(32,'big'))[-20:].hex()

@dataclass(frozen=True)
class Wallet:
    private_key:int
    address:str
    @classmethod
    def from_seed(cls, seed):
        key=(int.from_bytes(keccak256(seed.encode()),'big')%(N-1))+1
        return cls(key,address_for(point_mul(key)))
    def sign_personal(self,message):
        d=personal_digest(message); z=int.from_bytes(d,'big'); k=_rfc6979(self.private_key,d); x,y=point_mul(k)
        r=x%N; s=(inv(k,N)*(z+r*self.private_key))%N; rec=27+(y&1)
        if s>N//2: s=N-s; rec=27+(1-(y&1))
        return r.to_bytes(32,'big')+s.to_bytes(32,'big')+bytes([rec])

def build_message(address, nonce, origin, expires):
    return f'Wallet sign-in\nAddress: {address}\nNonce: {nonce}\nOrigin: {origin}\nExpires: {expires}'

class VerifyError(Exception): pass
class SecureVerifier:
    def __init__(self, clock): self.clock=clock; self.used=set(); self.lock=threading.Lock()
    def verify(self,message,signature,expected_origin):
        try:
            m=re.fullmatch(r'Wallet sign-in\nAddress: (0x[0-9a-f]{40})\nNonce: ([A-Za-z0-9._:-]{1,64})\nOrigin: (https://[A-Za-z0-9.-]{1,253})\nExpires: ([0-9]+)',message)
            if not m: raise VerifyError('malformed-message')
            address,nonce,origin,expires=m.groups(); expires=int(expires)
            if origin!=expected_origin: raise VerifyError('origin-mismatch')
            if self.clock()>expires: raise VerifyError('expired')
            if len(signature)!=65: raise VerifyError('malformed-signature')
            r=int.from_bytes(signature[:32],'big'); s=int.from_bytes(signature[32:64],'big'); v=signature[64]
            recovered=address_for(recover(personal_digest(message),r,s,v))
            if recovered!=address: raise VerifyError('wrong-signer')
            key=(address,nonce)
            with self.lock:
                if key in self.used: raise VerifyError('nonce-consumed')
                self.used.add(key)
            return True
        except VerifyError: raise
        except Exception as e: raise VerifyError('malformed-signature') from e

class VulnerableNoNonce(SecureVerifier):
    def verify(self,message,signature,expected_origin):
        old=self.used; self.used=set()
        try: return super().verify(message,signature,expected_origin)
        finally: self.used=old
class VulnerableOrigin(SecureVerifier):
    def verify(self,message,signature,expected_origin):
        return super().verify(message,signature,message.split('Origin: ',1)[1].split('\n',1)[0])
def canonicalize_evidence_results(results):
    """Return concurrency statuses in a stable order for persisted evidence."""
    return sorted(results)


class ConcurrentSigninService:
    def __init__(self,clock): self.verifier=SecureVerifier(clock)
    def attempt(self,message,sig,origin):
        try: self.verifier.verify(message,sig,origin); return 'accepted'
        except VerifyError as e: return 'rejected:'+str(e)
    def concurrent_attempts(self,message,sig,origin,count=32):
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=count) as pool: return list(pool.map(lambda _:self.attempt(message,sig,origin),range(count)))
