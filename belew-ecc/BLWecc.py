from . import ec
from . import registry
import random
import hashlib

curve = registry.get_curve("secp224r1")

def setCurve(curve):
	curve = registry.get_curve(curve)
	return curve


def prime_field_inv(a: int, n: int) -> int:
    """
    Extended euclidean algorithm to find modular inverses for integers
    """
    if a == 0:
        return 0
    lm, hm = 1, 0
    low, high = a % n, n
    while low > 1:
        r = high // low
        nm, new = hm - lm * r, high - low * r
        lm, low, hm, high = nm, new, lm, low
    return lm % n



def getPublicKeyPoint(da:int) -> ec.Point:
	da = da % curve.field.n
	return da*curve.g

def getPublicKey(code:str) -> str:
	daHex=getPrivateKey(code)
	da=int(daHex,16)
	qa=getPublicKeyPoint(da)
	return hex(qa.x)+'xbelewx'+hex(qa.y)

def pub2add(pub:str) ->str:
	q=hashlib.sha256(pub.encode())
	return '0x'+q.hexdigest()[:23]

def getPrivateKey(code:str) -> str:
	s=hashlib.sha256(code.encode()).hexdigest()
	w=23*int(s,16)
	return hex(w)

def getAddress(code:str) -> str:
	pub=getPublicKey(code)
	q=hashlib.sha256(pub.encode())
	return '0x'+q.hexdigest()[:23]

def sign(msg:str, pvt:str) -> str:
	(r,s)=signRaw(msg.encode(),int(pvt,16))
	return hex(r)+'xbelewx'+hex(s)

def signRaw(msg:bytes ,da:int) -> (int,int):
	z=int(hashlib.sha256(msg).hexdigest(),16)%curve.field.n
	k=random.randint(1,curve.field.n)
	g1=k*curve.g
	r=0
	s=0
	while r==0 or s==0:
		r=g1.x%curve.field.n
		s=prime_field_inv(k,curve.field.n)*(z+r*da)%curve.field.n
	return (r,s)

def verifyByPoints(msg:bytes ,r:int,s:int,x:int,y:int) -> bool:
	z=int(hashlib.sha256(msg).hexdigest(),16)%curve.field.n
	qa=ec.Point(curve,x,y)
	s=s%curve.field.n
	r=r%curve.field.n
	assert(qa.on_curve)
	assert(r<curve.field.n)
	assert(s<curve.field.n)
	u1=z*prime_field_inv(s,curve.field.n)%curve.field.n
	u2=r*prime_field_inv(s,curve.field.n)%curve.field.n
	g1=u1*curve.g+u2*qa
	return g1.x%curve.field.n==r

def verifyTx(msg:str, sgn:str, pub:str) -> bool:
	try:
		(r,s)=sgn.split('xbelewx')
		(x,y)=pub.split('xbelewx')
		return verifyByPoints(msg.encode(),int(r,16),int(s,16),int(x,16),int(y,16))
	except:
		return False

