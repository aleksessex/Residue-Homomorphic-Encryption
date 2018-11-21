# SAGEMath program for generating DGK keypairs

import json

keyFileName = "test-256"

# --------------------
# PARAMETER DEFINITION
# Size of message space
s = 148139

# Non-DGK parameters for Quadratic residue threshold function add-on
# QRRunOffset is an element within Z^*_s indicating the beginning of a QRRunLength of span QRs followed by QRRunLength non-QRs
# Determined externally through brute force search
QRRunOffset = 74051
QRRunLength = 20

# params
bitsOfSecurity = 256

# NIST Parameters for given bitsOfSecurity level
# https://www.keylength.com/en/4/
if bitsOfSecurity == 112:
	plen = 1024
	ulen = 224
elif bitsOfSecurity == 128:
	plen = 1536
	ulen = 256
elif bitsOfSecurity == 192:
	plen = 3840
	ulen = 384
elif bitsOfSecurity == 256:
	plen = 7680
	ulen = 512
else:
	plen = 1024
	ulen = 224

# Returns a random t-bit prime
def tprime(t):
	while True:
		p = Integer(randint(2^(t-1),2^t))
		if is_pseudoprime(p):
			return p

# Returns a DGK prime where p = 2 * s * u * w + 1 where:
# the subgroup of order s will contain message
# the subgroup of order u will contain the random factor (large enough that the DL is hard)
# the subgroup of order w is there to pad to plen bits (to prevent factorization)
def genDGKPrime():
	w = tprime(plen - ulen - ceil(log2(s)))
	while True:
		u = tprime(ulen)
		p = 2*s*u*w+1
		if isprime(p):
			return u,p

# Return a generator of a subgroup mod n which has order a in Z^*_p, and order b in Z^*_q
def findGenerator(a,p,b,q):
	while True:
		x = randint(2,p-1)
		gp = Integer(pow(x, Integer((p-1)/a), p))
		if gp != 1:
			break
	while True:
		x = randint(2, q-1)
		gq = Integer(pow(x, Integer((q-1)/b), q))
		if gq != 1:
			break

	return crt([gp,gq],[p,q])

# Validates the key pair
def validateKey(u,p,v,q,plen,ulen,s,g,h):
	if not (isprime(u) and isprime(p) and isprime(v) and isprime(q) and isprime((p-1)/(2*s*u)) and isprime((q-1)/(2*s*v))):
		print "Primality failure in one of the parameters or its subgroup"
		return False
	if not (pow(g,s,p) == 1 and pow(g,s,q) == 1 and pow(h,u,p) == 1 and pow(h,v,q) == 1):
		print "One of the generators has incorrect order"
		return False

	if not (ceil(log2(u)) >= ulen-1 and ceil(log2(v)) >= ulen-1):
		print "One of u,v has insufficient bit length"
		return False

	if not (ceil(log2(p)) >= plen-1 and ceil(log2(q)) >= plen-1):
		print "One of p,q has insufficient bit length"
		return False

	return True

# Generate keypair and write to json file
def genKey(fileName):
	prvKey = {}
	pubKey = {}
	u, p = genDGKPrime()
	v, q = genDGKPrime()
	n = p*q
	g = findGenerator(s,p,s,q)
	h = findGenerator(u,p,v,q)

	if not validateKey(u,p,v,q,plen,ulen,s,g,h):
		return False

	pubKey['n'] = str(n)
	pubKey['l'] = str(ulen)
	pubKey['s'] = str(s)
	pubKey['g'] = str(g)
	pubKey['h'] = str(h)

	# Add offset information to public key if defined
	try:
		pubKey['QRRunOffset'] = str(QRRunOffset)
		pubKey['QRRunLength'] = str(QRRunLength)
	except NameError:
		pass

	prvKey['u'] = str(u)
	prvKey['p'] = str(p)
	
	with open(fileName + '.prv', 'w') as prvOut:
		json.dump(prvKey, prvOut)
	prvOut.close()

	with open(fileName + '.pub', 'w') as pubOut:
		json.dump(pubKey, pubOut)
	pubOut.close()

	return True

if genKey(keyFileName):
	print "Key generation was successful"
else:
	print "Key generation failed"