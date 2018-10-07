import hashlib, json

def H(m):
  return hashlib.sha512(m).digest()

import ed25519
import os

# Load signing keys from location outside of repo
keys = json.loads(file('../../../misc/config/installer_signing_key.json', 'r').read())

def tobin(xs):
  return "".join(chr(x) for x in xs)

def gen_key():
  sk = os.urandom(32)
  pk = ed25519.publickey(sk)
  print 'sk', [ord(c) for c in sk]
  print 'pk', [ord(c) for c in pk]

hash = H(file('../tap/TunSafe-TAP-auto.exe', 'rb').read()) 
print hash.encode('hex'), repr(hash)

#m = 'test'
s = ed25519.signature(hash, tobin(keys['PRIVATE_KEY']), tobin(keys['PUBLIC_KEY']))
file('../tap/TunSafe-TAP-auto.exe.sig', 'wb').write(s.encode('hex'))
