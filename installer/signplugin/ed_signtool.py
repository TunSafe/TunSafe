import hashlib

def H(m):
  return hashlib.sha512(m).digest()

import ed25519
import os

sk = "".join(chr(c) for c in [4, 213, 116, 80, 117, 4, 70, 166, 244, 214, 234, 159, 197, 101, 182, 177, 106, 180, 68, 125, 51, 32, 159, 77, 27, 151, 233, 91, 109, 184, 147, 235])
pk = "".join(chr(c) for c in [79, 236, 107, 197, 85, 239, 235, 109, 123, 181, 230, 115, 206, 112, 218, 80, 174, 167, 119, 187, 113, 153, 17, 115, 77, 100, 154, 84, 181, 194, 254, 99])

hash = H(file('../tap/TunSafe-TAP-9.21.2.exe', 'rb').read()) 
print hash.encode('hex'), repr(hash)

#sk = os.urandom(32)
#pk = ed25519.publickey(sk)
#print 'sk', [ord(c) for c in sk]
#print 'pk', [ord(c) for c in pk]

#m = 'test'
s = ed25519.signature(hash,sk,pk)
file('../tap/TunSafe-TAP-9.21.2.exe.sig', 'wb').write(s.encode('hex'))
