ECC Package for Belew Chain, namely sealord, seaQlord, meso, et al.

Copyright (C) 2019 Belew Tech

In case of problems, bugs or questions, contact Belew Tech


usage:
>>> import belew-ecc as ecc
>>> pub = ecc.getPublicKey('test')
>>> pvt = ecc.getPrivateKey('test')
>>> address1 = ecc.getAddressByCode('test')
>>> address2 = ecc.getAddressByPublicKey(pub)
>>> address1 == address2

>>> signarture = ecc.sign('msg', pvt)
>>> verify('msg', signature, pub)