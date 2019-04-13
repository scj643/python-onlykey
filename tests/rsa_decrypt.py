from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from onlykey.client import OnlyKey, Message
import logging
import time
import binascii
import codecs
from cryptography.hazmat.primitives.asymmetric import padding

logging.basicConfig()

logger = logging.getLogger()

logger.info('Initializing OnlyKey')
ok = OnlyKey()
logger.info('Initialized')


def bin2hex(binStr):
    return binascii.hexlify(binStr)


def hex2bin(hexStr):
    return binascii.unhexlify(hexStr)


def pack_long(n):
    """this conert 10045587143827198209824131064458461027107542643158086193488942239589004873324146472911535357118684101051965945865943581473431374244810144984918148150975257L
    to "\xbf\xcd\xce\xa0K\x93\x85}\xf0\x18\xb3\xd3L}\x14\xdb\xce0\x00uE,\x05'\xeeW\x1c\xeb\xcf\x8b\x1f\xcc\xc5\xc1\xe2\x17\xb7\xa3\xb6C\x16\xea?\xcchz\xebF1\xb7\xb1\x86\xb8\n}\x82\xebx\xce\x1b\x13\xdf\xdb\x19"
    it seems to be want you wanted? it's 64 bytes.
    """
    h = b'%x' % n
    s = codecs.decode((b'0' * (len(h) % 2) + h), 'hex')
    return s


for key_length in [1024, 2048, 3072, 4096]:
    logger.info("Generating key of length: {}".format(key_length))
    priv_key = rsa.generate_private_key(65537, key_length, default_backend())  # type: rsa.RSAPrivateKey
    pub_key = priv_key.public_key()  # type: rsa.RSAPublicKey
    logger.info('p: {}'.format(priv_key.private_numbers().p))
    logger.info('q: {}'.format(priv_key.private_numbers().q))
    logger.info('n: {}'.format(pub_key.public_numbers().n))
    hexPrivKey = bin2hex(
        priv_key.private_bytes(encoding=serialization.Encoding.DER, format=serialization.PrivateFormat.PKCS8,
                               encryption_algorithm=serialization.NoEncryption())
    )
    hexPubKey = bin2hex(
        pub_key.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.PKCS1)
    )
    q_and_p = pack_long(priv_key.private_numbers().q) + pack_long(priv_key.private_numbers().p)
    public_n = pack_long(pub_key.public_numbers().n)
    if key_length == 1024:
        slot = 1
    if key_length == 2048:
        slot = 2
    if key_length == 3072:
        slot = 3
    if key_length == 4096:
        slot = 4
