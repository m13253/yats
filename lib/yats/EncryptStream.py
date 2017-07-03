#!/usr/bin/env python3

import hashlib
import os
import random
import struct
import zlib
try:
    import Crypto.Cipher.AES
except ImportError:
    sys.stderr.write('ERROR: Please have pycrypto for Python %s.%s.%s installed.\n' % tuple(sys.version_info)[:3])
    sys.exit(2)


class AESEncryptStream():

    def __init__(self, key):
        self.AES = Crypto.Cipher.AES.new(hashlib.sha256(key.encode('iso-8859-1', 'replace')).digest())
        self.undecrypted = b''
        self.unprocessed = b''

    def encrypt(self, stream, extradata=0):
        output = b''
        for i in range(random.randint(0, 4)):
            output += b'\0' + os.urandom(12)
        output += struct.pack('>BLLL', random.randint(1, 255), len(stream), zlib.crc32(stream) & 0xffffffff, extradata)
        stream = output + stream
        output = b''
        while stream:
            if len(stream) < 14:
                stream += os.urandom(14 - len(stream))
            output += os.urandom(1) + stream[:14] + os.urandom(1)
            stream = stream[14:]
        return self.AES.encrypt(output)

    def encryptjson(self, stream, extradata=0):
        return self.encrypt(json.dumps(stream).encode('utf-8', 'replace'), extradata)

    def decrypt(self, stream):
        stream = self.undecrypted + stream
        self.undecrypted = stream[len(stream) & ~0xf:len(stream)]
        stream = self.AES.decrypt(stream[:len(stream) & ~0xf])
        unfuzzied = self.unprocessed
        self.unprocessed = b''
        offset = 0
        while offset < len(stream):
            unfuzzied += stream[offset + 1:offset + 15]
            offset += 16
        output = []
        offset = 0
        while offset + 13 < len(unfuzzied):
            header = struct.unpack_from('>BLLL', unfuzzied, offset)
            if header[0]:
                chunkoutput = unfuzzied[offset + 13:offset + 13 + header[1]]
                if len(chunkoutput) != header[1]:
                    break
                offset += 13
                crcsum = zlib.crc32(chunkoutput) & 0xffffffff
                if crcsum == header[2]:
                    output.append((chunkoutput, header[3]))
                    offset += header[1]
                    offset_mod_14 = offset % 14
                    if offset_mod_14 != 0:
                        offset += 14 - offset_mod_14
                else:
                    raise ValueError('CRC mismatch: %08x!=%08x' % (crcsum, header[2]))
            else:
                offset += 13
        self.unprocessed = unfuzzied[offset:]
        return output

    def decryptjson(self, stream):
        return [(json.loads(i[0].decode('utf-8', 'replace')), i[1]) for i in self.decrypt(stream)]

    def havepending(self):
        return bool(self.undecrypted) or bool(self.unprocessed)

    def flushpending(self):
        self.undecrypted = b''
        self.unprocessed = b''
