#!/usr/bin/env python3

import hashlib
import logging
import random
import os
import socket
import struct
import sys
import time
import zlib
try:
    import Crypto.Cipher.AES
except ImportError:
    sys.stderr.write('ERROR: Please have pycrypto for Python %s.%s.%s installed.\n' % tuple(sys.version_info)[:3])
    sys.exit(2)

class AESEncryptStream():
    def __init__(self, key):
        self.AES=Crypto.Cipher.AES.new(hashlib.sha256(key.encode('iso-8859-1', 'replace')).digest())
        self.undecrypted=b''
        self.unprocessed=b''
    def encrypt(self, stream, extradata=0):
        output=b''
        for i in range(random.randint(0, 4)):
            output+=b'\0'+os.urandom(12)
        output+=struct.pack('>BLLL', random.randint(1, 255), len(stream), zlib.crc32(stream)&0xffffffff, extradata)
        stream=output+stream
        output=b''
        while stream:
            if len(stream)<14:
                stream+=os.urandom(14-len(stream))
            output+=os.urandom(1)+stream[:14]+os.urandom(1)
            stream=stream[14:]
        return self.AES.encrypt(output)
    def decrypt(self, stream):
        stream=self.undecrypted+stream
        self.undecrypted=stream[len(stream)&~0xf:len(stream)]
        stream=self.AES.decrypt(stream[:len(stream)&~0xf])
        unfuzzied=self.unprocessed
        self.unprocessed=b''
        offset=0
        while offset<len(stream):
            unfuzzied+=stream[offset+1:offset+15]
            offset+=16
        output=[]
        offset=0
        while offset+13<len(unfuzzied):
            header=struct.unpack_from('>BLLL', unfuzzied, offset)
            if header[0]:
                chunkoutput=unfuzzied[offset+13:offset+13+header[1]]
                if len(chunkoutput)!=header[1]:
                    break
                offset+=13
                crcsum=zlib.crc32(chunkoutput)&0xffffffff
                if crcsum==header[2]:
                    output.append((chunkoutput, header[3]))
                    offset+=header[1]
                    offset_mod_14=offset%14
                    if offset_mod_14!=0:
                        offset+=14-offset_mod_14
                else:
                    raise ValueError('CRC mismatch: %08x!=%08x' % (crcsum, header[2]))
            else:
                offset+=13
        self.unprocessed=unfuzzied[offset:]
        return output

def split_addr(s):
    res=[]
    pending=None
    while True:
        tmp=s.split(':', 1)
        if pending==None:
            if tmp[0].startswith('['):
                pending=tmp[0]
            else:
                res.append(tmp[0])
        else:
            pending+=':'+tmp[0]
            if pending.endswith(']'):
                res.append(pending)
                pending=None
        if len(tmp)>1:
            s=tmp[1]
        else:
            break
    if pending!=None:
        res.append(pending)
    return res

class Peer():
    def __init__(self):
        pass

class ClientPeer(Peer):
    def __init__(self):
        pass

    def parse_tunnel(self, tunnel_type, optstr):
        optsplt=split_addr(optstr)
        if tunnel_type in (0, 1):
            if len(optsplt)==3:
                optsplt.insert(0, '')
            elif len(optsplt)!=4:
                raise ValueError('Illegal forwarding option: %s' % optstr)
            else:
                self.listens.append((tunneltype,)+tuple(optsplt))
        elif tunnel_type==2:
            if len(optsplt)==1:
                optsplt.insert(0, '')
            elif len(optsplt)!=2:
                raise ValueError('Illegal forwarding option: %s' % optstr)
            else:
                self.listens.append((2,)+tuple(optsplt)+(None, None))
        else:
            raise ValueError('Illegal tunnel type: %s' % repr(tunnel_type))

    def start_client(self, bind, port, target):
        pass

    def client_loop(self):
        pass

def ServerPeer(Peer):
    def __init__(self):
        pass

    def start_server(self, bind, port):
        pass

    def server_loop(self):
        pass

if __name__=='__main__':
    logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.INFO)
    import optparse
    optparser=optparse.OptionParser(usage='Usage: %prog [-b bind_address] -k key -p port <-d | [-L [bind_address:]port:host:hostport] [-R [bind_address:]port:host:hostport] [-D [bind_address:]port] server_address>')
    optparser.add_option('-d', '--daemon', action="store_true", default=False, help='Run server side instead of client side')
    optparser.add_option('-p', '--port', type="int", help='The port that this program runs on')
    optparser.add_option('-k', '--key', help='The password for AES encryption')
    optparser.add_option('-b', '--bind', help='The address that the server listens on')
    optparser.add_option('-L', '--local', action="append", default=[], help='The same as ssh -L')
    optparser.add_option('-R', '--remote', action="append", default=[], help='The same as ssh -R')
    optparser.add_option('-D', '--dynamic', action="append", default=[], help='The same as ssh -D')
    (options, args)=optparser.parse_args()
    if options.port==None:
        logging.error('Port number must be specified.')
        sys.exit(1)
    if options.key==None:
        logging.error('Password must be specified.')
        sys.exit(1)
    elif not 0<options.port<65535:
        logging.error('Port number must be between 0 and 65535.')
        sys.exit(1)
    elif options.daemon:
        start_service(options.bind, options.port)
        sys.exit(service_loop())
    elif len(args)!=1:
        logging.error('You must specify a server to connect to.')
        sys.exit(1)
    elif len(options.local)==0 and len(options.remote)==0 and len(options.dynamic)==0:
        logging.error('You must specify one of -L, -R or -D.')
        sys.exit(1)
    else:
        start_client(options.bind, options.port, args[0])
        for i in options.local:
            client_addtunnel(parse_tunnel(0, i))
        for i in options.remote:
            client_addtunnel(parse_tunnel(1, i))
        for i in options.dynamic:
            client_addtunnel(parse_tunnel(2, i))
        sys.exit(client_loop())

