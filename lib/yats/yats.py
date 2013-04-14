#!/usr/bin/env python3

import asyncore
import hashlib
import json
import logging
import os
import random
import socket
import struct
import sys
import time
import uuid
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
    def encryptjson(self, stream, extradata=0):
        return self.encrypt(json.dumps(stream).encode('utf-8', 'replace'), extradata)
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
    def decryptjson(self, stream):
        return [(json.loads(i[0].decode('utf-8', 'replace')), i[1]) for i in self.decrypt(stream)]
    def havepending(self):
        return bool(self.undecrypted) or bool(self.unprocessed)
    def flushpending(self):
        self.undecrypted=b''
        self.unprocessed=b''

class MyAsyncDispatcher(asyncore.dispatcher):
    def __init__(self, sock=None, map=None):
        asyncore.dispatcher.__init__(self, sock=sock, map=map)
        self.wbuf=b''

    def handle_write(self):
        sent = self.send(self.wbuf)
        self.wbuf = self.wbuf[sent:]

    def handle_close(self):
        self.close()

    def writable(self):
        return len(self.wbuf)!=0

    def buffer(self, data):
        self.wbuf+=data
        return len(data)

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
    def __init__(self, bind, addr, key):
        Peer.__init__(self)
        self.key=key
        self.socks={}
        self.listens=[]
        if bind==None:
            bind=''
        ClientDisp(self, socket.AF_INET, (bind, 0), addr)

    def parse_tunnel(self, tunnel_type, optstr):
        optsplt=split_addr(optstr)
        if tunnel_type in (0, 1):
            if len(optsplt)==3:
                optsplt.insert(0, '')
            elif len(optsplt)!=4:
                raise ValueError('Illegal forwarding option: %s' % optstr)
            else:
                self.listens.append((tunnel_type,)+tuple(optsplt))
        elif tunnel_type==2:
            if len(optsplt)==1:
                optsplt.insert(0, '')
            elif len(optsplt)!=2:
                raise ValueError('Illegal forwarding option: %s' % optstr)
            else:
                self.listens.append((2,)+tuple(optsplt)+(None, None))
        else:
            raise ValueError('Illegal tunnel type: %s' % repr(tunnel_type))

    def loop(self):
        while self.socks:
            asyncore.loop(30, use_poll=True, map=self.socks, count=1) # Why don't the fucking Python use epoll??!
            for i in self.socks:
                try:
                    self.socks[i].send_ping()
                except AttributeError:
                    pass

class ServerPeer(Peer):
    def __init__(self, bind_addrs, key):
        Peer.__init__(self)
        self.key=key
        self.socks={}
        for bind_addr in bind_addrs:
            if bind_addr[0]==None:
                ServerDisp(self, ('::',)+bind_addr[1:])
            else:
                ServerDisp(self, bind_addr)

    def loop(self):
        while self.socks:
            asyncore.loop(30, use_poll=True, map=self.socks, count=1) # Why don't the fucking Python use epoll??!
            for i in self.socks:
                try:
                    self.socks[i].send_ping()
                except AttributeError:
                    pass

class ClientDisp(MyAsyncDispatcher):
    def __init__(self, peer, sock_family, bind_addr, target):
        MyAsyncDispatcher.__init__(self, map=peer.socks)
        self.peer=peer
        self.lastping=time.time()
        self.encrypter=AESEncryptStream(peer.key)
        self.wbuf=self.encrypter.encryptjson({'action': 'hello', 'time': time.time()})
        if bind_addr[0].startswith('[') and bind_addr[0].endswith(']'):
            bind_addr=bind_addr[0][1:-1]+bind_addr[1:]
        self.create_socket(sock_family, socket.SOCK_STREAM)
        self.bind((bind_addr))
        self.connect(target)

    def handle_connect(self):
        self.lastping=time.time()

    def handle_read(self):
        try:
            data_chunks=self.encrypter.decryptjson(self.recv(4096))
            logging.info(repr(data_chunks))
            for data, extdata in data_chunks:
                if not isinstance(data, dict):
                    self.close()
                    logging.error('Corrupted command.')
                elif extdata==0x706f6e67:
                    logging.info('Pong: %s', data['time'])
                    self.lastping=None
                elif extdata==0x70696e67:
                    logging.info('Ping')
                    self.wbuf+=self.encrypter.encryptjson({'time': time.time()}, 0x706f6e67)
                elif 'time' in data and not -900<data['time']-time.time()<900:
                    self.close()
                    logging.error('Time mismatch, possibly replay attack.')
                elif 'action' in data:
                    if data['action']=='hello':
                        if 'time' in data:
                            logging.info('Connection established.')
                        else:
                            self.close()
                            logging.error('Time not provided, possibly corrupted packet.')
                    else:
                        self.wbuf+=self.encrypter.encryptjson({'action': 'error', 'error': 'Unknown action'})
        except ValueError:
            self.close()

    def send_ping(self):
        curtime=time.time()
        if self.lastping==None and self.connected:
            self.wbuf+=self.encrypter.encryptjson({'time': time.time()}, 0x706f6e67)
            self.lastping=curtime
        elif self.lastping-curtime>60:
            self.close()

class ServerDisp(asyncore.dispatcher):
    def __init__(self, peer, bind_addr):
        asyncore.dispatcher.__init__(self, map=peer.socks)
        self.peer=peer
        if bind_addr[0].startswith('[') and bind_addr[0].endswith(']'):
            bind_addr=bind_addr[0][1:-1]+bind_addr[1:]
            sock_family=socket.AF_INET6
        elif bind_addr[0].find(':')!=-1:
            sock_family=socket.AF_INET6
        else:
            sock_family=socket.AF_INET
        self.create_socket(sock_family, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind(bind_addr)
        self.listen(5)

    def handle_accept(self):
        sock, addr=self.accept()
        logging.info('Accepted connection from %s:%s' % (addr[0], addr[1]))
        ServerHandler(sock, addr, self.peer)

class ServerHandler(MyAsyncDispatcher):
    def __init__(self, sock, addr, peer):
        MyAsyncDispatcher.__init__(self, sock=sock, map=peer.socks)
        self.lastping=time.time()
        self.auth=False
        self.data_tunnel=False
        self.peer=peer
        self.encrypter=AESEncryptStream(peer.key)

    def handle_read(self):
        try:
            data_chunks=self.encrypter.decrypt(self.recv(4096))
            logging.info(repr(data_chunks))
            if not data_chunks and not self.auth:
                self.close()
            for data, extdata in data_chunks:
                if extdata==0x706f6e67:
                    logging.info('Pong: %s', data['time'])
                    self.lastping=None
                elif extdata==0x70696e67:
                    logging.info('Ping')
                    self.wbuf+=self.encrypter.encryptjson({'time': time.time()}, 0x706f6e67)
                elif self.data_tunnel:
                    logging.info('Data: %s' % repr(data))
                else:
                    data=json.loads(data.decode('utf-8', 'replace'))
                    if not isinstance(data, dict):
                        self.close()
                        logging.error('Corrupted command.')
                    elif 'time' in data and not -900<data['time']-time.time()<900:
                        self.close()
                        logging.error('Time mismatch, possibly replay attack.')
                    elif 'action' in data:
                        if data['action']=='hello':
                            if 'time' in data:
                                self.auth=True
                                self.wbuf+=self.encrypter.encryptjson({'time': time.time(), 'action': 'hello'})
                            else:
                                self.close()
                                logging.error('Time not provided, possibly corrupted packet.')
                        else:
                            self.wbuf+=self.encrypter.encryptjson({'action': 'error', 'error': 'Unknown action'})
                            logging.error('Unknown command from client: %s' % repr(data['action']))
        except ValueError:
            self.close()

    def send_ping(self):
        curtime=time.time()
        if self.lastping==None and self.auth:
            self.wbuf+=self.encrypter.encryptjson({'time': time.time()}, 0x706f6e67)
            self.lastping=curtime
        elif self.lastping-curtime>60:
            self.close()

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
        sys.exit(ServerPeer([(options.bind, options.port)], options.key).loop())
    elif len(args)!=1:
        logging.error('You must specify a server to connect to.')
        sys.exit(1)
    elif len(options.local)==0 and len(options.remote)==0 and len(options.dynamic)==0:
        logging.error('You must specify one of -L, -R or -D.')
        sys.exit(1)
    else:
        client_peer=ClientPeer(options.bind, (args[0], options.port), options.key)
        for i in options.local:
            client_peer.parse_tunnel(0, i)
        for i in options.remote:
            client_peer.parse_tunnel(1, i)
        for i in options.dynamic:
            client_peer.parse_tunnel(2, i)
        sys.exit(client_peer.loop())

