#!/usr/bin/env python3

import logging
import sys

def main():
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

