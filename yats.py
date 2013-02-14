#!/usr/bin/env python3

import logging
import sys
import socket

def start_server(bind, port):
    pass

def start_client(bind, port, target, forwards):
    pass

def server_loop():
    pass

def client_loop():
    pass

if __name__=='__main__':
    logging.basicConfig(format='%(levelname)s: %(message)s', level=logging.INFO)
    import optparse
    optparser=optparse.OptionParser(usage='Usage: %prog [-b bind_address] -p port <-d | [-L [bind_address:]port:host:hostport] [-R [bind_address:]port:host:hostport] [-D [bind_address:]port] server_address>')
    optparser.add_option('-d', '--daemon', action="store_true", default=False, help='Run server side instead of client side')
    optparser.add_option('-p', '--port', type="int", help='The port that this program runs on')
    optparser.add_option('-b', '--bind', help='The address that the server listens on')
    optparser.add_option('-L', '--local', action="append", default=[], help='The same as ssh -L')
    optparser.add_option('-R', '--remote', action="append", default=[], help='The same as ssh -R')
    optparser.add_option('-D', '--dynamic', action="append", default=[], help='The same as ssh -D')
    (options, args)=optparser.parse_args()
    if options.port==None:
        logging.error('Port number must be specified.')
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
        start_client(options.bind, options.port, args[0], parseLRD(options.local, options.remote, options.dynamic))
        sys.exit(client_loop())

