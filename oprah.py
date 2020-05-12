#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import os
import sys
import socketserver
import hashlib
from pydes import des

secret = hashlib.md5(open('secret','rb').read()).hexdigest()
flag = 'hitb{%s}' % secret

KEY = os.urandom(8)

def pad(s):
    return s + (8 - len(s) % 8) * chr(8 - len(s) % 8)


def cbc_encrypt(plain):
    enc = des()
    enc.setkey(KEY)
    
    iv = os.urandom(8)
    plain = pad(plain)
    blocks = [plain[i:i+8] for i in range(0, len(plain), 8)]

    ct = iv
    for block in blocks:
        pt = ''.join([chr(ord(a) ^ ord(b)) for a,b in zip(iv, block)])
        iv = enc.encrypt_block(pt)
	ct += iv
    return ct


class MyTCPHandler(socketserver.StreamRequestHandler):

    def handle(self):
        enc_flag = cbc_encrypt(flag)
        self.wfile.write("You get a flag, you get a flag, everybody gets a flag: %s\n" %
                enc_flag.encode('hex'))
	return


if __name__ == "__main__":
    HOST, PORT = "localhost", 6001
    server = socketserver.TCPServer((HOST, PORT), MyTCPHandler)
    server.serve_forever()
