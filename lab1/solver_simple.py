#!/usr/bin/env python3
# -*- coding: utf-8 -*-
## Lab sample file for the AUP course by Chun-Ying Huang
import zlib
import base64
import sys
from pwn import *
from itertools import permutations
from solpow import solve_pow

if len(sys.argv) > 1:
    ## for remote access
    r = remote('up.zoolab.org', 10155)
    solve_pow(r)
else:
    ## for local testing
    r = process('./guess.dist.py', shell=False)

def recv():
    msg = r.recvline().strip()
    msg = base64.b64decode(msg)
    msg = zlib.decompress(msg[4:])#.decode()
    a = int.from_bytes(msg[0:4], 'big')  
    b = int.from_bytes(msg[5:9], 'big') 
    
    msg = f"{a}A{b}B"
    return msg

def recvmsg():
    
    msg = r.recvline().strip().decode()
    msg = base64.b64decode(msg)
    return zlib.decompress(msg[4:]).decode()

#msg1 = msg1.decode('utf-8')
#msg1 = base64.b64decode(msg1.encode())
#m1 = zlib.decompress(msg1[4:]).decode()
def sendmsg(m):
    
    zm = zlib.compress(m.encode())
    mlen = len(zm)
    encoded_msg = base64.b64encode(mlen.to_bytes(4, 'little') + zm).decode()
    r.sendline(encoded_msg)

def filter(guess, filter):
    a = sum(1 for i in range(4) if guess[i] == filter[i])
    b = sum(1 for i in range(4) if guess[i] in filter) - a
    return f"{a}A{b}B"




print(recvmsg())

count =0
comb = [''.join(p) for p in permutations('0123456789', 4)]
while count < 10:
    if not comb:
        break
    guess = comb.pop(0)  # pick
        
    print(f"Trying guess #{count + 1}: {guess}")
    
    sendmsg(guess)
    prompt = recvmsg()
    print(f"{prompt}")
    hint = recv()
    print(f"hint: {hint}")
    response = recvmsg()
    print(f"Response: {response}")

    comb = [g for g in comb if filter(g, guess) == hint]
    

    

    
    
            
    
    count += 1


# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
