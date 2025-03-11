#!/usr/bin/env python3
## Lab sample file for the AUP course by Chun-Ying Huang

import sys
import random
import base64
import zlib

msg0 = """MSG0"""
msg1 = """MSG1"""
msg2 = """MSG2"""
msg3 = """MSG3"""
msg4 = """MSG4"""

def sendmsg(m):
    zm = zlib.compress(m)
    mlen = len(zm)
    print('>>>', base64.b64encode(mlen.to_bytes(4, 'big') + zm).decode(), '<<<')

def recv_all():
    """Continuously receive and print all server messages."""
    try:
        while True:
            msg = r.recv(timeout=1)
            if not msg:
                break  # No more data from the server
            print(f"Raw response: {msg}")
            
            # Try decoding if the response might be encoded
            try:
                decoded_msg = base64.b64decode(msg.strip())
                decompressed_msg = zlib.decompress(decoded_msg[4:]).decode()
                print(f"Decoded message: {decompressed_msg}")
            except Exception as e:
                print(f"Could not decode message: {e}")
                
    except EOFError:
        print("Connection closed by the server (EOFError).")



ans, _ = list("0123456789"), sendmsg(msg0.encode())
random.shuffle(ans)
guess, ans, count = '', ''.join(ans[0:4]), 0

while guess != ans:
    guess = recvmsg(f"#{count+1} Enter your input (4 digits): ").strip()
    if len(set(guess)) != 4: sendmsg(msg1.encode()); continue
    a = sum([ 1 if guess[i] == ans[i]   else 0 for i in range(4) ])
    b = sum([ 1 if guess[i] in set(ans) else 0 for i in range(4) ]) - a
    sendmsg(a.to_bytes(4, 'big') + b'A' + b.to_bytes(4, 'big') + b'B')
    count += 1
    if guess == ans: sendmsg(msg1.encode()); break
    elif count < 10: sendmsg(msg2.encode())
    else: sendmsg(msg3.encode()); break # count >= 10
