from pwn import *
conn = remote('34.117.59.81',80)


conn.send(b'GET /ip HTTP/1.1\r\nHost: ipinfo.io\r\nUser-Agent: curl/7.88.1\r\nAccept: */*\r\n\r\n')

res=conn.recv()
r = res.decode('utf-8', errors='ignore')


last = ''.join([char for char in r if char.isdigit() or char == '.'])[-15:]

print(last)


