from pwn import remote # type: ignore

p = remote("tamuctf.com", 443, ssl=True, sni="void")
p.interactive()
