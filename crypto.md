# Crypto-100 Randbox

We need to break 10 trivial ciphers, using known plaintext attack (server allows to encrypt 20 plain texts total). Here is the exploit 

```python
import pwn, re
pwn.context(log_level="debug")
r = pwn.remote("randBox-iw8w3ae3.9447.plumbing",9447)
alph = re.match('.*\'(.*)\'.*', r.readline()).group(1)

s = re.match('.*\'(.*)\'.*', r.readline()).group(1)
r.readline()
r.send(alph + '\n')
alph_c = r.readline().strip()
r.readline()
d = {}
for p, c in zip(alph, alph_c):
    d[c] = p
r.send("".join(map(d.get, s)) + '\n')

r.readline()
r.readline()
s = re.match('.*\'(.*)\'.*', r.readline()).group(1)
r.readline()
r.send("1" + "0"*31 + '\n')
c = r.readline().strip()
r.readline()
s = s[c.find("1"):] + s[:c.find("1")]
r.send(s + '\n')
for i in xrange(3):
    r.readline()
    r.readline()
    s = re.match('.*\'(.*)\'.*', r.readline()).group(1)
    r.readline()
    r.send(alph + '\n')
    alph_c = r.readline().strip()
    r.readline()
    d = {}
    for p, c in zip(alph, alph_c):
        d[c] = p
    r.send("".join(map(d.get, s)) + '\n')

r.readline()
r.readline()
s = re.match('.*\'(.*)\'.*', r.readline()).group(1)
r.readline()
r.send('0' * 32 + '\n')
alph_c = r.readline().strip()
r.readline()
r.send("".join("{:x}".format((int(c1, 16) - int(c2, 16)) % 16) for c1, c2 in zip(s, alph_c)) + '\n')


r.readline()
r.readline()
r.readline()
s = re.match('.*\'(.*)\'.*', r.readline()).group(1)
r.readline()

r.send('0\n')
alph_c = r.readline().strip()
aa = ""
for c in s:
    aa += "{:x}".format(int(c, 16) ^ int(alph_c, 16))
    alph_c = aa[-1]
r.send(aa + '\n')

r.readline()
r.readline()
r.readline()
s = re.match('.*\'(.*)\'.*', r.readline()).group(1)
r.readline()
r.send('0\n')
alph_c = r.readline().strip()
r.readline()
aa = ""
for c in s:
    aa += "{:x}".format((int(c, 16) - int(alph_c, 16)) % 16)
    alph_c = c
r.send(aa + '\n')


r.readline()
r.readline()
s = re.match('.*\'(.*)\'.*', r.readline()).group(1)
r.readline()
r.send('0\n')
alph_c = r.readline().strip()
r.readline()
aa = ""
for c in s:
    aa += "{:x}".format((int(c, 16) ^ int(alph_c, 16)) % 16)
    alph_c = aa[-1]
r.send(aa + '\n')

r.readline()
r.readline()
s = re.match('.*\'(.*)\'.*', r.readline()).group(1)
r.readline()
r.send('00\n')
alph_c = r.readline().strip()
r.readline()

aa = ""
for i in xrange(len(s)):
    if i % 2 == 0:
        aa += "{:x}".format(int(s[i+1], 16) ^ int(alph_c[0], 16))
    else:
        aa += "{:x}".format(int(s[i], 16) ^ int(s[i-1], 16) ^ int(aa[-1], 16))

r.send(aa + "\n")
r.interactive()
```

# Crypto-150, 200 and 300 (Dub-key, wob-key and wob-key-hard)

We need to break homemade signature algorithm. This task can be reduced to determining structure of "secret" part.

Exploit (solves wob-key-hard with prob. ~1/10):

```python
from pwn import *
from hashlib import sha1
import subprocess
import sys

context(log_level="DEBUG")
#r = remote("localhost", 9447)
r = remote("wob-key-e1g2l93c.9447.plumbing", 9447)
start = r.recv(0xc)
s = subprocess.check_output(["./sha1ebalka", start])[:-1]
r.send(s)

def send(zalupa):
    r.readline()
    r.readline()
    r.readline()    
    r.send('01')
    r.send(''.join(map(chr, zalupa)).encode('base64').replace('\n', ''))
    return int(r.readline().strip())


    
res1 = send(range(128, 256))
alones = []
for alone in range(128, 256):
    x = range(128, 256)
    x[alone - 128] = alone + 1 if alone != 255 else 128
    res2 = send(x)
    if res2 == res1 * 2:
        print "Found!!1 alone =", alone
        alones.append(alone)
        break

alone = alones[0]

def gencyc(where_alone):
    res = []
    for i in xrange(128, 256):
        if i == alone:
            res.append(where_alone)
            continue
        next = i + 1        
        if next == 256:
            next = 128
        if next == alone:
            next = next + 1
            if next == 256:
                next = 128
        res.append(next)
    return res

def gencyc2(where_alone):
    x = gencyc(where_alone)
    x[-1] = 255
    return x
    
xx = send(gencyc(alone))
cyclen = []
for cyc in range(128):
    yy = send(gencyc(cyc))    
    assert yy % xx == 0, "zalupa"
    cyclen.append(yy // xx)

chainlen = []
for i in xrange(128):
    if cyclen[i] < 128:
        chainlen.append(-cyclen[i] + 1)
    else:
        chainlen.append(cyclen[i] - 128)

print chainlen

cyclen2 = []
xx = send(gencyc2(alone))
for cyc in range(128):
    yy = send(gencyc2(cyc))
    assert yy % xx == 0, "zalupa"
    cyclen2.append(yy // xx - 1)
    
presecret = [None] * 128
rank = {}
for (rrr, c) in enumerate(filter(lambda x: x != alone, range(255, 127, -1)), 1):
    rank[(0, rrr)] = [c]

for i, (cl, cl2) in sorted(enumerate(zip(chainlen, cyclen2)), key=lambda x : x[1][0]):
#    print rank, (i, (cl, cyclen2))
    if cl < 0:
        presecret[i] = [cl]
    else:
        presecret[i] = rank[(cl - 1, cl2 - cl)]
        rank.setdefault((cl, cl2 - cl), []).append(i)
    
print presecret
if sum(map(len, filter(lambda x: len(x) > 1, presecret))) > 50:
    print "Bad luck :("
    raise SystemExit(1)

final = [None] * 128
for i, (cl, cl2) in sorted(enumerate(zip(chainlen, cyclen2)), key=lambda x : x[1][0]):
    pos_final = []
    for j in presecret[i]:
        if j >= 128:
            pos_final.append(j)
        else:
            pos_final.append(final[j])
    if len(set(pos_final)) != 1:
        print "bad bad bad", pos_final, i, (cl, cl2)
    final[i] = pos_final[0]

print final

secret = [None] * 128
for i in xrange(128):
    if len(presecret[i]) == 1:
        secret[i] = presecret[i][0]
    else:
        d = {}
        for j in presecret[i]:
            x = range(128, 256)
            x[final[i] - 128] = j
            xx = send(x)
            x[alone - 128] = i
            yy = send(x)
            assert yy % xx == 0
            d[j] = yy // xx
        secret[i] = min(d, key = d.get)
    

print secret

def cycleLen(data, place):
	seen = {}
	count = 0;
	while not place in seen:
            if data[place] < 0:
                count += -data[place]
                break
            seen[place] = 1;
            count += 1;
            place = data[place];
	return count

def realSign(data1, data2):
        data = data1 + map(ord, data2)
	res = 1
	for i in range(256):
		res *= cycleLen(data, i);
	return res


#for i in enumerate(presecret):
    

r.readline()
r.readline()
r.readline()
r.send("02")

for i in xrange(0x11):
    c = r.readline()
    if c != "You need to sign:\n":
        print c
        break
    s = r.readline().strip().decode('base64')
    r.send(str(realSign(secret, s)).zfill(620))

r.recvall()
r.close()
#r.interactive()
```