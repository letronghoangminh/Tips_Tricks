# Tips and Tricks for CTF and HTB boxes
## General

## CVE 
- Sometimes old version CVEs could work, try them if you don't have other choices.

## Scanning
- Nmap: Scanning UDP is not reliable, always try more scanning with UDP ports (run with --top-ports and -sC or -sV for probing)
- Nmap: Always remember to run Nmap with UDP and vulnerable scripts
- Nmap: Can't run SYN scan through Proxy and sometimes VPN
- WPScan: only use enumerate all plugins or all themes at once, not both at the same time. 

## Linux
- Check users's mails
- Always try hijacking path if the PATH is writable. 
- Check port knocking if some ports are filtered at /etc/knockd.conf (depends)
- Always patiently check for weird files and folders
- Use ltrace for better anaylysing system calls
- Exploit for shell command injection: newline=$'\n' ; bla${newline}/bin/bash${newline}bla or $(printf 'bla\n/bin/bash\nbla')

## Windows
- Always check local exploits first
- `systeminfo`: Hotifx(s) : N/a means the box hasn't updated 
- Web Server uses WebDav protocol: Use davtest and cadaver to exploit.
- Migrate to another process if you have an unstable shell.
- Always try snmp-check on Windows boxes

## Softwares:
- VNC is a remote access application and can be accessed with vncviewer
- Use odat for Oracle Database, and use --sysdba for make the user privileged
- Config for IKE VPN -> Conceal box in HTB.


## Web Security
- Bypass eval blacklist a-zA-Z https://ironhackers.es/en/tutoriales/saltandose-waf-ejecucion-de-codigo-php-sin-letras/
- SSTI Jinja 2 https://www.onsecurity.io/blog/server-side-template-injection-with-jinja2/
- You can include(file_descriptor) in PHP with /dev/fd/
- Check SSL certificate for more informations
- Always enumerate on subdomains and virtual hosts
- Url can be automatically changed to lowercase to bypass filter (GOOGLE.COM -> google.com), even schemes like HtTp or FiLe
- Object.getOwnPropertyNames(obj).get() or .value to get property from object in Javascript
- Sometimes unquoted urllib python can be bypassed by double encoding
- If the chall uses child_prcocess and we can modify it's variables, try prototype pollution for modifying shell variable to 'bash' (thanks nhoc n3mo)

## Forensics
- Image steg: zsteg, stegsolve, steghide, stegdetect
- Text steg: stegsnow
- Other steg: binwalk, foremost
- Memory Dump: volatility
- Sound analysing: Audacity, Sonic Visualizer
