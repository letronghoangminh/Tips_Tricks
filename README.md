# Tips and Tricks for CTF and HTB boxes
## General
- Always remember to run Nmap with UDP and vulnerable scripts
- Can't run SYN scan through Proxy and sometimes VPN

## Linux
- Check users's mails
- Always try hijacking path if the PATH is writable. 
- Check port knocking if some ports are filtered at /etc/knockd.conf (depends)
- Always patiently check for weird files and folders
- Use ltrace for better anaylysing system calls
- Exploit for command injection: newline=$'\n' ; bla${newline}/bin/bash${newline}bla or $(printf 'bla\n/bin/bash\nbla')
- VNC is a remote access application and can be accessed with vncviewer

## Windows
- Always check local exploits first
- `systeminfo`: Hotifx(s) : N/a means the box hasn't updated 
- Web Server uses WebDav protocol: Use davtest and cadaver to exploit.
- Migrate to another process if you have an unstable shell.
- Use odat for Oracle Database, and use --sysdba for make the user privileged
- Always try snmp-check on Windows boxes


## Web Security
- Bypass eval blacklist a-zA-Z https://ironhackers.es/en/tutoriales/saltandose-waf-ejecucion-de-codigo-php-sin-letras/
- SSTI Jinja 2 https://www.onsecurity.io/blog/server-side-template-injection-with-jinja2/
- You can include(file_descriptor) in PHP with /dev/fd/
- Check SSL certificate for more informations
- Always enumerate on subdomains and virtual hosts
- Url can be automatically changed to lowercase to bypass filter (GOOGLE.COM -> google.com)
- Object.getOwnPropertyNames(obj).get() or .value to get property from object
- Sometimes unquoted urllib python can be bypassed by double encoding

## Forensics
- Image steg: zsteg, stegsolve, steghide, stegdetect
- Text steg: stegsnow
- Other steg: binwalk, foremost
- Memory Dump: volatility
- Sound analysing: Audacity, Sonic Visualizer
