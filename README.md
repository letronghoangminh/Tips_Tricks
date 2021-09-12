# Tips and Tricks for CTF and HTB boxes
## Linux
- Check users's mails
- Always try hijacking path if the PATH is writable. 


## Windows
- Always check local exploits first
- `systeminfo`: Hotifx(s) : N/a means the box hasn't updated 
- Web Server uses WebDav protocol: Use davtest and cadaver to exploit.


## Web Security
- Bypass eval blacklist a-zA-Z https://ironhackers.es/en/tutoriales/saltandose-waf-ejecucion-de-codigo-php-sin-letras/
- SSTI Jinja 2 https://www.onsecurity.io/blog/server-side-template-injection-with-jinja2/
- You can include(file_descriptor) in PHP with /dev/fd/
- Check SSL certificate for more informations

## Forensics
