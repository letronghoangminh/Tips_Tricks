# Tips and Tricks for CTF and HTB boxes
## Linux
- Check users's mails
- Always try hijacking path if the PATH is writable. 
- Check port knocking if some ports are filtered at /etc/knockd.conf (depends)
- Always patiently check for weird files and folders


## Windows
- Always check local exploits first
- `systeminfo`: Hotifx(s) : N/a means the box hasn't updated 
- Web Server uses WebDav protocol: Use davtest and cadaver to exploit.
- Migrate to another process if you have an unstable shell.
- Use odat for Oracle Database, and use --sysdba for make the user privileged


## Web Security
- Bypass eval blacklist a-zA-Z https://ironhackers.es/en/tutoriales/saltandose-waf-ejecucion-de-codigo-php-sin-letras/
- SSTI Jinja 2 https://www.onsecurity.io/blog/server-side-template-injection-with-jinja2/
- You can include(file_descriptor) in PHP with /dev/fd/
- Check SSL certificate for more informations
- Always enumerate on subdomains and virtual hosts
- Url can be automatically changed to lowercase to bypass filter (GOOGLE.COM -> google.com)
- Object.getOwnPropertyNames(obj).get() or .value to get property from object

## Forensics
