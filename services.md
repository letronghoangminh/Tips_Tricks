# Checklists for enumerating services

## FTP
- `ls -la` to list everything
- try with anonymous user
- try every users with their passwords
- Write permission
- Can we access the ftp directory but not from FTP?
- Brute forcing with usernames

## SSH
- Before Openssh 7.2, can enumerate usernames
- Debian old version can be exploited by creating id_rsa files with public keys
- Try usernames as passwords
- Always brute forcing with usernames

## HTTP
- Nikto
- Directory scanning with many wordlists
- Parameters fuzzing
- Vhost, subdomain fuzzing
- Inspecting sources
- Inspecting HTTP headers
- Find cms version, cms scanning, public exploits
- Login page: SQL Injection, NoSQL Injection, LDAP Injection
- Vulnerable version of web servers
- Cookies, session, response headers,...
- JS, CSS files

## SMB
- Try with smbclient and smbmap
- Switching min protocol
- Brute force with usernames
- Look for vulnerable version
- enum4linux

## IMAP, POP
- Can enum usernames
- Try with new creds 

## SMTP
- For some exloits

## DNS
- Zone transfer
- Finding records
