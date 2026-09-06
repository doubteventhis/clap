# Usage
```
┌──(kali㉿kali)-[~/tools/cldap]
└─$ ./cldap --help                               
Usage: ./cldap -dc <ip> [probes...] [enumeration...] [options]

Probes:
  -cldap     CLDAP NETLOGON probe (UDP 389)
  -tls       TLS certificate probe (TCP 636)
  -rootdse   RootDSE query over LDAPS (requires -tls)

Enumeration:
  -user      Username or path to username wordlist
  -computer  Computer name or path to computer wordlist

Options:
  -dc        DC IP address (required)
  -domain    Domain name (auto-discovered if omitted)
  -workers   Concurrent goroutines (default 10)
  -timeout   Per-request timeout (default 3s)
  -v         Verbose: also print accounts not found
  -q         Quiet: suppress per-account stdout output
  -o         Write found accounts to file

Examples:
  ./cldap -dc 10.0.0.1 -cldap -tls -rootdse
  ./cldap -dc 10.0.0.1 -tls -rootdse
  ./cldap -dc 10.0.0.1 -tls
  ./cldap -dc 10.0.0.1 -cldap -user users.txt
  ./cldap -dc 10.0.0.1 -user Administrator
  ./cldap -dc 10.0.0.1 -user names.txt -computer machines.txt -workers 20
```

uses cldap to enumeration domain information. can also brute force users and computers in ad
<img width="723" height="609" alt="image" src="https://github.com/user-attachments/assets/265f74a3-c909-4bac-819a-fc3a2f4cb7a0" />
