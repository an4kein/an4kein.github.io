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

