---
title:     "Hack The Box - Bounty"
tags: [windows,easy]
categories: HackTheBox
---

![1.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-bounty/1.jpg)

## Enumeration

### Nmap
Vamos comecar a enumeracao usando nosso nmap de sempre

```
root@kali:~/HTB-Windows/bounty# nmap -sV -sC -oA nmap/initial   10.10.10.93
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-26 17:59 EDT
Nmap scan report for 10.10.10.93
Host is up (0.36s latency).
Not shown: 999 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: Bounty
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

Se voce observou o nmap por padrao so faz o scan em 1000 portas **999 filtered ports**, quando queremos escanear as 65535 portas usamos as opcoes `-p-` ou `-p1-65353` ou voce pode usar tambem opcoes como `--top-ports <NUMERO DE PORTAS>` ou escolher individualmente as portas a serem escaneadas, usando a opcao `-p<SUA PORTA>` LEIA o manual do nmap para aprender mais 


Continuando, ate o momento encontramos apenas a porta 80 aberta e tambem foi feito o scan nas portas TCP dependendo do caso poderia ser necessario fazer scan  nas UDPs tambem.

Navegando ate a porta 80 encontro essa imagem 

![2.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-bounty/2.jpg)
