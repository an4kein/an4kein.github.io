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
root@kali:~/HTB-Windows/arctic# amap -1 10.10.10.11 8300
amap v5.4 (www.thc.org/thc-amap) started at 2020-06-24 19:11:00 - APPLICATION MAPPING mode

this connect
this connect
this connect
this connect
this connect
this connect
this connect
this connect
this connect
this connect
this connect
this connect
this connect
this connect
this connect
this connect
this connect
this connect
this connect
this connect
this connect
this connect
this connect

Unidentified ports: 10.10.10.11:8300/tcp (total 1).

amap v5.4 finished at 2020-06-24 19:11:12
```

No entanto, como eh uma port 8300 e na maioria das vezes portas 8080,8081,8090 nessa faixa tem um servico web envolvido, entao eu acessei via browser 

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

