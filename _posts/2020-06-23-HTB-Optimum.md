---
title:     "Hack The Box - Optimum"
tags: [windows,easy]
categories: HackTheBox
---

![1.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-optimum/1.jpg)

Voce pode acessar a maquina atraves deste link: https://www.hackthebox.eu/home/machines/profile/6

## Enumeration

Como de costume, iniciamos usando o nmap pois eh a fase inicial de enumeracao. e eh de extrema importancia!

```
root@kali:~/HTB-Windows/optimum# nmap -Pn -sV -p- -oN nmap/initial 10.10.10.8
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-22 22:50 EDT
Nmap scan report for 10.10.10.8
Host is up (0.19s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    HttpFileServer httpd 2.3
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 374.86 seconds
```

Conforme o resultado do nmap, de todas as portas tcp encontramos apenas a port 80 aberta e nela tem um servico interessante...
**HttpFileServer httpd 2.3**

Antes de continuar com a enumeracao vamos verificar se existe algum exploit pra esse servico.

![2.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-optimum/2.jpg)

Realmente, existe exploit pra esse servico em especial. Porem, estou com problemas de instabilidade com a maquina. :/

Depois de reiniciar a maquina, ela volta a funcionar perfeitamente..

Uma breve pesquisa por exploits prontos, encontro rapidamente um funcional e em seguida ja tenho uma reverse shell.

## Exploitation

***reference:*** https://gist.githubusercontent.com/AfroThundr3007730/834858b381634de8417f301620a2ccf9/raw/783473905951169e49afaf5958e89b23f5a8743f/cve-2014-6287.py

lembre-se de ler o codigo e ajustar de acordo com sua necessidades..

![3.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-optimum/3.jpg)

## Privilege Escalation

