---
title:     "OffSec Proving Grounds - Fantastic"
tags: [linux,easy,Grafana 8.3.0]
categories: OffSecProvingGrounds
---

## Enumeration

### Varredura Inicial com Nmap

Para iniciar a enumeração da máquina **"Fanatastic"**, foi realizada uma varredura completa de portas utilizando o `nmap`, com o objetivo de identificar todas as portas abertas.

```
nmap -T4 -p- -Pn 192.168.225.181 -oN nmap-all-ports.log -v
```

### Uso do NmapAutomator

Em paralelo, utilizei a ferramenta `NmapAutomator` para agilizar o processo de varredura. O NmapAutomator é um script que automatiza diferentes tipos de varredura utilizando o `nmap`, facilitando a análise e coleta de informações da máquina.

```
nmapAutomator.sh -H 192.168.225.181 -t All -o nmapautomator.log
```

![image](https://github.com/user-attachments/assets/956cc459-e377-4af5-be04-1185e50779d0)

Encontrei as portas 22, 3000 e 9090 abertas. Sabemos que a porta 22 é usada para o **SSH**, então, como costumo fazer, decidi investigar as portas desconhecidas ou menos típicas, como as portas 3000 e 9090. Ao acessá-las via navegador, descobri que a porta **3000** estava rodando o **Prometheus** e a porta **9090** estava executando o **Grafana**. 

![image](https://github.com/user-attachments/assets/9dd2a0e8-3af3-470c-b7e0-c6e1f284a726)

![image](https://github.com/user-attachments/assets/b7821d12-7c5a-461c-a8d6-0fed8db417b8)

Usando o **Kali Linux** e a ferramenta **searchsploit**, encontrei uma exploração que parecia promissora. A vulnerabilidade identificada foi: 

**Grafana 8.3.0 - Directory Traversal and Arbitrary File Read**, conforme mostrado na imagem abaixo.

![image](https://github.com/user-attachments/assets/6dd6a90b-0bbf-4fe8-8853-292394cb5b14)

Isso indica que a versão do Grafana em execução na máquina possui uma vulnerabilidade que pode permitir a leitura de arquivos arbitrários através de uma exploração de "directory traversal", potencialmente oferecendo acesso a arquivos sensíveis no sistema.

## Exploitation

Usamos a opção **-m** no **searchsploit** para fazer o **mirror** do exploit encontrado. 

![image](https://github.com/user-attachments/assets/dae91a96-26cf-40a5-bdb3-71371388a43a)

Em seguida, executamos a exploração com o seguinte comando:

```
python3 50581.py -H http://192.168.225.181:3000
```

![image](https://github.com/user-attachments/assets/cdc467f8-0379-4a69-bd21-4732682d6bdf)

Conforme demonstrado na imagem acima, conseguimos ver claramente o arquivo **passwd** localizado no diretório **/etc**. Isso confirma que o exploit de **Directory Traversal** funcionou corretamente, permitindo o acesso a arquivos sensíveis do sistema, como o **/etc/passwd**, que contém informações sobre os usuários do sistema.
