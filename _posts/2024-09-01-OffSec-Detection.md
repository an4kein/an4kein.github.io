---
title:     "OffSec Proving Grounds - Detection"
tags: [Linux,easy,OffSec,changedetection,rce]
categories: OffSecProvingGrounds
---

## Enumeration

A primeira etapa no processo de exploração foi a enumeração da máquina alvo utilizando o **Nmap**. Realizei um scan completo de portas para identificar todos os serviços em execução no endereço IP **192.168.246.97**. 

O comando utilizado foi:

```
nmap -T4 -p- -v 192.168.246.97 -oN nmap-all-ports.log
```

Esse comando varreu todas as portas disponíveis (0-65535) e salvou os resultados no arquivo `nmap-all-ports.log` para análise posterior. A técnica **T4** foi usada para acelerar a varredura, sem comprometer a precisão.

![image](https://github.com/user-attachments/assets/58c52c09-854f-465f-b90d-6545fb16bc46)

### Uso do nmapAutomator

Em paralelo, utilizei o script [nmapAutomator.sh](https://github.com/21y4d/nmapAutomator), que facilita e agiliza o processo de enumeração. Esse script permite executar varreduras completas em segundo plano, otimizando nosso tempo ao automatizar várias etapas do processo de enumeração.

O comando utilizado foi:

```
nmapAutomator.sh -H 192.168.246.97 -t All -o nmapautomator.log
```

![image](https://github.com/user-attachments/assets/5238ba5a-536a-4fc6-a365-a4076c1d5082)

Esse comando executa uma varredura completa (**All**) no alvo especificado (**192.168.246.97**), e salva os resultados no arquivo `nmapautomator.log`. O **nmapAutomator.sh** é uma ferramenta eficaz para agilizar o processo de enumeração e permite que a varredura seja realizada em segundo plano enquanto outras atividades são conduzidas.

### Análise dos Resultados

Após a execução dos scans, tanto manualmente com o **Nmap** quanto com o **nmapAutomator.sh**, analisaremos os resultados para identificar portas abertas, serviços em execução, e quaisquer possíveis vulnerabilidades. A partir daqui, a próxima etapa envolverá a inspeção detalhada dos serviços detectados, procurando por potenciais vulnerabilidades que possam ser exploradas para obter acesso ao sistema.

### Identificação das Portas Abertas

Após a análise dos resultados das varreduras, foram identificadas duas portas abertas na máquina alvo:

- **Porta 22**: Comumente usada para **SSH**.
- **Porta 5000**: Uma porta menos comum, não usualmente associada a serviços SSH.

Dado que a porta **5000** não é uma porta padrão para SSH, decidimos investigá-la primeiro.

### Investigação da Porta 5000

Ao acessar a porta **5000** via navegador, digitando o endereço `http://192.168.246.97:5000`, encontramos uma aplicação em execução chamada **changedetection**. Essa ferramenta é usada para monitorar mudanças em páginas web, enviando alertas quando uma alteração é detectada.

![image](https://github.com/user-attachments/assets/7a3ec28b-551e-471c-a053-05ce6620540d)

A presença do **changedetection** na porta 5000 é interessante e pode oferecer uma superfície de ataque que merece ser explorada. A próxima etapa envolverá a análise da aplicação para identificar potenciais vulnerabilidades que possam ser exploradas para obter acesso ao sistema.




