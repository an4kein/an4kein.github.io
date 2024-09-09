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
