---
title:     "OffSec Proving Grounds - Levram"
tags: [linux,easy,CVE-2021-43857]
categories: OffSecProvingGrounds
---


## Enumeration

### 1. **Enumeração Inicial com NmapAutomator e Nmap**

A primeira etapa de exploração da máquina **Lavram** começou com a execução de uma varredura inicial para identificar portas abertas e serviços rodando no sistema.

#### **Passo 1**: Utilizando **NmapAutomator** para agilizar a enumeração:

```bash
└─$ nmapAutomator.sh -H 192.168.199.24 -t All -o nmapautomator-all-ports
```

O **NmapAutomator** é uma ferramenta que automatiza diferentes tipos de varredura do **Nmap**, permitindo uma enumeração mais rápida e organizada. Isso inclui a varredura de todas as portas (com a flag **-t All**) para garantir que nenhuma porta importante seja deixada de fora.

#### **Passo 2**: Executando uma varredura manual com **Nmap**:

```bash
└─$ nmap -T4 -p- -v 192.168.199.24 -oN nmap-all-ports
```

Nesta etapa, foi realizada uma varredura manual usando **Nmap** com as opções:

- **-T4**: Aumenta a agressividade da varredura, acelerando o processo.
- **-p-**: Varre todas as portas, de 1 a 65535.
- **-v**: Habilita a saída verbosa, mostrando o progresso da varredura em tempo real.
- **-oN**: Salva os resultados da varredura em um arquivo de log para referência futura.

Essas etapas de enumeração são fundamentais para mapear o cenário da máquina alvo e identificar possíveis pontos de exploração, como serviços vulneráveis, portas não documentadas e possíveis vetores de ataque.

![image](https://github.com/user-attachments/assets/f937d320-61ce-45fb-af4e-984358ba1f04)

Navegando até a porta 8000, encontrei um serviço chamado Gerapy, que por sua vez é vulnerável ao CVE-2021-43857.

![image](https://github.com/user-attachments/assets/60d06174-7893-4886-8a40-76aa0ee4e2ae)

Então, pesquisei por explorações disponíveis usando o searchsploit com o objetivo de encontrar alguma vulnerabilidade para o Gerapy.

![image](https://github.com/user-attachments/assets/395904c8-9125-4d91-bf69-ddc970b7c175)

Encontrei uma exploração correspondente ao nosso cenário, porém, era necessário estar autenticado para explorá-la corretamente. Utilizando as credenciais admin:admin
, que é uma senha padrão frequentemente testada, consegui fazer login na aplicação. Com isso, pude explorar a vulnerabilidade utilizando o exploit disponível.

![image](https://github.com/user-attachments/assets/4e5bf515-2352-4281-9625-7246823ccd87)

Ao tentar executar o exploit, recebi um erro de lista vazia, que estava ocorrendo porque ainda não havia sido criado nenhum projeto no dashboard.

![image](https://github.com/user-attachments/assets/6c8fa1ff-0379-445c-bbe3-f87ba5810447)

