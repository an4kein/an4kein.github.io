---
title:     "OffSec Proving Grounds - GLPI"
tags: [linux,easy,CVE-2022-35914,jetty]
categories: OffSecProvingGrounds
---

![image](https://github.com/user-attachments/assets/d3fd4974-59c0-4d1f-89d1-31268ff1fb87)

## Enumeration

### 1. **Enumeração Inicial com NmapAutomator e Nmap**

A primeira fase de exploração da máquina **GLPI** começou com a realização de uma varredura para identificar portas abertas e os serviços em execução no sistema.

#### **Passo 1**: Utilizando o **NmapAutomator** para agilizar a enumeração:

```bash
└─$ nmapAutomator.sh -H 192.168.199.24 -t All -o nmapautomator-all-ports
```

O **NmapAutomator** é uma ferramenta que automatiza diferentes varreduras do **Nmap**, proporcionando uma enumeração mais eficiente e organizada. Aqui, usamos a opção **-t All** para realizar uma varredura completa em todas as portas, garantindo que nenhum serviço relevante seja omitido.

#### **Passo 2**: Executando uma varredura manual com **Nmap**:

```
└─$ nmap -T4 -p- -v 192.168.199.24 -oN nmap-all-ports
```

![image](https://github.com/user-attachments/assets/d5b6c065-e80b-4d0e-8cb2-98dc26d1b482)

![image](https://github.com/user-attachments/assets/ca540d76-65c0-49f2-a1a7-575681ddfb6c)

Essa varredura manual com o **Nmap** utiliza o parâmetro **-p-** para escanear todas as 65.535 portas, garantindo a cobertura total. A opção **-T4** ajusta o tempo para uma varredura mais rápida, e **-v** ativa o modo verbose, fornecendo feedback detalhado durante o processo. Os resultados são salvos no arquivo **nmap-all-ports** para consulta posterior.

