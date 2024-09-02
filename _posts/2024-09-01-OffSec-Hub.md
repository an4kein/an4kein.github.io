---
title:     "OffSec Proving Grounds - Hub"
tags: [Linux,easy,OffSec,CVE-2024-27697,rce]
categories: OffSecProvingGrounds
---

## Enumeration

Nesta etapa, iremos realizar a enumeração da máquina chamada `hub` utilizando a ferramenta `nmapAutomator`, que automatiza o processo de varredura com o `nmap` de forma mais eficiente e completa.

1. **Execução do nmapAutomator:**

   Utilizaremos o seguinte comando para realizar a varredura completa da máquina:

   ```
   nmapAutomator.sh -H 192.168.246.25 -t All -o nmapautomator.log
   ```
   
   - `-H 192.168.246.25`: Especifica o endereço IP da máquina alvo (`hub`).
   - `-t All`: Realiza todos os tipos de varredura, incluindo varreduras de portas, enumeração de serviços e detecção de vulnerabilidades.
   - `-o nmapautomator.log`: Salva a saída da varredura em um arquivo de log chamado `nmapautomator.log` para referência futura.
  
   ![image](https://github.com/user-attachments/assets/61335892-d8d0-4f50-91de-35818174db4a)

2. **Análise dos resultados:**

   Após a execução do `nmapAutomator`, revisaremos o arquivo de log gerado para identificar portas abertas, serviços em execução e possíveis vulnerabilidades.

3. **Enumeração avançada:**

   Com base nos resultados obtidos, focaremos em serviços específicos que possam apresentar vulnerabilidades exploráveis, como servidores web, bancos de dados, ou outros serviços críticos.

