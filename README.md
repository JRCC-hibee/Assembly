# Urna Eletrônica Brasileira — ESP32 RISC-V (100% Assembly) + Python Core + Stack Portainer/Traefik

Sistema de votação inspirado na **Urna Eletrônica Brasileira (TSE)**, pré-configurado para rodar sob **Docker + Portainer + Traefik (`https://urnassembly.hibeeapps.com.br`)**:

1. **Periféricos 100% em Assembly RISC-V (`rv32imc` para ESP32-C3 / ESP32-C6):**
   - `firmware_esp32_asm/main/urna_keypad_riscv.S`: Varredura de teclado matricial 4x4 (0–9, `BRANCO`, `CORRIGE`, `CONFIRMA`) com *debounce* determinístico diretamente nos registradores `GPIO_OUT_W1TS_REG`, `GPIO_OUT_W1TC_REG` e `GPIO_IN_REG`.
   - `firmware_esp32_asm/main/urna_display_ili9341_riscv.S`: Driver SPI e motor gráfico RGB565 **100% em Assembly RISC-V** para o display colorido **TFT ILI9341 320x240**, desenhando caixas de dígitos, glifos e tela `"FIM"`.
   - `firmware_esp32_asm/main/urna_buzzer_riscv.S`: Gerador acústico em Assembly para o bip de tecla e o som bitonal oficial `"FIM"` (*Si6 / Sol#6*).
   - `firmware_esp32_asm/main/urna_fsm_riscv.S`: Máquina de estados da votação e empacotador binário UART0 (`0xAA ... 0x55`).
2. **Motor Eleitoral e Banco de Dados em Python (`FastAPI` + `PostgreSQL 16`):**
   - Composição idêntica às eleições gerais brasileiras de **1º Turno** (*Deputado Federal [4], Deputado Estadual [5], Senador [3], Governador [2], Presidente [2]*) e **2º Turno** (*Governador [2], Presidente [2]*).
   - Suporte integral a **Voto Nominal**, **Voto de Legenda** (nos cargos proporcionais), **Voto em Branco** e **Voto Nulo**.
   - **Fluxo de Seção Eleitoral:** Inicialização na seção → Impressão da **Zerésima** assinada (comprovando `0` votos) → Votação → Encerramento → Impressão do **Boletim de Urna (BU)** em bobina térmica de 48 colunas.
   - **Preparação para Transmissão e Cópia em Cartucho (`.cartucho.zip`):** Exporta o **RDV (Registro Digital do Voto)** embaralhado criptograficamente via `CSPRNG` (sem vínculo com a ordem do eleitor), o **BU eletrônico**, a cadeia de logs auditáveis encadeada por `SHA-256` e a assinatura digital `Ed25519`.

---

## Como Publicar no seu VPS via Portainer + Traefik (`urnassembly.hibeeapps.com.br`)

1. **DNS:** Crie uma entrada tipo **A** (ou **CNAME**) no seu provedor de DNS (`hibeeapps.com.br`) apontando `urnassembly` para o IP da sua VPS.
2. **Portainer:** Acesse `https://beeportainer.hibeeapps.com.br` → **Stacks** → **+ Add stack**.
3. **Name:** `urnassembly`
4. **Build method:** Selecione **Repository**:
   - **Repository URL:** `https://github.com/JRCC-hibee/Assembly`
   - **Repository reference:** `refs/heads/main`
   - **Compose path:** `docker-compose.yml`
5. Clique em **Deploy the stack**. O Traefik emitirá automaticamente o certificado SSL Let's Encrypt (`leresolver`) na rede `traefik_public` e publicará em `https://urnassembly.hibeeapps.com.br`.
