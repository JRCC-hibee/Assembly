# Urna Eletrônica Brasileira — ESP32 RISC-V (100% Assembly) + Python Core + Stack Portainer

Sistema de votação inspirado na **Urna Eletrônica Brasileira (TSE)** com:
1. **Periféricos 100% em Assembly RISC-V (`rv32imc` para ESP32-C3 / ESP32-C6):**
   - `firmware_esp32_asm/main/urna_keypad_riscv.S`: Varredura de teclado matricial 4x4 (0–9, `BRANCO`, `CORRIGE`, `CONFIRMA`) com *debounce* determinístico diretamente nos registradores `GPIO_OUT_W1TS_REG`, `GPIO_OUT_W1TC_REG` e `GPIO_IN_REG`.
   - `firmware_esp32_asm/main/urna_display_ili9341_riscv.S`: Driver SPI e motor gráfico RGB565 **100% em Assembly RISC-V** para o display colorido **TFT ILI9341 320x240**, desenhando caixas de dígitos, glifos e tela `"FIM"`.
   - `firmware_esp32_asm/main/urna_buzzer_riscv.S`: Gerador acústico em Assembly para o bip de tecla e o som bitonal oficial `"FIM"` (*Si6 / Sol#6*).
   - `firmware_esp32_asm/main/urna_fsm_riscv.S`: Máquina de estados da votação e empacotador binário UART0 (`0xAA ... 0x55`).
2. **Motor Eleitoral e Banco de Dados em Python (`FastAPI` + `PostgreSQL` / `SQLite`):**
   - Composição idêntica às eleições gerais brasileiras de **1º Turno** (*Deputado Federal [4], Deputado Estadual [5], Senador [3], Governador [2], Presidente [2]*) e **2º Turno** (*Governador [2], Presidente [2]*).
   - Suporte integral a **Voto Nominal**, **Voto de Legenda** (nos cargos proporcionais), **Voto em Branco** e **Voto Nulo**.
   - **Fluxo de Seção Eleitoral:** Inicialização na seção → Impressão da **Zerésima** assinada (comprovando `0` votos) → Votação → Encerramento → Impressão do **Boletim de Urna (BU)** em bobina térmica de 48 colunas.
   - **Preparação para Transmissão e Cópia em Cartucho (`.cartucho.zip`):** Exporta o **RDV (Registro Digital do Voto)** embaralhado criptograficamente via `CSPRNG` (sem vínculo com a ordem do eleitor), o **BU eletrônico**, a cadeia de logs auditáveis encadeada por `SHA-256` e a assinatura digital `Ed25519`.

---

## Como Publicar no seu VPS via Portainer (Stack Git)

1. Acesse o seu **Portainer** → **Stacks** → **Add stack**.
2. Selecione **Repository** (Git):
   - **Repository URL:** `https://github.com/JRCC-hibee/Assembly`
   - **Repository reference:** `refs/heads/main`
   - **Compose path:** `docker-compose.yml`
3. (Opcional) Defina as variáveis de ambiente no Portainer (`URNA_PORT=8000`, `POSTGRES_PASSWORD`, `URNA_ZONA`, `URNA_SECAO`, `URNA_MUNICIPIO`).
4. Clique em **Deploy the stack**.
5. Acesse `http://IP_DO_SEU_VPS:8000` para abrir o painel do mesário, cadastrar candidatos, emitir a Zerésima, votar, imprimir o Boletim de Urna e baixar o Cartucho RDV.
