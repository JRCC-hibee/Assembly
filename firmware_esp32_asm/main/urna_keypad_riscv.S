# ==============================================================================
# urna_keypad_riscv.S
# Driver 100% Assembly RISC-V (rv32imc - ESP32-C3 / ESP32-C6)
# Teclado Matricial da Urna Eletrônica Brasileira (4x4 -> 13 teclas ativas)
# Mapeamento: Dígitos 0-9, BRANCO (0x0A), CORRIGE (0x0B), CONFIRMA (0x0C)
# ==============================================================================

    .section .rodata
    .align 2

# Endereços base dos registradores GPIO do ESP32-C3 (TRM Espressif Cap. 5)
    .equ GPIO_BASE_ADDR,        0x60004000
    .equ GPIO_OUT_REG,          0x60004004
    .equ GPIO_OUT_W1TS_REG,     0x60004008
    .equ GPIO_OUT_W1TC_REG,     0x6000400C
    .equ GPIO_ENABLE_W1TS_REG,  0x60004024
    .equ GPIO_ENABLE_W1TC_REG,  0x60004028
    .equ GPIO_IN_REG,           0x6000403C

# Máscaras de pinos da matriz:
# Linhas (Outputs): GPIO 0, 1, 2, 3
# Colunas (Inputs Pull-Up): GPIO 4, 5, 6, 7
    .equ ROW_MASK_ALL,          0x0000000F
    .equ COL_MASK_ALL,          0x000000F0
    .equ COL_SHIFT,             4

# Códigos de Teclas da Urna Eletrônica
    .equ KEY_NONE,              0xFF
    .equ KEY_BRANCO,            0x0A
    .equ KEY_CORRIGE,           0x0B
    .equ KEY_CONFIRMA,          0x0C

# Tabela de Decodificação 4x4 (16 bytes: Linha * 4 + Coluna)
keypad_lookup_table:
    .byte   1,          2,          3,          KEY_NONE    # Linha 0: 1, 2, 3, -
    .byte   4,          5,          6,          KEY_NONE    # Linha 1: 4, 5, 6, -
    .byte   7,          8,          9,          KEY_NONE    # Linha 2: 7, 8, 9, -
    .byte   KEY_BRANCO, 0,          KEY_CORRIGE,KEY_CONFIRMA# Linha 3: BRANCO, 0, CORRIGE, CONFIRMA

    .section .text
    .align 2
    .global keypad_init_asm
    .global keypad_scan_asm
    .global keypad_wait_release_asm

# ------------------------------------------------------------------------------
# void keypad_init_asm(void)
# Configura GPIO 0..3 como saída em nível alto e GPIO 4..7 como entrada.
# ------------------------------------------------------------------------------
keypad_init_asm:
    li      t0, GPIO_ENABLE_W1TS_REG
    li      t1, ROW_MASK_ALL
    sw      t1, 0(t0)                   # Habilita saída nas linhas (GPIO 0..3)

    li      t0, GPIO_ENABLE_W1TC_REG
    li      t1, COL_MASK_ALL
    sw      t1, 0(t0)                   # Garante entrada nas colunas (GPIO 4..7)

    li      t0, GPIO_OUT_W1TS_REG
    li      t1, ROW_MASK_ALL
    sw      t1, 0(t0)                   # Todas as linhas em nível lógico ALTO (1)
    ret

# ------------------------------------------------------------------------------
# uint8_t keypad_scan_asm(void)
# Varre as 4 linhas da matriz com debounce determinístico em Assembly RISC-V.
# Retorno em a0: código da tecla (0..9, 0x0A=BRANCO, 0x0B=CORRIGE, 0x0C=CONFIRMA, 0xFF=Nenhuma)
# ------------------------------------------------------------------------------
keypad_scan_asm:
    addi    sp, sp, -16
    sw      ra, 12(sp)
    sw      s0, 8(sp)
    sw      s1, 4(sp)

    li      s0, 0                       # s0 = índice da linha atual (0..3)

.L_scan_row_loop:
    li      t0, 4
    bge     s0, t0, .L_no_key_detected

    # Coloca todas as linhas em ALTO (1)
    li      t0, GPIO_OUT_W1TS_REG
    li      t1, ROW_MASK_ALL
    sw      t1, 0(t0)

    # Coloca apenas a linha s0 em BAIXO (0)
    li      t0, GPIO_OUT_W1TC_REG
    li      t1, 1
    sll     t1, t1, s0                  # t1 = (1 << row)
    sw      t1, 0(t0)

    # Pequeno atraso de estabilização elétrica do barramento (~5us)
    li      t2, 200
.L_settle_delay:
    addi    t2, t2, -1
    bnez    t2, .L_settle_delay

    # Lê registrador de entrada GPIO_IN_REG
    li      t0, GPIO_IN_REG
    lw      t3, 0(t0)
    srli    t3, t3, COL_SHIFT
    andi    t3, t3, 0x0F                # Isola os 4 bits das colunas (ativos em 0)

    li      t4, 0x0F
    beq     t3, t4, .L_next_row         # Se 0b1111, nenhuma coluna pressionada nesta linha

    # Debounce em Assembly (~15ms) e releitura de confirmação
    li      t2, 480000
.L_debounce_loop:
    addi    t2, t2, -1
    bnez    t2, .L_debounce_loop

    lw      t5, 0(t0)
    srli    t5, t5, COL_SHIFT
    andi    t5, t5, 0x0F
    bne     t3, t5, .L_next_row         # Ruído descartado se leitura mudou

    # Identifica qual coluna (0..3) está em nível 0
    li      s1, 0                       # s1 = índice da coluna (0..3)
.L_find_col_loop:
    li      t0, 4
    bge     s1, t0, .L_next_row
    srl     t6, t3, s1
    andi    t6, t6, 1
    beqz    t6, .L_key_found            # Encontrou bit 0 (tecla pressionada)
    addi    s1, s1, 1
    j       .L_find_col_loop

.L_key_found:
    # Restaura linhas para ALTO
    li      t0, GPIO_OUT_W1TS_REG
    li      t1, ROW_MASK_ALL
    sw      t1, 0(t0)

    # Calcula índice na tabela: offset = (s0 * 4) + s1
    slli    t0, s0, 2
    add     t0, t0, s1
    la      t1, keypad_lookup_table
    add     t1, t1, t0
    lbu     a0, 0(t1)                   # Carrega código da tecla em a0
    j       .L_scan_exit

.L_next_row:
    addi    s0, s0, 1
    j       .L_scan_row_loop

.L_no_key_detected:
    li      t0, GPIO_OUT_W1TS_REG
    li      t1, ROW_MASK_ALL
    sw      t1, 0(t0)
    li      a0, KEY_NONE

.L_scan_exit:
    lw      s1, 4(sp)
    lw      s0, 8(sp)
    lw      ra, 12(sp)
    addi    sp, sp, 16
    ret

# ------------------------------------------------------------------------------
# void keypad_wait_release_asm(void)
# Bloqueia até que o eleitor solte a tecla pressionada (evita repetição múltipla).
# ------------------------------------------------------------------------------
keypad_wait_release_asm:
    li      t0, GPIO_OUT_W1TC_REG
    li      t1, ROW_MASK_ALL
    sw      t1, 0(t0)                   # Todas as linhas em 0 para detectar qualquer coluna baixa

.L_wait_rel_loop:
    li      t0, GPIO_IN_REG
    lw      t2, 0(t0)
    srli    t2, t2, COL_SHIFT
    andi    t2, t2, 0x0F
    li      t3, 0x0F
    bne     t2, t3, .L_wait_rel_loop    # Enquanto houver coluna != 0x0F, aguarda

    li      t0, GPIO_OUT_W1TS_REG
    li      t1, ROW_MASK_ALL
    sw      t1, 0(t0)
    ret
