# ==============================================================================
# urna_fsm_riscv.S
# Máquina de Estados Principal (100% Assembly RISC-V rv32imc)
# Controla a fila de cargos (1º e 2º Turnos), buffer de dígitos, Teclado,
# Display TFT ILI9341 320x240 SPI, Buzzer e transmissão UART0 de pacotes para o Python
# ==============================================================================

    .section .rodata
    .align 2

# Registradores da UART0 do ESP32-C3 para envio/recebimento de frames binários
    .equ UART0_FIFO_REG,        0x60000000
    .equ UART0_STATUS_REG,      0x6000001C

# Códigos de Teclas
    .equ KEY_NONE,              0xFF
    .equ KEY_BRANCO,            0x0A
    .equ KEY_CORRIGE,           0x0B
    .equ KEY_CONFIRMA,          0x0C

# Sequência de dígitos exigidos para cada cargo no 1º Turno Nacional:
# 0: Deputado Federal (4), 1: Deputado Estadual (5), 2: Senador (3), 3: Governador (2), 4: Presidente (2)
turno1_cargo_digits:
    .byte   4, 5, 3, 2, 2

    .section .bss
    .align 2
# Buffer em RAM para armazenar os dígitos digitados pelo eleitor no cargo atual
digit_buffer:
    .space  8
current_cargo_idx:
    .space  1
current_digit_pos:
    .space  1
voto_em_branco_flag:
    .space  1

    .section .text
    .align 2
    .global urna_asm_main

# ------------------------------------------------------------------------------
# Sub-rotina interna: uart0_send_byte_asm(a0 = byte)
# Envia 1 byte pelo registrador FIFO da UART0 em Assembly puro
# ------------------------------------------------------------------------------
uart0_send_byte_asm:
    li      t0, UART0_FIFO_REG
    andi    a0, a0, 0xFF
    sw      a0, 0(t0)
    ret

# ------------------------------------------------------------------------------
# Sub-rotina interna: uart0_send_vote_packet_asm(void)
# Envia pacote binário de voto confirmado ao Backend Python:
# Formato: [0xAA (SYNC)] [cargo_idx] [branco_flag] [num_digits] [d0] [d1] [d2] [d3] [d4] [0x55 (EOF)]
# ------------------------------------------------------------------------------
uart0_send_vote_packet_asm:
    addi    sp, sp, -16
    sw      ra, 12(sp)
    sw      s0, 8(sp)

    li      a0, 0xAA                    # Header SYNC
    call    uart0_send_byte_asm

    la      t0, current_cargo_idx
    lbu     a0, 0(t0)
    call    uart0_send_byte_asm

    la      t0, voto_em_branco_flag
    lbu     a0, 0(t0)
    call    uart0_send_byte_asm

    la      t0, current_digit_pos
    lbu     a0, 0(t0)
    call    uart0_send_byte_asm

    li      s0, 0
.L_pkt_digits:
    li      t0, 5
    bge     s0, t0, .L_pkt_end
    la      t1, digit_buffer
    add     t1, t1, s0
    lbu     a0, 0(t1)
    call    uart0_send_byte_asm
    addi    s0, s0, 1
    j       .L_pkt_digits

.L_pkt_end:
    li      a0, 0x55                    # Trailer EOF
    call    uart0_send_byte_asm

    lw      s0, 8(sp)
    lw      ra, 12(sp)
    addi    sp, sp, 16
    ret

# ------------------------------------------------------------------------------
# void urna_asm_main(void)
# Loop principal da Urna Eletrônica no ESP32 RISC-V
# ------------------------------------------------------------------------------
urna_asm_main:
    # Inicializa periféricos 100% em Assembly
    call    keypad_init_asm
    call    buzzer_init_asm
    call    ili9341_init_asm

.L_start_voter_session:
    # Inicia sessão no primeiro cargo (Índice 0 = Deputado Federal)
    la      t0, current_cargo_idx
    sb      zero, 0(t0)

.L_load_cargo_screen:
    # Zera posição de dígitos e flag de voto em branco
    la      t0, current_digit_pos
    sb      zero, 0(t0)
    la      t0, voto_em_branco_flag
    sb      zero, 0(t0)

    # Limpa buffer de dígitos com 0xFF
    la      t0, digit_buffer
    li      t1, 0xFF
    sb      t1, 0(t0)
    sb      t1, 1(t0)
    sb      t1, 2(t0)
    sb      t1, 3(t0)
    sb      t1, 4(t0)

    # Obtém quantidade de dígitos do cargo atual
    la      t0, current_cargo_idx
    lbu     t1, 0(t0)
    la      t2, turno1_cargo_digits
    add     t2, t2, t1
    lbu     a0, 0(t2)

    # Desenha tela do cargo no display TFT ILI9341
    call    ili9341_draw_urna_screen_asm

.L_poll_keypad_loop:
    call    keypad_scan_asm
    li      t0, KEY_NONE
    beq     a0, t0, .L_poll_keypad_loop

    mv      s0, a0                      # s0 = tecla pressionada
    call    buzzer_beep_key_asm
    call    keypad_wait_release_asm

    # Verifica se foi tecla CORRIGE (0x0B)
    li      t0, KEY_CORRIGE
    beq     s0, t0, .L_load_cargo_screen

    # Verifica se foi tecla BRANCO (0x0A)
    li      t0, KEY_BRANCO
    beq     s0, t0, .L_handle_branco

    # Verifica se foi tecla CONFIRMA (0x0C)
    li      t0, KEY_CONFIRMA
    beq     s0, t0, .L_handle_confirma

    # Caso contrário, é dígito numérico (0..9)
    la      t0, voto_em_branco_flag
    lbu     t1, 0(t0)
    bnez    t1, .L_poll_keypad_loop     # Se já apertou BRANCO, ignora números até CORRIGE

    # Verifica se ainda há caixas disponíveis para o cargo atual
    la      t0, current_cargo_idx
    lbu     t1, 0(t0)
    la      t2, turno1_cargo_digits
    add     t2, t2, t1
    lbu     t3, 0(t2)                   # t3 = max_digits do cargo

    la      t0, current_digit_pos
    lbu     t4, 0(t0)                   # t4 = pos atual
    bge     t4, t3, .L_poll_keypad_loop # Todas as caixas já preenchidas

    # Salva dígito no buffer e desenha no display ILI9341
    la      t5, digit_buffer
    add     t5, t5, t4
    sb      s0, 0(t5)

    mv      a0, t4                      # box_index
    mv      a1, s0                      # digit_val
    call    ili9341_draw_digit_box_asm

    # Incrementa posição do cursor
    la      t0, current_digit_pos
    lbu     t4, 0(t0)
    addi    t4, t4, 1
    sb      t4, 0(t0)
    j       .L_poll_keypad_loop

.L_handle_branco:
    # Só aceita BRANCO se nenhum dígito tiver sido digitado
    la      t0, current_digit_pos
    lbu     t1, 0(t0)
    bnez    t1, .L_poll_keypad_loop

    la      t0, voto_em_branco_flag
    li      t1, 1
    sb      t1, 0(t0)
    j       .L_poll_keypad_loop

.L_handle_confirma:
    # Valida se é Voto em Branco, Voto de Legenda (2 dígitos em proporcionais) ou Cargo Completo
    la      t0, voto_em_branco_flag
    lbu     t1, 0(t0)
    bnez    t1, .L_commit_cargo_vote

    la      t0, current_cargo_idx
    lbu     t1, 0(t0)
    la      t2, turno1_cargo_digits
    add     t2, t2, t1
    lbu     t3, 0(t2)                   # t3 = max_digits

    la      t0, current_digit_pos
    lbu     t4, 0(t0)                   # t4 = dígitos digitados

    beq     t4, t3, .L_commit_cargo_vote

    # Permite Voto de Legenda (2 dígitos) para Deputado Federal (idx 0) e Estadual (idx 1)
    li      t5, 2
    blt     t1, t5, .L_check_legenda
    j       .L_poll_keypad_loop

.L_check_legenda:
    li      t5, 2
    beq     t4, t5, .L_commit_cargo_vote
    j       .L_poll_keypad_loop

.L_commit_cargo_vote:
    # Transmite pacote binário do voto para o Backend Python
    call    uart0_send_vote_packet_asm

    # Avança para o próximo cargo
    la      t0, current_cargo_idx
    lbu     t1, 0(t0)
    addi    t1, t1, 1
    sb      t1, 0(t0)

    li      t2, 5                       # Total de cargos do 1º turno = 5
    blt     t1, t2, .L_load_cargo_screen

    # Todos os cargos concluídos! Exibe tela "FIM" e toca som longo
    call    ili9341_draw_fim_screen_asm
    call    buzzer_play_fim_asm

    # Aguarda liberação do próximo eleitor
    li      t0, 12000000
.L_fim_pause:
    addi    t0, t0, -1
    bnez    t0, .L_fim_pause
    j       .L_start_voter_session
