# ==============================================================================
# urna_buzzer_riscv.S
# Gerador Acústico 100% Assembly RISC-V (rv32imc - ESP32-C3 / ESP32-C6)
# Reproduz o bip curto de tecla e o som oficial bitonal "FIM" ("Pilili" TSE)
# ==============================================================================

    .section .rodata
    .align 2

    .equ GPIO_OUT_W1TS_REG,     0x60004008
    .equ GPIO_OUT_W1TC_REG,     0x6000400C
    .equ GPIO_ENABLE_W1TS_REG,  0x60004024

# Pino do Buzzer Piezoelétrico: GPIO 20
    .equ PIN_BUZZER,            (1 << 20)

    .section .text
    .align 2
    .global buzzer_init_asm
    .global buzzer_beep_key_asm
    .global buzzer_play_fim_asm

# ------------------------------------------------------------------------------
# void buzzer_init_asm(void)
# ------------------------------------------------------------------------------
buzzer_init_asm:
    li      t0, GPIO_ENABLE_W1TS_REG
    li      t1, PIN_BUZZER
    sw      t1, 0(t0)

    li      t0, GPIO_OUT_W1TC_REG
    sw      t1, 0(t0)
    ret

# ------------------------------------------------------------------------------
# Sub-rotina interna: buzzer_tone_asm(a0 = half_period_loops, a1 = cycles)
# Gera onda quadrada pura em Assembly RISC-V no pino do buzzer
# ------------------------------------------------------------------------------
buzzer_tone_asm:
    li      t0, GPIO_OUT_W1TS_REG
    li      t1, GPIO_OUT_W1TC_REG
    li      t2, PIN_BUZZER

.L_tone_cycle:
    blez    a1, .L_tone_done
    sw      t2, 0(t0)                   # Buzzer HIGH
    mv      t3, a0
.L_wait_high:
    addi    t3, t3, -1
    bnez    t3, .L_wait_high

    sw      t2, 0(t1)                   # Buzzer LOW
    mv      t3, a0
.L_wait_low:
    addi    t3, t3, -1
    bnez    t3, .L_wait_low

    addi    a1, a1, -1
    j       .L_tone_cycle

.L_tone_done:
    ret

# ------------------------------------------------------------------------------
# void buzzer_beep_key_asm(void)
# Bip curto ao pressionar qualquer tecla numérica (~40ms @ 2kHz)
# ------------------------------------------------------------------------------
buzzer_beep_key_asm:
    addi    sp, sp, -16
    sw      ra, 12(sp)

    li      a0, 8000
    li      a1, 80
    call    buzzer_tone_asm

    lw      ra, 12(sp)
    addi    sp, sp, 16
    ret

# ------------------------------------------------------------------------------
# void buzzer_play_fim_asm(void)
# Som oficial de confirmação final da Urna Eletrônica (alternância Si6 / Sol#6 ~ 1.2s)
# ------------------------------------------------------------------------------
buzzer_play_fim_asm:
    addi    sp, sp, -16
    sw      ra, 12(sp)
    sw      s0, 8(sp)

    li      s0, 6                       # 6 repetições bitonais rápidas ("pi-li-li-li-li-li")
.L_fim_loop:
    blez    s0, .L_fim_done

    # Nota 1 (~1975 Hz - B6)
    li      a0, 6500
    li      a1, 160
    call    buzzer_tone_asm

    # Nota 2 (~1661 Hz - G#6)
    li      a0, 7700
    li      a1, 160
    call    buzzer_tone_asm

    addi    s0, s0, -1
    j       .L_fim_loop

.L_fim_done:
    lw      s0, 8(sp)
    lw      ra, 12(sp)
    addi    sp, sp, 16
    ret
