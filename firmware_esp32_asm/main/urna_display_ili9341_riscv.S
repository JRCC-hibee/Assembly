# ==============================================================================
# urna_display_ili9341_riscv.S
# Driver 100% Assembly RISC-V (rv32imc - ESP32-C3 / ESP32-C6)
# Display Colorido TFT ILI9341 320x240 via SPI (RGB565)
# Renderiza layout da Urna Eletrônica: Caixas de Dígitos, Nome, Partido, Mensagem "FIM"
# ==============================================================================

    .section .rodata
    .align 2

# Registradores GPIO para controle SPI Bit-Bang de Alta Velocidade / Linhas DC, CS, RST
    .equ GPIO_OUT_W1TS_REG,     0x60004008
    .equ GPIO_OUT_W1TC_REG,     0x6000400C
    .equ GPIO_ENABLE_W1TS_REG,  0x60004024

# Pinos SPI do Display ILI9341 no ESP32-C3:
# GPIO 8  = TFT_CS   (Chip Select)
# GPIO 9  = TFT_DC   (Data/Command: 0=Cmd, 1=Data)
# GPIO 10 = TFT_RST  (Reset)
# GPIO 18 = TFT_SCLK (SPI Clock)
# GPIO 19 = TFT_MOSI (SPI MOSI)
    .equ PIN_TFT_CS,            (1 << 8)
    .equ PIN_TFT_DC,            (1 << 9)
    .equ PIN_TFT_RST,           (1 << 10)
    .equ PIN_TFT_SCLK,          (1 << 18)
    .equ PIN_TFT_MOSI,          (1 << 19)
    .equ PIN_TFT_ALL_MASK,      (PIN_TFT_CS | PIN_TFT_DC | PIN_TFT_RST | PIN_TFT_SCLK | PIN_TFT_MOSI)

# Comandos Nativos do Controlador ILI9341
    .equ ILI9341_SWRESET,       0x01
    .equ ILI9341_SLPOUT,        0x11
    .equ ILI9341_DISPON,        0x29
    .equ ILI9341_CASET,         0x2A
    .equ ILI9341_PASET,         0x2B
    .equ ILI9341_RAMWR,         0x2C
    .equ ILI9341_MADCTL,        0x36
    .equ ILI9341_PIXFMT,        0x3A

# Paleta de Cores RGB565 Oficial da Urna Eletrônica
    .equ COLOR_WHITE,           0xFFFF
    .equ COLOR_BLACK,           0x0000
    .equ COLOR_GRAY_BG,         0xEF7D
    .equ COLOR_GREEN_CONFIRMA,  0x05E0
    .equ COLOR_ORANGE_CORRIGE,  0xFC60

# Dimensões em Modo Paisagem (Landscape 320x240)
    .equ SCREEN_WIDTH,          320
    .equ SCREEN_HEIGHT,         240

# Fonte Bitmap 8x8 para dígitos 0-9 e letras 'F', 'I', 'M' (8 bytes por glifo)
font8x8_digits:
    .byte 0x3C,0x66,0x6E,0x76,0x66,0x66,0x3C,0x00 # '0'
    .byte 0x18,0x38,0x18,0x18,0x18,0x18,0x7E,0x00 # '1'
    .byte 0x3C,0x66,0x06,0x1C,0x30,0x66,0x7E,0x00 # '2'
    .byte 0x3C,0x66,0x06,0x1C,0x06,0x66,0x3C,0x00 # '3'
    .byte 0x0C,0x1C,0x3C,0x6C,0x7E,0x0C,0x1E,0x00 # '4'
    .byte 0x7E,0x60,0x7C,0x06,0x06,0x66,0x3C,0x00 # '5'
    .byte 0x1C,0x30,0x60,0x7C,0x66,0x66,0x3C,0x00 # '6'
    .byte 0x7E,0x66,0x06,0x0C,0x18,0x18,0x18,0x00 # '7'
    .byte 0x3C,0x66,0x66,0x3C,0x66,0x66,0x3C,0x00 # '8'
    .byte 0x3C,0x66,0x66,0x3E,0x06,0x0C,0x38,0x00 # '9'
    .byte 0x7E,0x60,0x60,0x7C,0x60,0x60,0x60,0x00 # 'F' (idx 10)
    .byte 0x3C,0x18,0x18,0x18,0x18,0x18,0x3C,0x00 # 'I' (idx 11)
    .byte 0x63,0x77,0x7F,0x6B,0x63,0x63,0x63,0x00 # 'M' (idx 12)

    .section .text
    .align 2
    .global ili9341_init_asm
    .global ili9341_fill_rect_asm
    .global ili9341_draw_urna_screen_asm
    .global ili9341_draw_digit_box_asm
    .global ili9341_draw_fim_screen_asm

# ------------------------------------------------------------------------------
# Sub-rotina interna: spi_write_byte_asm (a0 = byte a transmitir)
# Transmite 8 bits MSB-first via registradores GPIO W1TS/W1TC em Assembly RISC-V
# ------------------------------------------------------------------------------
spi_write_byte_asm:
    li      t0, GPIO_OUT_W1TS_REG
    li      t1, GPIO_OUT_W1TC_REG
    li      t2, 8                       # Contador de 8 bits
    li      t3, PIN_TFT_MOSI
    li      t4, PIN_TFT_SCLK

.L_spi_bit_loop:
    andi    t5, a0, 0x80                # Testa bit 7 (MSB)
    beqz    t5, .L_mosi_low
    sw      t3, 0(t0)                   # MOSI = 1
    j       .L_clock_pulse
.L_mosi_low:
    sw      t3, 0(t1)                   # MOSI = 0

.L_clock_pulse:
    sw      t4, 0(t0)                   # SCLK = 1 (borda de subida captura dado)
    slli    a0, a0, 1
    sw      t4, 0(t1)                   # SCLK = 0
    addi    t2, t2, -1
    bnez    t2, .L_spi_bit_loop
    ret

# ------------------------------------------------------------------------------
# Sub-rotina interna: ili9341_send_cmd_asm (a0 = comando 8-bit)
# ------------------------------------------------------------------------------
ili9341_send_cmd_asm:
    addi    sp, sp, -16
    sw      ra, 12(sp)

    li      t0, GPIO_OUT_W1TC_REG
    li      t1, (PIN_TFT_DC | PIN_TFT_CS)
    sw      t1, 0(t0)                   # DC = 0 (Comando), CS = 0

    call    spi_write_byte_asm

    li      t0, GPIO_OUT_W1TS_REG
    li      t1, PIN_TFT_CS
    sw      t1, 0(t0)                   # CS = 1

    lw      ra, 12(sp)
    addi    sp, sp, 16
    ret

# ------------------------------------------------------------------------------
# Sub-rotina interna: ili9341_send_data8_asm (a0 = dado 8-bit)
# ------------------------------------------------------------------------------
ili9341_send_data8_asm:
    addi    sp, sp, -16
    sw      ra, 12(sp)

    li      t0, GPIO_OUT_W1TS_REG
    li      t1, PIN_TFT_DC
    sw      t1, 0(t0)                   # DC = 1 (Dado)

    li      t0, GPIO_OUT_W1TC_REG
    li      t1, PIN_TFT_CS
    sw      t1, 0(t0)                   # CS = 0

    call    spi_write_byte_asm

    li      t0, GPIO_OUT_W1TS_REG
    li      t1, PIN_TFT_CS
    sw      t1, 0(t0)                   # CS = 1

    lw      ra, 12(sp)
    addi    sp, sp, 16
    ret

# ------------------------------------------------------------------------------
# Sub-rotina interna: ili9341_send_data16_asm (a0 = halfword 16-bit big-endian)
# ------------------------------------------------------------------------------
ili9341_send_data16_asm:
    addi    sp, sp, -16
    sw      ra, 12(sp)
    sw      s0, 8(sp)

    mv      s0, a0
    srli    a0, s0, 8
    andi    a0, a0, 0xFF
    call    ili9341_send_data8_asm

    andi    a0, s0, 0xFF
    call    ili9341_send_data8_asm

    lw      s0, 8(sp)
    lw      ra, 12(sp)
    addi    sp, sp, 16
    ret

# ------------------------------------------------------------------------------
# void ili9341_init_asm(void)
# Inicializa os pinos SPI e executa a sequência de boot do painel TFT ILI9341
# ------------------------------------------------------------------------------
ili9341_init_asm:
    addi    sp, sp, -16
    sw      ra, 12(sp)

    # Habilita pinos como saída
    li      t0, GPIO_ENABLE_W1TS_REG
    li      t1, PIN_TFT_ALL_MASK
    sw      t1, 0(t0)

    # Pulso de Hardware Reset (RST = 1 -> 0 -> 1)
    li      t0, GPIO_OUT_W1TS_REG
    li      t1, (PIN_TFT_RST | PIN_TFT_CS)
    sw      t1, 0(t0)

    li      t0, GPIO_OUT_W1TC_REG
    li      t1, PIN_TFT_RST
    sw      t1, 0(t0)

    li      t2, 800000
.L_rst_wait1:
    addi    t2, t2, -1
    bnez    t2, .L_rst_wait1

    li      t0, GPIO_OUT_W1TS_REG
    li      t1, PIN_TFT_RST
    sw      t1, 0(t0)

    li      t2, 2400000
.L_rst_wait2:
    addi    t2, t2, -1
    bnez    t2, .L_rst_wait2

    # Software Reset + Sleep Out
    li      a0, ILI9341_SWRESET
    call    ili9341_send_cmd_asm

    li      a0, ILI9341_SLPOUT
    call    ili9341_send_cmd_asm

    # Formato de Pixel: 16-bit RGB565 (0x55)
    li      a0, ILI9341_PIXFMT
    call    ili9341_send_cmd_asm
    li      a0, 0x55
    call    ili9341_send_data8_asm

    # Orientação Landscape 320x240 (MADCTL = 0x28)
    li      a0, ILI9341_MADCTL
    call    ili9341_send_cmd_asm
    li      a0, 0x28
    call    ili9341_send_data8_asm

    # Display ON
    li      a0, ILI9341_DISPON
    call    ili9341_send_cmd_asm

    lw      ra, 12(sp)
    addi    sp, sp, 16
    ret

# ------------------------------------------------------------------------------
# void ili9341_fill_rect_asm(uint16_t x, uint16_t y, uint16_t w, uint16_t h, uint16_t color)
# Argumentos: a0=x, a1=y, a2=w, a3=h, a4=color (RGB565)
# ------------------------------------------------------------------------------
ili9341_fill_rect_asm:
    addi    sp, sp, -32
    sw      ra, 28(sp)
    sw      s0, 24(sp)
    sw      s1, 20(sp)
    sw      s2, 16(sp)
    sw      s3, 12(sp)
    sw      s4, 8(sp)

    mv      s0, a0                      # x
    mv      s1, a1                      # y
    mv      s2, a2                      # w
    mv      s3, a3                      # h
    mv      s4, a4                      # color

    # Define janela de colunas (CASET)
    li      a0, ILI9341_CASET
    call    ili9341_send_cmd_asm
    mv      a0, s0
    call    ili9341_send_data16_asm
    add     a0, s0, s2
    addi    a0, a0, -1
    call    ili9341_send_data16_asm

    # Define janela de páginas/linhas (PASET)
    li      a0, ILI9341_PASET
    call    ili9341_send_cmd_asm
    mv      a0, s1
    call    ili9341_send_data16_asm
    add     a0, s1, s3
    addi    a0, a0, -1
    call    ili9341_send_data16_asm

    # Inicia gravação na GRAM (RAMWR)
    li      a0, ILI9341_RAMWR
    call    ili9341_send_cmd_asm

    mul     s2, s2, s3                  # Total de pixels = w * h
.L_fill_pixel_loop:
    blez    s2, .L_fill_done
    mv      a0, s4
    call    ili9341_send_data16_asm
    addi    s2, s2, -1
    j       .L_fill_pixel_loop

.L_fill_done:
    lw      s4, 8(sp)
    lw      s3, 12(sp)
    lw      s2, 16(sp)
    lw      s1, 20(sp)
    lw      s0, 24(sp)
    lw      ra, 28(sp)
    addi    sp, sp, 32
    ret

# ------------------------------------------------------------------------------
# void ili9341_draw_urna_screen_asm(uint8_t num_digits)
# Desenha o layout oficial da Urna Eletrônica e as caixas vazias para o cargo atual
# a0 = quantidade de dígitos do cargo (2, 3, 4 ou 5)
# ------------------------------------------------------------------------------
ili9341_draw_urna_screen_asm:
    addi    sp, sp, -24
    sw      ra, 20(sp)
    sw      s0, 16(sp)
    sw      s1, 12(sp)

    mv      s0, a0                      # s0 = total de caixas de dígitos

    # Fundo branco oficial da tela da urna (320x240)
    li      a0, 0
    li      a1, 0
    li      a2, SCREEN_WIDTH
    li      a3, SCREEN_HEIGHT
    li      a4, COLOR_WHITE
    call    ili9341_fill_rect_asm

    # Linha divisória inferior (instruções Aperte a tecla: VERDE / LARANJA)
    li      a0, 0
    li      a1, 195
    li      a2, SCREEN_WIDTH
    li      a3, 2
    li      a4, COLOR_BLACK
    call    ili9341_fill_rect_asm

    # Moldura da foto do candidato (canto superior direito)
    li      a0, 230
    li      a1, 15
    li      a2, 75
    li      a3, 95
    li      a4, COLOR_GRAY_BG
    call    ili9341_fill_rect_asm

    # Desenha as N caixas de dígitos (cada caixa 32x42px com borda preta de 2px)
    li      s1, 0                       # s1 = índice da caixa atual
.L_box_loop:
    bge     s1, s0, .L_box_done

    # x = 20 + s1 * 38
    li      t0, 38
    mul     a0, s1, t0
    addi    a0, a0, 20
    li      a1, 70
    li      a2, 32
    li      a3, 42
    li      a4, COLOR_BLACK
    call    ili9341_fill_rect_asm

    # Miolo branco da caixa (borda de 2px)
    li      t0, 38
    mul     a0, s1, t0
    addi    a0, a0, 22
    li      a1, 72
    li      a2, 28
    li      a3, 38
    li      a4, COLOR_WHITE
    call    ili9341_fill_rect_asm

    addi    s1, s1, 1
    j       .L_box_loop

.L_box_done:
    lw      s1, 12(sp)
    lw      s0, 16(sp)
    lw      ra, 20(sp)
    addi    sp, sp, 24
    ret

# ------------------------------------------------------------------------------
# void ili9341_draw_digit_box_asm(uint8_t box_index, uint8_t digit_val)
# Renderiza um glifo ampliado 3x (24x24px) dentro da caixa de dígito `box_index`
# a0 = box_index (0..4), a1 = digit_val (0..9)
# ------------------------------------------------------------------------------
ili9341_draw_digit_box_asm:
    addi    sp, sp, -32
    sw      ra, 28(sp)
    sw      s0, 24(sp)
    sw      s1, 20(sp)
    sw      s2, 16(sp)
    sw      s3, 12(sp)
    sw      s4, 8(sp)

    # Calcula coordenada X base do dígito = 24 + box_index * 38
    li      t0, 38
    mul     s0, a0, t0
    addi    s0, s0, 24                  # s0 = base_x
    li      s1, 79                      # s1 = base_y

    # Ponteiro do glifo = font8x8_digits + (digit_val * 8)
    la      t1, font8x8_digits
    slli    t2, a1, 3
    add     s2, t1, t2                  # s2 = ponteiro da linha do glifo

    li      s3, 0                       # s3 = linha do glifo (0..7)
.L_glyph_row:
    li      t0, 8
    bge     s3, t0, .L_glyph_done
    add     t1, s2, s3
    lbu     s4, 0(t1)                   # s4 = bitmap da linha atual

    li      t3, 0                       # t3 = coluna (0..7)
.L_glyph_col:
    li      t0, 8
    bge     t3, t0, .L_glyph_next_row

    li      t4, 0x80
    srl     t4, t4, t3
    and     t5, s4, t4
    beqz    t5, .L_skip_pixel

    # Desenha bloco 3x3 para cada pixel ativo do glifo
    mv      t6, t3
    sw      t3, 4(sp)
    li      t0, 3
    mul     a0, t6, t0
    add     a0, s0, a0
    mul     a1, s3, t0
    add     a1, s1, a1
    li      a2, 3
    li      a3, 3
    li      a4, COLOR_BLACK
    call    ili9341_fill_rect_asm
    lw      t3, 4(sp)

.L_skip_pixel:
    addi    t3, t3, 1
    j       .L_glyph_col

.L_glyph_next_row:
    addi    s3, s3, 1
    j       .L_glyph_row

.L_glyph_done:
    lw      s4, 8(sp)
    lw      s3, 12(sp)
    lw      s2, 16(sp)
    lw      s1, 20(sp)
    lw      s0, 24(sp)
    lw      ra, 28(sp)
    addi    sp, sp, 32
    ret

# ------------------------------------------------------------------------------
# void ili9341_draw_fim_screen_asm(void)
# Exibe a tela clássica "FIM" em letras garrafais centralizadas no display 320x240
# ------------------------------------------------------------------------------
ili9341_draw_fim_screen_asm:
    addi    sp, sp, -16
    sw      ra, 12(sp)

    # Limpa toda a tela em branco
    li      a0, 0
    li      a1, 0
    li      a2, SCREEN_WIDTH
    li      a3, SCREEN_HEIGHT
    li      a4, COLOR_WHITE
    call    ili9341_fill_rect_asm

    # Barra verde inferior de confirmação concluída
    li      a0, 40
    li      a1, 180
    li      a2, 240
    li      a3, 12
    li      a4, COLOR_GREEN_CONFIRMA
    call    ili9341_fill_rect_asm

    # Renderiza 'F', 'I', 'M' usando os glifos 10, 11 e 12 nas posições centrais
    li      a0, 1
    li      a1, 10                      # 'F'
    call    ili9341_draw_digit_box_asm

    li      a0, 2
    li      a1, 11                      # 'I'
    call    ili9341_draw_digit_box_asm

    li      a0, 3
    li      a1, 12                      # 'M'
    call    ili9341_draw_digit_box_asm

    lw      ra, 12(sp)
    addi    sp, sp, 16
    ret
