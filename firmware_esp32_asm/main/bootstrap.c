/*
 * bootstrap.c — Ponto de entrada mínimo do RTOS para saltar ao Core 100% Assembly RISC-V
 * Arquitetura Alvo: ESP32-C3 / ESP32-C6 (rv32imc)
 */

extern void urna_asm_main(void);

void app_main(void)
{
    /* Transfere controle imediato e definitivo para a máquina de estados em Assembly RISC-V */
    urna_asm_main();
}
