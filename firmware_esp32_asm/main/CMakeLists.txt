idf_component_register(
    SRCS
        "bootstrap.c"
        "urna_keypad_riscv.S"
        "urna_display_ili9341_riscv.S"
        "urna_buzzer_riscv.S"
        "urna_fsm_riscv.S"
    INCLUDE_DIRS "."
)
