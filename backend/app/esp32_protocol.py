"""
esp32_protocol.py
Decodificador e Codificador de Pacotes Binários para comunicação com o ESP32 RISC-V (Assembly).
Formato do frame recebido da UART0 / Socket do ESP32 (`urna_fsm_riscv.S`):
  Byte 0: 0xAA (SYNC Header)
  Byte 1: cargo_idx (0..4)
  Byte 2: voto_em_branco_flag (0 ou 1)
  Byte 3: num_digits (0..5)
  Bytes 4..8: d0, d1, d2, d3, d4 (cada byte 0..9 ou 0xFF se vazio)
  Byte 9: 0x55 (EOF Trailer)
"""

from .election_engine import get_cargos_por_turno


def decode_esp32_vote_frame(frame: bytes, turno: int = 1) -> dict:
    if len(frame) != 10 or frame[0] != 0xAA or frame[9] != 0x55:
        raise ValueError("Frame binário ESP32 inválido (SYNC 0xAA / EOF 0x55 incorretos).")

    cargo_idx = frame[1]
    branco_flag = bool(frame[2])
    num_digits = frame[3]
    raw_digits = frame[4:9]

    cargos = get_cargos_por_turno(turno)
    if cargo_idx >= len(cargos):
        raise ValueError(f"Índice de cargo {cargo_idx} fora do intervalo para o {turno}º turno.")

    digits_str = ""
    for i in range(min(num_digits, 5)):
        d = raw_digits[i]
        if 0 <= d <= 9:
            digits_str += str(d)

    return {
        "cargo": cargos[cargo_idx]["codigo"],
        "branco": branco_flag,
        "numero": digits_str,
    }
