"""
tse_reverse_analyzer.py
Motor de Engenharia Reversa e Auditoria Forense de Arquivos Oficiais do TSE:
  - `-log.jez` (ZIP Deflate contendo `logd.dat` em ISO-8859-1 com eventos LOGD/GAP/VOTA e MAC de 16 hex)
  - `-imgbu.dat` (Espelho oficial do Boletim de Urna impresso na seção em ISO-8859-1)
  - `-rdv.dat` (Registro Digital do Voto em binário ASN.1 DER - decodificação real voto a voto)
  - `-bu.dat` (EntidadeBoletimUrna em ASN.1 DER)
  - `-vota.vsc` (Catálogo de assinaturas e certificados digitais ICP-Brasil/TSE)
"""

import io
import re
import zipfile
import hashlib
from collections import Counter
from datetime import datetime


TIPO_VOTO_ASN1_MAP = {
    1: "LEGENDA",
    2: "NOMINAL",
    3: "BRANCO",
    4: "NULO",
    5: "AUSENCIA_VOTO",
}


def extrair_prefixo_seccao(filename: str) -> str:
    """
    Extrai o prefixo identificador da seção a partir do nome oficial do arquivo TSE.
    Ex: 'o03221pr7407101710017-log.jez' -> 'o03221pr7407101710017'
    """
    base = filename.split("/")[-1].split("\\")[-1]
    m = re.match(r"^(o\d{5}[a-z]{2}\d{13,14})-", base, re.IGNORECASE)
    if m:
        return m.group(1).lower()
    return re.sub(r"-(bu\.dat|imgbu\.dat|log\.jez|rdv\.dat|vota\.vsc|vscmr\.vsc)$", "", base, flags=re.IGNORECASE)


def decodificar_rdv_asn1_der(rdv_bytes: bytes) -> dict:
    """
    Decodifica diretamente os registros binários ASN.1 DER do arquivo `-rdv.dat` do TSE.
    Estrutura ASN.1 de cada VotoDigitado no RDV da UE2020:
      0x30 <len: 0x03..0x0C>
        0x0A 0x01 <tipo_voto: 1=Legenda, 2=Nominal, 3=Branco, 4=Nulo>
        [0x12 <len_digitos> <ascii_digits: ex '13', '22', '00', '23'>]
    Retorna a contagem exata de votos nominais, brancos, nulos, legendas e até quais números nulos foram digitados!
    """
    sha256_hex = hashlib.sha256(rdv_bytes).hexdigest().upper()

    # Extrai strings ASCII de cabeçalho (timestamp de geração, versão da aplicação, código de carga)
    ascii_headers = [s.decode("ascii", errors="ignore") for s in re.findall(rb"[ -~]{6,}", rdv_bytes[:260])]

    votos_extraidos = []
    contagem_por_tipo = Counter()
    contagem_nominais = Counter()
    detalhe_nulos_digitados = Counter()
    contagem_legendas = Counter()

    pos = 0
    n = len(rdv_bytes)
    while pos < n - 4:
        if rdv_bytes[pos] == 0x30 and rdv_bytes[pos + 2] == 0x0A and rdv_bytes[pos + 3] == 0x01:
            seq_len = rdv_bytes[pos + 1]
            tipo_code = rdv_bytes[pos + 4]

            # Caso 1: Voto sem dígitos (ex: BRANCO -> 30 03 0a 01 03)
            if seq_len == 3 and tipo_code in (1, 2, 3, 4, 5):
                tipo_str = TIPO_VOTO_ASN1_MAP.get(tipo_code, f"TIPO_{tipo_code}")
                votos_extraidos.append({
                    "ordem_embaralhada_rdv": len(votos_extraidos) + 1,
                    "tipo_voto": tipo_str,
                    "numero_digitado": None,
                })
                contagem_por_tipo[tipo_str] += 1
                pos += 5
                continue

            # Caso 2: Voto com NumericString (0x12 <dig_len> <digits>)
            if 5 <= seq_len <= 10 and pos + 2 + seq_len <= n and rdv_bytes[pos + 5] == 0x12:
                dig_len = rdv_bytes[pos + 6]
                if 3 + 2 + dig_len == seq_len and tipo_code in (1, 2, 3, 4, 5):
                    dig_str = rdv_bytes[pos + 7 : pos + 7 + dig_len].decode("ascii", errors="ignore")
                    if dig_str.isdigit():
                        tipo_str = TIPO_VOTO_ASN1_MAP.get(tipo_code, f"TIPO_{tipo_code}")
                        votos_extraidos.append({
                            "ordem_embaralhada_rdv": len(votos_extraidos) + 1,
                            "tipo_voto": tipo_str,
                            "numero_digitado": dig_str,
                        })
                        contagem_por_tipo[tipo_str] += 1
                        if tipo_str == "NOMINAL":
                            contagem_nominais[dig_str] += 1
                        elif tipo_str == "NULO":
                            detalhe_nulos_digitados[dig_str] += 1
                        elif tipo_str == "LEGENDA":
                            contagem_legendas[dig_str] += 1
                        pos += 2 + seq_len
                        continue
        pos += 1

    return {
        "tamanho_bytes": len(rdv_bytes),
        "sha256": sha256_hex,
        "cabecalho_strings": ascii_headers[:8],
        "total_votos_no_rdv": len(votos_extraidos),
        "resumo_tipos": dict(contagem_por_tipo),
        "votos_nominais_por_numero": dict(contagem_nominais),
        "votos_nulos_numeros_digitados": dict(detalhe_nulos_digitados),
        "votos_legenda_por_partido": dict(contagem_legendas),
        "amostra_votos_embaralhados": votos_extraidos[:150],
    }


def decodificar_imgbu_tse(imgbu_bytes: bytes) -> dict:
    """
    Extrai o espelho oficial do Boletim de Urna (`-imgbu.dat`) codificado em ISO-8859-1,
    parseando todos os metadados da seção, comparecimento biométrico/biográfico e votos por candidato.
    """
    sha256_hex = hashlib.sha256(imgbu_bytes).hexdigest().upper()
    raw_text = imgbu_bytes.decode("iso-8859-1", errors="ignore")

    idx_justica = raw_text.find("Justiça Eleitoral")
    if idx_justica == -1:
        idx_justica = raw_text.find("Boletim de Urna")
    clean_text = raw_text[max(0, idx_justica):] if idx_justica != -1 else raw_text

    # Corta o dump binário de matriz gráfica do QR Code / Certificado X.509 após "============= BU DIGITAL ============="
    idx_bu_digital = clean_text.find("============= BU DIGITAL =============")
    bloco_binario_qr_bytes = b""
    if idx_bu_digital != -1:
        pos_raw_bin = imgbu_bytes.find(b"============= BU DIGITAL =============")
        if pos_raw_bin != -1:
            bloco_binario_qr_bytes = imgbu_bytes[pos_raw_bin:]
        clean_text = clean_text[:idx_bu_digital].rstrip()

    clean_lines = []
    for line in clean_text.splitlines():
        # Mantém apenas caracteres ASCII imprimíveis e Latin-1 legíveis (evitando símbolos de controle 0x80..0x9F)
        sanitized = "".join(
            ch for ch in line if (32 <= ord(ch) <= 126) or (160 <= ord(ch) <= 255) or ch == "\t"
        )
        clean_lines.append(sanitized)

    if bloco_binario_qr_bytes:
        qr_sha256 = hashlib.sha256(bloco_binario_qr_bytes).hexdigest().upper()
        clean_lines.extend([
            "",
            "============= BU DIGITAL =============",
            "[BLOCO BINÁRIO QR CODE E CERTIFICADO ICP-BRASIL/TSE]",
            f"Tamanho do Payload Binário : {len(bloco_binario_qr_bytes)} bytes",
            "Assinatura SHA-256 do Bloco QR/Certificado:",
            f"  {qr_sha256[:32]}",
            f"  {qr_sha256[32:]}",
            "======================================",
        ])

    espelho_bu = "\n".join(clean_lines)

    def _find_int(regex_pat: str, default: int = 0) -> int:
        m = re.search(regex_pat, espelho_bu, re.IGNORECASE)
        return int(m.group(1)) if m else default

    def _find_str(regex_pat: str, default: str = "") -> str:
        m = re.search(regex_pat, espelho_bu, re.IGNORECASE)
        return m.group(1).strip() if m else default

    municipio_cod = _find_str(r"Munic[íi]pio\s+(\d{4,6})")
    municipio_nome = ""
    linhas_bu = [l.strip() for l in espelho_bu.splitlines() if l.strip()]
    for i, l in enumerate(linhas_bu):
        if l.startswith("Munic") and i + 1 < len(linhas_bu):
            cand_cidade = linhas_bu[i + 1]
            if not cand_cidade.startswith("Zona"):
                municipio_nome = cand_cidade
            break

    zona = _find_str(r"Zona Eleitoral\s+(\d+)")
    local_votacao = _find_str(r"Local de Vota[çc][ãa]o\s+(\d+)")
    secao = _find_str(r"Se[çc][ãa]o Eleitoral\s+(\d+)")
    eleitores_aptos = _find_int(r"Eleitores aptos\s+(\d+)")
    comparecimento = _find_int(r"Comparecimento\s+(\d+)")
    hab_biometrica = _find_int(r"Habilita[çc][ãa]o biom[ée]trica\s+(\d+)")
    hab_biografica = _find_int(r"Habilita[çc][ãa]o biogr[áa]fica\s+(\d+)")
    hab_sem_biometria = _find_int(r"Habilita[çc][ãa]o sem biometria\s+(\d+)")
    faltosos = _find_int(r"Eleitores faltosos\s+(\d+)")
    codigo_ue = _find_str(r"C[óo]digo identifica[çc][ãa]o UE\s+(\d+)")
    data_abertura = _find_str(r"Data de abertura da UE\s+(\d{2}/\d{2}/\d{4})")
    horario_abertura = _find_str(r"Hor[áa]rio de abertura\s+(\d{2}:\d{2}:\d{2})")
    horario_fechamento = _find_str(r"Hor[áa]rio de fechamento\s+(\d{2}:\d{2}:\d{2})")
    total_nominais = _find_int(r"Total de votos Nominais\s+(\d+)")
    brancos = _find_int(r"Brancos\s+(\d+)")
    nulos = _find_int(r"Nulos\s+(\d+)")
    total_apurado = _find_int(r"Total Apurado\s+(\d+)")

    candidatos_bu = []
    in_cand_block = False
    for line in clean_lines:
        if "Nome do candidato" in line and "Votos" in line:
            in_cand_block = True
            continue
        if in_cand_block:
            if "----" in line or "Eleitores aptos" in line or "Total de votos" in line:
                if candidatos_bu:
                    break
            m_cand = re.match(r"^\s*([A-ZÀ-Ú0-9\s\.\-']+?)\s+(\d{2,5})\s+(\d{4})\s*$", line)
            if m_cand:
                candidatos_bu.append({
                    "nome": m_cand.group(1).strip(),
                    "numero": m_cand.group(2),
                    "votos": int(m_cand.group(3)),
                })

    return {
        "tamanho_bytes": len(imgbu_bytes),
        "sha256": sha256_hex,
        "municipio_codigo": municipio_cod,
        "municipio_nome": municipio_nome,
        "zona": zona,
        "local_votacao": local_votacao,
        "secao": secao,
        "codigo_ue": codigo_ue,
        "data_abertura": data_abertura,
        "horario_abertura": horario_abertura,
        "horario_fechamento": horario_fechamento,
        "eleitores_aptos": eleitores_aptos,
        "comparecimento": comparecimento,
        "habilitacao_biometrica": hab_biometrica,
        "habilitacao_biografica": hab_biografica,
        "habilitacao_sem_biometria": hab_sem_biometria,
        "faltosos": faltosos,
        "total_nominais": total_nominais,
        "brancos": brancos,
        "nulos": nulos,
        "total_apurado": total_apurado,
        "candidatos": candidatos_bu,
        "espelho_bobina": espelho_bu[:4500],
    }


def decodificar_log_jez_tse(log_jez_bytes: bytes, data_alvo_filtro: str = "") -> dict:
    """
    Descompacta o arquivo `-log.jez` do TSE em memória, extrai o `logd.dat` (ISO-8859-1).
    Como a Mídia da Urna (MI) acumula no mesmo `logd.dat` o 1º Turno (04/10/2026) e o 2º Turno (25/10/2026),
    identifica automaticamente a data do último dia de votação (ou usa `data_alvo_filtro`) para reconstruir
    com precisão cirúrgica todos os eleitores daquele turno e também exibir o resumo do 1º turno!
    """
    sha256_jez = hashlib.sha256(log_jez_bytes).hexdigest().upper()

    with zipfile.ZipFile(io.BytesIO(log_jez_bytes), "r") as zf:
        names = zf.namelist()
        target_name = "logd.dat" if "logd.dat" in names else names[0]
        raw_logd = zf.read(target_name)

    text_logd = raw_logd.decode("iso-8859-1", errors="ignore")
    lines = text_logd.splitlines()

    # Descobre todas as datas em que houve "O voto do eleitor foi computado" (ex: 04/10/2026 [1ºT] e 25/10/2026 [2ºT])
    votos_por_data = Counter()
    for l in lines:
        if "O voto do eleitor foi computado" in l and len(l) >= 10:
            votos_por_data[l[:10]] += 1

    datas_votacao_ordenadas = sorted(
        votos_por_data.keys(),
        key=lambda d: datetime.strptime(d, "%d/%m/%Y") if re.match(r"^\d{2}/\d{2}/\d{4}$", d) else datetime.min,
    )
    data_eleicao_principal = data_alvo_filtro or (datas_votacao_ordenadas[-1] if datas_votacao_ordenadas else "")

    metadados_urna = {
        "modelo_ue": "",
        "versao_aplicacao": "",
        "serial_ue": "",
        "serial_mv": "",
        "municipio": "",
        "zona": "",
        "secao": "",
        "turno": "",
        "data_eleicao_analisada": data_eleicao_principal,
        "historico_votos_por_data_no_log": dict(votos_por_data),
        "urna_ligada_em": "",
        "impressora_serial": "",
    }

    contagem_subsistemas = Counter()
    contagem_niveis = Counter()
    etapas_assinatura_sucesso = 0
    alertas_e_erros = []

    ciclos_votacao = []
    eventos_dia_votacao = []

    t_aguardando = None
    t_id_digitado = None
    tipo_doc_digitado = ""
    tentativas_digital = 0
    foi_habilitacao_biografica = False
    t_habilitado = None
    tipo_habilitacao = ""
    teclas_indevidas_ciclo = 0
    cargos_confirmados = []
    eventos_ciclo_atual = []
    macs_validos = 0
    macs_invalidos = 0

    hab_biometrica_log = 0
    hab_biografica_log = 0
    hab_sem_bio_log = 0
    total_teclas_indevidas = 0
    total_id_invalido = 0

    for line_num, line in enumerate(lines, start=1):
        parts = line.split("\t")
        if len(parts) < 5:
            continue

        ts_str = parts[0].strip()
        data_cur = ts_str[:10]
        nivel = parts[1].strip()
        serial_ue = parts[2].strip()
        subsistema = parts[3].strip()
        msg = parts[4].strip()
        mac_hex = parts[5].strip() if len(parts) >= 6 else ""

        contagem_subsistemas[subsistema] += 1
        contagem_niveis[nivel] += 1

        if re.fullmatch(r"[0-9A-Fa-f]{16}", mac_hex):
            macs_validos += 1
        else:
            macs_invalidos += 1

        if not metadados_urna["serial_ue"] and serial_ue:
            metadados_urna["serial_ue"] = serial_ue

        if "Identificação do Modelo de Urna:" in msg:
            metadados_urna["modelo_ue"] = msg.split(":", 1)[1].strip()
        elif "Versão da aplicação:" in msg:
            metadados_urna["versao_aplicacao"] = msg.split(":", 1)[1].strip()
        elif "Serial da MV:" in msg:
            metadados_urna["serial_mv"] = msg.split(":", 1)[1].strip()
        elif msg.startswith("Município:"):
            metadados_urna["municipio"] = msg.split(":", 1)[1].strip()
        elif msg.startswith("Zona Eleitoral:"):
            metadados_urna["zona"] = msg.split(":", 1)[1].strip()
        elif msg.startswith("Seção Eleitoral:"):
            metadados_urna["secao"] = msg.split(":", 1)[1].strip()
        elif msg.startswith("Turno da UE:"):
            metadados_urna["turno"] = msg.split(":", 1)[1].strip()
        elif "Urna ligada em" in msg and (not data_eleicao_principal or data_cur == data_eleicao_principal):
            metadados_urna["urna_ligada_em"] = msg
        elif "Detectada impressora com serial" in msg:
            metadados_urna["impressora_serial"] = msg.split("serial", 1)[1].strip()
        elif "Verificação de assinatura - Etapa" in msg and "[SUCESSO]" in msg and (not data_eleicao_principal or data_cur == data_eleicao_principal):
            etapas_assinatura_sucesso += 1

        # Filtra eventos VOTA e alertas especificamente para a data da eleição analisada (ex: 25/10/2026)
        if data_eleicao_principal and data_cur != data_eleicao_principal:
            continue

        try:
            dt = datetime.strptime(ts_str, "%d/%m/%Y %H:%M:%S")
        except Exception:
            dt = None

        if nivel not in ("INFO",):
            alertas_e_erros.append({
                "linha": line_num,
                "timestamp": ts_str,
                "nivel": nivel,
                "subsistema": subsistema,
                "mensagem": msg,
                "mac": mac_hex,
            })

        if subsistema == "VOTA" and dt:
            if len(eventos_dia_votacao) < 400:
                eventos_dia_votacao.append({
                    "linha": line_num,
                    "timestamp": ts_str,
                    "nivel": nivel,
                    "mensagem": msg,
                    "mac": mac_hex,
                })

            if "Aguardando digitação do identificador do eleitor" in msg:
                t_aguardando = dt
                t_id_digitado = None
                tipo_doc_digitado = ""
                tentativas_digital = 0
                foi_habilitacao_biografica = False
                t_habilitado = None
                tipo_habilitacao = ""
                teclas_indevidas_ciclo = 0
                cargos_confirmados = []
                eventos_ciclo_atual = [{
                    "linha": line_num,
                    "hora": dt.strftime("%H:%M:%S"),
                    "nivel": nivel,
                    "mensagem": msg,
                    "mac": mac_hex,
                }]
            else:
                eventos_ciclo_atual.append({
                    "linha": line_num,
                    "hora": dt.strftime("%H:%M:%S"),
                    "nivel": nivel,
                    "mensagem": msg,
                    "mac": mac_hex,
                })

            if "Identificador do eleitor digitado pelo mesário" in msg:
                t_id_digitado = dt

            elif "Identificador digitado pelo mesário foi:" in msg:
                if "CPF" in msg:
                    tipo_doc_digitado = "CPF"
                elif "Título" in msg:
                    tipo_doc_digitado = "TITULO"
                else:
                    tipo_doc_digitado = msg.split(":", 1)[1].strip()

            elif "Identificador do eleitor digitado inválido" in msg:
                total_id_invalido += 1

            elif "Solicita digital. Tentativa" in msg:
                tentativas_digital += 1

            elif "Dado digitado confere" in msg and "Solicita digital do mesário" not in msg:
                foi_habilitacao_biografica = True

            elif "Tipo de habilitação do eleitor" in msg:
                if "[biométrica]" in msg:
                    tipo_habilitacao = "BIOMETRICA"
                elif "[biográfica]" in msg:
                    tipo_habilitacao = "BIOGRAFICA"
                else:
                    tipo_habilitacao = "SEM_BIOMETRIA"

            elif "Eleitor foi habilitado" in msg:
                t_habilitado = dt
                if tipo_habilitacao == "BIOMETRICA":
                    hab_biometrica_log += 1
                elif foi_habilitacao_biografica or tipo_habilitacao == "BIOGRAFICA":
                    tipo_habilitacao = "BIOGRAFICA"
                    hab_biografica_log += 1
                else:
                    tipo_habilitacao = "SEM_BIOMETRIA"
                    hab_sem_bio_log += 1

            elif "Tecla indevida pressionada" in msg:
                teclas_indevidas_ciclo += 1
                total_teclas_indevidas += 1

            elif "Voto confirmado para" in msg:
                m_cargo = re.search(r"\[(.*?)\]", msg)
                if m_cargo:
                    cargos_confirmados.append(m_cargo.group(1))

            elif "O voto do eleitor foi computado" in msg:
                t_computado = dt
                inicio_ref = t_id_digitado or t_aguardando or t_habilitado or t_computado
                hab_ref = t_habilitado or inicio_ref

                tempo_mesa_bio_s = max(0.0, (hab_ref - inicio_ref).total_seconds())
                tempo_cabine_s = max(0.0, (t_computado - hab_ref).total_seconds())
                tempo_ciclo_total_s = tempo_mesa_bio_s + tempo_cabine_s

                ciclos_votacao.append({
                    "seq": len(ciclos_votacao) + 1,
                    "linha_log": line_num,
                    "data_eleicao": data_eleicao_principal,
                    "faixa_horaria": t_computado.strftime("%H") + "h",
                    "hora_aguardando": t_aguardando.strftime("%H:%M:%S") if t_aguardando else inicio_ref.strftime("%H:%M:%S"),
                    "hora_inicio": inicio_ref.strftime("%H:%M:%S"),
                    "hora_habilitacao": hab_ref.strftime("%H:%M:%S"),
                    "hora_computado": t_computado.strftime("%H:%M:%S"),
                    "documento": tipo_doc_digitado or "TITULO",
                    "tipo_habilitacao": tipo_habilitacao or "BIOMETRICA",
                    "tentativas_digital": tentativas_digital,
                    "teclas_indevidas": teclas_indevidas_ciclo,
                    "cargos": cargos_confirmados,
                    "tempo_mesa_bio_s": round(tempo_mesa_bio_s, 1),
                    "tempo_cabine_s": round(tempo_cabine_s, 1),
                    "tempo_ciclo_total_s": round(tempo_ciclo_total_s, 1),
                    "mac_voto": mac_hex,
                    "eventos_detalhados": list(eventos_ciclo_atual),
                })

    tempos_cabine = [c["tempo_cabine_s"] for c in ciclos_votacao]
    tempos_mesa = [c["tempo_mesa_bio_s"] for c in ciclos_votacao]
    tempos_totais = [c["tempo_ciclo_total_s"] for c in ciclos_votacao]

    votos_por_hora = Counter()
    for c in ciclos_votacao:
        hh = c["hora_computado"][:2] + "h"
        votos_por_hora[hh] += 1

    return {
        "sha256_log_jez": sha256_jez,
        "tamanho_logd_descompactado_bytes": len(raw_logd),
        "total_linhas_logd": len(lines),
        "macs_validos": macs_validos,
        "macs_invalidos": macs_invalidos,
        "etapas_assinatura_software_ok": etapas_assinatura_sucesso,
        "metadados_urna": metadados_urna,
        "contagem_subsistemas": dict(contagem_subsistemas),
        "contagem_niveis": dict(contagem_niveis),
        "resumo_votacao_log": {
            "data_eleicao": data_eleicao_principal,
            "total_votos_computados": len(ciclos_votacao),
            "habilitacao_biometrica": hab_biometrica_log,
            "habilitacao_biografica": hab_biografica_log,
            "habilitacao_sem_biometria": hab_sem_bio_log,
            "total_teclas_indevidas": total_teclas_indevidas,
            "total_identificador_invalido": total_id_invalido,
            "tempo_medio_mesa_bio_s": round(sum(tempos_mesa) / max(len(tempos_mesa), 1), 1),
            "tempo_medio_cabine_s": round(sum(tempos_cabine) / max(len(tempos_cabine), 1), 1),
            "tempo_medio_ciclo_s": round(sum(tempos_totais) / max(len(tempos_totais), 1), 1),
            "tempo_minimo_cabine_s": round(min(tempos_cabine), 1) if tempos_cabine else 0.0,
            "tempo_maximo_ciclo_s": round(max(tempos_totais), 1) if tempos_totais else 0.0,
            "votos_por_hora": dict(sorted(votos_por_hora.items())),
        },
        "ciclos_eleitores": ciclos_votacao,
        "alertas_dia_eleicao": alertas_e_erros[:80],
        "amostra_eventos_vota": eventos_dia_votacao,
    }


def analisar_pacote_seccao_tse(arquivos_dict: dict[str, bytes]) -> dict:
    """
    Recebe um dicionário `{nome_arquivo: bytes}` de uma Seção Eleitoral do TSE
    (podendo conter `-log.jez`, `-imgbu.dat`, `-rdv.dat`, `-bu.dat`, `-vota.vsc`)
    e realiza o Cruzamento Forense Triplo (Log x IMGBU x RDV ASN.1).
    """
    log_report = None
    imgbu_report = None
    rdv_report = None
    outros_hashes = {}
    prefixo = ""

    # Primeiro processa o imgbu se existir para saber a data de abertura exata do BU
    for fname, content in arquivos_dict.items():
        low = fname.lower()
        if not prefixo:
            prefixo = extrair_prefixo_seccao(fname)
        if low.endswith("-imgbu.dat") or low.endswith("imgbu.dat"):
            imgbu_report = decodificar_imgbu_tse(content)
        elif low.endswith("-rdv.dat") or low.endswith("rdv.dat"):
            rdv_report = decodificar_rdv_asn1_der(content)

    data_alvo = imgbu_report.get("data_abertura", "") if imgbu_report else ""

    for fname, content in arquivos_dict.items():
        low = fname.lower()
        if low.endswith("-log.jez") or low.endswith(".jez"):
            log_report = decodificar_log_jez_tse(content, data_alvo_filtro=data_alvo)
        elif not (low.endswith("-imgbu.dat") or low.endswith("imgbu.dat") or low.endswith("-rdv.dat") or low.endswith("rdv.dat")):
            outros_hashes[fname] = {
                "tamanho_bytes": len(content),
                "sha256": hashlib.sha256(content).hexdigest().upper(),
            }

    batimentos = []
    anomalias_forenses = []

    votos_log = log_report["resumo_votacao_log"]["total_votos_computados"] if log_report else None
    votos_bu = imgbu_report["comparecimento"] if imgbu_report else None
    votos_rdv = rdv_report["total_votos_no_rdv"] if rdv_report else None

    if votos_log is not None and votos_bu is not None:
        ok_comp = votos_log == votos_bu
        batimentos.append({
            "item": "Comparecimento Total (Logd.dat vs Boletim de Urna)",
            "valor_log": votos_log,
            "valor_bu": votos_bu,
            "valor_rdv": votos_rdv if votos_rdv is not None else "-",
            "status": "CONFERE_100%" if ok_comp else "DIVERGENTE",
        })
        if not ok_comp:
            anomalias_forenses.append({
                "severidade": "CRITICA",
                "codigo": "DIVERGENCIA_LOG_VS_BU",
                "descricao": f"O logd.dat registrou {votos_log} votos computados, mas o Boletim de Urna aponta {votos_bu}.",
            })

    if votos_rdv is not None and votos_bu is not None:
        ok_rdv = votos_rdv == votos_bu
        batimentos.append({
            "item": "Total de Cédulas no RDV ASN.1 vs Boletim de Urna",
            "valor_log": votos_log if votos_log is not None else "-",
            "valor_bu": votos_bu,
            "valor_rdv": votos_rdv,
            "status": "CONFERE_100%" if ok_rdv else "DIVERGENTE",
        })
        if not ok_rdv:
            anomalias_forenses.append({
                "severidade": "CRITICA",
                "codigo": "DIVERGENCIA_RDV_VS_BU",
                "descricao": f"O arquivo binário -rdv.dat contém {votos_rdv} votos, divergindo do BU ({votos_bu}).",
            })

    if log_report and imgbu_report:
        bio_log = log_report["resumo_votacao_log"]["habilitacao_biometrica"]
        bio_bu = imgbu_report["habilitacao_biometrica"]
        ok_bio = bio_log == bio_bu
        batimentos.append({
            "item": "Habilitações Biométricas AFIS (Log vs BU)",
            "valor_log": bio_log,
            "valor_bu": bio_bu,
            "valor_rdv": "-",
            "status": "CONFERE_100%" if ok_bio else "DIVERGENTE",
        })

        biog_log = log_report["resumo_votacao_log"]["habilitacao_biografica"]
        biog_bu = imgbu_report["habilitacao_biografica"]
        batimentos.append({
            "item": "Habilitações Biográficas (Log vs BU)",
            "valor_log": biog_log,
            "valor_bu": biog_bu,
            "valor_rdv": "-",
            "status": "CONFERE_100%" if biog_log == biog_bu else "DIVERGENTE",
        })

        sbio_log = log_report["resumo_votacao_log"]["habilitacao_sem_biometria"]
        sbio_bu = imgbu_report["habilitacao_sem_biometria"]
        batimentos.append({
            "item": "Habilitações Sem Biometria c/ Mesário (Log vs BU)",
            "valor_log": sbio_log,
            "valor_bu": sbio_bu,
            "valor_rdv": "-",
            "status": "CONFERE_100%" if sbio_log == sbio_bu else "DIVERGENTE",
        })

    if rdv_report and imgbu_report:
        for cand in imgbu_report.get("candidatos", []):
            num = cand["numero"]
            qtd_bu = cand["votos"]
            qtd_rdv = rdv_report["votos_nominais_por_numero"].get(num, 0)
            ok_c = qtd_bu == qtd_rdv
            batimentos.append({
                "item": f"Candidato {cand['nome']} ({num}) — BU vs RDV Binário ASN.1",
                "valor_log": "SIGILO_CONSTITUCIONAL",
                "valor_bu": qtd_bu,
                "valor_rdv": qtd_rdv,
                "status": "CONFERE_100%" if ok_c else "DIVERGENTE",
            })

        br_bu = imgbu_report["brancos"]
        br_rdv = rdv_report["resumo_tipos"].get("BRANCO", 0)
        batimentos.append({
            "item": "Votos em Branco (BU vs RDV Binário ASN.1)",
            "valor_log": "-",
            "valor_bu": br_bu,
            "valor_rdv": br_rdv,
            "status": "CONFERE_100%" if br_bu == br_rdv else "DIVERGENTE",
        })

        nu_bu = imgbu_report["nulos"]
        nu_rdv = rdv_report["resumo_tipos"].get("NULO", 0)
        batimentos.append({
            "item": "Votos Nulos (BU vs RDV Binário ASN.1)",
            "valor_log": "-",
            "valor_bu": nu_bu,
            "valor_rdv": nu_rdv,
            "status": "CONFERE_100%" if nu_bu == nu_rdv else "DIVERGENTE",
        })

    if log_report:
        for c in log_report["ciclos_eleitores"]:
            if c["tempo_cabine_s"] < 2.0:
                anomalias_forenses.append({
                    "severidade": "CRITICA",
                    "codigo": "CABINE_SOBRE_HUMANA_TSE",
                    "descricao": f"Eleitor #{c['seq']} ({c['hora_computado']}): Tempo na cabine de apenas {c['tempo_cabine_s']}s (Linha #{c['linha_log']}).",
                })
            if c["hora_computado"] < "08:00:00":
                anomalias_forenses.append({
                    "severidade": "CRITICA",
                    "codigo": "VOTO_ANTES_08H_TSE",
                    "descricao": f"Eleitor #{c['seq']} votou às {c['hora_computado']} (antes das 08:00:00).",
                })

    veredito_geral = "SEÇÃO OFICIAL ÍNTEGRA — BATIMENTO TRIPLO (LOG.JEZ × IMGBU.DAT × RDV.DAT) 100% VALIDADO"
    risco_geral = "BAIXO"
    if any(b["status"] != "CONFERE_100%" for b in batimentos) or any(a["severidade"] == "CRITICA" for a in anomalias_forenses):
        veredito_geral = "DIVERGÊNCIA OU ANOMALIA CRÍTICA DETECTADA NA SEÇÃO"
        risco_geral = "CRITICO"

    return {
        "prefixo_seccao": prefixo,
        "veredito_geral": veredito_geral,
        "nivel_risco": risco_geral,
        "arquivos_recebidos": list(arquivos_dict.keys()),
        "batimentos_cruzados": batimentos,
        "anomalias_forenses": anomalias_forenses,
        "log_jez": log_report,
        "imgbu": imgbu_report,
        "rdv": rdv_report,
        "outros_arquivos": outros_hashes,
    }
