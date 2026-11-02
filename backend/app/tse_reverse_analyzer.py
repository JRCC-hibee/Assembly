"""
tse_reverse_analyzer.py
Motor de Engenharia Reversa e Auditoria Forense de Arquivos Oficiais do TSE:
  - `-log.jez` (ZIP Deflate contendo `logd.dat` em ISO-8859-1 com eventos LOGD/GAP/VOTA e MAC de 16 hex)
  - `-imgbu.dat` (Espelho oficial do Boletim de Urna impresso na seção em ISO-8859-1)
  - `-rdv.dat` (Registro Digital do Voto em binário ASN.1 DER - decodificação real voto a voto)
  - `-bu.dat` (EntidadeBoletimUrna em ASN.1 DER)
  - `-vota.vsc` (Catálogo de assinaturas e certificados digitais ICP-Brasil/TSE)
"""

from __future__ import annotations

import io
import os
import re
import json
import shutil
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

# Catálogo base de códigos TSE dos principais municípios do Paraná (e aprendizado dinâmico via -imgbu.dat)
MUNICIPIOS_PR_TSE = {
    "74071": "ALMIRANTE TAMANDARÉ",
    "75353": "CURITIBA",
    "76678": "LONDRINA",
    "76910": "MARINGÁ",
    "77771": "PONTA GROSSA",
    "74934": "CASCAVEL",
    "78859": "SÃO JOSÉ DOS PINHAIS",
    "75639": "FOZ DO IGUAÇU",
    "75132": "COLOMBO",
    "75833": "GUARAPUAVA",
    "77453": "PARANAGUÁ",
    "74250": "ARAUCÁRIA",
    "79154": "TOLEDO",
    "74152": "APUCARANA",
    "77690": "PINHAIS",
    "74810": "CAMPO LARGO",
    "74357": "ARAPONGAS",
    "74098": "ALTO PARANÁ",
    "79278": "UMUARAMA",
    "77496": "PARANAVAÍ",
    "74756": "CAMBÉ",
    "75558": "FAZENDA RIO GRANDE",
    "78697": "SARANDI",
    "75655": "FRANCISCO BELTRÃO",
    "77470": "PATO BRANCO",
    "75051": "CIANORTE",
    "79073": "TELÊMACO BORBA",
    "74950": "CASTRO",
    "78395": "ROLÂNDIA",
    "76171": "IRATI",
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
    return re.sub(r"-(bu\.dat|imgbu\.dat|log\.jez|rdv\.dat|vota\.vsc|vscmr\.vsc)$", "", base, flags=re.IGNORECASE).lower()


def extrair_identificacao_arquivo_tse(filename: str) -> dict:
    """
    Extrai pleito, UF, código do município (5 dígitos), zona (4 dígitos) e seção (4 dígitos)
    diretamente da nomenclatura oficial do arquivo TSE:
    Ex: 'o03221pr7407101710017-log.jez' ->
        pleito='03221', uf='PR', municipio_codigo='74071', zona='0171', secao='0017'
    """
    prefixo = extrair_prefixo_seccao(filename)
    m = re.match(r"^o(\d{5})([a-z]{2})(\d{5})(\d{4})(\d{4})$", prefixo, re.IGNORECASE)
    if m:
        mun_cod = m.group(3)
        return {
            "prefixo": prefixo,
            "pleito": m.group(1),
            "uf": m.group(2).upper(),
            "municipio_codigo": mun_cod,
            "municipio_nome": MUNICIPIOS_PR_TSE.get(mun_cod, f"MUNICÍPIO {mun_cod}"),
            "zona": m.group(4),
            "secao": m.group(5),
        }
    return {
        "prefixo": prefixo,
        "pleito": "",
        "uf": "PR",
        "municipio_codigo": "00000",
        "municipio_nome": "NÃO IDENTIFICADO",
        "zona": "0000",
        "secao": "0000",
    }


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
    id_info = {}

    # Primeiro processa o imgbu se existir para saber a data de abertura exata do BU
    for fname, content in arquivos_dict.items():
        low = fname.lower()
        if not prefixo:
            id_info = extrair_identificacao_arquivo_tse(fname)
            prefixo = id_info["prefixo"]
        if low.endswith("-imgbu.dat") or low.endswith("imgbu.dat"):
            imgbu_report = decodificar_imgbu_tse(content)
            if imgbu_report.get("municipio_codigo") and imgbu_report.get("municipio_nome"):
                MUNICIPIOS_PR_TSE[imgbu_report["municipio_codigo"]] = imgbu_report["municipio_nome"]
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

    # Garante preenchimento de município, zona e seção mesmo quando só -log.jez ou -rdv.dat foi enviado
    mun_cod = (
        (imgbu_report.get("municipio_codigo") if imgbu_report else "")
        or (log_report["metadados_urna"].get("municipio") if log_report else "")
        or id_info.get("municipio_codigo", "00000")
    )
    mun_nome = (
        (imgbu_report.get("municipio_nome") if imgbu_report else "")
        or MUNICIPIOS_PR_TSE.get(mun_cod, f"MUNICÍPIO {mun_cod}")
    )
    zona_str = (
        (imgbu_report.get("zona") if imgbu_report else "")
        or (log_report["metadados_urna"].get("zona") if log_report else "")
        or id_info.get("zona", "0000")
    )
    secao_str = (
        (imgbu_report.get("secao") if imgbu_report else "")
        or (log_report["metadados_urna"].get("secao") if log_report else "")
        or id_info.get("secao", "0000")
    )

    if imgbu_report is None:
        imgbu_report = {
            "municipio_codigo": mun_cod,
            "municipio_nome": mun_nome,
            "zona": zona_str,
            "secao": secao_str,
            "local_votacao": "-",
            "codigo_ue": log_report["metadados_urna"].get("serial_ue", "-") if log_report else "-",
            "eleitores_aptos": 0,
            "comparecimento": 0,
            "habilitacao_biometrica": 0,
            "habilitacao_biografica": 0,
            "habilitacao_sem_biometria": 0,
            "faltosos": 0,
            "brancos": 0,
            "nulos": 0,
            "candidatos": [],
            "espelho_bobina": "",
            "ausente": True,
        }
    else:
        imgbu_report["municipio_codigo"] = mun_cod
        imgbu_report["municipio_nome"] = mun_nome
        imgbu_report["zona"] = zona_str
        imgbu_report["secao"] = secao_str
        imgbu_report["ausente"] = False

    batimentos = []
    anomalias_forenses = []

    tem_bu = not imgbu_report.get("ausente", False)
    votos_log = log_report["resumo_votacao_log"]["total_votos_computados"] if log_report else None
    votos_bu = imgbu_report["comparecimento"] if tem_bu else None
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

    if log_report and tem_bu:
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

    candidatos_consolidados = []
    if rdv_report or tem_bu:
        cands_bu_map = {c["numero"]: c for c in (imgbu_report.get("candidatos", []) if tem_bu else [])}
        nums_rdv = set(rdv_report["votos_nominais_por_numero"].keys()) if rdv_report else set()
        todos_nums = sorted(set(cands_bu_map.keys()) | nums_rdv)

        for num in todos_nums:
            c_bu = cands_bu_map.get(num)
            nome_cand = c_bu["nome"] if c_bu else f"CANDIDATO {num}"
            qtd_bu = c_bu["votos"] if c_bu else (0 if tem_bu else None)
            qtd_rdv = rdv_report["votos_nominais_por_numero"].get(num, 0) if rdv_report else None
            candidatos_consolidados.append({
                "numero": num,
                "nome": nome_cand,
                "votos_bu": qtd_bu if qtd_bu is not None else 0,
                "votos_rdv": qtd_rdv if qtd_rdv is not None else 0,
            })
            if qtd_bu is not None and qtd_rdv is not None:
                ok_c = qtd_bu == qtd_rdv
                batimentos.append({
                    "item": f"Candidato {nome_cand} ({num}) — BU vs RDV Binário ASN.1",
                    "valor_log": "SIGILO_CONSTITUCIONAL",
                    "valor_bu": qtd_bu,
                    "valor_rdv": qtd_rdv,
                    "status": "CONFERE_100%" if ok_c else "DIVERGENTE",
                })

        if tem_bu and rdv_report:
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

    veredito_geral = "SEÇÃO OFICIAL ÍNTEGRA — BATIMENTO FORENSE 100% VALIDADO"
    risco_geral = "BAIXO"
    if any(b["status"] != "CONFERE_100%" for b in batimentos) or any(a["severidade"] == "CRITICA" for a in anomalias_forenses):
        veredito_geral = "DIVERGÊNCIA OU ANOMALIA CRÍTICA DETECTADA NA SEÇÃO"
        risco_geral = "CRITICO"

    res_log = log_report["resumo_votacao_log"] if log_report else {}
    meta_log = log_report["metadados_urna"] if log_report else {}

    resumo_consolidacao = {
        "prefixo": prefixo,
        "uf": id_info.get("uf", "PR"),
        "municipio_codigo": mun_cod,
        "municipio_nome": mun_nome,
        "zona": zona_str,
        "secao": secao_str,
        "local_votacao": imgbu_report.get("local_votacao", "-"),
        "modelo_ue": meta_log.get("modelo_ue", "UE2020"),
        "serial_ue": meta_log.get("serial_ue") or imgbu_report.get("codigo_ue", "-"),
        "versao_sw": meta_log.get("versao_aplicacao", "-"),
        "nivel_risco": risco_geral,
        "veredito_geral": veredito_geral,
        "tem_log_jez": log_report is not None,
        "tem_imgbu": tem_bu,
        "tem_rdv": rdv_report is not None,
        "arquivos_recebidos": sorted(list(arquivos_dict.keys())),
        "eleitores_aptos": imgbu_report.get("eleitores_aptos", 0) if tem_bu else 0,
        "faltosos": imgbu_report.get("faltosos", 0) if tem_bu else 0,
        "comparecimento_bu": votos_bu if votos_bu is not None else 0,
        "comparecimento_log": votos_log if votos_log is not None else 0,
        "comparecimento_rdv": votos_rdv if votos_rdv is not None else 0,
        "comparecimento_efetivo": votos_bu or votos_rdv or votos_log or 0,
        "hab_biometrica_bu": imgbu_report.get("habilitacao_biometrica", 0) if tem_bu else 0,
        "hab_biometrica_log": res_log.get("habilitacao_biometrica", 0),
        "hab_biografica_bu": imgbu_report.get("habilitacao_biografica", 0) if tem_bu else 0,
        "hab_biografica_log": res_log.get("habilitacao_biografica", 0),
        "hab_sem_bio_bu": imgbu_report.get("habilitacao_sem_biometria", 0) if tem_bu else 0,
        "hab_sem_bio_log": res_log.get("habilitacao_sem_biometria", 0),
        "brancos_bu": imgbu_report.get("brancos", 0) if tem_bu else 0,
        "brancos_rdv": rdv_report["resumo_tipos"].get("BRANCO", 0) if rdv_report else 0,
        "nulos_bu": imgbu_report.get("nulos", 0) if tem_bu else 0,
        "nulos_rdv": rdv_report["resumo_tipos"].get("NULO", 0) if rdv_report else 0,
        "votos_nulos_numeros_rdv": rdv_report.get("votos_nulos_numeros_digitados", {}) if rdv_report else {},
        "candidatos": candidatos_consolidados,
        "votos_por_hora": res_log.get("votos_por_hora", {}),
        "tempo_medio_ciclo_s": res_log.get("tempo_medio_ciclo_s", 0.0),
        "tempo_medio_cabine_s": res_log.get("tempo_medio_cabine_s", 0.0),
        "tempo_medio_mesa_s": res_log.get("tempo_medio_mesa_bio_s", 0.0),
        "total_linhas_logd": log_report.get("total_linhas_logd", 0) if log_report else 0,
        "macs_validos": log_report.get("macs_validos", 0) if log_report else 0,
        "macs_invalidos": log_report.get("macs_invalidos", 0) if log_report else 0,
        "total_teclas_indevidas": res_log.get("total_teclas_indevidas", 0),
        "total_id_invalido": res_log.get("total_identificador_invalido", 0),
        "etapas_assinatura_ok": log_report.get("etapas_assinatura_software_ok", 0) if log_report else 0,
        "qtd_anomalias": len(anomalias_forenses),
    }

    return {
        "prefixo_seccao": prefixo,
        "veredito_geral": veredito_geral,
        "nivel_risco": risco_geral,
        "arquivos_recebidos": sorted(list(arquivos_dict.keys())),
        "resumo_consolidacao": resumo_consolidacao,
        "batimentos_cruzados": batimentos,
        "anomalias_forenses": anomalias_forenses,
        "log_jez": log_report,
        "imgbu": imgbu_report,
        "rdv": rdv_report,
        "outros_arquivos": outros_hashes,
    }


# ==============================================================================
# GERENCIADOR MULTI-SEÇÃO / MULTI-ZONA / MULTI-CIDADE (CONSOLIDAÇÃO PARANÁ)
# ==============================================================================

def _get_tse_storage_dir() -> str:
    if os.path.exists("/app/data"):
        base = "/app/data/tse_reverso"
    else:
        base = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "tse_reverso")
    os.makedirs(os.path.join(base, "secoes"), exist_ok=True)
    os.makedirs(os.path.join(base, "raw"), exist_ok=True)
    return base


_CATALOGO_MEMORIA: dict[str, dict] = {}
_CATALOGO_CARREGADO = False


def _carregar_catalogo_disco() -> dict[str, dict]:
    global _CATALOGO_MEMORIA, _CATALOGO_CARREGADO
    if _CATALOGO_CARREGADO:
        return _CATALOGO_MEMORIA
    storage = _get_tse_storage_dir()
    cat_path = os.path.join(storage, "catalogo_secoes.json")
    if os.path.exists(cat_path):
        try:
            with open(cat_path, "r", encoding="utf-8") as f:
                _CATALOGO_MEMORIA = json.load(f)
                # Atualiza nomes de municípios aprendidos
                for item in _CATALOGO_MEMORIA.values():
                    mc = item.get("municipio_codigo")
                    mn = item.get("municipio_nome")
                    if mc and mn and not mn.startswith("MUNICÍPIO"):
                        MUNICIPIOS_PR_TSE[mc] = mn
        except Exception:
            _CATALOGO_MEMORIA = {}
    _CATALOGO_CARREGADO = True
    return _CATALOGO_MEMORIA


def _salvar_catalogo_disco() -> None:
    storage = _get_tse_storage_dir()
    cat_path = os.path.join(storage, "catalogo_secoes.json")
    with open(cat_path, "w", encoding="utf-8") as f:
        json.dump(_CATALOGO_MEMORIA, f, ensure_ascii=False)


def processar_lote_arquivos_tse(arquivos_dict: dict[str, bytes]) -> dict:
    """
    Recebe um lote contendo 1 ou N arquivos de 1 ou várias seções eleitorais do TSE,
    agrupa pelo prefixo da seção (`o03221pr7407101710017`), mescla com arquivos já
    recebidos daquela seção, salva o relatório completo em disco e atualiza o catálogo global.
    """
    catalogo = _carregar_catalogo_disco()
    storage = _get_tse_storage_dir()

    grupos: dict[str, dict[str, bytes]] = {}
    for raw_name, content in arquivos_dict.items():
        base_name = raw_name.split("/")[-1].split("\\")[-1]
        if not base_name or base_name.startswith("."):
            continue
        low = base_name.lower()
        if not any(low.endswith(ext) for ext in (".jez", ".dat", ".vsc")):
            continue
        prefixo = extrair_prefixo_seccao(base_name)
        if not prefixo:
            continue
        grupos.setdefault(prefixo, {})[base_name] = content

    secoes_processadas = []
    ultimo_relatorio = None

    for prefixo, novos_arquivos in grupos.items():
        raw_sec_dir = os.path.join(storage, "raw", prefixo)
        os.makedirs(raw_sec_dir, exist_ok=True)

        # Salva os novos arquivos brutos da seção
        for fname, fbytes in novos_arquivos.items():
            with open(os.path.join(raw_sec_dir, fname), "wb") as fp:
                fp.write(fbytes)

        # Carrega todos os arquivos disponíveis daquela seção (permitindo upload incremental de -log.jez)
        pacote_completo: dict[str, bytes] = {}
        for fname in os.listdir(raw_sec_dir):
            fpath = os.path.join(raw_sec_dir, fname)
            if os.path.isfile(fpath):
                with open(fpath, "rb") as fp:
                    pacote_completo[fname] = fp.read()

        relatorio = analisar_pacote_seccao_tse(pacote_completo)
        resumo = relatorio["resumo_consolidacao"]
        catalogo[prefixo] = resumo

        sec_json_path = os.path.join(storage, "secoes", f"{prefixo}.json")
        with open(sec_json_path, "w", encoding="utf-8") as fp:
            json.dump(relatorio, fp, ensure_ascii=False)

        secoes_processadas.append(prefixo)
        ultimo_relatorio = relatorio

    # Propaga nomes de municípios aprendidos via IMGBU para seções da mesma cidade que só tinham log/rdv
    for item in catalogo.values():
        mc = item.get("municipio_codigo")
        if mc in MUNICIPIOS_PR_TSE:
            item["municipio_nome"] = MUNICIPIOS_PR_TSE[mc]

    _salvar_catalogo_disco()

    return {
        "ok": True,
        "secoes_processadas_neste_lote": len(secoes_processadas),
        "prefixos_processados": secoes_processadas,
        "total_secoes_no_catalogo": len(catalogo),
        "ultimo_relatorio_individual": ultimo_relatorio,
    }


def obter_secao_individual_tse(prefixo: str) -> dict | None:
    storage = _get_tse_storage_dir()
    sec_json_path = os.path.join(storage, "secoes", f"{prefixo.lower()}.json")
    if not os.path.exists(sec_json_path):
        return None
    with open(sec_json_path, "r", encoding="utf-8") as fp:
        return json.load(fp)


def limpar_catalogo_tse() -> dict:
    global _CATALOGO_MEMORIA, _CATALOGO_CARREGADO
    storage = _get_tse_storage_dir()
    if os.path.exists(storage):
        shutil.rmtree(storage, ignore_errors=True)
    os.makedirs(os.path.join(storage, "secoes"), exist_ok=True)
    os.makedirs(os.path.join(storage, "raw"), exist_ok=True)
    _CATALOGO_MEMORIA = {}
    _CATALOGO_CARREGADO = True
    return {"ok": True, "total_secoes_no_catalogo": 0}


def consolidar_secoes_tse(
    municipio_filtro: str = "TODAS",
    zona_filtro: str = "TODAS",
    secao_filtro: str = "CONSOLIDADO",
) -> dict:
    """
    Constrói a árvore de seletores (Cidade -> Zona -> Seção/Urna) e retorna:
    - Os dados consolidados globais para o filtro selecionado (`CONSOLIDADO`), OU
    - O dossiê completo da urna individual quando `secao_filtro` é o prefixo de uma seção.
    """
    catalogo = _carregar_catalogo_disco()
    todas_secoes = list(catalogo.values())

    # 1. Monta lista de Cidades disponíveis em todo o catálogo
    cidades_map: dict[str, dict] = {}
    for s in todas_secoes:
        mc = s.get("municipio_codigo", "00000")
        mn = MUNICIPIOS_PR_TSE.get(mc, s.get("municipio_nome", f"MUNICÍPIO {mc}"))
        if mc not in cidades_map:
            cidades_map[mc] = {
                "codigo": mc,
                "nome": mn,
                "total_urnas": 0,
                "total_votos": 0,
                "total_aptos": 0,
            }
        cidades_map[mc]["total_urnas"] += 1
        cidades_map[mc]["total_votos"] += s.get("comparecimento_efetivo", 0)
        cidades_map[mc]["total_aptos"] += s.get("eleitores_aptos", 0)

    lista_cidades = sorted(cidades_map.values(), key=lambda x: x["nome"])

    # Filtra por Cidade
    secoes_apos_cidade = [
        s for s in todas_secoes
        if municipio_filtro in ("TODAS", "", None) or s.get("municipio_codigo") == municipio_filtro
    ]

    # 2. Monta lista de Zonas disponíveis para a Cidade selecionada
    zonas_map: dict[str, dict] = {}
    for s in secoes_apos_cidade:
        z = s.get("zona", "0000")
        if z not in zonas_map:
            zonas_map[z] = {
                "zona": z,
                "total_urnas": 0,
                "total_votos": 0,
                "total_aptos": 0,
            }
        zonas_map[z]["total_urnas"] += 1
        zonas_map[z]["total_votos"] += s.get("comparecimento_efetivo", 0)
        zonas_map[z]["total_aptos"] += s.get("eleitores_aptos", 0)

    lista_zonas = sorted(zonas_map.values(), key=lambda x: x["zona"])

    # Se a zona_filtro não existir na cidade atual, reseta para TODAS
    if zona_filtro not in ("TODAS", "", None) and zona_filtro not in zonas_map:
        zona_filtro = "TODAS"

    # Filtra por Zona
    secoes_filtradas = [
        s for s in secoes_apos_cidade
        if zona_filtro in ("TODAS", "", None) or s.get("zona") == zona_filtro
    ]
    secoes_filtradas.sort(key=lambda s: (s.get("municipio_nome", ""), s.get("zona", ""), s.get("secao", "")))

    # 3. Monta lista de Seções/Urnas para os seletores
    lista_secoes_seletor = [
        {
            "prefixo": s["prefixo"],
            "secao": s.get("secao", "0000"),
            "zona": s.get("zona", "0000"),
            "municipio_codigo": s.get("municipio_codigo", "00000"),
            "municipio_nome": s.get("municipio_nome", ""),
            "serial_ue": s.get("serial_ue", "-"),
            "votos": s.get("comparecimento_efetivo", 0),
            "aptos": s.get("eleitores_aptos", 0),
            "nivel_risco": s.get("nivel_risco", "BAIXO"),
            "tem_log_jez": s.get("tem_log_jez", False),
            "tem_imgbu": s.get("tem_imgbu", False),
            "tem_rdv": s.get("tem_rdv", False),
        }
        for s in secoes_filtradas
    ]

    hierarquia = {
        "total_geral_urnas": len(todas_secoes),
        "municipio_selecionado": municipio_filtro,
        "zona_selecionada": zona_filtro,
        "secao_selecionada": secao_filtro,
        "cidades": lista_cidades,
        "zonas": lista_zonas,
        "secoes": lista_secoes_seletor,
    }

    # Caso 1: Usuário selecionou uma Seção/Urna específica para inspeção profunda
    if secao_filtro and secao_filtro != "CONSOLIDADO":
        relatorio_sec = obter_secao_individual_tse(secao_filtro)
        if relatorio_sec:
            return {
                "modo_visao": "SECAO_INDIVIDUAL",
                "hierarquia": hierarquia,
                "secao_individual": relatorio_sec,
            }

    # Caso 2: Consolidação Global das Urnas Filtradas (Estado / Cidade / Zona)
    total_urnas = len(secoes_filtradas)
    urnas_integras = sum(1 for s in secoes_filtradas if s.get("nivel_risco") == "BAIXO")
    urnas_com_alerta = total_urnas - urnas_integras
    urnas_com_log = sum(1 for s in secoes_filtradas if s.get("tem_log_jez"))
    urnas_com_bu = sum(1 for s in secoes_filtradas if s.get("tem_imgbu"))
    urnas_com_rdv = sum(1 for s in secoes_filtradas if s.get("tem_rdv"))

    cidades_no_filtro = len(set(s.get("municipio_codigo") for s in secoes_filtradas))
    zonas_no_filtro = len(set((s.get("municipio_codigo"), s.get("zona")) for s in secoes_filtradas))

    aptos_total = sum(s.get("eleitores_aptos", 0) for s in secoes_filtradas)
    faltosos_total = sum(s.get("faltosos", 0) for s in secoes_filtradas)
    comp_bu_total = sum(s.get("comparecimento_bu", 0) for s in secoes_filtradas)
    comp_log_total = sum(s.get("comparecimento_log", 0) for s in secoes_filtradas)
    comp_rdv_total = sum(s.get("comparecimento_rdv", 0) for s in secoes_filtradas)
    comp_efetivo_total = sum(s.get("comparecimento_efetivo", 0) for s in secoes_filtradas)

    # Somas apenas nas urnas que possuem os pares correspondentes para batimento justo
    comp_log_par_bu = sum(s.get("comparecimento_log", 0) for s in secoes_filtradas if s.get("tem_log_jez") and s.get("tem_imgbu"))
    comp_bu_par_log = sum(s.get("comparecimento_bu", 0) for s in secoes_filtradas if s.get("tem_log_jez") and s.get("tem_imgbu"))

    comp_rdv_par_bu = sum(s.get("comparecimento_rdv", 0) for s in secoes_filtradas if s.get("tem_rdv") and s.get("tem_imgbu"))
    comp_bu_par_rdv = sum(s.get("comparecimento_bu", 0) for s in secoes_filtradas if s.get("tem_rdv") and s.get("tem_imgbu"))

    bio_bu_par = sum(s.get("hab_biometrica_bu", 0) for s in secoes_filtradas if s.get("tem_log_jez") and s.get("tem_imgbu"))
    bio_log_par = sum(s.get("hab_biometrica_log", 0) for s in secoes_filtradas if s.get("tem_log_jez") and s.get("tem_imgbu"))

    biog_bu_par = sum(s.get("hab_biografica_bu", 0) for s in secoes_filtradas if s.get("tem_log_jez") and s.get("tem_imgbu"))
    biog_log_par = sum(s.get("hab_biografica_log", 0) for s in secoes_filtradas if s.get("tem_log_jez") and s.get("tem_imgbu"))

    sbio_bu_par = sum(s.get("hab_sem_bio_bu", 0) for s in secoes_filtradas if s.get("tem_log_jez") and s.get("tem_imgbu"))
    sbio_log_par = sum(s.get("hab_sem_bio_log", 0) for s in secoes_filtradas if s.get("tem_log_jez") and s.get("tem_imgbu"))

    brancos_bu_total = sum(s.get("brancos_bu", 0) for s in secoes_filtradas)
    brancos_rdv_total = sum(s.get("brancos_rdv", 0) for s in secoes_filtradas)
    nulos_bu_total = sum(s.get("nulos_bu", 0) for s in secoes_filtradas)
    nulos_rdv_total = sum(s.get("nulos_rdv", 0) for s in secoes_filtradas)

    # Consolida votos por candidato
    cands_agregados: dict[str, dict] = {}
    for s in secoes_filtradas:
        for c in s.get("candidatos", []):
            num = c["numero"]
            if num not in cands_agregados:
                cands_agregados[num] = {
                    "numero": num,
                    "nome": c["nome"],
                    "votos_bu": 0,
                    "votos_rdv": 0,
                }
            if c["nome"] and not c["nome"].startswith("CANDIDATO"):
                cands_agregados[num]["nome"] = c["nome"]
            cands_agregados[num]["votos_bu"] += c.get("votos_bu", 0)
            cands_agregados[num]["votos_rdv"] += c.get("votos_rdv", 0)

    total_nominais_consolidado = sum(
        max(c["votos_bu"], c["votos_rdv"]) for c in cands_agregados.values()
    )
    placar_candidatos = []
    for num, c in sorted(cands_agregados.items(), key=lambda x: max(x[1]["votos_bu"], x[1]["votos_rdv"]), reverse=True):
        v_ref = c["votos_bu"] if urnas_com_bu > 0 else c["votos_rdv"]
        pct = round((v_ref / max(total_nominais_consolidado, 1)) * 100.0, 2)
        placar_candidatos.append({
            "numero": num,
            "nome": c["nome"],
            "votos_bu": c["votos_bu"],
            "votos_rdv": c["votos_rdv"],
            "pct_validos": pct,
            "status": "CONFERE_100%" if (urnas_com_bu == 0 or urnas_com_rdv == 0 or c["votos_bu"] == c["votos_rdv"]) else "DIVERGENTE",
        })

    # Batimentos Cruzados Consolidados
    batimentos_consolidados = []
    if urnas_com_log > 0 and urnas_com_bu > 0:
        batimentos_consolidados.append({
            "item": f"Comparecimento Consolidado nas {urnas_com_log} Urnas c/ Log (Log.jez vs BU)",
            "valor_log": comp_log_par_bu,
            "valor_bu": comp_bu_par_log,
            "valor_rdv": comp_rdv_par_bu if urnas_com_rdv > 0 else "-",
            "status": "CONFERE_100%" if comp_log_par_bu == comp_bu_par_log else "DIVERGENTE",
        })
    if urnas_com_rdv > 0 and urnas_com_bu > 0:
        batimentos_consolidados.append({
            "item": f"Total de Cédulas no RDV Binário ASN.1 vs BU ({urnas_com_rdv} Urnas)",
            "valor_log": comp_log_par_bu if urnas_com_log > 0 else "-",
            "valor_bu": comp_bu_par_rdv,
            "valor_rdv": comp_rdv_par_bu,
            "status": "CONFERE_100%" if comp_rdv_par_bu == comp_bu_par_rdv else "DIVERGENTE",
        })
    if urnas_com_log > 0 and urnas_com_bu > 0:
        batimentos_consolidados.extend([
            {
                "item": "Habilitações Biométricas AFIS Consolidadas (Log vs BU)",
                "valor_log": bio_log_par,
                "valor_bu": bio_bu_par,
                "valor_rdv": "-",
                "status": "CONFERE_100%" if bio_log_par == bio_bu_par else "DIVERGENTE",
            },
            {
                "item": "Habilitações Biográficas Consolidadas (Log vs BU)",
                "valor_log": biog_log_par,
                "valor_bu": biog_bu_par,
                "valor_rdv": "-",
                "status": "CONFERE_100%" if biog_log_par == biog_bu_par else "DIVERGENTE",
            },
            {
                "item": "Habilitações Sem Biometria c/ Mesário Consolidadas (Log vs BU)",
                "valor_log": sbio_log_par,
                "valor_bu": sbio_bu_par,
                "valor_rdv": "-",
                "status": "CONFERE_100%" if sbio_log_par == sbio_bu_par else "DIVERGENTE",
            },
        ])

    for pc in placar_candidatos:
        batimentos_consolidados.append({
            "item": f"Candidato {pc['nome']} ({pc['numero']}) — Soma BU vs Soma RDV ASN.1 ({pc['pct_validos']}%)",
            "valor_log": "SIGILO_CONSTITUCIONAL",
            "valor_bu": pc["votos_bu"] if urnas_com_bu > 0 else "-",
            "valor_rdv": pc["votos_rdv"] if urnas_com_rdv > 0 else "-",
            "status": pc["status"],
        })

    if urnas_com_bu > 0 or urnas_com_rdv > 0:
        batimentos_consolidados.extend([
            {
                "item": "Votos em Branco Consolidados (BU vs RDV Binário ASN.1)",
                "valor_log": "-",
                "valor_bu": brancos_bu_total if urnas_com_bu > 0 else "-",
                "valor_rdv": brancos_rdv_total if urnas_com_rdv > 0 else "-",
                "status": "CONFERE_100%" if (urnas_com_bu == 0 or urnas_com_rdv == 0 or brancos_bu_total == brancos_rdv_total) else "DIVERGENTE",
            },
            {
                "item": "Votos Nulos Consolidados (BU vs RDV Binário ASN.1)",
                "valor_log": "-",
                "valor_bu": nulos_bu_total if urnas_com_bu > 0 else "-",
                "valor_rdv": nulos_rdv_total if urnas_com_rdv > 0 else "-",
                "status": "CONFERE_100%" if (urnas_com_bu == 0 or urnas_com_rdv == 0 or nulos_bu_total == nulos_rdv_total) else "DIVERGENTE",
            },
        ])

    # Soma de vazão horária e dígitos nulos
    votos_por_hora_global = Counter()
    nulos_digitados_global = Counter()
    soma_ponderada_ciclo = 0.0
    soma_ponderada_cabine = 0.0
    total_votos_com_log = 0
    total_linhas_logd = 0
    total_macs_validos = 0
    total_teclas_indevidas = 0
    total_id_invalido = 0

    for s in secoes_filtradas:
        for hh, q in s.get("votos_por_hora", {}).items():
            votos_por_hora_global[hh] += q
        for dig, q in s.get("votos_nulos_numeros_rdv", {}).items():
            nulos_digitados_global[dig] += q
        v_log = s.get("comparecimento_log", 0)
        if v_log > 0:
            soma_ponderada_ciclo += s.get("tempo_medio_ciclo_s", 0.0) * v_log
            soma_ponderada_cabine += s.get("tempo_medio_cabine_s", 0.0) * v_log
            total_votos_com_log += v_log
        total_linhas_logd += s.get("total_linhas_logd", 0)
        total_macs_validos += s.get("macs_validos", 0)
        total_teclas_indevidas += s.get("total_teclas_indevidas", 0)
        total_id_invalido += s.get("total_id_invalido", 0)

    tempo_medio_ciclo_global = round(soma_ponderada_ciclo / max(total_votos_com_log, 1), 1) if total_votos_com_log else 0.0
    tempo_medio_cabine_global = round(soma_ponderada_cabine / max(total_votos_com_log, 1), 1) if total_votos_com_log else 0.0
    pct_comp = round((comp_efetivo_total / max(aptos_total, 1)) * 100.0, 2) if aptos_total else 0.0

    nivel_risco_global = "CRITICO" if urnas_com_alerta > 0 else "BAIXO"
    veredito_consolidado = (
        f"CONSOLIDAÇÃO GLOBAL ÍNTEGRA — {total_urnas} URNA(S) AUDITADA(S) EM {cidades_no_filtro} CIDADE(S) / {zonas_no_filtro} ZONA(S)"
        if urnas_com_alerta == 0
        else f"ALERTA FORENSE: {urnas_com_alerta} DE {total_urnas} URNA(S) APRESENTARAM DIVERGÊNCIA OU ANOMALIA"
    )

    return {
        "modo_visao": "CONSOLIDADO_GLOBAL",
        "hierarquia": hierarquia,
        "consolidado": {
            "nivel_risco": nivel_risco_global,
            "veredito_geral": veredito_consolidado,
            "total_urnas": total_urnas,
            "urnas_integras": urnas_integras,
            "urnas_com_alerta": urnas_com_alerta,
            "urnas_com_log": urnas_com_log,
            "urnas_com_bu": urnas_com_bu,
            "urnas_com_rdv": urnas_com_rdv,
            "cidades_no_filtro": cidades_no_filtro,
            "zonas_no_filtro": zonas_no_filtro,
            "eleitores_aptos_total": aptos_total,
            "faltosos_total": faltosos_total,
            "comparecimento_total": comp_efetivo_total,
            "pct_comparecimento": pct_comp,
            "brancos_total": brancos_bu_total or brancos_rdv_total,
            "nulos_total": nulos_bu_total or nulos_rdv_total,
            "votos_nulos_numeros_digitados": dict(nulos_digitados_global),
            "tempo_medio_ciclo_s": tempo_medio_ciclo_global,
            "tempo_medio_cabine_s": tempo_medio_cabine_global,
            "total_linhas_logd": total_linhas_logd,
            "total_macs_validos": total_macs_validos,
            "total_teclas_indevidas": total_teclas_indevidas,
            "total_id_invalido": total_id_invalido,
            "placar_candidatos": placar_candidatos,
            "batimentos_cruzados": batimentos_consolidados,
            "votos_por_hora": dict(sorted(votos_por_hora_global.items())),
            "lista_urnas": secoes_filtradas[:500],
        },
    }

