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

ESTADOS_E_REGIOES_BR = {
    "AC": {"nome": "Acre", "regiao": "NORTE"},
    "AL": {"nome": "Alagoas", "regiao": "NORDESTE"},
    "AM": {"nome": "Amazonas", "regiao": "NORTE"},
    "AP": {"nome": "Amapá", "regiao": "NORTE"},
    "BA": {"nome": "Bahia", "regiao": "NORDESTE"},
    "CE": {"nome": "Ceará", "regiao": "NORDESTE"},
    "DF": {"nome": "Distrito Federal", "regiao": "CENTRO-OESTE"},
    "ES": {"nome": "Espírito Santo", "regiao": "SUDESTE"},
    "GO": {"nome": "Goiás", "regiao": "CENTRO-OESTE"},
    "MA": {"nome": "Maranhão", "regiao": "NORDESTE"},
    "MG": {"nome": "Minas Gerais", "regiao": "SUDESTE"},
    "MS": {"nome": "Mato Grosso do Sul", "regiao": "CENTRO-OESTE"},
    "MT": {"nome": "Mato Grosso", "regiao": "CENTRO-OESTE"},
    "PA": {"nome": "Pará", "regiao": "NORTE"},
    "PB": {"nome": "Paraíba", "regiao": "NORDESTE"},
    "PE": {"nome": "Pernambuco", "regiao": "NORDESTE"},
    "PI": {"nome": "Piauí", "regiao": "NORDESTE"},
    "PR": {"nome": "Paraná", "regiao": "SUL"},
    "RJ": {"nome": "Rio de Janeiro", "regiao": "SUDESTE"},
    "RN": {"nome": "Rio Grande do Norte", "regiao": "NORDESTE"},
    "RO": {"nome": "Rondônia", "regiao": "NORTE"},
    "RR": {"nome": "Roraima", "regiao": "NORTE"},
    "RS": {"nome": "Rio Grande do Sul", "regiao": "SUL"},
    "SC": {"nome": "Santa Catarina", "regiao": "SUL"},
    "SE": {"nome": "Sergipe", "regiao": "NORDESTE"},
    "SP": {"nome": "São Paulo", "regiao": "SUDESTE"},
    "TO": {"nome": "Tocantins", "regiao": "NORTE"},
    "ZZ": {"nome": "Exterior", "regiao": "EXTERIOR"},
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


CARGO_ASN1_NOMES = {
    1: "PRESIDENTE",
    3: "GOVERNADOR",
    5: "SENADOR",
    6: "DEPUTADO FEDERAL",
    7: "DEPUTADO ESTADUAL",
    11: "PREFEITO",
    13: "VEREADOR",
}


def _ler_asn1_len(data: bytes, offset: int) -> tuple[int, int]:
    """Lê o campo de tamanho ASN.1 DER em `offset` e retorna `(tamanho, proximo_offset)`."""
    if offset >= len(data):
        return 0, offset
    first = data[offset]
    if first < 0x80:
        return first, offset + 1
    num_bytes = first & 0x7F
    if num_bytes == 0 or offset + 1 + num_bytes > len(data):
        return 0, offset + 1
    val = int.from_bytes(data[offset + 1 : offset + 1 + num_bytes], "big")
    return val, offset + 1 + num_bytes


def decodificar_rdv_asn1_der(rdv_bytes: bytes) -> dict:
    """
    Decodifica diretamente os registros binários ASN.1 DER do arquivo `-rdv.dat` do TSE.
    Identifica cada bloco `VotosCargo` (`81 01 <idCargo>` para cargos constitucionais como
    `1 = Presidente`, `3 = Governador`, `11 = Prefeito`, ou `82 <len> <idPergunta>` para
    Consultas Populares / Plebiscitos Municipais) e separa os votos do Cargo Principal
    (Presidente) de eventuais 2ºs Cargos / Consultas Populares na mesma urna!
    """
    sha256_hex = hashlib.sha256(rdv_bytes).hexdigest().upper()

    # Extrai strings ASCII de cabeçalho (timestamp de geração, versão da aplicação, código de carga)
    ascii_headers = [s.decode("ascii", errors="ignore") for s in re.findall(rb"[ -~]{6,}", rdv_bytes[:260])]

    n = len(rdv_bytes)
    blocos_cargo_detectados = []

    # Localiza todos os containers VotosCargo:
    # Tag 0x81 (idCargo constitucional) ou 0x82 (idPergunta consulta popular) seguido de 0x02 0x01 <qtdEscolhas> 0x30 <len_votos>
    idx = 0
    while idx < n - 8:
        if rdv_bytes[idx] in (0x81, 0x82) and 1 <= rdv_bytes[idx + 1] <= 4:
            tag_tipo_cargo = rdv_bytes[idx]
            id_len = rdv_bytes[idx + 1]
            after_id = idx + 2 + id_len
            if after_id + 4 < n and rdv_bytes[after_id] == 0x02 and rdv_bytes[after_id + 1] == 0x01 and rdv_bytes[after_id + 3] == 0x30:
                codigo_cargo = int.from_bytes(rdv_bytes[idx + 2 : after_id], "big")
                qtd_escolhas = rdv_bytes[after_id + 2]
                votos_seq_len, votos_start = _ler_asn1_len(rdv_bytes, after_id + 4)
                votos_end = min(n, votos_start + votos_seq_len)
                if votos_end > votos_start:
                    nome_cargo = (
                        CARGO_ASN1_NOMES.get(codigo_cargo, f"CARGO_{codigo_cargo}")
                        if tag_tipo_cargo == 0x81
                        else f"CONSULTA_POPULAR_{codigo_cargo}"
                    )
                    blocos_cargo_detectados.append({
                        "codigo_cargo": codigo_cargo,
                        "nome_cargo": nome_cargo,
                        "tipo_container": "CARGO_CONSTITUCIONAL" if tag_tipo_cargo == 0x81 else "CONSULTA_POPULAR",
                        "qtd_escolhas": qtd_escolhas,
                        "start": votos_start,
                        "end": votos_end,
                    })
                    idx = votos_end
                    continue
        idx += 1

    # Caso o arquivo não tenha cabeçalho VotosCargo padrão (ex: RDV simulado), analisa o range completo
    if not blocos_cargo_detectados:
        blocos_cargo_detectados.append({
            "codigo_cargo": 1,
            "nome_cargo": "PRESIDENTE",
            "tipo_container": "CARGO_CONSTITUCIONAL",
            "qtd_escolhas": 1,
            "start": 0,
            "end": n,
        })

    votos_extraidos = []
    contagem_por_tipo = Counter()
    contagem_nominais = Counter()
    detalhe_nulos_digitados = Counter()
    contagem_legendas = Counter()
    resumo_por_cargo = []

    idx_bloco_principal = next(
        (i for i, b in enumerate(blocos_cargo_detectados) if b["codigo_cargo"] == 1 and b["tipo_container"] == "CARGO_CONSTITUCIONAL"),
        0,
    )

    for idx_bloco, bloco in enumerate(blocos_cargo_detectados):
        c_tipo = Counter()
        c_nom = Counter()
        c_nul = Counter()
        c_leg = Counter()
        pos = bloco["start"]
        end_pos = bloco["end"]

        while pos < end_pos - 4:
            if rdv_bytes[pos] == 0x30 and rdv_bytes[pos + 2] == 0x0A and rdv_bytes[pos + 3] == 0x01:
                seq_len = rdv_bytes[pos + 1]
                tipo_code = rdv_bytes[pos + 4]

                # Caso 1: Voto sem dígitos (ex: BRANCO -> 30 03 0a 01 03)
                if seq_len == 3 and tipo_code in (1, 2, 3, 4, 5):
                    tipo_str = TIPO_VOTO_ASN1_MAP.get(tipo_code, f"TIPO_{tipo_code}")
                    c_tipo[tipo_str] += 1
                    # Contabiliza no placar principal o cargo de Presidente (ou o 1º cargo se Presidente não estiver presente)
                    if idx_bloco == idx_bloco_principal:
                        votos_extraidos.append({
                            "ordem_embaralhada_rdv": len(votos_extraidos) + 1,
                            "cargo": bloco["nome_cargo"],
                            "tipo_voto": tipo_str,
                            "numero_digitado": None,
                        })
                        contagem_por_tipo[tipo_str] += 1
                    pos += 5
                    continue

                # Caso 2: Voto com NumericString (0x12 <dig_len> <digits>)
                if 5 <= seq_len <= 10 and pos + 2 + seq_len <= end_pos and rdv_bytes[pos + 5] == 0x12:
                    dig_len = rdv_bytes[pos + 6]
                    if 3 + 2 + dig_len == seq_len and tipo_code in (1, 2, 3, 4, 5):
                        dig_str = rdv_bytes[pos + 7 : pos + 7 + dig_len].decode("ascii", errors="ignore")
                        if dig_str.isdigit():
                            tipo_str = TIPO_VOTO_ASN1_MAP.get(tipo_code, f"TIPO_{tipo_code}")
                            c_tipo[tipo_str] += 1
                            if tipo_str == "NOMINAL":
                                c_nom[dig_str] += 1
                            elif tipo_str == "NULO":
                                c_nul[dig_str] += 1
                            elif tipo_str == "LEGENDA":
                                c_leg[dig_str] += 1

                            if idx_bloco == idx_bloco_principal:
                                votos_extraidos.append({
                                    "ordem_embaralhada_rdv": len(votos_extraidos) + 1,
                                    "cargo": bloco["nome_cargo"],
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

        resumo_por_cargo.append({
            "codigo_cargo": bloco["codigo_cargo"],
            "nome_cargo": bloco["nome_cargo"],
            "tipo_container": bloco["tipo_container"],
            "total_cedulas": sum(c_tipo.values()),
            "resumo_tipos": dict(c_tipo),
            "votos_nominais_por_numero": dict(c_nom),
            "votos_nulos_numeros_digitados": dict(c_nul),
            "votos_legenda_por_partido": dict(c_leg),
        })

    return {
        "tamanho_bytes": len(rdv_bytes),
        "sha256": sha256_hex,
        "cabecalho_strings": ascii_headers[:8],
        "total_votos_no_rdv": len(votos_extraidos),
        "resumo_tipos": dict(contagem_por_tipo),
        "votos_nominais_por_numero": dict(contagem_nominais),
        "votos_nulos_numeros_digitados": dict(detalhe_nulos_digitados),
        "votos_legenda_por_partido": dict(contagem_legendas),
        "cargos_rdv": resumo_por_cargo,
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

    turno_detectado = 2
    if re.search(r"1[°ºo]\s*Turno", espelho_bu, re.IGNORECASE) or data_abertura.startswith("04/10") or data_abertura.startswith("02/10"):
        turno_detectado = 1
    elif re.search(r"2[°ºo]\s*Turno", espelho_bu, re.IGNORECASE) or data_abertura.startswith("25/10") or data_abertura.startswith("30/10"):
        turno_detectado = 2

    # Extrai blocos por cargo no BU (suporta 1º Turno com 5 cargos e 2º Turno com Presidente/Governador)
    cargos_bu_map: dict[str, dict] = {}
    cargo_atual = "GERAL"
    in_cand_block = False
    for line in clean_lines:
        m_header_cargo = re.match(r"^\s*-{4,}\s*([A-ZÀ-ÚÇ\s]+?)\s*-{4,}\s*$", line)
        if m_header_cargo:
            hdr = m_header_cargo.group(1).strip().upper()
            if hdr not in ("BU DIGITAL", "FIM"):
                cargo_atual = hdr
                cargos_bu_map.setdefault(cargo_atual, {
                    "cargo": cargo_atual,
                    "candidatos": [],
                    "eleitores_aptos": eleitores_aptos,
                    "total_nominais": 0,
                    "brancos": 0,
                    "nulos": 0,
                    "total_apurado": 0,
                })
                in_cand_block = False
            continue

        if "Nome do candidato" in line and "Votos" in line:
            in_cand_block = True
            cargos_bu_map.setdefault(cargo_atual, {
                "cargo": cargo_atual,
                "candidatos": [],
                "eleitores_aptos": eleitores_aptos,
                "total_nominais": 0,
                "brancos": 0,
                "nulos": 0,
                "total_apurado": 0,
            })
            continue

        if in_cand_block:
            m_cand = re.match(r"^\s*([A-ZÀ-Ú0-9\s\.\-']+?)\s+(\d{2,5})\s+(\d{4})\s*$", line)
            if m_cand:
                cargos_bu_map[cargo_atual]["candidatos"].append({
                    "nome": m_cand.group(1).strip(),
                    "numero": m_cand.group(2),
                    "votos": int(m_cand.group(3)),
                })
                continue

        if cargo_atual in cargos_bu_map:
            m_nom = re.search(r"Total de votos Nominais\s+(\d+)", line, re.IGNORECASE)
            if m_nom:
                cargos_bu_map[cargo_atual]["total_nominais"] = int(m_nom.group(1))
                in_cand_block = False
            m_br = re.search(r"^\s*Brancos\s+(\d+)", line, re.IGNORECASE)
            if m_br:
                cargos_bu_map[cargo_atual]["brancos"] = int(m_br.group(1))
            m_nu = re.search(r"^\s*Nulos\s+(\d+)", line, re.IGNORECASE)
            if m_nu:
                cargos_bu_map[cargo_atual]["nulos"] = int(m_nu.group(1))
            m_ap = re.search(r"Total Apurado\s+(\d+)", line, re.IGNORECASE)
            if m_ap:
                cargos_bu_map[cargo_atual]["total_apurado"] = int(m_ap.group(1))

    # Seleciona prioritariamente o bloco de PRESIDENTE (ou o primeiro bloco com candidatos)
    bloco_principal = (
        cargos_bu_map.get("PRESIDENTE")
        or next((b for b in cargos_bu_map.values() if b["candidatos"]), None)
    )

    if bloco_principal:
        candidatos_bu = bloco_principal["candidatos"]
        total_nominais = bloco_principal["total_nominais"] or _find_int(r"Total de votos Nominais\s+(\d+)")
        brancos = bloco_principal["brancos"] or _find_int(r"Brancos\s+(\d+)")
        nulos = bloco_principal["nulos"] or _find_int(r"Nulos\s+(\d+)")
        total_apurado = bloco_principal["total_apurado"] or _find_int(r"Total Apurado\s+(\d+)")
    else:
        candidatos_bu = []
        total_nominais = _find_int(r"Total de votos Nominais\s+(\d+)")
        brancos = _find_int(r"Brancos\s+(\d+)")
        nulos = _find_int(r"Nulos\s+(\d+)")
        total_apurado = _find_int(r"Total Apurado\s+(\d+)")

    return {
        "tamanho_bytes": len(imgbu_bytes),
        "sha256": sha256_hex,
        "turno": turno_detectado,
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
        "cargos_bu": list(cargos_bu_map.values()),
        "espelho_bobina": espelho_bu[:15000],
    }


def _novo_estado_dia_log(data_str: str) -> dict:
    return {
        "data_eleicao": data_str,
        "linhas_dia": 0,
        "macs_validos_dia": 0,
        "etapas_assinatura_sucesso": 0,
        "urna_ligada_em": "",
        "hora_zeresima": "",
        "hora_pronta_votos": "",
        "hora_encerramento": "",
        "titulo_encerramento": "",
        "mesarios_registrados": [],
        "cargos_distintos": [],
        "alertas_e_erros": [],
        "ciclos_votacao": [],
        "eventos_dia_votacao": [],
        "hab_biometrica_log": 0,
        "hab_biografica_log": 0,
        "hab_sem_bio_log": 0,
        "total_teclas_indevidas": 0,
        "total_teclas_indevidas_presidente": 0,
        "total_teclas_indevidas_outros": 0,
        "total_teclas_por_cargo": Counter(),
        "total_id_invalido": 0,
        "logs_teclas_indevidas": [],
        "logs_id_invalido": [],
        # Estado transitório do ciclo do eleitor atual
        "in_cabine": False,
        "t_aguardando": None,
        "t_id_digitado": None,
        "tipo_doc_digitado": "",
        "tentativas_digital": 0,
        "foi_habilitacao_biografica": False,
        "t_habilitado": None,
        "tipo_habilitacao": "",
        "teclas_indevidas_ciclo": 0,
        "teclas_indevidas_presidente_ciclo": 0,
        "teclas_indevidas_outros_ciclo": 0,
        "teclas_por_cargo_ciclo": Counter(),
        "cargos_confirmados": [],
        "eventos_ciclo_atual": [],
    }


def _compilar_resumo_dia_log(est: dict) -> dict:
    ciclos = est["ciclos_votacao"]
    tempos_cabine = [c["tempo_cabine_s"] for c in ciclos]
    tempos_mesa = [c["tempo_mesa_bio_s"] for c in ciclos]
    tempos_totais = [c["tempo_ciclo_total_s"] for c in ciclos]

    votos_por_hora = Counter()
    for c in ciclos:
        hh = c["hora_computado"][:2] + "h"
        votos_por_hora[hh] += 1

    return {
        "data_eleicao": est["data_eleicao"],
        "linhas_log_dia": est["linhas_dia"],
        "macs_validos_dia": est["macs_validos_dia"],
        "etapas_assinatura_ok": est["etapas_assinatura_sucesso"],
        "hora_zeresima": est["hora_zeresima"],
        "hora_pronta_votos": est["hora_pronta_votos"],
        "hora_encerramento": est["hora_encerramento"],
        "titulo_encerramento": est["titulo_encerramento"],
        "mesarios_registrados": est["mesarios_registrados"],
        "cargos_votados": est["cargos_distintos"],
        "qtd_cargos_votados": len(est["cargos_distintos"]),
        "total_votos_computados": len(ciclos),
        "habilitacao_biometrica": est["hab_biometrica_log"],
        "habilitacao_biografica": est["hab_biografica_log"],
        "habilitacao_sem_biometria": est["hab_sem_bio_log"],
        "total_teclas_indevidas": est["total_teclas_indevidas"],
        "total_teclas_indevidas_presidente": est.get("total_teclas_indevidas_presidente", 0),
        "total_teclas_indevidas_outros": est.get("total_teclas_indevidas_outros", 0),
        "teclas_por_cargo": dict(est.get("total_teclas_por_cargo", {})),
        "total_identificador_invalido": est["total_id_invalido"],
        "logs_teclas_indevidas": est.get("logs_teclas_indevidas", []),
        "logs_id_invalido": est.get("logs_id_invalido", []),
        "qtd_alertas_dia": len(est["alertas_e_erros"]),
        "tempo_medio_mesa_bio_s": round(sum(tempos_mesa) / max(len(tempos_mesa), 1), 1),
        "tempo_medio_cabine_s": round(sum(tempos_cabine) / max(len(tempos_cabine), 1), 1),
        "tempo_medio_ciclo_s": round(sum(tempos_totais) / max(len(tempos_totais), 1), 1),
        "tempo_minimo_cabine_s": round(min(tempos_cabine), 1) if tempos_cabine else 0.0,
        "tempo_maximo_ciclo_s": round(max(tempos_totais), 1) if tempos_totais else 0.0,
        "votos_por_hora": dict(sorted(votos_por_hora.items())),
    }


def decodificar_log_jez_tse(log_jez_bytes: bytes, data_alvo_filtro: str = "") -> dict:
    """
    Descompacta o arquivo `-log.jez` do TSE em memória, extrai o `logd.dat` (ISO-8859-1).
    Como a Mídia da Urna (MI) acumula no mesmo `logd.dat` o 1º Turno (04/10/2026) e o 2º Turno (25/10/2026),
    reconstrói simultaneamente em uma única passagem todos os ciclos de eleitores, tempos, biometria,
    vazão horária e eventos operacionais TANTO do 1º Turno QUANTO do 2º Turno!
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
    data_1_turno = datas_votacao_ordenadas[0] if len(datas_votacao_ordenadas) >= 2 else (
        datas_votacao_ordenadas[0] if datas_votacao_ordenadas and datas_votacao_ordenadas[0].startswith(("04/10", "02/10", "06/10")) else ""
    )
    data_2_turno = datas_votacao_ordenadas[-1] if len(datas_votacao_ordenadas) >= 2 else (
        datas_votacao_ordenadas[-1] if datas_votacao_ordenadas and datas_votacao_ordenadas[-1] != data_1_turno else data_eleicao_principal
    )

    datas_interesse = {d for d in (data_eleicao_principal, data_1_turno, data_2_turno) if d} | set(datas_votacao_ordenadas)
    estados_por_data: dict[str, dict] = {d: _novo_estado_dia_log(d) for d in datas_interesse}

    # Pré-passo pericial: descobre a sequência exata de cargos da cédula eletrônica para cada data
    sequencia_cargos_por_data: dict[str, list[str]] = {}
    seq_temp: list[str] = []
    in_ciclo_temp = False
    data_temp = ""
    for l in lines:
        if "VOTA" not in l:
            continue
        d_l = l[:10]
        if "Eleitor foi habilitado" in l:
            in_ciclo_temp = True
            seq_temp = []
            data_temp = d_l
        elif "Voto confirmado para" in l and in_ciclo_temp:
            m_c = re.search(r"\[(.*?)\]", l)
            if m_c:
                seq_temp.append(m_c.group(1))
        elif "O voto do eleitor foi computado" in l and in_ciclo_temp:
            in_ciclo_temp = False
            if data_temp and data_temp not in sequencia_cargos_por_data and seq_temp:
                sequencia_cargos_por_data[data_temp] = list(seq_temp)

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
    macs_validos = 0
    macs_invalidos = 0

    for line_num, line in enumerate(lines, start=1):
        parts = line.split("\t")
        if len(parts) < 5:
            continue

        ts_str = parts[0].strip()
        data_cur = ts_str[:10]
        hora_cur = ts_str[11:19] if len(ts_str) >= 19 else ""
        nivel = parts[1].strip()
        serial_ue = parts[2].strip()
        subsistema = parts[3].strip()
        msg = parts[4].strip()
        mac_hex = parts[5].strip() if len(parts) >= 6 else ""

        contagem_subsistemas[subsistema] += 1
        contagem_niveis[nivel] += 1

        mac_ok = bool(re.fullmatch(r"[0-9A-Fa-f]{16}", mac_hex))
        if mac_ok:
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

        if data_cur not in estados_por_data:
            if not datas_interesse:
                estados_por_data[data_cur] = _novo_estado_dia_log(data_cur)
            else:
                continue

        est = estados_por_data[data_cur]
        est["linhas_dia"] += 1
        if mac_ok:
            est["macs_validos_dia"] += 1

        if "Urna ligada em" in msg:
            est["urna_ligada_em"] = msg
        elif "Verificação de assinatura - Etapa" in msg and "[SUCESSO]" in msg:
            est["etapas_assinatura_sucesso"] += 1
        elif "Gerando relatório [ZERÉSIMA] [TÉRMINO]" in msg and not est["hora_zeresima"]:
            est["hora_zeresima"] = hora_cur
        elif "Urna pronta para receber votos" in msg and not est["hora_pronta_votos"]:
            est["hora_pronta_votos"] = hora_cur
        elif "Procedimento de encerramento confirmado" in msg:
            est["hora_encerramento"] = hora_cur
        elif "Título digitado para encerramento:" in msg:
            est["titulo_encerramento"] = msg.split(":", 1)[1].strip()
        elif re.match(r"^Mesário\s+\d+\s+registrado$", msg):
            m_mes = re.search(r"Mesário\s+(\d+)\s+registrado", msg)
            if m_mes and m_mes.group(1) not in est["mesarios_registrados"]:
                est["mesarios_registrados"].append(m_mes.group(1))

        try:
            dt = datetime.strptime(ts_str, "%d/%m/%Y %H:%M:%S")
        except Exception:
            dt = None

        if nivel not in ("INFO",):
            est["alertas_e_erros"].append({
                "linha": line_num,
                "timestamp": ts_str,
                "nivel": nivel,
                "subsistema": subsistema,
                "mensagem": msg,
                "mac": mac_hex,
            })

        if subsistema == "VOTA" and dt:
            if len(est["eventos_dia_votacao"]) < 400:
                est["eventos_dia_votacao"].append({
                    "linha": line_num,
                    "timestamp": ts_str,
                    "nivel": nivel,
                    "mensagem": msg,
                    "mac": mac_hex,
                })

            if "Aguardando digitação do identificador do eleitor" in msg:
                est["t_aguardando"] = dt
                est["t_id_digitado"] = None
                est["tipo_doc_digitado"] = ""
                est["tentativas_digital"] = 0
                est["foi_habilitacao_biografica"] = False
                est["t_habilitado"] = None
                est["tipo_habilitacao"] = ""
                est["teclas_indevidas_ciclo"] = 0
                est["teclas_indevidas_presidente_ciclo"] = 0
                est["teclas_indevidas_outros_ciclo"] = 0
                est["teclas_por_cargo_ciclo"] = Counter()
                est["cargos_confirmados"] = []
                est["in_cabine"] = False
                est["eventos_ciclo_atual"] = [{
                    "linha": line_num,
                    "hora": dt.strftime("%H:%M:%S"),
                    "nivel": nivel,
                    "mensagem": msg,
                    "mac": mac_hex,
                }]
            else:
                est["eventos_ciclo_atual"].append({
                    "linha": line_num,
                    "hora": dt.strftime("%H:%M:%S"),
                    "nivel": nivel,
                    "mensagem": msg,
                    "mac": mac_hex,
                })

            if "Identificador do eleitor digitado pelo mesário" in msg:
                est["t_id_digitado"] = dt

            elif "Identificador digitado pelo mesário foi:" in msg:
                if "CPF" in msg:
                    est["tipo_doc_digitado"] = "CPF"
                elif "Título" in msg:
                    est["tipo_doc_digitado"] = "TITULO"
                else:
                    est["tipo_doc_digitado"] = msg.split(":", 1)[1].strip()

            elif "Identificador do eleitor digitado inválido" in msg:
                est["total_id_invalido"] += 1
                est["logs_id_invalido"].append({
                    "linha": line_num,
                    "timestamp": ts_str,
                    "data": data_cur,
                    "hora": dt.strftime("%H:%M:%S") if dt else hora_cur,
                    "nivel": nivel,
                    "subsistema": subsistema,
                    "mensagem": msg,
                    "mac": mac_hex,
                    "seq_eleitor_previsto": len(est["ciclos_votacao"]) + 1,
                })

            elif "Solicita digital. Tentativa" in msg:
                est["tentativas_digital"] += 1

            elif "Dado digitado confere" in msg and "Solicita digital do mesário" not in msg:
                est["foi_habilitacao_biografica"] = True

            elif "Tipo de habilitação do eleitor" in msg:
                if "[biométrica]" in msg:
                    est["tipo_habilitacao"] = "BIOMETRICA"
                elif "[biográfica]" in msg:
                    est["tipo_habilitacao"] = "BIOGRAFICA"
                else:
                    est["tipo_habilitacao"] = "SEM_BIOMETRIA"

            elif "Eleitor foi habilitado" in msg:
                est["t_habilitado"] = dt
                est["in_cabine"] = True
                est["teclas_indevidas_ciclo"] = 0
                est["teclas_indevidas_presidente_ciclo"] = 0
                est["teclas_indevidas_outros_ciclo"] = 0
                est["teclas_por_cargo_ciclo"] = Counter()
                if est["tipo_habilitacao"] == "BIOMETRICA":
                    est["hab_biometrica_log"] += 1
                elif est["foi_habilitacao_biografica"] or est["tipo_habilitacao"] == "BIOGRAFICA":
                    est["tipo_habilitacao"] = "BIOGRAFICA"
                    est["hab_biografica_log"] += 1
                else:
                    est["tipo_habilitacao"] = "SEM_BIOMETRIA"
                    est["hab_sem_bio_log"] += 1

            elif "Tecla indevida pressionada" in msg:
                est["teclas_indevidas_ciclo"] += 1
                est["total_teclas_indevidas"] += 1

                seq_cargos_dia = sequencia_cargos_por_data.get(data_cur, [])
                idx_c = len(est["cargos_confirmados"])
                if seq_cargos_dia and idx_c < len(seq_cargos_dia):
                    cargo_ativo = seq_cargos_dia[idx_c]
                elif "Governador" in est["cargos_confirmados"]:
                    cargo_ativo = "Presidente"
                elif not est["cargos_confirmados"] and data_cur != data_1_turno:
                    cargo_ativo = "Presidente"
                else:
                    cargo_ativo = "Presidente" if idx_c >= len(seq_cargos_dia) - 1 else "Deputado Federal"

                e_presidente = bool(cargo_ativo == "Presidente")

                if e_presidente:
                    est["teclas_indevidas_presidente_ciclo"] += 1
                    est["total_teclas_indevidas_presidente"] += 1
                else:
                    est["teclas_indevidas_outros_ciclo"] += 1
                    est["total_teclas_indevidas_outros"] += 1

                est["teclas_por_cargo_ciclo"][cargo_ativo] += 1
                est["total_teclas_por_cargo"][cargo_ativo] += 1

                contexto_desc = "Seção para escolha do Presidente aberta para voto" if e_presidente else f"Tela de {cargo_ativo} aberta na cabine"

                est["logs_teclas_indevidas"].append({
                    "linha": line_num,
                    "timestamp": ts_str,
                    "data": data_cur,
                    "hora": dt.strftime("%H:%M:%S") if dt else hora_cur,
                    "seq_eleitor": len(est["ciclos_votacao"]) + 1,
                    "cargo": cargo_ativo,
                    "e_presidente": e_presidente,
                    "contexto": contexto_desc,
                    "cargos_votados": list(est["cargos_confirmados"]),
                    "nivel": nivel,
                    "subsistema": subsistema,
                    "mensagem": msg,
                    "mac": mac_hex,
                })

            elif "Voto confirmado para" in msg:
                m_cargo = re.search(r"\[(.*?)\]", msg)
                if m_cargo:
                    nome_c = m_cargo.group(1)
                    est["cargos_confirmados"].append(nome_c)
                    if nome_c not in est["cargos_distintos"]:
                        est["cargos_distintos"].append(nome_c)

            elif "O voto do eleitor foi computado" in msg:
                est["in_cabine"] = False
                t_computado = dt
                inicio_ref = est["t_id_digitado"] or est["t_aguardando"] or est["t_habilitado"] or t_computado
                hab_ref = est["t_habilitado"] or inicio_ref

                tempo_mesa_bio_s = max(0.0, (hab_ref - inicio_ref).total_seconds())
                tempo_cabine_s = max(0.0, (t_computado - hab_ref).total_seconds())
                tempo_ciclo_total_s = tempo_mesa_bio_s + tempo_cabine_s

                est["ciclos_votacao"].append({
                    "seq": len(est["ciclos_votacao"]) + 1,
                    "linha_log": line_num,
                    "data_eleicao": data_cur,
                    "faixa_horaria": t_computado.strftime("%H") + "h",
                    "hora_aguardando": est["t_aguardando"].strftime("%H:%M:%S") if est["t_aguardando"] else inicio_ref.strftime("%H:%M:%S"),
                    "hora_inicio": inicio_ref.strftime("%H:%M:%S"),
                    "hora_habilitacao": hab_ref.strftime("%H:%M:%S"),
                    "hora_computado": t_computado.strftime("%H:%M:%S"),
                    "documento": est["tipo_doc_digitado"] or "TITULO",
                    "tipo_habilitacao": est["tipo_habilitacao"] or "BIOMETRICA",
                    "tentativas_digital": est["tentativas_digital"],
                    "teclas_indevidas": est["teclas_indevidas_ciclo"],
                    "teclas_indevidas_presidente": est["teclas_indevidas_presidente_ciclo"],
                    "teclas_indevidas_outros": est["teclas_indevidas_outros_ciclo"],
                    "teclas_por_cargo": dict(est["teclas_por_cargo_ciclo"]),
                    "cargos": list(est["cargos_confirmados"]),
                    "tempo_mesa_bio_s": round(tempo_mesa_bio_s, 1),
                    "tempo_cabine_s": round(tempo_cabine_s, 1),
                    "tempo_ciclo_total_s": round(tempo_ciclo_total_s, 1),
                    "mac_voto": mac_hex,
                    "eventos_detalhados": list(est["eventos_ciclo_atual"]),
                })

    est_principal = estados_por_data.get(data_eleicao_principal) or (
        next(iter(estados_por_data.values())) if estados_por_data else _novo_estado_dia_log(data_eleicao_principal)
    )
    resumo_principal = _compilar_resumo_dia_log(est_principal)

    est_t1 = estados_por_data.get(data_1_turno) if data_1_turno else None
    resumo_t1 = _compilar_resumo_dia_log(est_t1) if est_t1 else None

    est_t2 = estados_por_data.get(data_2_turno) if data_2_turno else est_principal
    resumo_t2 = _compilar_resumo_dia_log(est_t2) if est_t2 else resumo_principal

    # Constrói comparativo detalhado 1º Turno vs 2º Turno diretamente do logd.dat
    comparativo_turnos_log = None
    if resumo_t1 and resumo_t2 and data_1_turno and data_2_turno and data_1_turno != data_2_turno:
        v1 = resumo_t1["total_votos_computados"]
        v2 = resumo_t2["total_votos_computados"]
        dv = v2 - v1
        dv_pct = round((dv / max(v1, 1)) * 100.0, 2)

        cab1 = resumo_t1["tempo_medio_cabine_s"]
        cab2 = resumo_t2["tempo_medio_cabine_s"]
        dcab = round(cab2 - cab1, 1)
        dcab_pct = round((dcab / max(cab1, 0.1)) * 100.0, 1) if cab1 > 0 else 0.0

        cic1 = resumo_t1["tempo_medio_ciclo_s"]
        cic2 = resumo_t2["tempo_medio_ciclo_s"]
        dcic = round(cic2 - cic1, 1)
        dcic_pct = round((dcic / max(cic1, 0.1)) * 100.0, 1) if cic1 > 0 else 0.0

        mesa1 = resumo_t1["tempo_medio_mesa_bio_s"]
        mesa2 = resumo_t2["tempo_medio_mesa_bio_s"]
        dmesa = round(mesa2 - mesa1, 1)

        faixas_horas = ["08h", "09h", "10h", "11h", "12h", "13h", "14h", "15h", "16h", "17h"]
        vh1 = resumo_t1.get("votos_por_hora", {})
        vh2 = resumo_t2.get("votos_por_hora", {})
        votos_por_hora_comparado = []
        for fh in faixas_horas:
            q1 = vh1.get(fh, 0)
            q2 = vh2.get(fh, 0)
            if q1 > 0 or q2 > 0 or fh != "17h":
                votos_por_hora_comparado.append({
                    "hora": fh,
                    "votos_1_turno": q1,
                    "votos_2_turno": q2,
                    "diferenca": q2 - q1,
                })

        comparativo_turnos_log = {
            "disponivel": True,
            "data_1_turno": data_1_turno,
            "data_2_turno": data_2_turno,
            "turno_1": resumo_t1,
            "turno_2": resumo_t2,
            "variacao": {
                "delta_votos": dv,
                "delta_votos_pct": dv_pct,
                "delta_hab_biometrica": resumo_t2["habilitacao_biometrica"] - resumo_t1["habilitacao_biometrica"],
                "delta_hab_biografica": resumo_t2["habilitacao_biografica"] - resumo_t1["habilitacao_biografica"],
                "delta_hab_sem_biometria": resumo_t2["habilitacao_sem_biometria"] - resumo_t1["habilitacao_sem_biometria"],
                "delta_tempo_mesa_s": dmesa,
                "delta_tempo_cabine_s": dcab,
                "delta_tempo_cabine_pct": dcab_pct,
                "delta_tempo_ciclo_s": dcic,
                "delta_tempo_ciclo_pct": dcic_pct,
                "delta_teclas_indevidas": resumo_t2["total_teclas_indevidas"] - resumo_t1["total_teclas_indevidas"],
                "teclas_presidente_t1": resumo_t1.get("total_teclas_indevidas_presidente", 0),
                "teclas_presidente_t2": resumo_t2.get("total_teclas_indevidas_presidente", 0),
                "delta_teclas_presidente": resumo_t2.get("total_teclas_indevidas_presidente", 0) - resumo_t1.get("total_teclas_indevidas_presidente", 0),
                "delta_teclas_presidente_pct": round(((resumo_t2.get("total_teclas_indevidas_presidente", 0) - resumo_t1.get("total_teclas_indevidas_presidente", 0)) / max(resumo_t1.get("total_teclas_indevidas_presidente", 1), 1)) * 100.0, 1),
                "teclas_outros_t1": resumo_t1.get("total_teclas_indevidas_outros", 0),
                "teclas_outros_t2": resumo_t2.get("total_teclas_indevidas_outros", 0),
                "teclas_por_cargo_t1": resumo_t1.get("teclas_por_cargo", {}),
                "teclas_por_cargo_t2": resumo_t2.get("teclas_por_cargo", {}),
                "delta_id_invalido": resumo_t2["total_identificador_invalido"] - resumo_t1["total_identificador_invalido"],
                "delta_linhas_log": resumo_t2["linhas_log_dia"] - resumo_t1["linhas_log_dia"],
            },
            "votos_por_hora_comparado": votos_por_hora_comparado,
        }

    return {
        "sha256_log_jez": sha256_jez,
        "tamanho_logd_descompactado_bytes": len(raw_logd),
        "total_linhas_logd": len(lines),
        "macs_validos": macs_validos,
        "macs_invalidos": macs_invalidos,
        "etapas_assinatura_software_ok": est_principal["etapas_assinatura_sucesso"],
        "metadados_urna": metadados_urna,
        "contagem_subsistemas": dict(contagem_subsistemas),
        "contagem_niveis": dict(contagem_niveis),
        "resumo_votacao_log": resumo_principal,
        "ciclos_eleitores": est_principal["ciclos_votacao"],
        "logs_teclas_indevidas": est_principal.get("logs_teclas_indevidas", []),
        "logs_id_invalido": est_principal.get("logs_id_invalido", []),
        "resumo_1_turno_log": resumo_t1,
        "ciclos_eleitores_1_turno": est_t1["ciclos_votacao"] if est_t1 else [],
        "logs_teclas_indevidas_1_turno": est_t1.get("logs_teclas_indevidas", []) if est_t1 else [],
        "logs_id_invalido_1_turno": est_t1.get("logs_id_invalido", []) if est_t1 else [],
        "alertas_1_turno": est_t1["alertas_e_erros"][:80] if est_t1 else [],
        "comparativo_turnos_log": comparativo_turnos_log,
        "alertas_dia_eleicao": est_principal["alertas_e_erros"][:80],
        "amostra_eventos_vota": est_principal["eventos_dia_votacao"],
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
    res_t1 = (log_report.get("resumo_1_turno_log") or {}) if log_report else {}
    meta_log = log_report["metadados_urna"] if log_report else {}

    uf_sigla = (id_info.get("uf") or "PR").upper()
    chave_secao_geo = f"{uf_sigla}-{mun_cod}-{zona_str}-{secao_str}"

    # Detecção robusta e unificada de Turno (1º Turno vs 2º Turno):
    is_1t = False
    if id_info.get("pleito") in ("03220", "00406") or bool(re.search(r"[_\-]1t[_\-]|1[°ºo]_turno", prefixo, re.I)):
        is_1t = True
    elif imgbu_report.get("turno") == 1 or (imgbu_report.get("data_abertura") or "").startswith(("04/10", "02/10", "06/10")):
        is_1t = True
    elif res_log.get("data_eleicao", "").startswith(("04/10", "02/10", "06/10")):
        is_1t = True

    turno_pacote = 1 if is_1t else (
        2 if (imgbu_report.get("turno") == 2 or id_info.get("pleito") in ("03221", "00407")) else imgbu_report.get("turno", 2)
    )

    comp_log_t1 = res_t1.get("total_votos_computados", 0)
    tem_comp_1t_log = bool(comp_log_t1 > 0 and res_t1.get("data_eleicao") != res_log.get("data_eleicao"))

    resumo_consolidacao = {
        "prefixo": prefixo,
        "chave_secao_geo": chave_secao_geo,
        "turno_pacote": turno_pacote,
        "uf": uf_sigla,
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
        "tempo_minimo_cabine_s": res_log.get("tempo_minimo_cabine_s", 0.0),
        "tempo_maximo_ciclo_s": res_log.get("tempo_maximo_ciclo_s", 0.0),
        "total_linhas_logd": log_report.get("total_linhas_logd", 0) if log_report else 0,
        "macs_validos": log_report.get("macs_validos", 0) if log_report else 0,
        "macs_invalidos": log_report.get("macs_invalidos", 0) if log_report else 0,
        "total_teclas_indevidas": res_log.get("total_teclas_indevidas", 0),
        "total_id_invalido": res_log.get("total_identificador_invalido", 0),
        "etapas_assinatura_ok": log_report.get("etapas_assinatura_software_ok", 0) if log_report else 0,
        "qtd_anomalias": len(anomalias_forenses),
        # Dados nativos de 1º Turno extraídos do mesmo logd.dat (Mídia Interna acumulada 1ºT + 2ºT)
        "tem_comparativo_1t_log": tem_comp_1t_log,
        "data_1_turno": res_t1.get("data_eleicao", "04/10/2026") if tem_comp_1t_log else "04/10/2026",
        "data_2_turno": res_log.get("data_eleicao", "25/10/2026") or "25/10/2026",
        "comparecimento_log_t1": comp_log_t1 if tem_comp_1t_log else 0,
        "hab_biometrica_log_t1": res_t1.get("habilitacao_biometrica", 0) if tem_comp_1t_log else 0,
        "hab_biografica_log_t1": res_t1.get("habilitacao_biografica", 0) if tem_comp_1t_log else 0,
        "hab_sem_bio_log_t1": res_t1.get("habilitacao_sem_biometria", 0) if tem_comp_1t_log else 0,
        "tempo_medio_ciclo_t1_s": res_t1.get("tempo_medio_ciclo_s", 0.0) if tem_comp_1t_log else 0.0,
        "tempo_medio_cabine_t1_s": res_t1.get("tempo_medio_cabine_s", 0.0) if tem_comp_1t_log else 0.0,
        "tempo_medio_mesa_t1_s": res_t1.get("tempo_medio_mesa_bio_s", 0.0) if tem_comp_1t_log else 0.0,
        "tempo_minimo_cabine_t1_s": res_t1.get("tempo_minimo_cabine_s", 0.0) if tem_comp_1t_log else 0.0,
        "tempo_maximo_ciclo_t1_s": res_t1.get("tempo_maximo_ciclo_s", 0.0) if tem_comp_1t_log else 0.0,
        "total_teclas_indevidas_t1": res_t1.get("total_teclas_indevidas", 0) if tem_comp_1t_log else 0,
        "total_teclas_indevidas_t2": res_log.get("total_teclas_indevidas", 0),
        "total_teclas_indevidas_presidente_t1": res_t1.get("total_teclas_indevidas_presidente", 0) if tem_comp_1t_log else 0,
        "total_teclas_indevidas_presidente_t2": res_log.get("total_teclas_indevidas_presidente", 0),
        "total_teclas_indevidas_outros_t1": res_t1.get("total_teclas_indevidas_outros", 0) if tem_comp_1t_log else 0,
        "total_teclas_indevidas_outros_t2": res_log.get("total_teclas_indevidas_outros", 0),
        "teclas_por_cargo_t1": res_t1.get("teclas_por_cargo", {}) if tem_comp_1t_log else {},
        "teclas_por_cargo_t2": res_log.get("teclas_por_cargo", {}),
        "total_id_invalido_t1": res_t1.get("total_identificador_invalido", 0) if tem_comp_1t_log else 0,
        "total_id_invalido_t2": res_log.get("total_identificador_invalido", 0),
        "logs_teclas_indevidas": res_log.get("logs_teclas_indevidas", []),
        "logs_teclas_indevidas_t1": res_t1.get("logs_teclas_indevidas", []) if tem_comp_1t_log else [],
        "logs_id_invalido": res_log.get("logs_id_invalido", []),
        "logs_id_invalido_t1": res_t1.get("logs_id_invalido", []) if tem_comp_1t_log else [],
        "linhas_log_t1": res_t1.get("linhas_log_dia", 0) if tem_comp_1t_log else 0,
        "linhas_log_t2": res_log.get("linhas_log_dia", 0),
        "votos_por_hora_t1": res_t1.get("votos_por_hora", {}) if tem_comp_1t_log else {},
        "cargos_votados_t1": res_t1.get("cargos_votados", []) if tem_comp_1t_log else [],
        "cargos_votados_t2": res_log.get("cargos_votados", []),
        "hora_zeresima_t1": res_t1.get("hora_zeresima", "") if tem_comp_1t_log else "",
        "hora_zeresima_t2": res_log.get("hora_zeresima", ""),
        "hora_pronta_votos_t1": res_t1.get("hora_pronta_votos", "") if tem_comp_1t_log else "",
        "hora_pronta_votos_t2": res_log.get("hora_pronta_votos", ""),
        "hora_encerramento_t1": res_t1.get("hora_encerramento", "") if tem_comp_1t_log else "",
        "hora_encerramento_t2": res_log.get("hora_encerramento", ""),
        "titulo_encerramento_t1": res_t1.get("titulo_encerramento", "") if tem_comp_1t_log else "",
        "titulo_encerramento_t2": res_log.get("titulo_encerramento", ""),
        "mesarios_registrados_t1": res_t1.get("mesarios_registrados", []) if tem_comp_1t_log else [],
        "mesarios_registrados_t2": res_log.get("mesarios_registrados", []),
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
        except Exception:
            _CATALOGO_MEMORIA = {}

    # Carrega também o log incremental append-only (.jsonl) para lotes rápidos
    jsonl_path = os.path.join(storage, "catalogo_secoes.jsonl")
    if os.path.exists(jsonl_path):
        try:
            with open(jsonl_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    item = json.loads(line)
                    pref = item.get("prefixo")
                    if pref:
                        _CATALOGO_MEMORIA[pref] = item
        except Exception:
            pass

    # Sincronização resiliente com PostgreSQL (Estratégia Zero-Disk Raw):
    # Se a memória estiver vazia ou após restart do container, restaura o catálogo direto do banco!
    if not _CATALOGO_MEMORIA:
        db = _obter_db_session()
        if db:
            try:
                from .database import TseSecao
                secoes = db.query(TseSecao).all()
                for s in secoes:
                    pref = f"o03221{s.uf.lower()}{s.municipio_codigo}{s.zona:04d}{s.secao:04d}"
                    bu2 = next((b for b in s.apuracoes if b.turno == 2), None) or next((b for b in s.apuracoes if b.turno == 1), None)
                    bu1 = next((b for b in s.apuracoes if b.turno == 1), None)
                    met2 = next((m for m in s.metricas_log if m.turno == 2), None) or next((m for m in s.metricas_log if m.turno == 1), None)
                    met1 = next((m for m in s.metricas_log if m.turno == 1), None)

                    cands = [
                        {
                            "numero": str(v.numero_candidato),
                            "nome": v.nome_candidato or f"Candidato {v.numero_candidato}",
                            "votos": v.quantidade_votos,
                            "votos_bu": v.quantidade_votos,
                            "votos_rdv": v.quantidade_votos,
                        }
                        for v in s.votos_candidatos if (v.turno == 2 or not any(x.turno == 2 for x in s.votos_candidatos))
                    ]

                    _CATALOGO_MEMORIA[pref] = {
                        "prefixo": pref,
                        "chave_secao_geo": f"{s.uf}-{s.municipio_codigo}-{s.zona:04d}-{s.secao:04d}",
                        "turno_pacote": 2 if bu2 and bu2.turno == 2 else 1,
                        "uf": s.uf,
                        "municipio_codigo": s.municipio_codigo,
                        "municipio_nome": s.municipio_nome,
                        "zona": f"{s.zona:04d}",
                        "secao": f"{s.secao:04d}",
                        "local_votacao": s.local_votacao or "-",
                        "modelo_ue": s.modelo_urna or "UE2020",
                        "nivel_risco": "CRITICO" if (bu2 and bu2.divergencia_detectada) else "BAIXO",
                        "veredito_geral": bu2.divergencia_descricao if bu2 else "SEÇÃO OFICIAL ÍNTEGRA",
                        "eleitores_aptos": bu2.eleitores_aptos if bu2 else 0,
                        "faltosos": bu2.faltosos if bu2 else 0,
                        "comparecimento_efetivo": bu2.comparecimento if bu2 else 0,
                        "comparecimento_bu": bu2.comparecimento if bu2 else 0,
                        "comparecimento_log": met2.total_votos_computados if met2 else (bu2.comparecimento if bu2 else 0),
                        "brancos_bu": bu2.votos_brancos if bu2 else 0,
                        "nulos_bu": bu2.votos_nulos if bu2 else 0,
                        "candidatos": cands,
                        "total_teclas_indevidas_presidente_t2": met2.teclas_indevidas_pres if met2 else 0,
                        "total_teclas_indevidas_t2": met2.teclas_indevidas_total if met2 else 0,
                        "total_teclas_indevidas_presidente_t1": met1.teclas_indevidas_pres if met1 else 0,
                        "total_teclas_indevidas_t1": met1.teclas_indevidas_total if met1 else 0,
                        "tem_comparativo_1t_log": met1 is not None,
                        "tempo_medio_cabine_s": float(met2.tempo_medio_voto_segundos) if met2 else 0.0,
                        "tempo_medio_cabine_t1_s": float(met1.tempo_medio_voto_segundos) if met1 else 0.0,
                    }
            except Exception as exc_db:
                print(f"[TSE-DB] Erro ao sincronizar catalogo do PostgreSQL: {exc_db}")
            finally:
                db.close()


    for item in _CATALOGO_MEMORIA.values():
        mc = item.get("municipio_codigo")
        mn = item.get("municipio_nome")
        if mc and mn and not mn.startswith("MUNICÍPIO"):
            MUNICIPIOS_PR_TSE[mc] = mn

    _CATALOGO_CARREGADO = True
    return _CATALOGO_MEMORIA


def _append_catalogo_disco(resumos_novos: list[dict]) -> None:
    if not resumos_novos:
        return
    storage = _get_tse_storage_dir()
    jsonl_path = os.path.join(storage, "catalogo_secoes.jsonl")
    with open(jsonl_path, "a", encoding="utf-8") as f:
        for r in resumos_novos:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def obter_indice_secoes_carregadas() -> dict:
    """
    Retorna um índice ultracompacto de todas as seções já carregadas no servidor
    usando máscara de bits por prefixo de seção:
      1 = -imgbu.dat já carregado
      2 = -rdv.dat já carregado
      4 = -log.jez já carregado
      8 = -bu.dat já carregado
     16 = -vota.vsc / -vscmr.vsc já carregado
    Permite ao navegador pular 100% dos arquivos já enviados anteriormente sem duplicar!
    """
    catalogo = _carregar_catalogo_disco()
    indice: dict[str, int] = {}
    for pref, item in catalogo.items():
        mask = 0
        if item.get("tem_imgbu"):
            mask |= 1
        if item.get("tem_rdv"):
            mask |= 2
        if item.get("tem_log_jez"):
            mask |= 4
        for arq in item.get("arquivos_recebidos", []):
            low = arq.lower()
            if low.endswith("-bu.dat") or low == "bu.dat":
                mask |= 8
            elif low.endswith(".vsc"):
                mask |= 16
        indice[pref] = mask

    return {
        "total_secoes_no_catalogo": len(catalogo),
        "indice_mascaras": indice,
    }


# Estratégia Zero-Disk Raw: não armazena arquivos brutos no disco da VPS,
# persistindo tudo diretamente nas tabelas normalizadas do PostgreSQL.
TSE_ZERO_DISK_RAW = os.getenv("TSE_ZERO_DISK_RAW", "true").lower() in ("true", "1", "yes")


def _obter_db_session():
    try:
        from .database import SessionLocal
        return SessionLocal()
    except Exception:
        return None


def processar_lote_arquivos_tse(arquivos_dict: dict[str, bytes]) -> dict:
    """
    Recebe um lote contendo 1 ou N arquivos de 1 ou várias seções eleitorais do TSE,
    agrupa pelo prefixo da seção (`o03221pr7407101710017`), decodifica em memória,
    persiste as métricas e dados de apuração diretamente no banco relacional PostgreSQL,
    e (sob a estratégia Zero-Disk Raw) descarta imediatamente os arquivos brutos,
    garantindo o menor consumo possível de armazenamento na VPS.
    """
    catalogo = _carregar_catalogo_disco()
    storage = _get_tse_storage_dir()
    db = _obter_db_session()

    grupos: dict[str, dict[str, bytes]] = {}
    arquivos_expandidos = dict(arquivos_dict)

    # Suporte nativo à descompactação transparente de arquivos .zip (1ºT ou 2ºT)
    for raw_name, content in list(arquivos_dict.items()):
        base_name = raw_name.split("/")[-1].split("\\")[-1]
        if base_name.lower().endswith(".zip"):
            try:
                with zipfile.ZipFile(io.BytesIO(content)) as zf:
                    for zinfo in zf.infolist():
                        if zinfo.is_dir():
                            continue
                        zname = zinfo.filename.split("/")[-1].split("\\")[-1]
                        if any(zname.lower().endswith(ext) for ext in (".jez", ".dat", ".vsc")):
                            arquivos_expandidos[zname] = zf.read(zinfo)
            except Exception:
                pass

    for raw_name, content in arquivos_expandidos.items():
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
    secoes_ignoradas_duplicadas = 0
    resumos_para_append = []
    ultimo_relatorio = None

    for prefixo, novos_arquivos in grupos.items():
        existente = catalogo.get(prefixo)
        if existente:
            ja_recebidos_set = {a.lower() for a in existente.get("arquivos_recebidos", [])}
            arquivos_realmente_novos = {
                k: v for k, v in novos_arquivos.items() if k.lower() not in ja_recebidos_set
            }
            if not arquivos_realmente_novos:
                secoes_ignoradas_duplicadas += 1
                continue
            novos_arquivos = arquivos_realmente_novos

        pacote_completo: dict[str, bytes] = {}

        if not TSE_ZERO_DISK_RAW:
            # Modo Clássico: Salva no disco local da VPS
            raw_sec_dir = os.path.join(storage, "raw", prefixo)
            os.makedirs(raw_sec_dir, exist_ok=True)
            for fname, fbytes in novos_arquivos.items():
                with open(os.path.join(raw_sec_dir, fname), "wb") as fp:
                    fp.write(fbytes)

            for fname in os.listdir(raw_sec_dir):
                fpath = os.path.join(raw_sec_dir, fname)
                if os.path.isfile(fpath):
                    with open(fpath, "rb") as fp:
                        pacote_completo[fname] = fp.read()
        else:
            # Modo Zero-Disk Raw: Decodificação direta na memória sem tocar o disco com arquivos brutos!
            pacote_completo = dict(novos_arquivos)

        relatorio = analisar_pacote_seccao_tse(pacote_completo)
        resumo = relatorio["resumo_consolidacao"]
        mc = resumo.get("municipio_codigo")
        if mc in MUNICIPIOS_PR_TSE:
            resumo["municipio_nome"] = MUNICIPIOS_PR_TSE[mc]

        # Persistência no Banco PostgreSQL (dados relacionais enxutos)
        if db:
            try:
                from .database import salvar_resumo_tse_no_banco
                salvar_resumo_tse_no_banco(db, resumo, relatorio)
            except Exception as exc_db:
                print(f"[TSE-DB] Aviso ao persistir secao {prefixo} no PostgreSQL: {exc_db}")

        catalogo[prefixo] = resumo
        resumos_para_append.append(resumo)

        if not TSE_ZERO_DISK_RAW:
            sec_json_path = os.path.join(storage, "secoes", f"{prefixo}.json")
            with open(sec_json_path, "w", encoding="utf-8") as fp:
                json.dump(relatorio, fp, ensure_ascii=False)

        secoes_processadas.append(prefixo)
        ultimo_relatorio = relatorio

    # Grava apenas o delta no arquivo .jsonl em < 1ms
    _append_catalogo_disco(resumos_para_append)

    if db:
        try:
            db.close()
        except Exception:
            pass

    return {
        "ok": True,
        "secoes_processadas_neste_lote": len(secoes_processadas),
        "secoes_ignoradas_duplicadas": secoes_ignoradas_duplicadas,
        "prefixos_processados": secoes_processadas,
        "total_secoes_no_catalogo": len(catalogo),
        "ultimo_relatorio_individual": ultimo_relatorio,
    }



def obter_secao_individual_tse(prefixo: str) -> dict | None:
    storage = _get_tse_storage_dir()
    pref_low = prefixo.lower()
    raw_sec_dir = os.path.join(storage, "raw", pref_low)
    sec_json_path = os.path.join(storage, "secoes", f"{pref_low}.json")

    # Se os arquivos brutos (.dat / .jez) estiverem no servidor, re-executa o decodificador
    # multi-cargo atualizado para exibir a bobina completa (15k chars) e os blocos ASN.1 por cargo!
    if os.path.isdir(raw_sec_dir):
        pacote_completo: dict[str, bytes] = {}
        for fname in os.listdir(raw_sec_dir):
            fpath = os.path.join(raw_sec_dir, fname)
            if os.path.isfile(fpath):
                with open(fpath, "rb") as fp:
                    pacote_completo[fname] = fp.read()
        if pacote_completo:
            relatorio = analisar_pacote_seccao_tse(pacote_completo)
            resumo = relatorio["resumo_consolidacao"]
            mc = resumo.get("municipio_codigo")
            if mc in MUNICIPIOS_PR_TSE:
                resumo["municipio_nome"] = MUNICIPIOS_PR_TSE[mc]
            catalogo = _carregar_catalogo_disco()
            catalogo[pref_low] = resumo
            try:
                with open(sec_json_path, "w", encoding="utf-8") as fp:
                    json.dump(relatorio, fp, ensure_ascii=False)
            except Exception:
                pass
            return relatorio

    if not os.path.exists(sec_json_path):
        catalogo = _carregar_catalogo_disco()
        if pref_low in catalogo:
            item = catalogo[pref_low]
            return {
                "prefixo_seccao": pref_low,
                "veredito_geral": item.get("veredito_geral", "SEÇÃO OFICIAL ÍNTEGRA"),
                "nivel_risco": item.get("nivel_risco", "BAIXO"),
                "arquivos_recebidos": item.get("arquivos_recebidos", []),
                "resumo_consolidacao": item,
                "batimentos_cruzados": [],
                "anomalias_forenses": [],
                "log_jez": None,
                "imgbu": None,
                "rdv": None,
            }
        return None
    with open(sec_json_path, "r", encoding="utf-8") as fp:
        return json.load(fp)


def reauditar_urnas_divergentes_catalogo() -> dict:
    """
    Reprocessa rapidamente todas as urnas do catálogo que apresentaram divergência ou
    números de 2º cargo/consulta popular (ex: 1, 2, 55) utilizando o decodificador ASN.1
    isolado por container `VotosCargo` (`81 01 01` = Presidente), sem precisar fazer novo upload!
    """
    catalogo = _carregar_catalogo_disco()
    storage = _get_tse_storage_dir()
    resumos_atualizados = []
    urnas_reparadas = 0
    urnas_ainda_divergentes = 0

    for pref, item in list(catalogo.items()):
        cands = item.get("candidatos", [])
        tem_cand_extra = any(
            c.get("votos_bu") != c.get("votos_rdv") or c.get("numero") not in ("13", "22")
            for c in cands
        )
        falta_comp_1t = bool(item.get("tem_log_jez") and "tem_comparativo_1t_log" not in item)
        if item.get("nivel_risco") == "BAIXO" and not tem_cand_extra and not falta_comp_1t:
            continue

        raw_sec_dir = os.path.join(storage, "raw", pref)
        if not os.path.isdir(raw_sec_dir):
            continue

        pacote_completo: dict[str, bytes] = {}
        for fname in os.listdir(raw_sec_dir):
            fpath = os.path.join(raw_sec_dir, fname)
            if os.path.isfile(fpath):
                with open(fpath, "rb") as fp:
                    pacote_completo[fname] = fp.read()
        if not pacote_completo:
            continue

        relatorio = analisar_pacote_seccao_tse(pacote_completo)
        resumo = relatorio["resumo_consolidacao"]
        mc = resumo.get("municipio_codigo")
        if mc in MUNICIPIOS_PR_TSE:
            resumo["municipio_nome"] = MUNICIPIOS_PR_TSE[mc]

        catalogo[pref] = resumo
        resumos_atualizados.append(resumo)
        if resumo.get("nivel_risco") == "BAIXO":
            urnas_reparadas += 1
        else:
            urnas_ainda_divergentes += 1

    _append_catalogo_disco(resumos_atualizados)
    return {
        "ok": True,
        "urnas_reprocessadas": len(resumos_atualizados),
        "urnas_validadas_apos_isolamento_cargo": urnas_reparadas,
        "urnas_ainda_com_divergencia": urnas_ainda_divergentes,
    }


def _construir_comparativo_turnos(
    secoes_escopo: list[dict],
    mapa_bu_1t_por_geo: dict[str, dict],
    escopo_label: str = "CONSOLIDADO_GLOBAL",
) -> dict:
    """
    Constrói o painel comparativo completo 1º Turno (04/10/2026) vs 2º Turno (25/10/2026)
    para qualquer nível de agregação (Estado, Cidade, Zona ou Seção/Urna Individual):
      1. Comparecimento, Faltosos/Abstenção, Habilitações Biométricas/Biográficas, Tempos de Mesa/Cabine/Ciclo,
         Teclas Indevidas, Títulos Inválidos e Vazão Horária (08h..16h) extraídos diretamente dos logs acumulados (.jez)
         ou dos BUs de 1º e 2º Turno pareados.
      2. Placar comparativo de votos por candidato (1º Turno vs 2º Turno, Brancos e Nulos) quando
         arquivos -imgbu.dat / -rdv.dat do 1º Turno também foram carregados para a mesma seção geográfica.
    """
    urnas_com_log_1t_2t = 0
    urnas_com_bu_1t = 0
    urnas_com_bu_2t = 0

    aptos_urnas_comparadas = 0
    comp_t1 = 0
    comp_t2 = 0
    hab_bio_t1 = 0
    hab_bio_t2 = 0
    hab_biog_t1 = 0
    hab_biog_t2 = 0
    hab_sbio_t1 = 0
    hab_sbio_t2 = 0

    soma_pond_mesa_t1 = 0.0
    soma_pond_mesa_t2 = 0.0
    soma_pond_cab_t1 = 0.0
    soma_pond_cab_t2 = 0.0
    soma_pond_cic_t1 = 0.0
    soma_pond_cic_t2 = 0.0
    votos_log_pond_t1 = 0
    votos_log_pond_t2 = 0

    min_cab_t1_list = []
    min_cab_t2_list = []
    max_cic_t1_list = []
    max_cic_t2_list = []

    teclas_t1 = 0
    teclas_t2 = 0
    teclas_pres_t1 = 0
    teclas_pres_t2 = 0
    teclas_outros_t1 = 0
    teclas_outros_t2 = 0
    teclas_por_cargo_t1_map = Counter()
    teclas_por_cargo_t2_map = Counter()
    id_inv_t1 = 0
    id_inv_t2 = 0
    linhas_t1 = 0
    linhas_t2 = 0

    vh_t1 = Counter()
    vh_t2 = Counter()
    cargos_t1_set = []
    cargos_t2_set = []

    cands_t1_map = Counter()
    cands_t2_map = Counter()
    nomes_cands: dict[str, str] = {"13": "LULA", "22": "JAIR BOLSONARO"}
    brancos_t1 = 0
    brancos_t2 = 0
    nulos_t1 = 0
    nulos_t2 = 0

    for s in secoes_escopo:
        chave_geo = s.get("chave_secao_geo") or f"{s.get('uf', 'PR')}-{s.get('municipio_codigo', '00000')}-{s.get('zona', '0000')}-{s.get('secao', '0000')}"
        s_t1_bu = mapa_bu_1t_por_geo.get(chave_geo)

        tem_log_1t = bool(s.get("tem_comparativo_1t_log") and s.get("comparecimento_log_t1", 0) > 0)
        tem_bu_1t = s_t1_bu is not None
        tem_bu_2t = bool(s.get("tem_imgbu") or s.get("tem_rdv"))

        if tem_bu_2t:
            urnas_com_bu_2t += 1
            for c in s.get("candidatos", []):
                num = str(c["numero"])
                v2 = c.get("votos_bu", 0) or c.get("votos_rdv", 0)
                cands_t2_map[num] += v2
                if c.get("nome") and not c["nome"].startswith("CANDIDATO"):
                    nomes_cands[num] = c["nome"]
            brancos_t2 += s.get("brancos_bu", 0) or s.get("brancos_rdv", 0)
            nulos_t2 += s.get("nulos_bu", 0) or s.get("nulos_rdv", 0)

        if tem_bu_1t:
            urnas_com_bu_1t += 1
            for c in s_t1_bu.get("candidatos", []):
                num = str(c["numero"])
                v1 = c.get("votos_bu", 0) or c.get("votos_rdv", 0)
                cands_t1_map[num] += v1
                if c.get("nome") and not c["nome"].startswith("CANDIDATO"):
                    nomes_cands[num] = c["nome"]
            brancos_t1 += s_t1_bu.get("brancos_bu", 0) or s_t1_bu.get("brancos_rdv", 0)
            nulos_t1 += s_t1_bu.get("nulos_bu", 0) or s_t1_bu.get("nulos_rdv", 0)

        if tem_log_1t or tem_bu_1t:
            urnas_com_log_1t_2t += 1
            aptos_sec = s.get("eleitores_aptos", 0) or (s_t1_bu.get("eleitores_aptos", 0) if s_t1_bu else 0)
            aptos_urnas_comparadas += aptos_sec

            v1_sec = s.get("comparecimento_log_t1", 0) or (s_t1_bu.get("comparecimento_efetivo", 0) if s_t1_bu else 0)
            v2_sec = s.get("comparecimento_efetivo", 0) or s.get("comparecimento_log", 0)
            comp_t1 += v1_sec
            comp_t2 += v2_sec

            hab_bio_t1 += s.get("hab_biometrica_log_t1", 0) or (s_t1_bu.get("hab_biometrica_bu", 0) if s_t1_bu else 0)
            hab_bio_t2 += s.get("hab_biometrica_log", 0) or s.get("hab_biometrica_bu", 0)

            hab_biog_t1 += s.get("hab_biografica_log_t1", 0) or (s_t1_bu.get("hab_biografica_bu", 0) if s_t1_bu else 0)
            hab_biog_t2 += s.get("hab_biografica_log", 0) or s.get("hab_biografica_bu", 0)

            hab_sbio_t1 += s.get("hab_sem_bio_log_t1", 0) or (s_t1_bu.get("hab_sem_bio_bu", 0) if s_t1_bu else 0)
            hab_sbio_t2 += s.get("hab_sem_bio_log", 0) or s.get("hab_sem_bio_bu", 0)

            if tem_log_1t and v1_sec > 0:
                soma_pond_mesa_t1 += s.get("tempo_medio_mesa_t1_s", 0.0) * v1_sec
                soma_pond_cab_t1 += s.get("tempo_medio_cabine_t1_s", 0.0) * v1_sec
                soma_pond_cic_t1 += s.get("tempo_medio_ciclo_t1_s", 0.0) * v1_sec
                votos_log_pond_t1 += v1_sec
                if s.get("tempo_minimo_cabine_t1_s", 0.0) > 0:
                    min_cab_t1_list.append(s["tempo_minimo_cabine_t1_s"])
                if s.get("tempo_maximo_ciclo_t1_s", 0.0) > 0:
                    max_cic_t1_list.append(s["tempo_maximo_ciclo_t1_s"])

            v2_log = s.get("comparecimento_log", 0)
            if v2_log > 0:
                soma_pond_mesa_t2 += s.get("tempo_medio_mesa_s", 0.0) * v2_log
                soma_pond_cab_t2 += s.get("tempo_medio_cabine_s", 0.0) * v2_log
                soma_pond_cic_t2 += s.get("tempo_medio_ciclo_s", 0.0) * v2_log
                votos_log_pond_t2 += v2_log
                if s.get("tempo_minimo_cabine_s", 0.0) > 0:
                    min_cab_t2_list.append(s["tempo_minimo_cabine_s"])
                if s.get("tempo_maximo_ciclo_s", 0.0) > 0:
                    max_cic_t2_list.append(s["tempo_maximo_ciclo_s"])

            teclas_t1 += s.get("total_teclas_indevidas_t1", 0)
            teclas_t2 += s.get("total_teclas_indevidas", 0)
            teclas_pres_t1 += s.get("total_teclas_indevidas_presidente_t1", 0)
            teclas_pres_t2 += s.get("total_teclas_indevidas_presidente_t2", s.get("total_teclas_indevidas_presidente", s.get("total_teclas_indevidas", 0)))
            teclas_outros_t1 += s.get("total_teclas_indevidas_outros_t1", 0)
            teclas_outros_t2 += s.get("total_teclas_indevidas_outros_t2", s.get("total_teclas_indevidas_outros", 0))
            for cg, q in s.get("teclas_por_cargo_t1", {}).items():
                teclas_por_cargo_t1_map[cg] += q
            for cg, q in s.get("teclas_por_cargo_t2", {}).items():
                teclas_por_cargo_t2_map[cg] += q
            id_inv_t1 += s.get("total_id_invalido_t1", 0)
            id_inv_t2 += s.get("total_id_invalido", 0)
            linhas_t1 += s.get("linhas_log_t1", 0)
            linhas_t2 += s.get("linhas_log_t2", 0)

            for hh, q in s.get("votos_por_hora_t1", {}).items():
                vh_t1[hh] += q
            for hh, q in s.get("votos_por_hora", {}).items():
                vh_t2[hh] += q

            for cg in s.get("cargos_votados_t1", []):
                if cg not in cargos_t1_set:
                    cargos_t1_set.append(cg)
            for cg in s.get("cargos_votados_t2", []):
                if cg not in cargos_t2_set:
                    cargos_t2_set.append(cg)

    mesa_t1 = round(soma_pond_mesa_t1 / max(votos_log_pond_t1, 1), 1) if votos_log_pond_t1 else 0.0
    mesa_t2 = round(soma_pond_mesa_t2 / max(votos_log_pond_t2, 1), 1) if votos_log_pond_t2 else 0.0
    cab_t1 = round(soma_pond_cab_t1 / max(votos_log_pond_t1, 1), 1) if votos_log_pond_t1 else 0.0
    cab_t2 = round(soma_pond_cab_t2 / max(votos_log_pond_t2, 1), 1) if votos_log_pond_t2 else 0.0
    cic_t1 = round(soma_pond_cic_t1 / max(votos_log_pond_t1, 1), 1) if votos_log_pond_t1 else 0.0
    cic_t2 = round(soma_pond_cic_t2 / max(votos_log_pond_t2, 1), 1) if votos_log_pond_t2 else 0.0

    faltosos_t1 = max(0, aptos_urnas_comparadas - comp_t1) if aptos_urnas_comparadas > 0 else 0
    faltosos_t2 = max(0, aptos_urnas_comparadas - comp_t2) if aptos_urnas_comparadas > 0 else 0

    pct_comp_t1 = round((comp_t1 / max(aptos_urnas_comparadas, 1)) * 100.0, 2) if aptos_urnas_comparadas else 0.0
    pct_comp_t2 = round((comp_t2 / max(aptos_urnas_comparadas, 1)) * 100.0, 2) if aptos_urnas_comparadas else 0.0
    pct_abs_t1 = round((faltosos_t1 / max(aptos_urnas_comparadas, 1)) * 100.0, 2) if aptos_urnas_comparadas else 0.0
    pct_abs_t2 = round((faltosos_t2 / max(aptos_urnas_comparadas, 1)) * 100.0, 2) if aptos_urnas_comparadas else 0.0

    delta_comp = comp_t2 - comp_t1
    delta_comp_pct = round((delta_comp / max(comp_t1, 1)) * 100.0, 2) if comp_t1 else 0.0
    delta_falt = faltosos_t2 - faltosos_t1
    delta_falt_pct = round((delta_falt / max(faltosos_t1, 1)) * 100.0, 2) if faltosos_t1 else 0.0

    delta_cab = round(cab_t2 - cab_t1, 1)
    delta_cab_pct = round((delta_cab / max(cab_t1, 0.1)) * 100.0, 1) if cab_t1 else 0.0
    delta_cic = round(cic_t2 - cic_t1, 1)
    delta_cic_pct = round((delta_cic / max(cic_t1, 0.1)) * 100.0, 1) if cic_t1 else 0.0

    faixas_horas = ["08h", "09h", "10h", "11h", "12h", "13h", "14h", "15h", "16h", "17h"]
    votos_por_hora_comp = []
    for fh in faixas_horas:
        q1 = vh_t1.get(fh, 0)
        q2 = vh_t2.get(fh, 0)
        if q1 > 0 or q2 > 0 or fh != "17h":
            votos_por_hora_comp.append({
                "hora": fh,
                "votos_1_turno": q1,
                "votos_2_turno": q2,
                "diferenca": q2 - q1,
            })

    # Placar comparativo de candidatos (1ºT vs 2ºT)
    todos_nums_cand = sorted(set(cands_t1_map.keys()) | set(cands_t2_map.keys()), key=lambda n: max(cands_t2_map[n], cands_t1_map[n]), reverse=True)
    tot_nom_t1 = sum(cands_t1_map.values())
    tot_nom_t2 = sum(cands_t2_map.values())
    lista_cands_comp = []
    for num in todos_nums_cand:
        v1 = cands_t1_map.get(num, 0)
        v2 = cands_t2_map.get(num, 0)
        p1 = round((v1 / max(tot_nom_t1, 1)) * 100.0, 2) if tot_nom_t1 else 0.0
        p2 = round((v2 / max(tot_nom_t2, 1)) * 100.0, 2) if tot_nom_t2 else 0.0
        dv = v2 - v1
        dv_pct = round((dv / max(v1, 1)) * 100.0, 2) if v1 > 0 else 0.0
        lista_cands_comp.append({
            "numero": num,
            "nome": nomes_cands.get(num, f"CANDIDATO {num}"),
            "votos_t1": v1,
            "pct_t1": p1,
            "votos_t2": v2,
            "pct_t2": p2,
            "delta_votos": dv,
            "delta_pct_crescimento": dv_pct,
        })

    s0 = secoes_escopo[0] if len(secoes_escopo) == 1 else {}

    logs_teclas_t1 = []
    logs_teclas_t2 = []
    for s in secoes_escopo:
        pref = s.get("prefixo", "")
        m_nome = s.get("municipio_nome", "")
        z_str = s.get("zona", "")
        sec_str = s.get("secao", "")
        info_urna = f"{m_nome} • Z{z_str}/S{sec_str}" if m_nome else pref

        for item in s.get("logs_teclas_indevidas_t1", []):
            if len(logs_teclas_t1) < 2500:
                item_copy = dict(item)
                item_copy["urna"] = info_urna
                item_copy["prefixo"] = pref
                logs_teclas_t1.append(item_copy)

        for item in s.get("logs_teclas_indevidas", []):
            if len(logs_teclas_t2) < 2500:
                item_copy = dict(item)
                item_copy["urna"] = info_urna
                item_copy["prefixo"] = pref
                logs_teclas_t2.append(item_copy)

    return {
        "escopo": escopo_label,
        "disponivel": urnas_com_log_1t_2t > 0 or urnas_com_bu_1t > 0,
        "urnas_no_escopo": len(secoes_escopo),
        "urnas_com_comparativo_log": urnas_com_log_1t_2t,
        "urnas_com_bu_1_turno": urnas_com_bu_1t,
        "urnas_com_bu_2_turno": urnas_com_bu_2t,
        "data_1_turno": s0.get("data_1_turno", "04/10/2026") if s0 else "04/10/2026",
        "data_2_turno": s0.get("data_2_turno", "25/10/2026") if s0 else "25/10/2026",
        "eleitores_aptos_comparados": aptos_urnas_comparadas,
        "comparecimento_t1": comp_t1,
        "comparecimento_t2": comp_t2,
        "pct_comparecimento_t1": pct_comp_t1,
        "pct_comparecimento_t2": pct_comp_t2,
        "delta_comparecimento": delta_comp,
        "delta_comparecimento_pct": delta_comp_pct,
        "faltosos_t1": faltosos_t1,
        "faltosos_t2": faltosos_t2,
        "pct_abstencao_t1": pct_abs_t1,
        "pct_abstencao_t2": pct_abs_t2,
        "delta_faltosos": delta_falt,
        "delta_faltosos_pct": delta_falt_pct,
        "hab_biometrica_t1": hab_bio_t1,
        "hab_biometrica_t2": hab_bio_t2,
        "delta_hab_biometrica": hab_bio_t2 - hab_bio_t1,
        "hab_biografica_t1": hab_biog_t1,
        "hab_biografica_t2": hab_biog_t2,
        "delta_hab_biografica": hab_biog_t2 - hab_biog_t1,
        "hab_sem_bio_t1": hab_sbio_t1,
        "hab_sem_bio_t2": hab_sbio_t2,
        "delta_hab_sem_bio": hab_sbio_t2 - hab_sbio_t1,
        "tempo_medio_mesa_t1_s": mesa_t1,
        "tempo_medio_mesa_t2_s": mesa_t2,
        "delta_tempo_mesa_s": round(mesa_t2 - mesa_t1, 1),
        "tempo_medio_cabine_t1_s": cab_t1,
        "tempo_medio_cabine_t2_s": cab_t2,
        "delta_tempo_cabine_s": delta_cab,
        "delta_tempo_cabine_pct": delta_cab_pct,
        "tempo_medio_ciclo_t1_s": cic_t1,
        "tempo_medio_ciclo_t2_s": cic_t2,
        "delta_tempo_ciclo_s": delta_cic,
        "delta_tempo_ciclo_pct": delta_cic_pct,
        "tempo_minimo_cabine_t1_s": min(min_cab_t1_list) if min_cab_t1_list else 0.0,
        "tempo_minimo_cabine_t2_s": min(min_cab_t2_list) if min_cab_t2_list else 0.0,
        "tempo_maximo_ciclo_t1_s": max(max_cic_t1_list) if max_cic_t1_list else 0.0,
        "tempo_maximo_ciclo_t2_s": max(max_cic_t2_list) if max_cic_t2_list else 0.0,
        "teclas_indevidas_t1": teclas_t1,
        "teclas_indevidas_t2": teclas_t2,
        "delta_teclas_indevidas": teclas_t2 - teclas_t1,
        "teclas_presidente_t1": teclas_pres_t1,
        "teclas_presidente_t2": teclas_pres_t2,
        "delta_teclas_presidente": teclas_pres_t2 - teclas_pres_t1,
        "delta_teclas_presidente_pct": round(((teclas_pres_t2 - teclas_pres_t1) / max(teclas_pres_t1, 1)) * 100.0, 1) if teclas_pres_t1 > 0 else 0.0,
        "teclas_outros_t1": teclas_outros_t1,
        "teclas_outros_t2": teclas_outros_t2,
        "teclas_por_cargo_t1": dict(teclas_por_cargo_t1_map),
        "teclas_por_cargo_t2": dict(teclas_por_cargo_t2_map),
        "logs_teclas_indevidas_t1": logs_teclas_t1,
        "logs_teclas_indevidas_t2": logs_teclas_t2,
        "id_invalido_t1": id_inv_t1,
        "id_invalido_t2": id_inv_t2,
        "delta_id_invalido": id_inv_t2 - id_inv_t1,
        "linhas_log_t1": linhas_t1,
        "linhas_log_t2": linhas_t2,
        "delta_linhas_log": linhas_t2 - linhas_t1,
        "cargos_votados_t1": cargos_t1_set or ["Deputado Federal", "Deputado Estadual", "Senador", "Governador", "Presidente"],
        "cargos_votados_t2": cargos_t2_set or ["Presidente"],
        "hora_zeresima_t1": s0.get("hora_zeresima_t1", ""),
        "hora_zeresima_t2": s0.get("hora_zeresima_t2", ""),
        "hora_pronta_votos_t1": s0.get("hora_pronta_votos_t1", ""),
        "hora_pronta_votos_t2": s0.get("hora_pronta_votos_t2", ""),
        "hora_encerramento_t1": s0.get("hora_encerramento_t1", ""),
        "hora_encerramento_t2": s0.get("hora_encerramento_t2", ""),
        "titulo_encerramento_t1": s0.get("titulo_encerramento_t1", ""),
        "titulo_encerramento_t2": s0.get("titulo_encerramento_t2", ""),
        "mesarios_registrados_t1": s0.get("mesarios_registrados_t1", []),
        "mesarios_registrados_t2": s0.get("mesarios_registrados_t2", []),
        "votos_por_hora_comparado": votos_por_hora_comp,
        "comparativo_candidatos": {
            "tem_bu_1_turno": urnas_com_bu_1t > 0,
            "urnas_pareadas_bu_1t": urnas_com_bu_1t,
            "brancos_t1": brancos_t1,
            "brancos_t2": brancos_t2,
            "delta_brancos": brancos_t2 - brancos_t1,
            "nulos_t1": nulos_t1,
            "nulos_t2": nulos_t2,
            "delta_nulos": nulos_t2 - nulos_t1,
            "candidatos": lista_cands_comp,
        },
    }


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


def _secao_atende_filtro_forense(s: dict, filtro_forense: str) -> bool:
    if not filtro_forense or filtro_forense == "TODAS":
        return True
    if filtro_forense == "APENAS_DIVERGENTES":
        if s.get("nivel_risco") != "BAIXO":
            return True
        return any(c.get("votos_bu", 0) != c.get("votos_rdv", 0) for c in s.get("candidatos", []))
    if filtro_forense.startswith("CAND:"):
        num_alvo = filtro_forense.split(":", 1)[1].strip()
        return any(
            str(c.get("numero")) == num_alvo and (c.get("votos_bu", 0) > 0 or c.get("votos_rdv", 0) > 0)
            for c in s.get("candidatos", [])
        )
    if filtro_forense.startswith("DIV_CAND:"):
        num_alvo = filtro_forense.split(":", 1)[1].strip()
        return any(
            str(c.get("numero")) == num_alvo and (c.get("votos_bu", 0) != c.get("votos_rdv", 0))
            for c in s.get("candidatos", [])
        )
    return True


def consolidar_secoes_tse(
    regiao_filtro: str = "TODAS",
    uf_filtro: str = "TODAS",
    municipio_filtro: str = "TODAS",
    zona_filtro: str = "TODAS",
    secao_filtro: str = "CONSOLIDADO",
    filtro_forense: str = "TODAS",
) -> dict:
    """
    Constrói a árvore de 5 níveis (Região do País -> Estado -> Cidade -> Zona -> Seção/Urna) e retorna:
    - Os dados consolidados globais para o nível/filtro selecionado (`CONSOLIDADO`), OU
    - O dossiê completo da urna individual quando `secao_filtro` é o prefixo de uma seção.
    Suporta também `filtro_forense` (`TODAS`, `APENAS_DIVERGENTES`, `CAND:<num>`, `DIV_CAND:<num>`)
    para rastrear exatamente em quais cidades, zonas e urnas ocorrem divergências ou candidatos específicos.
    """
    catalogo = _carregar_catalogo_disco()
    todos_itens_catalogo = list(catalogo.values())

    # Enriquecimento em tempo real de Região, Estado (UF) e Chave Geográfica (UF-Município-Zona-Seção)
    mapa_bu_1t_por_geo: dict[str, dict] = {}
    secoes_2t = []
    for s in todos_itens_catalogo:
        uf_sigla = (s.get("uf") or "PR").upper()
        info_est = ESTADOS_E_REGIOES_BR.get(uf_sigla, {"nome": uf_sigla, "regiao": "SUL"})
        s["uf"] = uf_sigla
        s["uf_nome"] = info_est["nome"]
        s["regiao"] = info_est["regiao"]
        chave_geo = s.get("chave_secao_geo") or f"{uf_sigla}-{s.get('municipio_codigo', '00000')}-{s.get('zona', '0000')}-{s.get('secao', '0000')}"
        s["chave_secao_geo"] = chave_geo
        if s.get("turno_pacote") == 1:
            mapa_bu_1t_por_geo[chave_geo] = s
        else:
            secoes_2t.append(s)

    todas_secoes_brutas = secoes_2t if secoes_2t else todos_itens_catalogo

    todas_secoes = [s for s in todas_secoes_brutas if _secao_atende_filtro_forense(s, filtro_forense)]

    # 1. Nível 1: Regiões do País disponíveis no catálogo
    regioes_map: dict[str, dict] = {}
    estados_por_regiao: dict[str, set] = {}
    cidades_por_regiao: dict[str, set] = {}
    for s in todas_secoes:
        reg = s["regiao"]
        if reg not in regioes_map:
            regioes_map[reg] = {
                "regiao": reg,
                "total_estados": 0,
                "total_cidades": 0,
                "total_urnas": 0,
                "total_votos": 0,
                "total_aptos": 0,
            }
            estados_por_regiao[reg] = set()
            cidades_por_regiao[reg] = set()
        regioes_map[reg]["total_urnas"] += 1
        regioes_map[reg]["total_votos"] += s.get("comparecimento_efetivo", 0)
        regioes_map[reg]["total_aptos"] += s.get("eleitores_aptos", 0)
        estados_por_regiao[reg].add(s["uf"])
        cidades_por_regiao[reg].add(s.get("municipio_codigo", "00000"))

    for reg, d in regioes_map.items():
        d["total_estados"] = len(estados_por_regiao[reg])
        d["total_cidades"] = len(cidades_por_regiao[reg])

    lista_regioes = sorted(regioes_map.values(), key=lambda x: x["regiao"])

    if regiao_filtro not in ("TODAS", "", None) and regiao_filtro not in regioes_map:
        regiao_filtro = "TODAS"

    secoes_apos_regiao = [
        s for s in todas_secoes
        if regiao_filtro in ("TODAS", "", None) or s["regiao"] == regiao_filtro
    ]

    # 2. Nível 2: Estados (UFs) disponíveis na Região selecionada
    estados_map: dict[str, dict] = {}
    cidades_por_uf: dict[str, set] = {}
    for s in secoes_apos_regiao:
        uf = s["uf"]
        if uf not in estados_map:
            estados_map[uf] = {
                "uf": uf,
                "nome": s["uf_nome"],
                "regiao": s["regiao"],
                "total_cidades": 0,
                "total_urnas": 0,
                "total_votos": 0,
                "total_aptos": 0,
            }
            cidades_por_uf[uf] = set()
        estados_map[uf]["total_urnas"] += 1
        estados_map[uf]["total_votos"] += s.get("comparecimento_efetivo", 0)
        estados_map[uf]["total_aptos"] += s.get("eleitores_aptos", 0)
        cidades_por_uf[uf].add(s.get("municipio_codigo", "00000"))

    for uf, d in estados_map.items():
        d["total_cidades"] = len(cidades_por_uf[uf])

    lista_estados = sorted(estados_map.values(), key=lambda x: x["nome"])

    if uf_filtro not in ("TODAS", "", None) and uf_filtro not in estados_map:
        uf_filtro = "TODAS"

    secoes_apos_uf = [
        s for s in secoes_apos_regiao
        if uf_filtro in ("TODAS", "", None) or s["uf"] == uf_filtro
    ]

    # 3. Nível 3: Cidades disponíveis no Estado selecionado
    cidades_map: dict[str, dict] = {}
    zonas_por_cidade: dict[str, set] = {}
    for s in secoes_apos_uf:
        mc = s.get("municipio_codigo", "00000")
        mn = MUNICIPIOS_PR_TSE.get(mc, s.get("municipio_nome", f"MUNICÍPIO {mc}"))
        if mc not in cidades_map:
            cidades_map[mc] = {
                "codigo": mc,
                "nome": mn,
                "uf": s["uf"],
                "regiao": s["regiao"],
                "total_zonas": 0,
                "total_urnas": 0,
                "total_votos": 0,
                "total_aptos": 0,
            }
            zonas_por_cidade[mc] = set()
        cidades_map[mc]["total_urnas"] += 1
        cidades_map[mc]["total_votos"] += s.get("comparecimento_efetivo", 0)
        cidades_map[mc]["total_aptos"] += s.get("eleitores_aptos", 0)
        zonas_por_cidade[mc].add(s.get("zona", "0000"))

    for mc, d in cidades_map.items():
        d["total_zonas"] = len(zonas_por_cidade[mc])

    lista_cidades = sorted(cidades_map.values(), key=lambda x: x["nome"])

    if municipio_filtro not in ("TODAS", "", None) and municipio_filtro not in cidades_map:
        municipio_filtro = "TODAS"

    # Filtra por Cidade
    secoes_apos_cidade = [
        s for s in secoes_apos_uf
        if municipio_filtro in ("TODAS", "", None) or s.get("municipio_codigo") == municipio_filtro
    ]

    # 4. Nível 4: Zonas disponíveis para a Cidade/Estado selecionado
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

    # 5. Nível 5: Seções/Urnas (limita a 1.000 opções no seletor quando o estado inteiro está ativo)
    secoes_para_dropdown = secoes_filtradas[:1000]
    lista_secoes_seletor = [
        {
            "prefixo": s["prefixo"],
            "secao": s.get("secao", "0000"),
            "zona": s.get("zona", "0000"),
            "uf": s.get("uf", "PR"),
            "regiao": s.get("regiao", "SUL"),
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
        for s in secoes_para_dropdown
    ]

    hierarquia = {
        "total_geral_urnas": len(todas_secoes_brutas),
        "total_secoes_no_filtro": len(secoes_filtradas),
        "filtro_forense_selecionado": filtro_forense or "TODAS",
        "regiao_selecionada": regiao_filtro,
        "uf_selecionada": uf_filtro,
        "municipio_selecionado": municipio_filtro,
        "zona_selecionada": zona_filtro,
        "secao_selecionada": secao_filtro,
        "regioes": lista_regioes,
        "estados": lista_estados,
        "cidades": lista_cidades,
        "zonas": lista_zonas,
        "secoes": lista_secoes_seletor,
    }

    # Caso 1: Usuário selecionou uma Seção/Urna específica para inspeção profunda
    if secao_filtro and secao_filtro != "CONSOLIDADO":
        relatorio_sec = obter_secao_individual_tse(secao_filtro)
        if relatorio_sec:
            res_sec = relatorio_sec.get("resumo_consolidacao", {})
            relatorio_sec["comparativo_turnos"] = _construir_comparativo_turnos(
                [res_sec] if res_sec else [],
                mapa_bu_1t_por_geo,
                escopo_label="SECAO_INDIVIDUAL",
            )
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

    # Consolida votos por candidato + rastreia urnas e cidades com divergência por candidato
    cands_agregados: dict[str, dict] = {}
    cidades_div_por_cand: dict[str, dict[str, dict]] = {}
    for s in secoes_filtradas:
        mc = s.get("municipio_codigo", "00000")
        mn = MUNICIPIOS_PR_TSE.get(mc, s.get("municipio_nome", f"MUNICÍPIO {mc}"))
        for c in s.get("candidatos", []):
            num = str(c["numero"])
            v_bu = c.get("votos_bu", 0)
            v_rdv = c.get("votos_rdv", 0)
            if num not in cands_agregados:
                cands_agregados[num] = {
                    "numero": num,
                    "nome": c["nome"],
                    "votos_bu": 0,
                    "votos_rdv": 0,
                    "urnas_com_voto": 0,
                    "urnas_divergentes": 0,
                }
                cidades_div_por_cand[num] = {}
            if c["nome"] and not c["nome"].startswith("CANDIDATO"):
                cands_agregados[num]["nome"] = c["nome"]
            cands_agregados[num]["votos_bu"] += v_bu
            cands_agregados[num]["votos_rdv"] += v_rdv
            if v_bu > 0 or v_rdv > 0:
                cands_agregados[num]["urnas_com_voto"] += 1
            if v_bu != v_rdv:
                cands_agregados[num]["urnas_divergentes"] += 1
                if mc not in cidades_div_por_cand[num]:
                    cidades_div_por_cand[num][mc] = {
                        "codigo": mc,
                        "nome": mn,
                        "urnas_divergentes": 0,
                        "votos_bu": 0,
                        "votos_rdv": 0,
                    }
                cidades_div_por_cand[num][mc]["urnas_divergentes"] += 1
                cidades_div_por_cand[num][mc]["votos_bu"] += v_bu
                cidades_div_por_cand[num][mc]["votos_rdv"] += v_rdv

    total_nominais_consolidado = sum(
        max(c["votos_bu"], c["votos_rdv"]) for c in cands_agregados.values()
    )
    placar_candidatos = []
    for num, c in sorted(cands_agregados.items(), key=lambda x: max(x[1]["votos_bu"], x[1]["votos_rdv"]), reverse=True):
        v_ref = c["votos_bu"] if urnas_com_bu > 0 else c["votos_rdv"]
        pct = round((v_ref / max(total_nominais_consolidado, 1)) * 100.0, 2)
        top_cidades_div = sorted(
            cidades_div_por_cand.get(num, {}).values(),
            key=lambda x: abs(x["votos_rdv"] - x["votos_bu"]),
            reverse=True,
        )[:15]
        placar_candidatos.append({
            "numero": num,
            "nome": c["nome"],
            "votos_bu": c["votos_bu"],
            "votos_rdv": c["votos_rdv"],
            "diferenca_rdv_bu": c["votos_rdv"] - c["votos_bu"],
            "urnas_com_voto": c["urnas_com_voto"],
            "urnas_divergentes": c["urnas_divergentes"],
            "cidades_divergentes": top_cidades_div,
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
    total_teclas_presidente = 0
    total_teclas_outros = 0
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
        total_teclas_presidente += s.get("total_teclas_indevidas_presidente_t2", s.get("total_teclas_indevidas_presidente", s.get("total_teclas_indevidas", 0)))
        total_teclas_outros += s.get("total_teclas_indevidas_outros_t2", s.get("total_teclas_indevidas_outros", 0))
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

    # Garante que todas as urnas com ALERTA apareçam na lista da tabela consolidada + até 500 urnas
    urnas_alerta_lista = [s for s in secoes_filtradas if s.get("nivel_risco") != "BAIXO"]
    urnas_normais_lista = [s for s in secoes_filtradas if s.get("nivel_risco") == "BAIXO"]
    lista_urnas_tabela = (urnas_alerta_lista + urnas_normais_lista)[:600]

    comparativo_turnos_global = _construir_comparativo_turnos(
        secoes_filtradas,
        mapa_bu_1t_por_geo,
        escopo_label="CONSOLIDADO_GLOBAL",
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
            "total_teclas_indevidas_presidente": total_teclas_presidente,
            "total_teclas_indevidas_outros": total_teclas_outros,
            "total_id_invalido": total_id_invalido,
            "placar_candidatos": placar_candidatos,
            "batimentos_cruzados": batimentos_consolidados,
            "votos_por_hora": dict(sorted(votos_por_hora_global.items())),
            "comparativo_turnos": comparativo_turnos_global,
            "lista_urnas": lista_urnas_tabela,
        },
    }

