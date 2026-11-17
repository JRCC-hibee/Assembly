"""
Módulo Pericial: Auditor e Processador Forense de Logs de Preparação das Urnas (GEDAI-UE / TSE).

Decodifica arquivos `.jez` gerados pelo GEDAI-UE (tanto em pacotes `.zip` completos como
`log_gedai_1t_PR_041020261441.zip` quanto pastas abertas com múltiplos `.jez`):
  - Descompacta o envelope externo `.jez` -> arquivo interno `.jez` (`gedai-ue.log`) + `.vsc`.
  - Extrai metadados da estação conforme o layout oficial (`UF`, `PLEITO`, `NM_COMPUTADOR`, `SERIAL_TPM`, `SERIAL_INSTALACAO`).
  - Rastreia correspondências de seção e contingência (`municipio`, `zona`, `secao`, `codigo_carga`, `id_urna`, `midia_carga`).
  - Contabiliza geração de Mídias de Carga (MC), Mídias de Votação (MV), Mídias de Resultado (MR: VOTA/ADH/SA/RED/VPP/AVPart/STE/ATUE)
    bem como sobrescritas e apagamentos prévios.
  - Consolida todos os ERROs e ALERTAs críticos de integridade (ex: hash autoassinado incorreto de tabcorr.vsc,
    assinatura inválida de banco, falhas de gravação em Flash, usuários sem perfil).
  - Executa batimento cruzado automático no banco PostgreSQL contra `TseSecao`, `TseApuracaoBU` e `TseRelatorioOficialTse`.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import func, or_

from .database import (
    ESTADOS_E_REGIOES_BR,
    TseApuracaoBU,
    TseGedaiCorrespondencia,
    TseGedaiEstacao,
    TseGedaiLote,
    TseRelatorioOficialTse,
    TseSecao,
)

try:
    from .tse_reverse_analyzer import MUNICIPIOS_PR_TSE
except Exception:
    MUNICIPIOS_PR_TSE = {}


_RE_FILENAME_GEDAI = re.compile(
    r"gedai-ue-([a-z]{2})-(\d{5})-oficial-([A-Za-z0-9_]+)-([A-Fa-f0-9]+)-([A-Fa-f0-9]+)-log\.jez$",
    re.IGNORECASE,
)
_RE_CORRESP_SECAO = re.compile(
    r"^(Transmitida|Recebida)\s+(?:a\s+)?correspond[êe]ncia\s+de\s+se[çc][ãa]o:\s+"
    r"munic[íi]pio\s+(\d+),\s+zona\s+(\d+),\s+se[çc][ãa]o\s+(\d+),\s+carga\s+(\d+),\s+"
    r"id\s+urna\s+(\d+),\s+mc\s+([0-9A-Fa-f]+)",
    re.IGNORECASE,
)
_RE_CORRESP_CONTING = re.compile(
    r"^(Transmitida|Recebida)\s+(?:a\s+)?correspond[êe]ncia\s+de\s+conting[êe]ncia:\s+"
    r"munic[íi]pio\s+(\d+),\s+zona\s+(\d+),\s+carga\s+(\d+),\s+"
    r"id\s+urna\s+(\d+),\s+mc\s+([0-9A-Fa-f]+)",
    re.IGNORECASE,
)
_RE_MIDIA_CARGA = re.compile(
    r"^M[íi]dia\s+de\s+carga\s+gerada\.\s+NS:([0-9A-Fa-f]+)\s+Z:(\d+)\s*\|\s*Se[çc][õo]es\s+\(M:(\d+)\)\s*(.+)$",
    re.IGNORECASE,
)
_RE_MIDIA_VOT_NS = re.compile(r"^M[íi]dia\s+de\s+vota[çc][ãa]o\s+gerada\.\s+NS:([0-9A-Fa-f]+)", re.IGNORECASE)
_RE_MIDIA_ADH_NS = re.compile(r"^Gera[çc][ãa]o\s+de\s+m[íi]dia\s+de\s+resultado\s+do\s+ADH\s*\|\s*n[úu]mero\s+de\s+s[ée]rie:\s*([0-9A-Fa-f]+)", re.IGNORECASE)
_RE_ZONA_COMP = re.compile(r"Z[A-Z]{2}(\d{3})[A-Z]+\d+", re.IGNORECASE)
_RE_MAC_HEX = re.compile(r"^[0-9A-Fa-f]{16}$")

_CRITICAL_KEYWORDS = (
    "tabcorr",
    "hash",
    "assinatura",
    "inconsistente",
    "banco de dados",
    "correspondência válida",
    "correspondencia valida",
    "não está oficializado",
    "nao esta oficializado",
    "protegida contra gravação",
    "protegida contra gravacao",
    "perfil",
    "autenticação",
    "autenticacao",
)


def _decode_gedai_log(raw: bytes) -> str:
    """Decodifica gedai-ue.log preservando acentuação (UTF-8 estrito ou fallback CP1252/Latin1)."""
    try:
        return raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return raw.decode("cp1252", errors="replace")


def _inferir_turno_por_pleito(pleito: Optional[str], nome_origem: str = "") -> int:
    """Identifica o turno (1 ou 2) a partir do código de pleito oficial ou nome do arquivo."""
    p = str(pleito or "").strip().lstrip("o")
    if p in ("03221", "3221", "407", "409"):
        return 2
    if p in ("03220", "3220", "406", "408"):
        return 1
    up = (nome_origem or "").upper()
    if "_2T_" in up or "2T_" in up or "T2" in up or "03221" in up:
        return 2
    return 1


def _extrair_inner_log_de_jez(raw_jez: bytes) -> tuple[str, dict[str, Any]]:
    """Extrai o conteúdo textual de gedai-ue.log de dentro do envelope duplo .jez + status .vsc."""
    meta = {"possui_vsc": False, "nome_interno_log": ""}
    if not raw_jez:
        return "", meta

    try:
        with zipfile.ZipFile(io.BytesIO(raw_jez)) as zf_outer:
            names_outer = zf_outer.namelist()
            meta["possui_vsc"] = any(n.lower().endswith(".vsc") for n in names_outer)

            # Caso 1: gedai-ue.log direto
            for n in names_outer:
                if n.lower().endswith(".log") or n.lower().endswith("logd.dat"):
                    meta["nome_interno_log"] = n
                    return _decode_gedai_log(zf_outer.read(n)), meta

            # Caso 2: envelope duplo (.jez interno contendo gedai-ue.log)
            for n in names_outer:
                if n.lower().endswith(".jez"):
                    inner_bytes = zf_outer.read(n)
                    try:
                        with zipfile.ZipFile(io.BytesIO(inner_bytes)) as zf_inner:
                            for iname in zf_inner.namelist():
                                if iname.lower().endswith(".log") or iname.lower().endswith("logd.dat"):
                                    meta["nome_interno_log"] = iname
                                    return _decode_gedai_log(zf_inner.read(iname)), meta
                    except zipfile.BadZipFile:
                        pass
    except zipfile.BadZipFile:
        # Fallback caso o próprio arquivo já seja texto de log
        if b"\tINFO\t" in raw_jez[:4096] or b"\tERRO\t" in raw_jez[:4096]:
            return _decode_gedai_log(raw_jez), meta

    return "", meta


def _parse_single_station_log(nome_arquivo: str, raw_jez: bytes) -> Optional[dict[str, Any]]:
    """Faz o parsing completo de uma estação GEDAI-UE (-log.jez)."""
    texto_log, inner_meta = _extrair_inner_log_de_jez(raw_jez)
    if not texto_log:
        return None

    base_fn = os.path.basename(nome_arquivo)
    m_fn = _RE_FILENAME_GEDAI.search(base_fn)
    uf = m_fn.group(1).upper() if m_fn else ""
    pleito = m_fn.group(2) if m_fn else ""
    computador = m_fn.group(3).upper() if m_fn else ""
    serial_tpm = m_fn.group(4).upper() if m_fn else ""
    serial_inst = m_fn.group(5).upper() if m_fn else ""

    m_zcomp = _RE_ZONA_COMP.match(computador) if computador else None
    zona_comp = int(m_zcomp.group(1)) if m_zcomp else None

    versao_gedai = ""
    usuarios_win: list[str] = []
    usuarios_odin: list[str] = []
    win_set: set[str] = set()
    odin_set: set[str] = set()
    operador_atual = ""

    primeira_dt = ""
    ultima_dt = ""
    total_linhas = 0
    mac_invalidos = 0

    corresp_secao_map: dict[tuple, dict[str, Any]] = {}
    corresp_conting_map: dict[tuple, dict[str, Any]] = {}
    corresp_secao_qtd_raw = 0
    corresp_conting_qtd_raw = 0

    midias_carga_lista: list[dict[str, Any]] = []
    mv_count = 0
    mr_count = 0
    sobrescritas_qtd = 0
    apagamentos_qtd = 0
    erros_list: list[dict[str, Any]] = []
    alertas_list: list[dict[str, Any]] = []
    eventos_criticos: list[dict[str, Any]] = []

    for ln in texto_log.splitlines():
        if not ln.strip():
            continue
        total_linhas += 1
        parts = ln.split("\t")
        if len(parts) < 3:
            continue

        dt_str = parts[0].strip()
        lvl = parts[1].strip().upper()
        msg = parts[2].strip()
        mac = parts[3].strip() if len(parts) >= 4 else ""

        if mac and not _RE_MAC_HEX.match(mac):
            mac_invalidos += 1

        if not primeira_dt:
            primeira_dt = dt_str
        ultima_dt = dt_str

        # Metadados de cabeçalho / sessão
        if msg.startswith("Abertura do GEDAI-UE -"):
            if not versao_gedai:
                versao_gedai = msg.replace("Abertura do GEDAI-UE -", "").strip()
            continue

        if msg.startswith("Computador:") and not computador:
            m_c = re.search(r"Computador:\s*([A-Za-z0-9_]+)", msg)
            if m_c:
                computador = m_c.group(1).upper()
                mz = _RE_ZONA_COMP.match(computador)
                zona_comp = int(mz.group(1)) if mz else zona_comp
            continue

        if msg.startswith("UF do computador:") and not uf:
            uf = msg.split(":", 1)[1].strip()[:2].upper()
            continue

        if msg.startswith("Pleito corrente:") and not pleito:
            m_p = re.search(r"(\d{5})", msg)
            if m_p:
                pleito = m_p.group(1)
            continue

        if msg.startswith("Usuário Windows:"):
            u_w = msg.split(":", 1)[1].strip()
            if u_w and u_w not in win_set:
                win_set.add(u_w)
                usuarios_win.append(u_w)
            if not operador_atual:
                operador_atual = u_w
            continue

        if msg.startswith("Usuário Odin:"):
            u_o = msg.replace("Usuário Odin:", "").strip()
            operador_atual = u_o.split("|")[0].strip()
            if u_o and u_o not in odin_set:
                odin_set.add(u_o)
                usuarios_odin.append(u_o)
            continue

        if lvl == "ERRO":
            erros_list.append({"data_hora": dt_str, "nivel": "ERRO", "mensagem": msg})
            msg_low = msg.lower()
            if len(eventos_criticos) < 80 or any(kw in msg_low for kw in _CRITICAL_KEYWORDS):
                eventos_criticos.append({"data_hora": dt_str, "nivel": "ERRO", "mensagem": msg})
            continue

        if lvl == "ALERTA":
            alertas_list.append({"data_hora": dt_str, "nivel": "ALERTA", "mensagem": msg})
            if len(eventos_criticos) < 80 or any(kw in msg.lower() for kw in _CRITICAL_KEYWORDS):
                eventos_criticos.append({"data_hora": dt_str, "nivel": "ALERTA", "mensagem": msg})
            continue

        # Correspondências de Seção Normal
        m_cs = _RE_CORRESP_SECAO.match(msg)
        if m_cs:
            acao_raw, mun_cod, z_str, sec_str, carga_cod, id_urna, mc_hex = m_cs.groups()
            corresp_secao_qtd_raw += 1
            acao = acao_raw.upper()
            mun_norm = str(int(mun_cod)).zfill(5) if mun_cod.isdigit() else mun_cod
            z_int = int(z_str)
            sec_int = int(sec_str)
            key = ("SECAO", acao, mun_norm, z_int, sec_int, carga_cod, id_urna, mc_hex.upper())
            corresp_secao_map[key] = {
                "computador": computador,
                "tipo": "SECAO",
                "acao": acao,
                "municipio_codigo": mun_norm,
                "zona": z_int,
                "secao": sec_int,
                "codigo_carga": carga_cod,
                "id_urna": id_urna,
                "midia_carga": mc_hex.upper(),
                "data_hora": dt_str,
                "operador": operador_atual,
            }
            continue

        # Correspondências de Contingência
        m_cc = _RE_CORRESP_CONTING.match(msg)
        if m_cc:
            acao_raw, mun_cod, z_str, carga_cod, id_urna, mc_hex = m_cc.groups()
            corresp_conting_qtd_raw += 1
            acao = acao_raw.upper()
            mun_norm = str(int(mun_cod)).zfill(5) if mun_cod.isdigit() else mun_cod
            z_int = int(z_str)
            key = ("CONTINGENCIA", acao, mun_norm, z_int, 0, carga_cod, id_urna, mc_hex.upper())
            corresp_conting_map[key] = {
                "computador": computador,
                "tipo": "CONTINGENCIA",
                "acao": acao,
                "municipio_codigo": mun_norm,
                "zona": z_int,
                "secao": 0,
                "codigo_carga": carga_cod,
                "id_urna": id_urna,
                "midia_carga": mc_hex.upper(),
                "data_hora": dt_str,
                "operador": operador_atual,
            }
            continue

        # Mídia de Carga (MC) com lista de seções
        m_mc = _RE_MIDIA_CARGA.match(msg)
        if m_mc:
            ns_mc, z_mc, m_mc_cod, secoes_raw = m_mc.groups()
            sec_list = [s.strip() for s in secoes_raw.strip().split() if s.strip().isdigit()]
            midias_carga_lista.append({
                "ns": ns_mc.upper(),
                "zona": int(z_mc),
                "municipio_codigo": str(int(m_mc_cod)).zfill(5) if m_mc_cod.isdigit() else m_mc_cod,
                "secoes": sec_list,
                "data_hora": dt_str,
                "operador": operador_atual,
            })
            continue

        # Mídias de Votação (MV) e Resultado (MR / ADH)
        if _RE_MIDIA_VOT_NS.match(msg):
            mv_count += 1
            continue

        if msg.startswith("Término da geração de mídias de resultado") or msg.startswith("Termino da geracao de midias de resultado") or _RE_MIDIA_ADH_NS.match(msg):
            mr_count += 1
            continue

        if msg.startswith("Sobrescrevendo mídia") or msg.startswith("Sobrescrevendo midia"):
            sobrescritas_qtd += 1
            if len(eventos_criticos) < 80:
                eventos_criticos.append({"data_hora": dt_str, "nivel": "SOBRESCRITA", "mensagem": msg})
            continue

        if msg.startswith("Apagando mídia") or msg.startswith("Apagando midia"):
            apagamentos_qtd += 1
            if len(eventos_criticos) < 80:
                eventos_criticos.append({"data_hora": dt_str, "nivel": "APAGAMENTO", "mensagem": msg})
            continue

    if not computador:
        computador = base_fn[:40]
    if not uf:
        uf = "PR"

    correspondencias = list(corresp_secao_map.values()) + list(corresp_conting_map.values())

    return {
        "nome_arquivo": base_fn,
        "computador": computador,
        "zona_computador": zona_comp,
        "serial_tpm": serial_tpm,
        "serial_instalacao": serial_inst,
        "uf": uf,
        "pleito": pleito,
        "turno": _inferir_turno_por_pleito(pleito, base_fn),
        "versao_gedai": versao_gedai,
        "possui_vsc": inner_meta.get("possui_vsc", False),
        "usuarios_windows": usuarios_win,
        "usuarios_odin": usuarios_odin,
        "primeira_data_hora": primeira_dt,
        "ultima_data_hora": ultima_dt,
        "total_linhas": total_linhas,
        "mac_invalidos": mac_invalidos,
        "corresp_secao_qtd": len(corresp_secao_map),
        "corresp_secao_raw": corresp_secao_qtd_raw,
        "corresp_contingencia_qtd": len(corresp_conting_map),
        "corresp_contingencia_raw": corresp_conting_qtd_raw,
        "midias_carga_qtd": len(midias_carga_lista),
        "midias_votacao_qtd": mv_count,
        "midias_resultado_qtd": mr_count,
        "sobrescritas_qtd": sobrescritas_qtd,
        "apagamentos_qtd": apagamentos_qtd,
        "erros": erros_list,
        "alertas": alertas_list,
        "eventos_criticos": eventos_criticos[:80],
        "midias_carga": midias_carga_lista,
        "correspondencias": correspondencias,
    }


def _normalizar_msg_agrupada(msg: str) -> str:
    """Agrupa mensagens similares de erro/alerta preservando assinatura sem poluir por timestamps/paths."""
    # Compacta quebras de linha e reduz prefixos C++ longos mantendo classe::metodo e descricao
    clean = msg.replace("\\n", " ").replace("\\r", " ").strip()
    m_desc = re.search(r"\)\s*(?:const)?:\d+:\d+\s*-\s*(.+)$", clean)
    if m_desc:
        return m_desc.group(1).strip()[:220]
    return clean[:220]


def _resolver_mapa_municipios(db, uf: str, mun_cods: set[str]) -> dict[str, str]:
    """Resolve código TSE -> Nome do Município consultando TseSecao e fallback PR."""
    mapa: dict[str, str] = {}
    for mc in mun_cods:
        if mc in MUNICIPIOS_PR_TSE:
            mapa[mc] = MUNICIPIOS_PR_TSE[mc]

    faltantes = [mc for mc in mun_cods if mc not in mapa and mc]
    if db is not None and faltantes:
        try:
            rows = (
                db.query(TseSecao.municipio_codigo, TseSecao.municipio_nome)
                .filter(TseSecao.uf == uf, TseSecao.municipio_codigo.in_(faltantes))
                .distinct()
                .all()
            )
            for cod, nome in rows:
                if cod and nome:
                    mapa[str(cod).zfill(5)] = nome
        except Exception as exc:
            print(f"[GEDAI] Aviso ao resolver municípios: {exc}")

    return mapa


def _analisar_anomalias_e_batimento(
    db,
    uf: str,
    turno: int,
    estacoes: list[dict[str, Any]],
    mun_nome_map: dict[str, str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """
    Executa inteligência forense sobre todas as estações e correspondências GEDAI:
      1. Seções preparadas com mais de 1 urna/carga diferente (repreparo / substituição).
      2. Urnas físicas (`id_urna`) gravadas em múltiplas seções diferentes.
      3. Zona da máquina (`ZPR001STD01`) divergente da Zona da correspondência gravada.
      4. Cruzamento contra `TseSecao` no PostgreSQL (cobertura das seções preparadas x apuradas)
         e contra contingências dos relatórios PDF SISTOT (`TseRelatorioOficialTse`).
    """
    sec_to_cargos: dict[tuple, dict[str, Any]] = {}
    urna_to_secs: dict[str, set[tuple]] = defaultdict(set)
    mc_unicas: set[str] = set()
    urnas_unicas: set[str] = set()
    contingencias_lista: list[dict[str, Any]] = []
    prep_cruzada_zona: list[dict[str, Any]] = []
    secoes_unicas_keys: set[tuple] = set()

    for est in estacoes:
        z_comp = est.get("zona_computador")
        for c in est.get("correspondencias", []):
            mc_cod = c["municipio_codigo"]
            mun_nome = mun_nome_map.get(mc_cod, f"MUNICÍPIO {mc_cod}")
            c["municipio_nome"] = mun_nome

            if c.get("midia_carga"):
                mc_unicas.add(c["midia_carga"])
            if c.get("id_urna"):
                urnas_unicas.add(c["id_urna"])

            if c["tipo"] == "SECAO":
                s_key = (mc_cod, c["zona"], c["secao"])
                secoes_unicas_keys.add(s_key)
                rec = sec_to_cargos.setdefault(s_key, {
                    "municipio_codigo": mc_cod,
                    "municipio_nome": mun_nome,
                    "zona": c["zona"],
                    "secao": c["secao"],
                    "combinacoes": set(),
                    "detalhes": [],
                })
                comb = (c["id_urna"], c["codigo_carga"])
                if comb not in rec["combinacoes"]:
                    rec["combinacoes"].add(comb)
                    rec["detalhes"].append({
                        "id_urna": c["id_urna"],
                        "codigo_carga": c["codigo_carga"],
                        "midia_carga": c["midia_carga"],
                        "computador": c["computador"],
                        "acao": c["acao"],
                        "data_hora": c["data_hora"],
                    })

                if c["id_urna"]:
                    urna_to_secs[c["id_urna"]].add((mc_cod, mun_nome, c["zona"], c["secao"], "SECAO"))

                if z_comp and c["zona"] != z_comp and len(prep_cruzada_zona) < 120:
                    prep_cruzada_zona.append({
                        "computador": c["computador"],
                        "zona_maquina": z_comp,
                        "municipio_nome": mun_nome,
                        "zona_secao": c["zona"],
                        "secao": c["secao"],
                        "id_urna": c["id_urna"],
                        "midia_carga": c["midia_carga"],
                    })
            else:
                if c["id_urna"]:
                    urna_to_secs[c["id_urna"]].add((mc_cod, mun_nome, c["zona"], 0, "CONTINGENCIA"))
                if len(contingencias_lista) < 500:
                    contingencias_lista.append({
                        "computador": c["computador"],
                        "municipio_codigo": mc_cod,
                        "municipio_nome": mun_nome,
                        "zona": c["zona"],
                        "codigo_carga": c["codigo_carga"],
                        "id_urna": c["id_urna"],
                        "midia_carga": c["midia_carga"],
                        "data_hora": c["data_hora"],
                    })

    secoes_multiplas_cargas = [
        {
            "municipio_codigo": r["municipio_codigo"],
            "municipio_nome": r["municipio_nome"],
            "zona": r["zona"],
            "secao": r["secao"],
            "qtd_combinacoes": len(r["combinacoes"]),
            "detalhes": r["detalhes"],
        }
        for r in sec_to_cargos.values()
        if len(r["combinacoes"]) > 1
    ]
    secoes_multiplas_cargas.sort(key=lambda x: (-x["qtd_combinacoes"], x["zona"], x["secao"]))

    urnas_multiplas_secoes = []
    for id_urna, occs in urna_to_secs.items():
        secs_distintas = {(m, z, s) for (m, _, z, s, t) in occs if t == "SECAO"}
        tem_cont = any(t == "CONTINGENCIA" for (*_, t) in occs)
        if len(secs_distintas) > 1 or (len(secs_distintas) >= 1 and tem_cont):
            urnas_multiplas_secoes.append({
                "id_urna": id_urna,
                "qtd_ocorrencias": len(occs),
                "ocorrencias": [
                    {"municipio_codigo": m, "municipio_nome": mn, "zona": z, "secao": s, "tipo": t}
                    for (m, mn, z, s, t) in sorted(occs)
                ],
            })
    urnas_multiplas_secoes.sort(key=lambda x: -x["qtd_ocorrencias"])

    mac_adulterados = sum(e.get("mac_invalidos", 0) for e in estacoes)

    anomalias = {
        "total_secoes_unicas": len(secoes_unicas_keys),
        "total_urnas_unicas": len(urnas_unicas),
        "total_midias_carga_unicas": len(mc_unicas),
        "mac_invalidos": mac_adulterados,
        "secoes_multiplas_cargas_qtd": len(secoes_multiplas_cargas),
        "secoes_multiplas_cargas": secoes_multiplas_cargas[:150],
        "urnas_multiplas_secoes_qtd": len(urnas_multiplas_secoes),
        "urnas_multiplas_secoes": urnas_multiplas_secoes[:150],
        "prep_cruzada_zona_qtd": len(prep_cruzada_zona),
        "prep_cruzada_zona": prep_cruzada_zona[:100],
        "contingencias_amostra": contingencias_lista[:150],
    }

    # Batimento contra o banco PostgreSQL (TseSecao + TseRelatorioOficialTse)
    batimento: dict[str, Any] = {
        "uf": uf,
        "turno": turno,
        "secoes_banco_uf": 0,
        "secoes_gedai_no_banco": 0,
        "secoes_gedai_ausentes_banco": 0,
        "amostra_ausentes_banco": [],
        "contingencias_sistot_cruzadas": 0,
        "contingencias_sistot_matches": [],
    }

    if db is not None:
        try:
            rows_db = (
                db.query(
                    TseSecao.municipio_codigo,
                    TseSecao.zona,
                    TseSecao.secao,
                )
                .join(TseApuracaoBU, TseApuracaoBU.secao_id == TseSecao.id)
                .filter(TseSecao.uf == uf, TseApuracaoBU.turno == turno)
                .all()
            )
            chaves_banco = {(str(m).zfill(5), int(z), int(s)) for (m, z, s) in rows_db}
            batimento["secoes_banco_uf"] = len(chaves_banco)

            if chaves_banco:
                presentes = secoes_unicas_keys & chaves_banco
                ausentes = sorted(secoes_unicas_keys - chaves_banco)
                batimento["secoes_gedai_no_banco"] = len(presentes)
                batimento["secoes_gedai_ausentes_banco"] = len(ausentes)
                batimento["cobertura_sobre_banco_pct"] = round(
                    (len(presentes) / max(len(chaves_banco), 1)) * 100.0, 2
                )
                batimento["amostra_ausentes_banco"] = [
                    {
                        "municipio_codigo": mc,
                        "municipio_nome": mun_nome_map.get(mc, f"MUNICÍPIO {mc}"),
                        "zona": z,
                        "secao": s,
                    }
                    for (mc, z, s) in ausentes[:100]
                ]

            # Cruza IDs de urnas/cargas preparados com Contingências oficiais dos PDFs SISTOT
            rels_pdf = (
                db.query(TseRelatorioOficialTse)
                .filter(TseRelatorioOficialTse.uf == uf, TseRelatorioOficialTse.turno == turno)
                .all()
            )
            cargas_gedai_map: dict[str, dict[str, Any]] = {}
            urnas_gedai_map: dict[str, dict[str, Any]] = {}
            for est in estacoes:
                for c in est.get("correspondencias", []):
                    if c.get("id_urna"):
                        urnas_gedai_map.setdefault(str(c["id_urna"]).lstrip("0") or c["id_urna"], c)
                    if c.get("codigo_carga"):
                        cargas_gedai_map.setdefault(str(c["codigo_carga"]).replace(".", ""), c)

            matches_sistot: list[dict[str, Any]] = []
            vistos_sistot: set[tuple] = set()
            for rel in rels_pdf:
                if not rel.contingencias_urnas_json:
                    continue
                try:
                    conts = json.loads(rel.contingencias_urnas_json)
                except Exception:
                    conts = []
                for ct in conts:
                    ue_id = str(ct.get("id_urna_efetivada") or "").strip().lstrip("0")
                    carga_ct = str(ct.get("id_carga") or "").replace(".", "").strip()
                    match_c = cargas_gedai_map.get(carga_ct) or urnas_gedai_map.get(ue_id)
                    if match_c:
                        mk = (ct.get("zona"), ct.get("secao"), ue_id)
                        if mk not in vistos_sistot:
                            vistos_sistot.add(mk)
                            matches_sistot.append({
                                "municipio": ct.get("municipio"),
                                "zona": ct.get("zona"),
                                "secao_efetivada": ct.get("secao"),
                                "id_urna_efetivada": ct.get("id_urna_efetivada"),
                                "id_carga_sistot": ct.get("id_carga"),
                                "computador_gedai": match_c.get("computador"),
                                "tipo_gedai": match_c.get("tipo"),
                                "midia_carga_gedai": match_c.get("midia_carga"),
                            })
            batimento["contingencias_sistot_cruzadas"] = len(matches_sistot)
            batimento["contingencias_sistot_matches"] = matches_sistot[:100]
        except Exception as exc_bat:
            print(f"[GEDAI] Aviso no batimento com PostgreSQL: {exc_bat}")

    return anomalias, batimento


def _compilar_lote_em_memoria(
    nome_origem: str,
    arquivos_jez: list[tuple[str, bytes]],
    db=None,
    tamanho_bytes: int = 0,
    hash_sha256: str = "",
) -> dict[str, Any]:
    """Processa uma coleção de pares `(nome_arquivo.jez, bytes)` e retorna estrutura completa do lote."""
    estacoes: list[dict[str, Any]] = []
    uf_counter: Counter = Counter()
    pleito_counter: Counter = Counter()
    erros_counter: Counter = Counter()
    alertas_counter: Counter = Counter()
    mun_cods: set[str] = set()

    for nome_arq, raw_bytes in arquivos_jez:
        est = _parse_single_station_log(nome_arq, raw_bytes)
        if not est:
            continue
        estacoes.append(est)
        if est.get("uf"):
            uf_counter[est["uf"]] += 1
        if est.get("pleito"):
            pleito_counter[est["pleito"]] += 1
        for err in est.get("erros", []):
            erros_counter[_normalizar_msg_agrupada(err["mensagem"])] += 1
        for al in est.get("alertas", []):
            alertas_counter[_normalizar_msg_agrupada(al["mensagem"])] += 1
        for c in est.get("correspondencias", []):
            if c.get("municipio_codigo"):
                mun_cods.add(c["municipio_codigo"])

    uf_principal = uf_counter.most_common(1)[0][0] if uf_counter else "PR"
    pleito_principal = pleito_counter.most_common(1)[0][0] if pleito_counter else "03220"
    turno_principal = _inferir_turno_por_pleito(pleito_principal, nome_origem)

    mun_nome_map = _resolver_mapa_municipios(db, uf_principal, mun_cods)
    anomalias, batimento = _analisar_anomalias_e_batimento(
        db=db,
        uf=uf_principal,
        turno=turno_principal,
        estacoes=estacoes,
        mun_nome_map=mun_nome_map,
    )

    resumo_erros = [{"mensagem": m, "ocorrencias": c} for m, c in erros_counter.most_common(60)]
    resumo_alertas = [{"mensagem": m, "ocorrencias": c} for m, c in alertas_counter.most_common(40)]

    return {
        "uf": uf_principal,
        "pleito": pleito_principal,
        "turno": turno_principal,
        "nome_origem": nome_origem,
        "tamanho_bytes": tamanho_bytes,
        "hash_sha256": hash_sha256,
        "total_estacoes": len(estacoes),
        "total_linhas": sum(e["total_linhas"] for e in estacoes),
        "total_corresp_secao": sum(e["corresp_secao_qtd"] for e in estacoes),
        "total_contingencias": sum(e["corresp_contingencia_qtd"] for e in estacoes),
        "total_secoes_unicas": anomalias["total_secoes_unicas"],
        "total_urnas_unicas": anomalias["total_urnas_unicas"],
        "total_midias_carga": sum(e["midias_carga_qtd"] for e in estacoes),
        "total_midias_votacao": sum(e["midias_votacao_qtd"] for e in estacoes),
        "total_midias_resultado": sum(e["midias_resultado_qtd"] for e in estacoes),
        "total_sobrescritas": sum(e["sobrescritas_qtd"] + e["apagamentos_qtd"] for e in estacoes),
        "total_erros": sum(len(e["erros"]) for e in estacoes),
        "total_alertas": sum(len(e["alertas"]) for e in estacoes),
        "resumo_erros": resumo_erros,
        "resumo_alertas": resumo_alertas,
        "anomalias": anomalias,
        "batimento": batimento,
        "estacoes": estacoes,
    }


def extrair_jez_de_zip_bytes(zip_bytes: bytes) -> list[tuple[str, bytes]]:
    """Extrai todos os arquivos .jez de um pacote .zip GEDAI-UE."""
    pares: list[tuple[str, bytes]] = []
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        for name in sorted(zf.namelist()):
            if name.lower().endswith("-log.jez") or name.lower().endswith(".jez"):
                pares.append((os.path.basename(name), zf.read(name)))
    return pares


def processar_pacote_gedai_para_banco(
    db,
    nome_origem: str,
    zip_bytes: Optional[bytes] = None,
    arquivos_individuais: Optional[list[tuple[str, bytes]]] = None,
) -> dict[str, Any]:
    """
    Decodifica um lote GEDAI-UE (via .zip ou lista de .jez enviados de pasta local)
    e grava no PostgreSQL (`TseGedaiLote`, `TseGedaiEstacao`, `TseGedaiCorrespondencia`).
    """
    pares_jez: list[tuple[str, bytes]] = []
    hasher = hashlib.sha256()
    tamanho_total = 0

    if zip_bytes:
        tamanho_total = len(zip_bytes)
        hasher.update(zip_bytes)
        pares_jez = extrair_jez_de_zip_bytes(zip_bytes)
    elif arquivos_individuais:
        for fn, raw in sorted(arquivos_individuais, key=lambda item: item[0]):
            if not raw:
                continue
            low = fn.lower()
            if low.endswith(".zip"):
                tamanho_total += len(raw)
                hasher.update(raw)
                pares_jez.extend(extrair_jez_de_zip_bytes(raw))
            elif low.endswith(".jez") or low.endswith(".log"):
                tamanho_total += len(raw)
                hasher.update(raw)
                pares_jez.append((os.path.basename(fn), raw))

    if not pares_jez:
        raise ValueError("Nenhum arquivo .jez de log do GEDAI-UE foi encontrado no envio.")

    compilado = _compilar_lote_em_memoria(
        nome_origem=os.path.basename(nome_origem) if nome_origem else "Lote GEDAI-UE",
        arquivos_jez=pares_jez,
        db=db,
        tamanho_bytes=tamanho_total,
        hash_sha256=hasher.hexdigest(),
    )
    if compilado["total_estacoes"] == 0:
        raise ValueError("Os arquivos .jez enviados não contêm registros válidos no formato gedai-ue.log.")

    # Evita duplicidade exata do mesmo arquivo/hash ou atualiza caso reprocessado
    lote_existente = (
        db.query(TseGedaiLote)
        .filter(TseGedaiLote.hash_sha256 == compilado["hash_sha256"])
        .first()
    )
    if lote_existente:
        db.delete(lote_existente)
        db.flush()

    lote_db = TseGedaiLote(
        uf=compilado["uf"],
        pleito=compilado["pleito"],
        turno=compilado["turno"],
        nome_origem=compilado["nome_origem"],
        tamanho_bytes=compilado["tamanho_bytes"],
        hash_sha256=compilado["hash_sha256"],
        total_estacoes=compilado["total_estacoes"],
        total_linhas=compilado["total_linhas"],
        total_corresp_secao=compilado["total_corresp_secao"],
        total_contingencias=compilado["total_contingencias"],
        total_secoes_unicas=compilado["total_secoes_unicas"],
        total_urnas_unicas=compilado["total_urnas_unicas"],
        total_midias_carga=compilado["total_midias_carga"],
        total_midias_votacao=compilado["total_midias_votacao"],
        total_midias_resultado=compilado["total_midias_resultado"],
        total_sobrescritas=compilado["total_sobrescritas"],
        total_erros=compilado["total_erros"],
        total_alertas=compilado["total_alertas"],
        resumo_erros_json=json.dumps(compilado["resumo_erros"], ensure_ascii=False),
        resumo_alertas_json=json.dumps(compilado["resumo_alertas"], ensure_ascii=False),
        anomalias_cruzamento_json=json.dumps(compilado["anomalias"], ensure_ascii=False),
        batimento_banco_json=json.dumps(compilado["batimento"], ensure_ascii=False),
    )
    db.add(lote_db)
    db.flush()

    def _trunc(val: Any, max_len: int) -> Optional[str]:
        if val is None:
            return None
        s = str(val).strip()
        return s[:max_len] if len(s) > max_len else s

    corresp_mappings: list[dict[str, Any]] = []
    for est in compilado["estacoes"]:
        est_db = TseGedaiEstacao(
            lote_id=lote_db.id,
            nome_arquivo=_trunc(est["nome_arquivo"], 255) or "desconhecido.jez",
            computador=_trunc(est["computador"], 80) or "ESTACAO",
            zona_computador=est["zona_computador"],
            serial_tpm=_trunc(est["serial_tpm"], 128),
            serial_instalacao=_trunc(est["serial_instalacao"], 128),
            uf=_trunc(est["uf"], 10),
            pleito=_trunc(est["pleito"], 10),
            turno=est["turno"],
            versao_gedai=_trunc(est["versao_gedai"], 160),
            possui_vsc=est["possui_vsc"],
            usuarios_windows_json=json.dumps(est["usuarios_windows"], ensure_ascii=False),
            usuarios_odin_json=json.dumps(est["usuarios_odin"], ensure_ascii=False),
            primeira_data_hora=_trunc(est["primeira_data_hora"], 25),
            ultima_data_hora=_trunc(est["ultima_data_hora"], 25),
            total_linhas=est["total_linhas"],
            corresp_secao_qtd=est["corresp_secao_qtd"],
            corresp_contingencia_qtd=est["corresp_contingencia_qtd"],
            midias_carga_qtd=est["midias_carga_qtd"],
            midias_votacao_qtd=est["midias_votacao_qtd"],
            midias_resultado_qtd=est["midias_resultado_qtd"],
            sobrescritas_qtd=est["sobrescritas_qtd"],
            apagamentos_qtd=est["apagamentos_qtd"],
            erros_qtd=len(est["erros"]),
            alertas_qtd=len(est["alertas"]),
            eventos_criticos_json=json.dumps(est["eventos_criticos"], ensure_ascii=False),
            midias_carga_json=json.dumps(est["midias_carga"], ensure_ascii=False),
        )
        db.add(est_db)
        db.flush()

        for c in est["correspondencias"]:
            corresp_mappings.append({
                "lote_id": lote_db.id,
                "estacao_id": est_db.id,
                "computador": _trunc(c["computador"], 80) or "ESTACAO",
                "tipo": _trunc(c["tipo"], 20) or "SECAO",
                "acao": _trunc(c["acao"], 20) or "TRANSMITIDA",
                "municipio_codigo": _trunc(c["municipio_codigo"], 10) or "00000",
                "municipio_nome": _trunc(c.get("municipio_nome") or "", 120) or "",
                "zona": c["zona"],
                "secao": c["secao"],
                "codigo_carga": _trunc(c["codigo_carga"], 64),
                "id_urna": _trunc(c["id_urna"], 32),
                "midia_carga": _trunc(c["midia_carga"], 32),
                "data_hora": _trunc(c["data_hora"], 25),
                "operador": _trunc(c["operador"], 80),
            })

    if corresp_mappings:
        for idx in range(0, len(corresp_mappings), 5000):
            db.bulk_insert_mappings(TseGedaiCorrespondencia, corresp_mappings[idx:idx + 5000])

    db.commit()

    return {
        "status": "CONCLUIDO",
        "lote_id": lote_db.id,
        "uf": lote_db.uf,
        "pleito": lote_db.pleito,
        "turno": lote_db.turno,
        "nome_origem": lote_db.nome_origem,
        "total_estacoes": lote_db.total_estacoes,
        "total_linhas": lote_db.total_linhas,
        "total_corresp_secao": lote_db.total_corresp_secao,
        "total_contingencias": lote_db.total_contingencias,
        "total_secoes_unicas": lote_db.total_secoes_unicas,
        "total_urnas_unicas": lote_db.total_urnas_unicas,
        "total_erros": lote_db.total_erros,
        "total_alertas": lote_db.total_alertas,
    }


def listar_lotes_gedai(db) -> dict[str, Any]:
    """Lista todos os lotes GEDAI-UE processados no PostgreSQL."""
    rows = db.query(TseGedaiLote).order_by(TseGedaiLote.created_at.desc()).all()
    lotes = []
    for r in rows:
        lotes.append({
            "id": r.id,
            "uf": r.uf,
            "pleito": r.pleito,
            "turno": r.turno,
            "nome_origem": r.nome_origem,
            "tamanho_mb": round((r.tamanho_bytes or 0) / (1024 * 1024), 2),
            "total_estacoes": r.total_estacoes,
            "total_linhas": r.total_linhas,
            "total_corresp_secao": r.total_corresp_secao,
            "total_contingencias": r.total_contingencias,
            "total_secoes_unicas": r.total_secoes_unicas,
            "total_urnas_unicas": r.total_urnas_unicas,
            "total_midias_carga": r.total_midias_carga,
            "total_midias_votacao": r.total_midias_votacao,
            "total_midias_resultado": r.total_midias_resultado,
            "total_sobrescritas": r.total_sobrescritas,
            "total_erros": r.total_erros,
            "total_alertas": r.total_alertas,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        })
    return {"total": len(lotes), "lotes": lotes}


def _safe_json_load(raw: Optional[str], default: Any) -> Any:
    if not raw:
        return default
    try:
        return json.loads(raw)
    except Exception:
        return default


def obter_detalhe_lote_gedai(db, lote_id: int) -> Optional[dict[str, Any]]:
    """Retorna visão pericial completa de um lote GEDAI-UE (KPIs, estações, erros, alertas, cruzamentos)."""
    lote = db.query(TseGedaiLote).filter(TseGedaiLote.id == lote_id).first()
    if not lote:
        return None

    estacoes_db = (
        db.query(TseGedaiEstacao)
        .filter(TseGedaiEstacao.lote_id == lote_id)
        .order_by(TseGedaiEstacao.computador.asc())
        .all()
    )
    estacoes = []
    for e in estacoes_db:
        estacoes.append({
            "id": e.id,
            "nome_arquivo": e.nome_arquivo,
            "computador": e.computador,
            "zona_computador": e.zona_computador,
            "serial_tpm": e.serial_tpm,
            "serial_instalacao": e.serial_instalacao,
            "uf": e.uf,
            "pleito": e.pleito,
            "turno": e.turno,
            "versao_gedai": e.versao_gedai,
            "possui_vsc": e.possui_vsc,
            "usuarios_windows": _safe_json_load(e.usuarios_windows_json, []),
            "usuarios_odin": _safe_json_load(e.usuarios_odin_json, []),
            "primeira_data_hora": e.primeira_data_hora,
            "ultima_data_hora": e.ultima_data_hora,
            "total_linhas": e.total_linhas,
            "corresp_secao_qtd": e.corresp_secao_qtd,
            "corresp_contingencia_qtd": e.corresp_contingencia_qtd,
            "midias_carga_qtd": e.midias_carga_qtd,
            "midias_votacao_qtd": e.midias_votacao_qtd,
            "midias_resultado_qtd": e.midias_resultado_qtd,
            "sobrescritas_qtd": e.sobrescritas_qtd,
            "apagamentos_qtd": e.apagamentos_qtd,
            "erros_qtd": e.erros_qtd,
            "alertas_qtd": e.alertas_qtd,
            "eventos_criticos": _safe_json_load(e.eventos_criticos_json, []),
            "midias_carga": _safe_json_load(e.midias_carga_json, []),
        })

    return {
        "lote": {
            "id": lote.id,
            "uf": lote.uf,
            "uf_nome": ESTADOS_E_REGIOES_BR.get(lote.uf, {}).get("nome", lote.uf),
            "pleito": lote.pleito,
            "turno": lote.turno,
            "nome_origem": lote.nome_origem,
            "tamanho_mb": round((lote.tamanho_bytes or 0) / (1024 * 1024), 2),
            "hash_sha256": lote.hash_sha256,
            "total_estacoes": lote.total_estacoes,
            "total_linhas": lote.total_linhas,
            "total_corresp_secao": lote.total_corresp_secao,
            "total_contingencias": lote.total_contingencias,
            "total_secoes_unicas": lote.total_secoes_unicas,
            "total_urnas_unicas": lote.total_urnas_unicas,
            "total_midias_carga": lote.total_midias_carga,
            "total_midias_votacao": lote.total_midias_votacao,
            "total_midias_resultado": lote.total_midias_resultado,
            "total_sobrescritas": lote.total_sobrescritas,
            "total_erros": lote.total_erros,
            "total_alertas": lote.total_alertas,
            "created_at": lote.created_at.isoformat() if lote.created_at else None,
        },
        "resumo_erros": _safe_json_load(lote.resumo_erros_json, []),
        "resumo_alertas": _safe_json_load(lote.resumo_alertas_json, []),
        "anomalias": _safe_json_load(lote.anomalias_cruzamento_json, {}),
        "batimento": _safe_json_load(lote.batimento_banco_json, {}),
        "estacoes": estacoes,
    }


def consultar_correspondencias_gedai(
    db,
    lote_id: int,
    busca: str = "",
    tipo: str = "TODOS",
    zona: str = "",
    limit: int = 250,
    offset: int = 0,
) -> dict[str, Any]:
    """Busca paginada de correspondências (seção ou contingência) no banco para inspeção instantânea."""
    q = db.query(TseGedaiCorrespondencia).filter(TseGedaiCorrespondencia.lote_id == lote_id)

    t_up = (tipo or "TODOS").upper().strip()
    if t_up in ("SECAO", "CONTINGENCIA"):
        q = q.filter(TseGedaiCorrespondencia.tipo == t_up)

    if zona and str(zona).strip().isdigit():
        q = q.filter(TseGedaiCorrespondencia.zona == int(str(zona).strip()))

    termo = (busca or "").strip()
    if termo:
        like_pat = f"%{termo}%"
        clauses = [
            TseGedaiCorrespondencia.computador.ilike(like_pat),
            TseGedaiCorrespondencia.municipio_nome.ilike(like_pat),
            TseGedaiCorrespondencia.municipio_codigo.ilike(like_pat),
            TseGedaiCorrespondencia.id_urna.ilike(like_pat),
            TseGedaiCorrespondencia.codigo_carga.ilike(like_pat),
            TseGedaiCorrespondencia.midia_carga.ilike(like_pat),
        ]
        if termo.isdigit():
            n_val = int(termo)
            clauses.append(TseGedaiCorrespondencia.zona == n_val)
            clauses.append(TseGedaiCorrespondencia.secao == n_val)
        q = q.filter(or_(*clauses))

    total = q.count()
    lim = min(max(int(limit or 250), 1), 500)
    off = max(int(offset or 0), 0)

    rows = (
        q.order_by(
            TseGedaiCorrespondencia.zona.asc(),
            TseGedaiCorrespondencia.secao.asc(),
            TseGedaiCorrespondencia.computador.asc(),
        )
        .offset(off)
        .limit(lim)
        .all()
    )

    itens = [
        {
            "id": r.id,
            "computador": r.computador,
            "tipo": r.tipo,
            "acao": r.acao,
            "municipio_codigo": r.municipio_codigo,
            "municipio_nome": r.municipio_nome,
            "zona": r.zona,
            "secao": r.secao,
            "codigo_carga": r.codigo_carga,
            "id_urna": r.id_urna,
            "midia_carga": r.midia_carga,
            "data_hora": r.data_hora,
            "operador": r.operador,
        }
        for r in rows
    ]

    return {"total": total, "limit": lim, "offset": off, "itens": itens}


def detectar_arquivos_gedai_servidor() -> list[dict[str, Any]]:
    """Escaneia pastas do servidor por pacotes `log_gedai*.zip` ou pastas descompactadas `log_gedai_*`."""
    candidatos_dir = [
        os.getenv("TSE_IMPORT_DIR", "/app/tse_import"),
        "/app/tse_import",
        "/root/tse_import",
        "/app/data/tse_import",
        "/root/Downloads",
    ]
    diretorios: list[str] = []
    for d in candidatos_dir:
        if d and d not in diretorios:
            diretorios.append(d)

    encontrados: list[dict[str, Any]] = []
    vistos: set[str] = set()

    def _inspecionar_pasta_gedai(nome: str, caminho_dir: str) -> None:
        if caminho_dir in vistos or not os.path.isdir(caminho_dir):
            return
        try:
            arqs = [f for f in os.listdir(caminho_dir) if f.lower().endswith(".jez")]
        except Exception:
            return
        if not arqs:
            return
        vistos.add(caminho_dir)
        tam = 0
        for f in arqs:
            try:
                tam += os.path.getsize(os.path.join(caminho_dir, f))
            except Exception:
                pass
        encontrados.append({
            "nome": nome,
            "caminho": caminho_dir,
            "tipo": f"PASTA ({len(arqs)} .jez)",
            "tamanho_mb": round(tam / (1024 * 1024), 2),
        })

    for base_dir in diretorios:
        if not os.path.isdir(base_dir):
            continue
        try:
            # Caso o próprio diretório configurado já contenha arquivos .jez GEDAI
            if "gedai" in os.path.basename(base_dir).lower():
                _inspecionar_pasta_gedai(os.path.basename(base_dir), base_dir)
            for item in sorted(os.listdir(base_dir)):
                low = item.lower()
                if "gedai" not in low:
                    continue
                full = os.path.join(base_dir, item)
                if full in vistos:
                    continue
                if os.path.isfile(full) and low.endswith(".zip"):
                    vistos.add(full)
                    encontrados.append({
                        "nome": item,
                        "caminho": full,
                        "tipo": "ZIP",
                        "tamanho_mb": round(os.path.getsize(full) / (1024 * 1024), 2),
                    })
                elif os.path.isdir(full):
                    _inspecionar_pasta_gedai(item, full)
        except Exception:
            continue

    return encontrados


def processar_caminho_gedai_servidor(db, caminho: Optional[str] = None) -> dict[str, Any]:
    """Processa automaticamente arquivo .zip ou pasta de logs GEDAI presente no servidor."""
    alvos = [caminho] if caminho else [d["caminho"] for d in detectar_arquivos_gedai_servidor()]
    if not alvos:
        return {"status": "NENHUM_ARQUIVO", "mensagem": "Nenhum pacote log_gedai_*.zip ou pasta encontrado em /root/tse_import.", "processados": []}

    resultados = []
    for alvo in alvos:
        if not alvo or not os.path.exists(alvo):
            continue
        if os.path.isfile(alvo) and alvo.lower().endswith(".zip"):
            with open(alvo, "rb") as fp:
                res = processar_pacote_gedai_para_banco(db, os.path.basename(alvo), zip_bytes=fp.read())
            resultados.append(res)
        elif os.path.isdir(alvo):
            pares = []
            for fn in sorted(os.listdir(alvo)):
                if fn.lower().endswith(".jez"):
                    with open(os.path.join(alvo, fn), "rb") as fp:
                        pares.append((fn, fp.read()))
            if pares:
                res = processar_pacote_gedai_para_banco(db, os.path.basename(alvo), arquivos_individuais=pares)
                resultados.append(res)

    return {"status": "CONCLUIDO", "total_processados": len(resultados), "processados": resultados}


def _norm_ue_serial(val: Any) -> str:
    """Normaliza número de série / ID da Urna Eletrônica removendo zeros à esquerda."""
    s = re.sub(r"[^0-9A-Za-z]", "", str(val or "").strip())
    if not s or s.upper() in ("XXX", "NONE", "NULL", "NULO"):
        return ""
    if s.isdigit():
        return str(int(s))
    return s.lstrip("0") or s


def _parse_dt_br(val: Any) -> Optional[datetime]:
    """Faz parse seguro de datas/horas brasileiras (`DD/MM/YYYY HH:MM:SS` ou `DD/MM/YYYY`)."""
    txt = str(val or "").strip()
    if not txt or txt in ("-", "XXX"):
        return None
    for fmt in ("%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M", "%d/%m/%Y", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(txt[:19], fmt)
        except Exception:
            continue
    return None


def _extrair_metadados_hardware_bu(bu_db, espelho: str) -> dict[str, Optional[str]]:
    """Extrai UE efetivada, código de carga, flashcard e horários de abertura/fechamento do BU/Espelho."""
    esp = str(espelho or "")
    ue_raw = str(getattr(bu_db, "mac_urna", "") or "").strip() if bu_db else ""
    if not _norm_ue_serial(ue_raw):
        m_ue = re.search(
            r"(?:URNA\s+ELETR[ÔO]NICA\s+EFETIVADA\s*(?:\(S[ÉE]RIE\))?:?|C[óo]digo\s+identifica[çc][ãa]o\s+UE)\s+([0-9]{5,12})",
            esp,
            re.I,
        )
        ue_raw = m_ue.group(1).strip() if m_ue else ""

    m_carga = re.search(r"(?:C[ÓO]DIGO\s+DE\s+CARGA|C[óo]digo\s+da\s+carga):?\s*([^\r\n]+)", esp, re.I)
    m_mc = re.search(r"FLASHCARD:?\s*([A-Fa-f0-9]{4,16})", esp, re.I)
    m_ab = re.search(r"(?:DATA/HORA\s+ABERTURA|Hor[áa]rio\s+de\s+abertura):?\s*([^\r\n]+)", esp, re.I)
    m_enc = re.search(r"(?:DATA/HORA\s+ENCERRAMENTO|Hor[áa]rio\s+de\s+fechamento):?\s*([^\r\n]+)", esp, re.I)

    def _limpo(m) -> Optional[str]:
        if not m:
            return None
        v = m.group(1).strip()
        return None if (not v or v in ("-", "XXX", "#NULO#")) else v

    return {
        "ue_raw": ue_raw or None,
        "ue_norm": _norm_ue_serial(ue_raw) or None,
        "carga_bu": _limpo(m_carga),
        "flashcard_bu": (_limpo(m_mc) or "").upper() or None,
        "dt_abertura_bu": _limpo(m_ab),
        "dt_encerramento_bu": _limpo(m_enc),
    }


def _deduplicar_correspondencias_gedai(rows) -> list[dict[str, Any]]:
    """Agrupa registros `TRANSMITIDA`/`RECEBIDA` de uma mesma UE no GEDAI mantendo o evento mais completo."""
    por_chave: dict[tuple[str, str], dict[str, Any]] = {}
    for r in rows:
        ue_pad = str(r.id_urna or "").strip()
        ue_norm = _norm_ue_serial(ue_pad)
        carga = str(r.codigo_carga or "").strip()
        key = (ue_norm or ue_pad, carga)
        atual = por_chave.get(key)
        item = {
            "computador": r.computador,
            "tipo": r.tipo,
            "acao": r.acao,
            "municipio_codigo": r.municipio_codigo,
            "municipio_nome": r.municipio_nome,
            "zona": r.zona,
            "secao": r.secao,
            "id_urna": ue_pad,
            "id_urna_norm": ue_norm,
            "codigo_carga": carga,
            "midia_carga": r.midia_carga,
            "data_hora": r.data_hora,
            "operador": r.operador,
        }
        if not atual:
            por_chave[key] = item
        elif r.acao == "TRANSMITIDA" or (atual.get("acao") != "TRANSMITIDA" and str(r.data_hora or "") > str(atual.get("data_hora") or "")):
            por_chave[key] = item
    return sorted(por_chave.values(), key=lambda x: str(x.get("data_hora") or ""))


def _buscar_contingencia_sistot_secao(db, uf: str, mun_cod: str, mun_nome: str, zona: int, secao: int, turno: int) -> tuple[bool, Optional[dict[str, Any]]]:
    """Consulta relatórios oficiais SISTOT (Anexo V/XIII) para a UF/turno e localiza eventual ocorrência na seção."""
    try:
        rels = (
            db.query(TseRelatorioOficialTse)
            .filter(func.upper(TseRelatorioOficialTse.uf) == str(uf or "").upper().strip(), TseRelatorioOficialTse.turno == turno)
            .all()
        )
    except Exception as exc_s:
        try:
            db.rollback()
        except Exception:
            pass
        print(f"[TSE-SISTOT] Aviso SQL em _buscar_contingencia_sistot_secao: {exc_s}")
        return False, None

    sistot_disponivel = False
    mun_cod_z = str(mun_cod or "").strip().zfill(5)
    mun_norm = re.sub(r"[^A-Z0-9 ]", "", str(mun_nome or "").upper()).strip()

    try:
        for rel in rels:
            raw_cts = getattr(rel, "contingencias_urnas_json", None) or getattr(rel, "contingencias_json", None)
            if not raw_cts:
                continue
            cts = _safe_json_load(raw_cts, [])
            if not cts:
                continue
            sistot_disponivel = True
            for ct in cts:
                try:
                    ct_z = int(str(ct.get("zona") or "0").strip())
                    ct_s = int(str(ct.get("secao") or "0").strip())
                except Exception:
                    continue
                if ct_z != int(zona) or ct_s != int(secao):
                    continue
                ct_mun_raw = str(ct.get("municipio") or "").upper()
                ct_mun_norm = re.sub(r"[^A-Z0-9 ]", "", ct_mun_raw).strip()
                mun_ok = (not mun_norm) or (mun_cod_z in ct_mun_raw) or (mun_norm in ct_mun_norm) or (ct_mun_norm in mun_norm)
                if mun_ok:
                    return True, {
                        "relatorio_id": rel.id,
                        "arquivo_pdf": rel.nome_arquivo,
                        "municipio": ct.get("municipio"),
                        "data_hora_ocorrencia": ct.get("data_hora_ocorrencia"),
                        "id_urna_efetivada": str(ct.get("id_urna_efetivada") or "").strip(),
                        "id_urna_norm": _norm_ue_serial(ct.get("id_urna_efetivada")),
                        "id_carga": ct.get("id_carga"),
                        "id_mc": ct.get("id_mc"),
                        "data_carga": ct.get("data_carga"),
                    }
    except Exception as exc_loop:
        print(f"[TSE-SISTOT] Aviso ao inspecionar contingências SISTOT: {exc_loop}")
    return sistot_disponivel, None


def _calcular_decomposicao_urnas_turno(
    turno: int,
    bu_db,
    met_db,
    espelho: str,
    ciclos: Optional[list[dict[str, Any]]],
    origem_urna: str,
    ue_norm: Optional[str],
    titular_ids: set[str],
    titulares_gedai: list[dict[str, Any]],
    urna_efetivada_gedai: Optional[dict[str, Any]],
    sistot_occ: Optional[dict[str, Any]],
    corresp_tse: dict[str, Any],
    hw: dict[str, Any],
) -> Optional[dict[str, Any]]:
    """
    Calcula a totalização e decomposição separada entre as 2 urnas físicas da seção
    quando houve substituição de equipamento (Urna 1 Titular Substituída × Urna 2 Reserva Efetivada).
    Combina:
      1. Contagem de comparecimento/eleitores por máquina (via ciclos por serial_ue, diferença BU - Log Parcial
         ou perfil horário pré/pós-substituição baseado na curva da própria seção).
      2. Decomposição proporcional de votos por candidato, brancos e nulos em cada urna, acompanhada do
         Intervalo Matemático Estrito [Mínimo Garantido .. Máximo Possível] de cada candidato em cada máquina.
    """
    ceft_reg = corresp_tse.get("ceft") or {}
    csec_snaps = corresp_tse.get("csec_snapshots") or []
    ccont_match = corresp_tse.get("ccont_match") or {}
    alt_cesp = corresp_tse.get("alteracao_cesp") or {}

    outros_titulares = sorted(titular_ids - ({ue_norm} if ue_norm else set()))
    ue_titular = (
        ceft_reg.get("nr_urna_esperada")
        or (csec_snaps[0].get("nr_urna_esperada") if csec_snaps else None)
        or (outros_titulares[0] if outros_titulares else None)
        or (sorted(titular_ids)[0] if titular_ids else None)
    )
    ue_reserva = ue_norm or ceft_reg.get("nr_urna_efetivada")

    houve_troca = bool(
        origem_urna in ("RESERVA", "SUBSTITUTA_OUTRA_SECAO")
        or (ue_titular and ue_reserva and ue_titular != ue_reserva)
    )
    if not houve_troca or not ue_reserva:
        return None

    ue_titular = ue_titular or "TITULAR"

    # Metadados de custódia de cada equipamento
    ult_csec = csec_snaps[-1] if csec_snaps else {}
    prim_csec = csec_snaps[0] if csec_snaps else {}
    tit_g0 = titulares_gedai[-1] if titulares_gedai else {}
    efet_g = urna_efetivada_gedai or {}

    mc_u1 = (
        ceft_reg.get("cd_flashcard_esperada")
        or prim_csec.get("cd_flashcard_esperada")
        or tit_g0.get("midia_carga")
        or "-"
    )
    carga_u1 = (
        ceft_reg.get("cd_carga_esperada")
        or prim_csec.get("cd_carga_esperada")
        or tit_g0.get("codigo_carga")
        or "-"
    )
    est_u1 = (
        prim_csec.get("maquina_geracao")
        or ceft_reg.get("maquina_geracao")
        or tit_g0.get("computador")
        or "-"
    )
    dt_carga_u1 = (
        ceft_reg.get("dt_carga_esperada")
        or prim_csec.get("dt_carga_esperada")
        or tit_g0.get("data_hora")
        or "-"
    )

    mc_u2 = (
        hw.get("flashcard_bu")
        or ceft_reg.get("cd_flashcard_efetivada")
        or ccont_match.get("cd_flashcard")
        or efet_g.get("midia_carga")
        or (sistot_occ or {}).get("id_mc")
        or "-"
    )
    carga_u2 = (
        hw.get("carga_bu")
        or ceft_reg.get("cd_carga_efetivada")
        or efet_g.get("codigo_carga")
        or (sistot_occ or {}).get("id_carga")
        or "-"
    )
    est_u2 = (
        ccont_match.get("maquina")
        or efet_g.get("computador")
        or ceft_reg.get("maquina_geracao")
        or "-"
    )
    dt_carga_u2 = (
        ccont_match.get("dt_carga")
        or ceft_reg.get("dt_carga_efetivada")
        or efet_g.get("data_hora")
        or (sistot_occ or {}).get("data_carga")
        or "-"
    )

    # Totais oficiais da seção no BU
    comp_total = int(getattr(bu_db, "comparecimento", 0) or 0) if bu_db else 0
    brancos_sec = int(getattr(bu_db, "votos_brancos", 0) or 0) if bu_db else 0
    nulos_sec = int(getattr(bu_db, "votos_nulos", 0) or 0) if bu_db else 0
    cands_sec = list(getattr(bu_db, "candidatos", None) or []) if bu_db else []

    if comp_total <= 0 and espelho:
        m_cp = re.search(r"Comparecimento:?\s+(\d+)", str(espelho), re.I)
        if m_cp:
            comp_total = int(m_cp.group(1))
    if comp_total <= 0 and cands_sec:
        comp_total = sum(int(c.get("votos") or c.get("votos_bu") or 0) for c in cands_sec) + brancos_sec + nulos_sec
    if comp_total <= 0:
        return None

    faixas = ["08h", "09h", "10h", "11h", "12h", "13h", "14h", "15h", "16h", "17h"]
    pesos_padrao = {"08h": 34, "09h": 37, "10h": 36, "11h": 39, "12h": 30, "13h": 35, "14h": 28, "15h": 22, "16h": 12, "17h": 0}

    vph_met = _safe_json_load(getattr(met_db, "vazao_horaria_json", None), {}) if met_db else {}
    if not isinstance(vph_met, dict):
        vph_met = {}
    vph_bu = (getattr(bu_db, "vph", None) or {}) if bu_db else {}
    vph_outro = (getattr(bu_db, "vph_outro_turno", None) or {}) if bu_db else {}

    soma_vph_met = sum(int(vph_met.get(fh, 0) or 0) for fh in faixas)
    votos_log_met = int(getattr(met_db, "total_votos_computados", 0) or 0) if met_db else 0
    vph_ativo = vph_met if soma_vph_met > 0 else vph_bu

    horas_com_voto = [fh for fh in faixas if int(vph_ativo.get(fh, 0) or 0) > 0]
    primeira_hora_log = horas_com_voto[0] if horas_com_voto else "08h"

    # Detecção da hora exata/estimada da substituição
    hora_troca = "13h"
    horario_troca_fmt = "~13:00"
    fonte_horario = "LOG_VAZAO"

    if sistot_occ and sistot_occ.get("data_hora_ocorrencia"):
        dt_occ = _parse_dt_br(sistot_occ.get("data_hora_ocorrencia"))
        if dt_occ and 8 <= dt_occ.hour <= 17:
            hora_troca = f"{dt_occ.hour:02d}h"
            horario_troca_fmt = dt_occ.strftime("%H:%M:%S")
            fonte_horario = "SISTOT_PDF"
    elif primeira_hora_log >= "09h":
        hora_troca = primeira_hora_log
        horario_troca_fmt = f"A partir das {primeira_hora_log}"
        if ult_csec and ult_csec.get("nr_urna_esperada") == ue_titular and ult_csec.get("hh_geracao"):
            horario_troca_fmt = f"A partir das {primeira_hora_log} (CESP {ult_csec.get('hh_geracao')[:5]})"
        fonte_horario = "CURVA_HORARIA_LOG"
    elif alt_cesp and alt_cesp.get("dt_carga_nova"):
        dt_nv = _parse_dt_br(alt_cesp.get("dt_carga_nova"))
        if dt_nv and 8 <= dt_nv.hour <= 17:
            hora_troca = f"{dt_nv.hour:02d}h"
            horario_troca_fmt = dt_nv.strftime("%H:%M:%S")
            fonte_horario = "SNAPSHOT_CESP"
    elif ult_csec and ult_csec.get("nr_urna_esperada") == ue_titular and ult_csec.get("hh_geracao"):
        hh_c = str(ult_csec.get("hh_geracao") or "")[:2]
        if hh_c.isdigit() and 8 <= int(hh_c) <= 16:
            hora_troca = f"{int(hh_c):02d}h"
            horario_troca_fmt = f"~{ult_csec.get('hh_geracao')[:5]}"
            fonte_horario = "CESP_DIA_ELEICAO"

    idx_troca = faixas.index(hora_troca) if hora_troca in faixas else 5
    vph_bruto_log = {fh: int(vph_ativo.get(fh, 0) or 0) for fh in faixas if int(vph_ativo.get(fh, 0) or 0) > 0 or fh != "17h"}

    # Cálculo dos eleitores em cada uma das 2 urnas (votos_u1 na Titular vs votos_u2 na Reserva)
    vph_u1: dict[str, int] = {fh: 0 for fh in faixas if fh != "17h"}
    vph_u2: dict[str, int] = {fh: 0 for fh in faixas if fh != "17h"}

    # Verifica se os próprios ciclos possuem serial_ue distinto por equipamento
    seriais_ciclos = Counter(
        _norm_ue_serial(c.get("serial_ue"))
        for c in (ciclos or [])
        if isinstance(c, dict) and _norm_ue_serial(c.get("serial_ue"))
    )

    if len(seriais_ciclos) >= 2 and ue_titular in seriais_ciclos and ue_reserva in seriais_ciclos:
        metodo_codigo = "LOG_MULTI_SERIAL"
        metodo_label = "Contagem Exata por Serial de Hardware no Log (logd.dat)"
        for c in (ciclos or []):
            s_c = _norm_ue_serial(c.get("serial_ue"))
            fh_c = str(c.get("faixa_horaria") or (str(c.get("hora_computado") or "08")[:2] + "h"))
            if s_c == ue_titular:
                vph_u1[fh_c] = vph_u1.get(fh_c, 0) + 1
            else:
                vph_u2[fh_c] = vph_u2.get(fh_c, 0) + 1
        votos_u1 = sum(vph_u1.values())
        votos_u2 = comp_total - votos_u1
        explicacao_metodologia = (
            f"O arquivo de log registra individualmente os votos computados com o número de série da Urna Titular "
            f"(#{ue_titular}: {votos_u1} votos) e da Urna Reserva (#{ue_reserva}: {votos_u2} votos)."
        )
    elif 0 < votos_log_met < comp_total:
        metodo_codigo = "DIFERENCA_BU_VS_LOG_RESERVA"
        metodo_label = f"Contagem Exata (BU Consolidado {comp_total}v − Log da Reserva {votos_log_met}v)"
        votos_u2 = votos_log_met
        votos_u1 = comp_total - votos_u2
        # Distribui vph_u2 conforme o log da reserva e vph_u1 conforme o perfil pré-troca
        if soma_vph_met > 0 and soma_vph_met <= votos_u2 + 2:
            for fh in faixas:
                if int(vph_met.get(fh, 0) or 0) > 0:
                    vph_u2[fh] = int(vph_met.get(fh, 0) or 0)
        else:
            horas_pos = faixas[idx_troca:9] or ["13h", "14h", "15h", "16h"]
            pesos_pos = [int(vph_outro.get(h, 0) or pesos_padrao.get(h, 20)) for h in horas_pos]
            soma_p = max(1, sum(pesos_pos))
            aloc = 0
            for h, p in zip(horas_pos, pesos_pos):
                q = int(round(votos_u2 * (p / soma_p)))
                vph_u2[h] = q
                aloc += q
            vph_u2[horas_pos[0]] = max(0, vph_u2.get(horas_pos[0], 0) + (votos_u2 - aloc))

        horas_pre = faixas[:idx_troca + 1] or ["08h", "09h", "10h", "11h", "12h", "13h"]
        pesos_pre = [int(vph_outro.get(h, 0) or pesos_padrao.get(h, 30)) for h in horas_pre]
        if len(pesos_pre) > 1 and vph_u2.get(hora_troca, 0) > 0:
            pesos_pre[-1] = max(1, pesos_pre[-1] - vph_u2.get(hora_troca, 0))
        soma_pre = max(1, sum(pesos_pre))
        aloc1 = 0
        for h, p in zip(horas_pre, pesos_pre):
            q = int(round(votos_u1 * (p / soma_pre)))
            vph_u1[h] = q
            aloc1 += q
        vph_u1[horas_pre[0]] = max(0, vph_u1.get(horas_pre[0], 0) + (votos_u1 - aloc1))
        explicacao_metodologia = (
            f"O Boletim de Urna final totalizou {comp_total} votos na seção, enquanto o log da Urna Reserva (#{ue_reserva}) "
            f"registrou exatamente {votos_u2} votos a partir das {hora_troca}. Os {votos_u1} votos anteriores foram "
            f"computados na Urna Titular (#{ue_titular}) das 08h às {hora_troca} e transferidos via Mídia de Votação."
        )
    elif primeira_hora_log >= "09h":
        # Caso em que 08h..(hora_troca-1) está zerado no log da reserva (ex.: 08h..12h = 0v e 13h..16h = 280v)
        metodo_codigo = "DECOMPOSICAO_CURVA_SECAO_PRE_POS_TROCA"
        tem_ref_1t = sum(int(vph_outro.get(fh, 0) or 0) for fh in faixas) > 0
        metodo_label = (
            f"Decomposição Horária Pré/Pós-{hora_troca} (Curva Base da Seção no {'1ºT' if turno == 2 else '2ºT'} × Log #{ue_reserva})"
            if tem_ref_1t else f"Decomposição Horária Pré/Pós-{hora_troca} (08h–{hora_troca} × {hora_troca}–17h)"
        )
        base_map = {
            fh: (int(vph_outro.get(fh, 0) or 0) if tem_ref_1t else pesos_padrao.get(fh, 0))
            for fh in faixas
        }
        v_troca_log = int(vph_ativo.get(hora_troca, 0) or 0)
        b_troca_tot = max(1, base_map.get(hora_troca, 35))
        if 0 < v_troca_log < b_troca_tot:
            b_u2_troca = v_troca_log
            b_u1_troca = b_troca_tot - v_troca_log
        else:
            b_u1_troca = b_troca_tot // 2
            b_u2_troca = b_troca_tot - b_u1_troca

        pesos_u1_map = {fh: (base_map.get(fh, 0) if i < idx_troca else (b_u1_troca if i == idx_troca else 0)) for i, fh in enumerate(faixas)}
        pesos_u2_map = {fh: (base_map.get(fh, 0) if i > idx_troca else (b_u2_troca if i == idx_troca else 0)) for i, fh in enumerate(faixas)}

        w1 = sum(pesos_u1_map.values())
        w2 = sum(pesos_u2_map.values())
        w_tot = max(1, w1 + w2)

        votos_u1 = int(round(comp_total * (w1 / w_tot)))
        votos_u2 = comp_total - votos_u1

        aloc1 = 0
        for fh in faixas[:idx_troca + 1]:
            q = int(round(votos_u1 * (pesos_u1_map[fh] / max(1, w1))))
            vph_u1[fh] = q
            aloc1 += q
        if votos_u1 - aloc1 != 0:
            fh_adj1 = faixas[min(idx_troca, 1)]
            vph_u1[fh_adj1] = max(0, vph_u1.get(fh_adj1, 0) + (votos_u1 - aloc1))

        aloc2 = 0
        for fh in faixas[idx_troca:9]:
            q = int(round(votos_u2 * (pesos_u2_map[fh] / max(1, w2))))
            vph_u2[fh] = q
            aloc2 += q
        if votos_u2 - aloc2 != 0:
            fh_adj2 = faixas[min(idx_troca + 1, 8)]
            vph_u2[fh_adj2] = max(0, vph_u2.get(fh_adj2, 0) + (votos_u2 - aloc2))

        explicacao_metodologia = (
            f"O log da seção inicia a contabilização na Urna Reserva (#{ue_reserva}) às {hora_troca} ({v_troca_log}v na faixa das {hora_troca}, "
            f"com 0v registrados das 08h às {faixas[max(0, idx_troca - 1)]}). Cruzando o comparecimento total do BU ({comp_total} eleitores) "
            f"com a curva horária real da própria seção ({'1º Turno' if turno == 2 else 'turno de referência'}), obtém-se "
            f"{votos_u1} eleitores na Urna Titular (#{ue_titular}, 08h–{hora_troca}) e {votos_u2} eleitores na Urna Reserva (#{ue_reserva}, {hora_troca}–17h)."
        )
    else:
        metodo_codigo = "CORTE_HORARIO_TROCA"
        metodo_label = f"Divisão Cronológica no Horário da Troca ({hora_troca})"
        for i, fh in enumerate(faixas[:9]):
            v_h = int(vph_ativo.get(fh, 0) or 0)
            if i < idx_troca:
                vph_u1[fh] = v_h
            elif i == idx_troca:
                u1_h = v_h // 2
                vph_u1[fh] = u1_h
                vph_u2[fh] = v_h - u1_h
            else:
                vph_u2[fh] = v_h
        soma_v = sum(vph_u1.values()) + sum(vph_u2.values())
        if soma_v > 0 and soma_v != comp_total:
            votos_u1 = int(round(comp_total * (sum(vph_u1.values()) / soma_v)))
            votos_u2 = comp_total - votos_u1
        else:
            votos_u1 = sum(vph_u1.values())
            votos_u2 = comp_total - votos_u1
        explicacao_metodologia = (
            f"Separação dos eleitores da seção ({comp_total} votos) antes e após o horário da substituição ({hora_troca}): "
            f"{votos_u1} eleitores na Urna Titular (#{ue_titular}) e {votos_u2} eleitores na Urna Reserva (#{ue_reserva})."
        )

    pct_u1 = round((votos_u1 / max(1, comp_total)) * 100.0, 1)
    pct_u2 = round(100.0 - pct_u1, 1)
    prop_u1 = votos_u1 / max(1, comp_total)

    # Decomposição proporcional + Limites Matemáticos Estritos [Mín, Máx] por candidato, brancos e nulos
    br_u1 = int(round(brancos_sec * prop_u1))
    br_u2 = max(0, brancos_sec - br_u1)
    nu_u1 = int(round(nulos_sec * prop_u1))
    nu_u2 = max(0, nulos_sec - nu_u1)

    cands_u1_list: list[dict[str, Any]] = []
    cands_u2_list: list[dict[str, Any]] = []
    soma_cands_u1 = 0
    alvo_nominais_u1 = max(0, votos_u1 - br_u1 - nu_u1)

    for c in cands_sec:
        num_c = str(c.get("numero") or "")
        nome_c = str(c.get("nome") or f"CANDIDATO {num_c}")
        v_tot_c = int(c.get("votos") or c.get("votos_bu") or 0)
        v_c_u1 = int(round(v_tot_c * prop_u1))
        soma_cands_u1 += v_c_u1
        cands_u1_list.append({
            "numero": num_c,
            "nome": nome_c,
            "votos_secao": v_tot_c,
            "votos_estimados": v_c_u1,
            "min_matematico": max(0, v_tot_c - votos_u2),
            "max_matematico": min(v_tot_c, votos_u1),
        })
        cands_u2_list.append({
            "numero": num_c,
            "nome": nome_c,
            "votos_secao": v_tot_c,
            "votos_estimados": max(0, v_tot_c - v_c_u1),
            "min_matematico": max(0, v_tot_c - votos_u1),
            "max_matematico": min(v_tot_c, votos_u2),
        })

    # Ajuste fino de arredondamento de 1 voto no candidato mais votado para fechar soma 100% exata
    diff_nom = alvo_nominais_u1 - soma_cands_u1
    if diff_nom != 0 and cands_u1_list:
        idx_maior = max(range(len(cands_u1_list)), key=lambda i: cands_u1_list[i]["votos_secao"])
        novo_v1 = max(
            cands_u1_list[idx_maior]["min_matematico"],
            min(cands_u1_list[idx_maior]["max_matematico"], cands_u1_list[idx_maior]["votos_estimados"] + diff_nom),
        )
        cands_u1_list[idx_maior]["votos_estimados"] = novo_v1
        cands_u2_list[idx_maior]["votos_estimados"] = cands_u1_list[idx_maior]["votos_secao"] - novo_v1

    tot_nom_u1 = max(1, sum(x["votos_estimados"] for x in cands_u1_list))
    tot_nom_u2 = max(1, sum(x["votos_estimados"] for x in cands_u2_list))
    for x in cands_u1_list:
        x["pct_na_urna"] = round((x["votos_estimados"] / tot_nom_u1) * 100.0, 1)
    for x in cands_u2_list:
        x["pct_na_urna"] = round((x["votos_estimados"] / tot_nom_u2) * 100.0, 1)

    return {
        "disponivel": True,
        "turno": turno,
        "hora_troca": hora_troca,
        "horario_troca_estimado": horario_troca_fmt,
        "fonte_horario": fonte_horario,
        "metodo_codigo": metodo_codigo,
        "metodo_label": metodo_label,
        "explicacao_metodologia": explicacao_metodologia,
        "nota_sigilo_tse": (
            "Nota Forense TSE: Na contingência, a Mídia de Votação (Flashcard) transfere os votos acumulados da Urna Titular "
            "para a Urna Reserva sem emitir BU parcial, gerando um único BU e RDV embaralhado às 17h para preservação do sigilo "
            "constitucional. O comparecimento por equipamento é extraído da curva de log × BU, e os votos por candidato exibem "
            "a decomposição proporcional exata e o intervalo matemático obrigatório [Mín–Máx] em cada máquina."
        ),
        "comparecimento_secao": comp_total,
        "brancos_secao": brancos_sec,
        "nulos_secao": nulos_sec,
        "urna_1": {
            "ordem": 1,
            "papel": "URNA 1 — TITULAR (SUBSTITUÍDA)",
            "serial": ue_titular,
            "flashcard": mc_u1,
            "codigo_carga": carga_u1,
            "estacao": est_u1,
            "dt_carga": dt_carga_u1,
            "periodo_operacao": f"08:00 às {hora_troca} (Antes da Substituição)",
            "votos_total": votos_u1,
            "pct_secao": pct_u1,
            "votos_por_hora": {k: v for k, v in vph_u1.items() if v > 0 or k in ("08h", "09h", "10h", "11h", "12h", hora_troca)},
            "brancos_estimados": br_u1,
            "nulos_estimados": nu_u1,
            "candidatos": cands_u1_list,
        },
        "urna_2": {
            "ordem": 2,
            "papel": "URNA 2 — RESERVA (EFETIVADA)",
            "serial": ue_reserva,
            "flashcard": mc_u2,
            "codigo_carga": carga_u2,
            "estacao": est_u2,
            "dt_carga": dt_carga_u2,
            "periodo_operacao": f"A partir das {hora_troca} às 17:00 (Após a Substituição)",
            "votos_total": votos_u2,
            "pct_secao": pct_u2,
            "votos_por_hora": {k: v for k, v in vph_u2.items() if v > 0 or k >= hora_troca},
            "votos_por_hora_bruto_log": vph_bruto_log,
            "votos_bruto_log_total": sum(vph_bruto_log.values()),
            "brancos_estimados": br_u2,
            "nulos_estimados": nu_u2,
            "candidatos": cands_u2_list,
        },
    }


def _classificar_custodia_turno(
    db,
    secao_db,
    turno: int,
    bu_db,
    espelho: str,
    ciclos: Optional[list[dict[str, Any]]] = None,
    met_db=None,
) -> dict[str, Any]:
    """Cruza BU × GEDAI-UE × SISTOT PDF para um turno específico da seção (Titular vs Reserva e momento da troca)."""
    try:
        from .database import garantir_tabelas_custodia_tse
        garantir_tabelas_custodia_tse()
    except Exception:
        pass

    uf = str(secao_db.uf or "").upper().strip()
    mun_cod = str(secao_db.municipio_codigo or "").strip().zfill(5)
    mun_nome = str(secao_db.municipio_nome or "")
    zona = int(secao_db.zona or 0)
    sec = int(secao_db.secao or 0)

    hw = _extrair_metadados_hardware_bu(bu_db, espelho)
    sistot_disponivel, sistot_occ = _buscar_contingencia_sistot_secao(db, uf, mun_cod, mun_nome, zona, sec, turno)

    ue_norm = hw["ue_norm"] or (sistot_occ["id_urna_norm"] if sistot_occ else None)

    corresp_tse = {
        "disponivel": False,
        "base_turno_carregada": False,
        "csec_snapshots": [],
        "ceft": None,
        "alteracao_cesp": None,
        "ccont_match": None,
    }
    try:
        from .tse_corresp_parser import buscar_custodia_corresp_secao
        corresp_tse = buscar_custodia_corresp_secao(db, uf, mun_cod, zona, sec, turno, ue_candidata=ue_norm)
    except Exception as exc_cor:
        print(f"[TSE-CORRESP] Aviso ao consultar CESP/CEFT da seção: {exc_cor}")

    ceft_reg = corresp_tse.get("ceft")
    alt_cesp = corresp_tse.get("alteracao_cesp")
    ccont_match = corresp_tse.get("ccont_match")
    csec_snaps = corresp_tse.get("csec_snapshots") or []

    if not ue_norm and ceft_reg and ceft_reg.get("nr_urna_efetivada"):
        ue_norm = ceft_reg["nr_urna_efetivada"]
    elif not ue_norm and csec_snaps and csec_snaps[-1].get("nr_urna_esperada"):
        ue_norm = csec_snaps[-1]["nr_urna_esperada"]
    ue_pad = ue_norm.zfill(8) if (ue_norm and ue_norm.isdigit()) else ue_norm

    if not hw.get("flashcard_bu") and ceft_reg and ceft_reg.get("cd_flashcard_efetivada"):
        hw["flashcard_bu"] = ceft_reg["cd_flashcard_efetivada"]
    elif not hw.get("flashcard_bu") and csec_snaps and csec_snaps[-1].get("cd_flashcard_esperada"):
        hw["flashcard_bu"] = csec_snaps[-1]["cd_flashcard_esperada"]
    if not hw.get("carga_bu") and ceft_reg and ceft_reg.get("cd_carga_efetivada"):
        hw["carga_bu"] = ceft_reg["cd_carga_efetivada"]
    elif not hw.get("carga_bu") and csec_snaps and csec_snaps[-1].get("cd_carga_esperada"):
        hw["carga_bu"] = csec_snaps[-1]["cd_carga_esperada"]

    lote_t = None
    try:
        lote_t = (
            db.query(TseGedaiLote)
            .filter(func.upper(TseGedaiLote.uf) == uf, TseGedaiLote.turno == turno)
            .order_by(TseGedaiLote.id.desc())
            .first()
        )
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
    gedai_disponivel = lote_t is not None

    titulares_gedai: list[dict[str, Any]] = []
    efetivada_gedai_matches: list[dict[str, Any]] = []

    mun_cands_g = list({mun_cod, mun_cod.lstrip("0") or mun_cod})
    if gedai_disponivel:
        try:
            rows_sec_gedai = (
                db.query(TseGedaiCorrespondencia)
                .join(TseGedaiLote, TseGedaiCorrespondencia.lote_id == TseGedaiLote.id)
                .filter(
                    func.upper(TseGedaiLote.uf) == uf,
                    TseGedaiLote.turno == turno,
                    TseGedaiCorrespondencia.municipio_codigo.in_(mun_cands_g),
                    TseGedaiCorrespondencia.zona == zona,
                    TseGedaiCorrespondencia.secao == sec,
                )
                .all()
            )
            titulares_gedai = _deduplicar_correspondencias_gedai(rows_sec_gedai)

            if not ue_norm and titulares_gedai and not sistot_occ:
                ue_norm = titulares_gedai[-1].get("id_urna_norm")
                ue_pad = titulares_gedai[-1].get("id_urna") or (ue_norm.zfill(8) if (ue_norm and ue_norm.isdigit()) else ue_norm)
            if titulares_gedai:
                if not hw.get("flashcard_bu"):
                    hw["flashcard_bu"] = titulares_gedai[-1].get("midia_carga")
                if not hw.get("carga_bu"):
                    hw["carga_bu"] = titulares_gedai[-1].get("codigo_carga")

            if ue_norm:
                cands_id = list({ue_norm, ue_norm.zfill(8), str(hw.get("ue_raw") or "").strip()} - {""})
                rows_ue_gedai = (
                    db.query(TseGedaiCorrespondencia)
                    .join(TseGedaiLote, TseGedaiCorrespondencia.lote_id == TseGedaiLote.id)
                    .filter(
                        func.upper(TseGedaiLote.uf) == uf,
                        TseGedaiLote.turno == turno,
                        TseGedaiCorrespondencia.id_urna.in_(cands_id),
                    )
                    .all()
                )
                efetivada_gedai_matches = _deduplicar_correspondencias_gedai(rows_ue_gedai)
        except Exception as exc_g:
            try:
                db.rollback()
            except Exception:
                pass
            print(f"[TSE-GEDAI] Aviso SQL em _classificar_custodia_turno: {exc_g}")

    titular_ids = {t["id_urna_norm"] for t in titulares_gedai if t.get("id_urna_norm")}
    if csec_snaps and csec_snaps[0].get("nr_urna_esperada"):
        titular_ids.add(csec_snaps[0]["nr_urna_esperada"])
    if ceft_reg and ceft_reg.get("nr_urna_esperada"):
        titular_ids.add(ceft_reg["nr_urna_esperada"])

    match_efet_mesma_sec = next(
        (m for m in efetivada_gedai_matches if m["tipo"] == "SECAO" and int(m["zona"] or 0) == zona and int(m["secao"] or 0) == sec and m["municipio_codigo"] == mun_cod),
        None,
    )
    match_efet_cont = next((m for m in efetivada_gedai_matches if m["tipo"] == "CONTINGENCIA"), None)
    match_efet_outra_sec = next(
        (m for m in efetivada_gedai_matches if m["tipo"] == "SECAO" and (int(m["zona"] or 0) != zona or int(m["secao"] or 0) != sec or m["municipio_codigo"] != mun_cod)),
        None,
    )
    urna_efetivada_gedai = match_efet_cont or match_efet_mesma_sec or match_efet_outra_sec

    # Indicadores combinados do pacote CESP/CEFT
    ceft_is_cont = bool(ceft_reg and ceft_reg.get("tp_divergencia") == "C")
    ceft_div_silenciosa = bool(
        ceft_reg
        and ceft_reg.get("nr_urna_esperada")
        and ceft_reg.get("nr_urna_efetivada")
        and ceft_reg.get("nr_urna_esperada") != ceft_reg.get("nr_urna_efetivada")
        and not ceft_is_cont
    )
    teve_red = bool(ceft_reg and ceft_reg.get("cd_origem_voto") == "R")
    cesp_trocou_ue = bool(alt_cesp and alt_cesp.get("ue_anterior") and alt_cesp.get("ue_nova") and alt_cesp["ue_anterior"] != alt_cesp["ue_nova"] and not str(alt_cesp["ue_anterior"]).startswith("("))

    # 1. Classificação Titular vs Reserva (GEDAI × CESP × CEFT × BU × SISTOT)
    origem_urna = "INDETERMINADO"
    origem_label = "Sem dados GEDAI/CESP/SISTOT deste turno"
    origem_detalhe = "Faça a ingestão do pacote GEDAI-UE, CESP/CEFT ou PDF SISTOT correspondente para auditar a origem da urna."

    if sistot_occ or match_efet_cont or ceft_is_cont or ceft_div_silenciosa or ccont_match or cesp_trocou_ue:
        origem_urna = "RESERVA"
        if ceft_div_silenciosa or (cesp_trocou_ue and not ceft_is_cont and not sistot_occ):
            origem_label = "URNA RESERVA / SUBSTITUÍDA (CESP/CEFT)"
        else:
            origem_label = "URNA RESERVA (CONTINGÊNCIA)"
        fontes_reserva = []
        if match_efet_cont:
            fontes_reserva.append(f"GEDAI Contingência ({match_efet_cont['computador']})")
        if ccont_match:
            fontes_reserva.append(f"Pool CCONT (Z:{int(ccont_match['zona_reserva']):04d} / {ccont_match['maquina']})")
        if ceft_is_cont:
            fontes_reserva.append("CEFT TP_DIVERGENCIA='C'")
        elif ceft_div_silenciosa:
            fontes_reserva.append(f"CEFT Divergência Silenciosa (TP='{ceft_reg.get('tp_divergencia') or 'VAZIO'}')")
        if cesp_trocou_ue:
            fontes_reserva.append(f"Alteração CESP ({alt_cesp['snapshot_momento']})")
        if sistot_occ:
            fontes_reserva.append("SISTOT PDF")
        tit_str = ", ".join(sorted(titular_ids - {ue_norm})) if (titular_ids - {ue_norm}) else (", ".join(sorted(titular_ids)) if titular_ids else "não listada")
        origem_detalhe = (
            f"A seção foi apurada com a UE #{ue_norm or '-'} em substituição à Titular prevista (#{tit_str}). "
            f"Fontes confirmatórias: {' + '.join(fontes_reserva)}."
        )
    elif gedai_disponivel and titulares_gedai and ue_norm:
        ids_gedai_only = {t["id_urna_norm"] for t in titulares_gedai if t.get("id_urna_norm")}
        if ue_norm in ids_gedai_only:
            if len(ids_gedai_only) > 1:
                origem_urna = "TITULAR_REPREPARADA"
                origem_label = "URNA TITULAR (COM RE-PREPARAÇÃO NO GEDAI)"
                origem_detalhe = (
                    f"O GEDAI registrou {len(ids_gedai_only)} UEs distintas como SEÇÃO antes da eleição "
                    f"({', '.join(sorted(ids_gedai_only))}). A UE {ue_norm} foi a efetivada no BU/CEFT."
                )
            else:
                origem_urna = "TITULAR"
                origem_label = "URNA TITULAR DA SEÇÃO"
                t0 = titulares_gedai[0]
                sufixo_ceft = " e coincide 100% com o par CESP/CEFT (Esperada = Efetivada)" if (ceft_reg and ceft_reg.get("nr_urna_efetivada") == ue_norm) else ""
                origem_detalhe = (
                    f"A UE #{ue_norm} apurada no BU coincide 100% com a carga Titular preparada no GEDAI "
                    f"({t0['computador']} em {t0['data_hora'] or '-'}){sufixo_ceft}."
                )
        elif match_efet_outra_sec:
            origem_urna = "SUBSTITUTA_OUTRA_SECAO"
            origem_label = f"URNA REMANEJADA (Original Z:{int(match_efet_outra_sec['zona']):04d}/S:{int(match_efet_outra_sec['secao']):04d})"
            origem_detalhe = (
                f"A UE efetivada ({ue_norm}) constava no GEDAI como SEÇÃO da Zona {int(match_efet_outra_sec['zona']):04d} / "
                f"Seção {int(match_efet_outra_sec['secao']):04d}, enquanto a titular prevista era {', '.join(sorted(ids_gedai_only)) or '-'}."
            )
        else:
            origem_urna = "RESERVA"
            origem_label = "URNA RESERVA / DIVERGENTE DA TITULAR GEDAI"
            origem_detalhe = (
                f"A UE efetivada no BU ({ue_norm}) diverge da(s) UE(s) preparada(s) como SEÇÃO no GEDAI ({', '.join(sorted(ids_gedai_only))})."
            )
    elif ceft_reg and ceft_reg.get("nr_urna_esperada") and ceft_reg.get("nr_urna_efetivada"):
        if ceft_reg["nr_urna_esperada"] == ceft_reg["nr_urna_efetivada"] and not (ceft_reg.get("tp_divergencia") or ""):
            origem_urna = "TITULAR"
            origem_label = "URNA TITULAR (CESP × CEFT • SEM LOG GEDAI)"
            origem_detalhe = (
                f"Embora esta seção não conste no pacote .jez do GEDAI carregado, o arquivo oficial CEFT ({ceft_reg['maquina_geracao'] or '-'}) "
                f"confirma UE Esperada #{ceft_reg['nr_urna_esperada']} = UE Efetivada #{ceft_reg['nr_urna_efetivada']}."
            )
    elif gedai_disponivel and titulares_gedai and not ue_norm:
        origem_urna = "TITULAR_PRESUMIDA" if sistot_disponivel else "GEDAI_PREPARADA"
        origem_label = "TITULAR PREPARADA NO GEDAI (BU sem nº série UE)"
        t0 = titulares_gedai[0]
        origem_detalhe = (
            f"O GEDAI registrou carga titular na estação {t0['computador']} (UE {t0['id_urna']}), "
            f"mas o BU carregado não informou NR_URNA_EFETIVADA para confronto direto."
        )
    elif sistot_disponivel:
        origem_urna = "SEM_OCORRENCIA_SISTOT"
        origem_label = "SEM CONTINGÊNCIA NO SISTOT (Sem GEDAI/CEFT do turno)"
        origem_detalhe = (
            f"O Anexo de Contingências do SISTOT para {uf} ({turno}ºT) foi auditado e não registra substituição para esta seção. "
            f"Envie o GEDAI-UE ou CESP/CEFT do {turno}ºT para confirmar o serial da titular."
        )

    if teve_red and ceft_reg:
        origem_detalhe = f"[⚠️ RED: {ceft_reg.get('ds_origem_voto') or 'BU gerado por RED em urna de seção'}] " + origem_detalhe

    # 2. Classificação do Momento da Substituição (Início / Pré-votação vs Durante a Votação)
    pleito_abertura_dt = datetime(2026, 10, 4 if turno == 1 else 25, 8, 0, 0)
    dt_ab_bu = _parse_dt_br(hw.get("dt_abertura_bu"))
    momento_substituicao = "INDETERMINADO"
    momento_label = "Não determinável sem GEDAI/CESP/SISTOT"
    momento_detalhe = origem_detalhe

    if sistot_occ and sistot_occ.get("data_hora_ocorrencia"):
        dt_occ = _parse_dt_br(sistot_occ.get("data_hora_ocorrencia"))
        hora_occ_str = dt_occ.strftime("%H:%M:%S") if dt_occ else str(sistot_occ.get("data_hora_ocorrencia"))
        if dt_occ and dt_occ.date() < pleito_abertura_dt.date():
            momento_substituicao = "INICIO_PRE_VOTACAO"
            momento_label = f"SUBSTITUIÇÃO PRÉ-VOTAÇÃO ({sistot_occ['data_hora_ocorrencia']})"
            momento_detalhe = (
                f"Ocorrência SISTOT registrada em {sistot_occ['data_hora_ocorrencia']}, anterior ao dia da eleição ({pleito_abertura_dt.strftime('%d/%m/%Y')})."
            )
        elif dt_occ and dt_occ < pleito_abertura_dt:
            momento_substituicao = "INICIO_PRE_VOTACAO"
            momento_label = f"SUBSTITUIÇÃO NO INÍCIO / PRÉ-ABERTURA ({hora_occ_str})"
            momento_detalhe = (
                f"Contingência efetivada às {hora_occ_str} (antes das 08:00:00), durante os preparativos iniciais/zerésima antes da votação."
            )
        elif dt_occ and dt_ab_bu and dt_occ <= dt_ab_bu:
            momento_substituicao = "INICIO_PRE_VOTACAO"
            momento_label = f"SUBSTITUIÇÃO NO INÍCIO ({hora_occ_str})"
            momento_detalhe = (
                f"Efetivada às {hora_occ_str}, antes/no momento da abertura da votação registrada no BU ({hw.get('dt_abertura_bu')})."
            )
        else:
            momento_substituicao = "DURANTE_VOTACAO"
            momento_label = f"SUBSTITUIÇÃO DURANTE A VOTAÇÃO ({hora_occ_str})"
            ref_ab = f" (abertura do BU às {hw.get('dt_abertura_bu')})" if hw.get("dt_abertura_bu") else " (horário oficial 08h–17h)"
            momento_detalhe = (
                f"Contingência efetivada no SISTOT em {sistot_occ['data_hora_ocorrencia']}, já no decorrer do pleito{ref_ab}."
            )
    elif cesp_trocou_ue and alt_cesp:
        dt_nova = _parse_dt_br(alt_cesp.get("dt_carga_nova"))
        dt_str = alt_cesp.get("dt_carga_nova") or alt_cesp.get("snapshot_momento") or "-"
        if dt_nova and dt_nova.date() < pleito_abertura_dt.date():
            momento_substituicao = "INICIO_PRE_VOTACAO"
            momento_label = f"TROCA NA VÉSPERA (CESP {dt_nova.strftime('%d/%m %H:%M')})"
            momento_detalhe = (
                f"Troca registrada entre snapshots do CESP com nova preparação em {dt_str}, antes do dia da votação."
            )
        elif dt_nova and dt_nova <= datetime(2026, 10, 4 if turno == 1 else 25, 8, 30, 0):
            momento_substituicao = "INICIO_PRE_VOTACAO"
            momento_label = f"SUBSTITUIÇÃO NO INÍCIO DO PLEITO (CESP {dt_nova.strftime('%H:%M:%S')})"
            momento_detalhe = (
                f"O snapshot CESP de {alt_cesp['snapshot_momento']} acusou ST={alt_cesp['st']} com carga substituta às {dt_nova.strftime('%H:%M:%S')} (abertura da seção)."
            )
        else:
            momento_substituicao = "DURANTE_VOTACAO"
            momento_label = f"SUBSTITUIÇÃO DURANTE A VOTAÇÃO (CESP {dt_str})"
            momento_detalhe = (
                f"Alteração registrada no snapshot CESP de {alt_cesp['snapshot_momento']} (carga em {dt_str})."
            )
    elif origem_urna in ("RESERVA", "SUBSTITUTA_OUTRA_SECAO"):
        momento_substituicao = "HORARIO_INDISPONIVEL"
        momento_label = "TROCA CONFIRMADA (Horário requer PDF SISTOT)"
        extra_cesp = ""
        if csec_snaps and ceft_reg:
            ult_cesp = csec_snaps[-1]
            if ult_cesp.get("nr_urna_esperada") != ceft_reg.get("nr_urna_efetivada"):
                extra_cesp = f" (Não constava alterada no CESP de {ult_cesp.get('dt_geracao')} {ult_cesp.get('hh_geracao')}; apareceu efetivada no CEFT)."
        momento_detalhe = (
            "A substituição de equipamento foi confirmada via CESP/CEFT/GEDAI, "
            f"mas a hora exata da troca (início vs durante a votação) exige o PDF de Contingências (SISTOT) deste turno.{extra_cesp}"
        )
    elif origem_urna == "TITULAR_REPREPARADA":
        momento_substituicao = "PREPARACAO_CARTORIO"
        momento_label = "TROCA NA PREPARAÇÃO (PRÉ-ELEIÇÃO)"
        datas_gedai = sorted({str(t.get("data_hora") or "") for t in titulares_gedai if t.get("data_hora")})
        momento_detalhe = (
            f"Ocorreram múltiplas preparações em cartório no GEDAI ({datas_gedai[0]} → {datas_gedai[-1]}), antes do envio à seção."
            if len(datas_gedai) >= 2 else "Múltiplas preparações registradas no GEDAI em cartório antes do pleito."
        )
    elif origem_urna in ("TITULAR", "SEM_OCORRENCIA_SISTOT"):
        momento_substituicao = "SEM_SUBSTITUICAO"
        momento_label = "SEM SUBSTITUIÇÃO NA SEÇÃO"
        momento_detalhe = (
            "Nenhum evento de contingência ou troca de equipamento detectado para esta seção neste turno."
        )
        if alt_cesp and alt_cesp.get("st") == "S":
            momento_substituicao = "PREPARACAO_CARTORIO"
            momento_label = f"RE-GERAÇÃO CESP ST=S (Mesma UE em {alt_cesp.get('dt_carga_nova') or '-'})"
            momento_detalhe = (
                f"O CESP marcou ST=S no snapshot {alt_cesp.get('snapshot_momento')} mantendo a mesma UE #{ue_norm}."
            )

    if teve_red:
        momento_detalhe = f"[⚠️ Origem CEFT: {ceft_reg.get('ds_origem_voto')}] " + momento_detalhe

    decomposicao_urnas = None
    try:
        decomposicao_urnas = _calcular_decomposicao_urnas_turno(
            turno=turno,
            bu_db=bu_db,
            met_db=met_db,
            espelho=espelho,
            ciclos=ciclos,
            origem_urna=origem_urna,
            ue_norm=ue_norm,
            titular_ids=titular_ids,
            titulares_gedai=titulares_gedai,
            urna_efetivada_gedai=urna_efetivada_gedai,
            sistot_occ=sistot_occ,
            corresp_tse=corresp_tse,
            hw=hw,
        )
        if decomposicao_urnas and decomposicao_urnas.get("disponivel") and momento_substituicao == "HORARIO_INDISPONIVEL":
            ht = decomposicao_urnas.get("hora_troca") or "13h"
            if ht >= "09h":
                momento_substituicao = "DURANTE_VOTACAO"
                momento_label = f"SUBSTITUIÇÃO DURANTE A VOTAÇÃO (A PARTIR DAS {ht})"
                u1_obj = decomposicao_urnas.get("urna_1") or {}
                u2_obj = decomposicao_urnas.get("urna_2") or {}
                momento_detalhe = (
                    f"Substituição em andamento do pleito identificada às {ht}: "
                    f"Urna Titular #{u1_obj.get('serial')} ({u1_obj.get('votos_total')} eleitores / {u1_obj.get('pct_secao')}%) → "
                    f"Urna Reserva #{u2_obj.get('serial')} ({u2_obj.get('votos_total')} eleitores / {u2_obj.get('pct_secao')}%)."
                )
    except Exception as exc_dec:
        print(f"[TSE-DECOMP] Aviso ao calcular decomposição das urnas no turno {turno}: {exc_dec}")

    return {
        "turno": turno,
        "tem_bu": bu_db is not None,
        "gedai_disponivel": gedai_disponivel,
        "sistot_disponivel": sistot_disponivel,
        "corresp_disponivel": bool(corresp_tse.get("disponivel")),
        "teve_red": teve_red,
        "ue_efetivada": ue_norm,
        "ue_efetivada_pad": ue_pad,
        "carga_bu": hw.get("carga_bu"),
        "flashcard_bu": hw.get("flashcard_bu"),
        "dt_abertura_bu": hw.get("dt_abertura_bu"),
        "dt_encerramento_bu": hw.get("dt_encerramento_bu"),
        "origem_urna": origem_urna,
        "origem_label": origem_label,
        "origem_detalhe": origem_detalhe,
        "momento_substituicao": momento_substituicao,
        "momento_label": momento_label,
        "momento_detalhe": momento_detalhe,
        "titulares_gedai": titulares_gedai,
        "urna_efetivada_gedai": urna_efetivada_gedai,
        "sistot_ocorrencia": sistot_occ,
        "corresp_tse": corresp_tse,
        "decomposicao_urnas": decomposicao_urnas,
    }


def analisar_custodia_urna_secao(
    db,
    secao_db,
    bu1=None,
    bu2=None,
    espelho_1t: str = "",
    espelho_2t: str = "",
    met1=None,
    met2=None,
    ciclos_1t: Optional[list[dict[str, Any]]] = None,
    ciclos_2t: Optional[list[dict[str, Any]]] = None,
) -> dict[str, Any]:
    """
    Constrói a cadeia completa de custódia da urna (1º e 2º turnos) cruzando GEDAI-UE, BU e SISTOT PDF
    para identificar se votou com a Urna Titular ou Reserva e se a substituição foi pré-votação ou durante.
    """
    def _fallback_turno(t_num: int, bu_obj, esp_txt: str) -> dict[str, Any]:
        hw_fb = _extrair_metadados_hardware_bu(bu_obj, esp_txt)
        return {
            "turno": t_num,
            "tem_bu": bu_obj is not None,
            "gedai_disponivel": False,
            "sistot_disponivel": False,
            "corresp_disponivel": False,
            "teve_red": False,
            "ue_efetivada": hw_fb.get("ue_norm"),
            "ue_efetivada_pad": (hw_fb.get("ue_norm") or "").zfill(8) if hw_fb.get("ue_norm") else None,
            "carga_bu": hw_fb.get("carga_bu"),
            "flashcard_bu": hw_fb.get("flashcard_bu"),
            "dt_abertura_bu": hw_fb.get("dt_abertura_bu"),
            "dt_encerramento_bu": hw_fb.get("dt_encerramento_bu"),
            "origem_urna": "INDETERMINADO",
            "origem_label": "Sem dados GEDAI/CESP/SISTOT deste turno",
            "origem_detalhe": "Faça a ingestão do pacote GEDAI-UE, CESP/CEFT ou PDF SISTOT correspondente para auditar a origem da urna.",
            "momento_substituicao": "INDETERMINADO",
            "momento_label": "Não determinável sem GEDAI/CESP/SISTOT",
            "momento_detalhe": "Faça a ingestão do pacote GEDAI-UE, CESP/CEFT ou PDF SISTOT correspondente para auditar a origem da urna.",
            "titulares_gedai": [],
            "urna_efetivada_gedai": None,
            "sistot_ocorrencia": None,
            "corresp_tse": {"disponivel": False, "base_turno_carregada": False, "csec_snapshots": [], "ceft": None, "alteracao_cesp": None, "ccont_match": None},
            "decomposicao_urnas": None,
        }

    try:
        info_t1 = _classificar_custodia_turno(db, secao_db, 1, bu1, espelho_1t, ciclos_1t, met_db=met1)
    except Exception as exc_t1:
        print(f"[TSE-CUSTODIA] Aviso turno 1: {exc_t1}")
        info_t1 = _fallback_turno(1, bu1, espelho_1t)

    try:
        info_t2 = _classificar_custodia_turno(db, secao_db, 2, bu2, espelho_2t, ciclos_2t, met_db=met2)
    except Exception as exc_t2:
        print(f"[TSE-CUSTODIA] Aviso turno 2: {exc_t2}")
        info_t2 = _fallback_turno(2, bu2, espelho_2t)

    ue1 = info_t1.get("ue_efetivada")
    ue2 = info_t2.get("ue_efetivada")
    mesma_ue = None
    if ue1 and ue2:
        mesma_ue = (ue1 == ue2)
        if mesma_ue:
            resumo_hw = f"Mesma UE física ({ue1}) utilizada no 1º e no 2º Turno."
        else:
            resumo_hw = f"Equipamento físico ALTERADO entre turnos: 1ºT UE {ue1} → 2ºT UE {ue2}."
    elif ue1 or ue2:
        resumo_hw = f"Hardware identificado apenas em um turno ({'1ºT: ' + ue1 if ue1 else '2ºT: ' + ue2})."
    else:
        resumo_hw = "Número de série da UE efetivada não disponível nos BUs carregados."

    return {
        "turno_1": info_t1,
        "turno_2": info_t2,
        "comparativo_hardware": {
            "ue_t1": ue1,
            "ue_t2": ue2,
            "mesma_urna_1t_2t": mesma_ue,
            "resumo": resumo_hw,
        },
    }
