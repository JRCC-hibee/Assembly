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

    corresp_mappings: list[dict[str, Any]] = []
    for est in compilado["estacoes"]:
        est_db = TseGedaiEstacao(
            lote_id=lote_db.id,
            nome_arquivo=est["nome_arquivo"],
            computador=est["computador"],
            zona_computador=est["zona_computador"],
            serial_tpm=est["serial_tpm"],
            serial_instalacao=est["serial_instalacao"],
            uf=est["uf"],
            pleito=est["pleito"],
            turno=est["turno"],
            versao_gedai=est["versao_gedai"],
            possui_vsc=est["possui_vsc"],
            usuarios_windows_json=json.dumps(est["usuarios_windows"], ensure_ascii=False),
            usuarios_odin_json=json.dumps(est["usuarios_odin"], ensure_ascii=False),
            primeira_data_hora=est["primeira_data_hora"],
            ultima_data_hora=est["ultima_data_hora"],
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
                "computador": c["computador"],
                "tipo": c["tipo"],
                "acao": c["acao"],
                "municipio_codigo": c["municipio_codigo"],
                "municipio_nome": c.get("municipio_nome") or "",
                "zona": c["zona"],
                "secao": c["secao"],
                "codigo_carga": c["codigo_carga"],
                "id_urna": c["id_urna"],
                "midia_carga": c["midia_carga"],
                "data_hora": c["data_hora"],
                "operador": c["operador"],
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
    diretorios = ["/root/tse_import", "/app/tse_import", "/root/Downloads"]
    encontrados: list[dict[str, Any]] = []
    vistos: set[str] = set()

    for base_dir in diretorios:
        if not os.path.isdir(base_dir):
            continue
        try:
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
                    qtd_jez = sum(1 for f in os.listdir(full) if f.lower().endswith(".jez"))
                    if qtd_jez > 0:
                        vistos.add(full)
                        encontrados.append({
                            "nome": item,
                            "caminho": full,
                            "tipo": f"PASTA ({qtd_jez} .jez)",
                            "tamanho_mb": round(
                                sum(
                                    os.path.getsize(os.path.join(full, f))
                                    for f in os.listdir(full)
                                    if f.lower().endswith(".jez")
                                ) / (1024 * 1024),
                                2,
                            ),
                        })
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
