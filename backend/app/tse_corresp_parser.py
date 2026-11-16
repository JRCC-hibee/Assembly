"""
Parser e Motor Forense para pacotes oficiais do TSE de Correspondência Esperada (CESP: csec/ccont)
e Correspondência Efetivada (CEFT: ceft), com cruzamento direto contra logs GEDAI-UE, BU e SISTOT.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import re
import zipfile
from typing import Any, Optional

from sqlalchemy import func

from .database import (
    ESTADOS_E_REGIOES_BR,
    TseCorrespArquivo,
    TseCorrespRegistro,
    TseGedaiCorrespondencia,
    TseGedaiEstacao,
    TseGedaiLote,
)


def _limpar_campo(val: Any) -> str:
    s = str(val or "").strip()
    if s.upper() in ("#NULO", "#NULO#", "#NE", "NONE", "NULL") or s in ("-1", "-3"):
        return ""
    return s


def _norm_ue_num(val: Any) -> str:
    s = _limpar_campo(val)
    if not s:
        return ""
    dig = re.sub(r"[^0-9A-Za-z]", "", s)
    if dig.isdigit():
        return str(int(dig))
    return dig.lstrip("0") or dig


def _norm_momento(dt_str: str, hh_str: str) -> str:
    dt = _limpar_campo(dt_str)
    hh = _limpar_campo(hh_str) or "00:00:00"
    m = re.match(r"^(\d{2})/(\d{2})/(\d{4})$", dt)
    if m:
        dt_iso = f"{m.group(3)}-{m.group(2)}-{m.group(1)}"
        return f"{dt_iso} {hh[:8]}"
    return f"{dt} {hh}".strip()


def _detectar_turno(nome_arq: str, pleito: str) -> int:
    pl = re.sub(r"\D", "", str(pleito or ""))
    if pl.endswith("221") or pl.endswith("407"):
        return 2
    low = (nome_arq or "").lower()
    if "_2t_" in low or "2t_" in low or "2turno" in low:
        return 2
    return 1


def _detectar_tipo_corresp_csv(nome_arq: str, fieldnames: list[str]) -> Optional[str]:
    cols = {str(c or "").strip().upper() for c in fieldnames}
    if "NR_URNA_EFETIVADA" in cols or "SQ_CORRESPONDENCIA_EFETIVADA" in cols:
        return "CEFT"
    if "NR_URNA_ESPERADA" in cols and "NR_SECAO" in cols:
        return "CESP_CSEC"
    if "NR_URNA_ESPERADA" in cols and "NR_ZONA" in cols:
        return "CESP_CCONT"
    low = os.path.basename(nome_arq or "").lower()
    if low.startswith("ceft"):
        return "CEFT"
    if low.startswith("csec"):
        return "CESP_CSEC"
    if low.startswith("ccont"):
        return "CESP_CCONT"
    return None


def _decodificar_texto_csv(raw_bytes: bytes) -> str:
    for enc in ("utf-8-sig", "latin1", "cp1252"):
        try:
            return raw_bytes.decode(enc)
        except Exception:
            continue
    return raw_bytes.decode("latin1", errors="replace")


def _extrair_csvs_entrada(
    arquivos_individuais: Optional[list[tuple[str, bytes]]] = None,
    zip_bytes: Optional[bytes] = None,
    zip_path: Optional[str] = None,
) -> list[tuple[str, bytes]]:
    """Extrai pares `(nome_csv, bytes)` de um `.zip` ou de arquivos `.csv`/`.zip` enviados."""
    out: list[tuple[str, bytes]] = []

    def _ler_zip(buf: bytes) -> None:
        with zipfile.ZipFile(io.BytesIO(buf), "r") as zf:
            for nm in sorted(zf.namelist()):
                if nm.lower().endswith(".csv") and not os.path.basename(nm).startswith("."):
                    out.append((os.path.basename(nm), zf.read(nm)))

    if zip_bytes is not None:
        _ler_zip(zip_bytes)
    elif zip_path:
        with open(zip_path, "rb") as fp:
            _ler_zip(fp.read())

    for nm, raw in (arquivos_individuais or []):
        low = (nm or "").lower()
        if low.endswith(".zip"):
            try:
                _ler_zip(raw)
            except Exception as exc:
                print(f"[CORRESP] Aviso ao abrir ZIP {nm}: {exc}")
        elif low.endswith(".csv"):
            out.append((os.path.basename(nm), raw))
    return out


def _int_ou_zero(val: Any) -> int:
    s = _limpar_campo(val)
    if not s:
        return 0
    try:
        return int(float(s))
    except Exception:
        return 0


def processar_corresp_csv_para_banco(
    db,
    nome_origem: str,
    raw_bytes: bytes,
) -> dict[str, Any]:
    """Lê um único CSV `csec_*.csv`, `ccont_*.csv` ou `ceft_*.csv` e grava em `tse_corresp_arquivos/registros`."""
    sha = hashlib.sha256(raw_bytes).hexdigest()
    existente = db.query(TseCorrespArquivo).filter(TseCorrespArquivo.hash_sha256 == sha).first()
    if existente:
        return {
            "status": "JA_EXISTENTE",
            "arquivo_id": existente.id,
            "tipo_arquivo": existente.tipo_arquivo,
            "nome_origem": existente.nome_origem,
            "uf": existente.uf,
            "turno": existente.turno,
            "momento_geracao": existente.momento_geracao,
            "total_registros": existente.total_registros,
        }

    txt = _decodificar_texto_csv(raw_bytes)
    reader = csv.DictReader(io.StringIO(txt), delimiter=";")
    if not reader.fieldnames:
        raise ValueError(f"Arquivo CSV sem cabeçalho válido: {nome_origem}")

    tipo_arq = _detectar_tipo_corresp_csv(nome_origem, reader.fieldnames)
    if not tipo_arq:
        raise ValueError(f"Layout CSV não reconhecido como CESP (csec/ccont) ou CEFT: {nome_origem}")

    tipo_reg = "CEFT" if tipo_arq == "CEFT" else ("CSEC" if tipo_arq == "CESP_CSEC" else "CCONT")

    rows_bulk: list[dict[str, Any]] = []
    uf_val = ""
    pleito_val = ""
    dt_ger = ""
    hh_ger = ""
    momento = ""
    turno_val = 1
    tot_alt = 0
    tot_cont_ceft = 0
    tot_red = 0

    for row in reader:
        if not uf_val:
            uf_val = _limpar_campo(row.get("SG_UF")).upper() or "PR"
            pleito_val = _limpar_campo(row.get("CD_PLEITO")).zfill(5) if _limpar_campo(row.get("CD_PLEITO")).isdigit() else _limpar_campo(row.get("CD_PLEITO"))
            dt_ger = _limpar_campo(row.get("DT_GERACAO"))
            hh_ger = _limpar_campo(row.get("HH_GERACAO"))
            momento = _norm_momento(dt_ger, hh_ger)
            turno_val = _detectar_turno(nome_origem, pleito_val)

        mun_cod = _limpar_campo(row.get("CD_MUNICIPIO")).zfill(5)
        mun_nm = _limpar_campo(row.get("NM_MUNICIPIO"))[:120]
        zona_i = _int_ou_zero(row.get("NR_ZONA"))
        sec_i = _int_ou_zero(row.get("NR_SECAO")) if tipo_reg != "CCONT" else 0
        loc_v = _int_ou_zero(row.get("NR_LOCAL_VOTACAO")) or None

        ue_esp = _norm_ue_num(row.get("NR_URNA_ESPERADA"))[:16]
        cg_esp = _limpar_campo(row.get("CD_CARGA_URNA_ESPERADA"))[:40]
        fc_esp = _limpar_campo(row.get("CD_FLASHCARD_URNA_ESPERADA")).upper()[:24]
        dt_c_esp = _limpar_campo(row.get("DT_CARGA_URNA_ESPERADA"))[:30]
        dt_r_esp = _limpar_campo(row.get("DT_RECBTO_URNA_ESPERADA"))[:30]
        st_alt = _limpar_campo(row.get("ST_CORRESP_ALTERADA"))[:10]

        sq_esp = _limpar_campo(row.get("SQ_CORRESPONDENCIA_ESPERADA"))[:24]
        sq_efet = _limpar_campo(row.get("SQ_CORRESPONDENCIA_EFETIVADA"))[:24]
        ue_efet = _norm_ue_num(row.get("NR_URNA_EFETIVADA"))[:16]
        cg_efet = _limpar_campo(row.get("CD_CARGA_URNA_EFETIVADA"))[:40]
        fc_efet = _limpar_campo(row.get("CD_FLASHCARD_URNA_EFETIVADA")).upper()[:24]
        dt_c_efet = _limpar_campo(row.get("DT_CARGA_URNA_EFETIVADA"))[:30]
        dt_r_efet = _limpar_campo(row.get("DT_RECBTO_URNA_EFETIVADA"))[:30]

        cd_orig = _limpar_campo(row.get("CD_ORIGEM_VOTO")).upper()[:8]
        ds_orig = _limpar_campo(row.get("DS_ORIGEM_VOTO"))[:120]
        tp_div = _limpar_campo(row.get("TP_DIVERGENCIA")).upper()[:8]

        if tipo_reg == "CSEC" and st_alt == "S":
            tot_alt += 1
        elif tipo_reg == "CEFT":
            if tp_div == "C":
                tot_cont_ceft += 1
                tot_alt += 1
            elif tp_div or (ue_esp and ue_efet and ue_esp != ue_efet):
                tot_alt += 1
            if cd_orig == "R":
                tot_red += 1

        rows_bulk.append({
            "tipo_registro": tipo_reg,
            "uf": uf_val[:10],
            "turno": turno_val,
            "momento_geracao": momento[:30],
            "municipio_codigo": mun_cod[:10],
            "municipio_nome": mun_nm,
            "zona": zona_i,
            "secao": sec_i,
            "local_votacao": loc_v,
            "nr_urna_esperada": ue_esp or None,
            "cd_carga_esperada": cg_esp or None,
            "cd_flashcard_esperada": fc_esp or None,
            "dt_carga_esperada": dt_c_esp or None,
            "dt_recbto_esperada": dt_r_esp or None,
            "st_corresp_alterada": st_alt or None,
            "sq_corresp_esperada": sq_esp or None,
            "sq_corresp_efetivada": sq_efet or None,
            "nr_urna_efetivada": ue_efet or None,
            "cd_carga_efetivada": cg_efet or None,
            "cd_flashcard_efetivada": fc_efet or None,
            "dt_carga_efetivada": dt_c_efet or None,
            "dt_recbto_efetivada": dt_r_efet or None,
            "cd_origem_voto": cd_orig or None,
            "ds_origem_voto": ds_orig or None,
            "tp_divergencia": tp_div or "",
            "nm_maquina_geracao": _limpar_campo(row.get("NM_MAQUINA_GERACAO_MIDIA"))[:60] or None,
            "nr_sri_tpm_geracao": _limpar_campo(row.get("NR_SRI_TPM_GERACAO_MIDIA"))[:128] or None,
            "nr_sri_instal_geracao": _limpar_campo(row.get("NR_SRI_INSTAL_GERACAO_MIDIA"))[:64] or None,
            "nm_maquina_transm": _limpar_campo(row.get("NM_MAQUINA_TRANSM_CORRESP"))[:60] or None,
            "nr_sri_tpm_transm": _limpar_campo(row.get("NR_SRI_TPM_TRANSM_CORRESP"))[:128] or None,
            "nr_sri_instal_transm": _limpar_campo(row.get("NR_SRI_INSTAL_TRANSM_CORRESP"))[:64] or None,
        })

    if not rows_bulk:
        raise ValueError(f"Arquivo CSV sem registros de correspondência: {nome_origem}")

    arq_db = TseCorrespArquivo(
        tipo_arquivo=tipo_arq,
        nome_origem=os.path.basename(nome_origem)[:255],
        uf=uf_val[:10],
        turno=turno_val,
        pleito=pleito_val[:10],
        dt_geracao=dt_ger[:25],
        hh_geracao=hh_ger[:20],
        momento_geracao=momento[:30],
        hash_sha256=sha,
        total_registros=len(rows_bulk),
        total_alteradas=tot_alt,
        total_contingencias_ceft=tot_cont_ceft,
        total_red=tot_red,
        resumo_json=json.dumps({
            "tipo_registro": tipo_reg,
            "total_registros": len(rows_bulk),
            "total_alteradas": tot_alt,
            "total_contingencias_ceft": tot_cont_ceft,
            "total_red": tot_red,
        }, ensure_ascii=False),
    )
    db.add(arq_db)
    db.flush()

    for r in rows_bulk:
        r["arquivo_id"] = arq_db.id

    for i in range(0, len(rows_bulk), 5000):
        db.bulk_insert_mappings(TseCorrespRegistro, rows_bulk[i:i + 5000])
    db.commit()

    return {
        "status": "PROCESSADO",
        "arquivo_id": arq_db.id,
        "tipo_arquivo": tipo_arq,
        "nome_origem": arq_db.nome_origem,
        "uf": arq_db.uf,
        "turno": arq_db.turno,
        "momento_geracao": arq_db.momento_geracao,
        "total_registros": len(rows_bulk),
        "total_alteradas": tot_alt,
        "total_contingencias_ceft": tot_cont_ceft,
        "total_red": tot_red,
    }


def processar_pacote_corresp_para_banco(
    db,
    arquivos_individuais: Optional[list[tuple[str, bytes]]] = None,
    zip_bytes: Optional[bytes] = None,
    zip_path: Optional[str] = None,
) -> dict[str, Any]:
    """Processa lote de arquivos/ZIPs CESP e CEFT retornando o resumo por CSV importado."""
    csvs = _extrair_csvs_entrada(
        arquivos_individuais=arquivos_individuais,
        zip_bytes=zip_bytes,
        zip_path=zip_path,
    )
    if not csvs:
        raise ValueError("Nenhum CSV válido (csec_*.csv, ccont_*.csv ou ceft_*.csv) encontrado no pacote.")

    resultados = []
    for nm, raw in csvs:
        try:
            resultados.append(processar_corresp_csv_para_banco(db, nm, raw))
        except Exception as exc:
            resultados.append({"status": "IGNORADO", "nome_origem": nm, "erro": str(exc)})

    processados = [r for r in resultados if r.get("status") in ("PROCESSADO", "JA_EXISTENTE")]
    if not processados:
        msgs = "; ".join(r.get("erro", "") for r in resultados if r.get("erro"))
        raise ValueError(msgs or "Nenhum CSV CESP/CEFT pôde ser importado.")

    return {
        "status": "CONCLUIDO",
        "total_arquivos": len(processados),
        "resultados": resultados,
    }


def detectar_arquivos_corresp_servidor() -> list[dict[str, Any]]:
    """Escaneia pastas do servidor por pacotes `CESP_*.zip`, `CEFT_*.zip` ou CSVs/pastas equivalentes."""
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

    for base_dir in diretorios:
        if not os.path.isdir(base_dir):
            continue
        try:
            for item in sorted(os.listdir(base_dir)):
                low = item.lower()
                is_corresp_nome = (
                    low.startswith("cesp_")
                    or low.startswith("ceft_")
                    or low.startswith("csec_")
                    or low.startswith("ccont_")
                )
                if not is_corresp_nome:
                    continue
                full = os.path.join(base_dir, item)
                if full in vistos:
                    continue
                if os.path.isfile(full) and (low.endswith(".zip") or low.endswith(".csv")):
                    vistos.add(full)
                    encontrados.append({
                        "nome": item,
                        "caminho": full,
                        "tipo": "CORRESP_ZIP" if low.endswith(".zip") else "CORRESP_CSV",
                        "tamanho_mb": round(os.path.getsize(full) / (1024 * 1024), 2),
                    })
                elif os.path.isdir(full):
                    csvs = [f for f in os.listdir(full) if f.lower().endswith(".csv")]
                    if csvs:
                        vistos.add(full)
                        tam = sum(os.path.getsize(os.path.join(full, f)) for f in csvs)
                        encontrados.append({
                            "nome": item,
                            "caminho": full,
                            "tipo": f"CORRESP_PASTA ({len(csvs)} .csv)",
                            "tamanho_mb": round(tam / (1024 * 1024), 2),
                        })
        except Exception:
            continue

    return encontrados


def processar_caminho_corresp_servidor(db, caminho: Optional[str] = None) -> dict[str, Any]:
    """Ingere pacotes/pastas/CSVs CESP e CEFT presentes no servidor."""
    alvos = [caminho] if caminho else [d["caminho"] for d in detectar_arquivos_corresp_servidor()]
    if not alvos:
        return {"status": "NENHUM_ARQUIVO", "total_processados": 0, "processados": []}

    resultados = []
    for alvo in alvos:
        if not alvo or not os.path.exists(alvo):
            continue
        if os.path.isfile(alvo) and alvo.lower().endswith(".zip"):
            resultados.append(processar_pacote_corresp_para_banco(db, zip_path=alvo))
        elif os.path.isfile(alvo) and alvo.lower().endswith(".csv"):
            with open(alvo, "rb") as fp:
                resultados.append(processar_pacote_corresp_para_banco(db, arquivos_individuais=[(os.path.basename(alvo), fp.read())]))
        elif os.path.isdir(alvo):
            pares = []
            for fn in sorted(os.listdir(alvo)):
                if fn.lower().endswith(".csv"):
                    with open(os.path.join(alvo, fn), "rb") as fp:
                        pares.append((fn, fp.read()))
            if pares:
                resultados.append(processar_pacote_corresp_para_banco(db, arquivos_individuais=pares))

    return {
        "status": "CONCLUIDO",
        "total_processados": sum(r.get("total_arquivos", 1) for r in resultados),
        "processados": resultados,
    }


def _carregar_ocorrencias_cruzadas(db, uf: str, turno: int) -> dict[str, Any]:
    """
    Executa o cruzamento completo entre snapshots CESP (`csec`/`ccont`), CEFT (`ceft`) e GEDAI-UE
    para a combinação `(uf, turno)` e retorna métricas resumidas + lista unificada de ocorrências.
    """
    arqs = (
        db.query(TseCorrespArquivo)
        .filter(TseCorrespArquivo.uf == uf, TseCorrespArquivo.turno == turno)
        .order_by(TseCorrespArquivo.momento_geracao.asc(), TseCorrespArquivo.id.asc())
        .all()
    )
    if not arqs:
        return {"disponivel": False, "uf": uf, "turno": turno, "arquivos": [], "resumo": {}, "ocorrencias": []}

    csec_arqs = [a for a in arqs if a.tipo_arquivo == "CESP_CSEC"]
    ccont_arqs = [a for a in arqs if a.tipo_arquivo == "CESP_CCONT"]
    ceft_arq = max((a for a in arqs if a.tipo_arquivo == "CEFT"), key=lambda a: (a.momento_geracao or "", a.id), default=None)

    # Carrega CSEC em ordem cronológica por chave (mun_cod, zona, secao)
    csec_por_arq: list[tuple[TseCorrespArquivo, dict[tuple[str, int, int], dict[str, Any]]]] = []
    for a in csec_arqs:
        rows = (
            db.query(
                TseCorrespRegistro.municipio_codigo,
                TseCorrespRegistro.municipio_nome,
                TseCorrespRegistro.zona,
                TseCorrespRegistro.secao,
                TseCorrespRegistro.nr_urna_esperada,
                TseCorrespRegistro.cd_carga_esperada,
                TseCorrespRegistro.cd_flashcard_esperada,
                TseCorrespRegistro.dt_carga_esperada,
                TseCorrespRegistro.st_corresp_alterada,
                TseCorrespRegistro.nm_maquina_geracao,
                TseCorrespRegistro.nr_sri_tpm_geracao,
            )
            .filter(TseCorrespRegistro.arquivo_id == a.id, TseCorrespRegistro.tipo_registro == "CSEC")
            .all()
        )
        mapa = {
            (r[0], int(r[2] or 0), int(r[3] or 0)): {
                "mun_cod": r[0], "mun_nome": r[1], "zona": int(r[2] or 0), "secao": int(r[3] or 0),
                "ue": r[4] or "", "carga": r[5] or "", "mc": r[6] or "",
                "dt_carga": r[7] or "", "st": r[8] or "", "maq": r[9] or "", "tpm": r[10] or "",
            }
            for r in rows
        }
        csec_por_arq.append((a, mapa))

    # Pool CCONT (último snapshot CCONT disponível para checar reservas)
    ccont_ues: dict[str, dict[str, Any]] = {}
    if ccont_arqs:
        ult_cc = ccont_arqs[-1]
        for r in (
            db.query(
                TseCorrespRegistro.nr_urna_esperada,
                TseCorrespRegistro.nm_maquina_geracao,
                TseCorrespRegistro.nr_sri_tpm_geracao,
                TseCorrespRegistro.cd_flashcard_esperada,
                TseCorrespRegistro.dt_carga_esperada,
            )
            .filter(TseCorrespRegistro.arquivo_id == ult_cc.id, TseCorrespRegistro.tipo_registro == "CCONT")
            .all()
        ):
            if r[0]:
                ccont_ues[r[0]] = {"maq": r[1] or "", "tpm": r[2] or "", "mc": r[3] or "", "dt_carga": r[4] or ""}

    # CEFT efetivado
    ceft_mapa: dict[tuple[str, int, int], dict[str, Any]] = {}
    if ceft_arq:
        for r in (
            db.query(
                TseCorrespRegistro.municipio_codigo,
                TseCorrespRegistro.municipio_nome,
                TseCorrespRegistro.zona,
                TseCorrespRegistro.secao,
                TseCorrespRegistro.nr_urna_esperada,
                TseCorrespRegistro.nr_urna_efetivada,
                TseCorrespRegistro.cd_carga_esperada,
                TseCorrespRegistro.cd_carga_efetivada,
                TseCorrespRegistro.cd_flashcard_efetivada,
                TseCorrespRegistro.dt_carga_esperada,
                TseCorrespRegistro.dt_carga_efetivada,
                TseCorrespRegistro.dt_recbto_efetivada,
                TseCorrespRegistro.cd_origem_voto,
                TseCorrespRegistro.ds_origem_voto,
                TseCorrespRegistro.tp_divergencia,
                TseCorrespRegistro.nm_maquina_geracao,
                TseCorrespRegistro.nr_sri_tpm_geracao,
            )
            .filter(TseCorrespRegistro.arquivo_id == ceft_arq.id, TseCorrespRegistro.tipo_registro == "CEFT")
            .all()
        ):
            ceft_mapa[(r[0], int(r[2] or 0), int(r[3] or 0))] = {
                "mun_cod": r[0], "mun_nome": r[1], "zona": int(r[2] or 0), "secao": int(r[3] or 0),
                "ue_esp": r[4] or "", "ue_efet": r[5] or "",
                "cg_esp": r[6] or "", "cg_efet": r[7] or "",
                "mc_efet": r[8] or "", "dt_carga_esp": r[9] or "", "dt_carga_efet": r[10] or "",
                "dt_rec_efet": r[11] or "", "cd_orig": r[12] or "", "ds_orig": r[13] or "",
                "tp_div": r[14] or "", "maq": r[15] or "", "tpm": r[16] or "",
            }

    # Conjuntos do GEDAI carregado no banco para (uf, turno)
    gedai_lotes = db.query(TseGedaiLote).filter(TseGedaiLote.uf == uf, TseGedaiLote.turno == turno).all()
    gedai_disponivel = len(gedai_lotes) > 0
    gedai_secoes_set: set[tuple[str, int, int]] = set()
    gedai_cont_ues_set: set[str] = set()
    gedai_estacoes_tpm: dict[str, set[str]] = {}
    if gedai_disponivel:
        lote_ids = [l.id for l in gedai_lotes]
        for (mc, z, s, tp, idu) in (
            db.query(
                TseGedaiCorrespondencia.municipio_codigo,
                TseGedaiCorrespondencia.zona,
                TseGedaiCorrespondencia.secao,
                TseGedaiCorrespondencia.tipo,
                TseGedaiCorrespondencia.id_urna,
            )
            .filter(TseGedaiCorrespondencia.lote_id.in_(lote_ids))
            .all()
        ):
            if tp == "SECAO":
                gedai_secoes_set.add((mc, int(z or 0), int(s or 0)))
            elif tp == "CONTINGENCIA" and idu:
                gedai_cont_ues_set.add(_norm_ue_num(idu))
        for (comp, stpm) in (
            db.query(TseGedaiEstacao.computador, TseGedaiEstacao.serial_tpm)
            .filter(TseGedaiEstacao.lote_id.in_(lote_ids))
            .all()
        ):
            if comp:
                gedai_estacoes_tpm.setdefault(comp, set()).add((stpm or "")[:8].upper())

    ocorrencias: list[dict[str, Any]] = []
    vistas_chaves_oc: set[tuple[str, str, int, int]] = set()

    qtd_alter_cesp = 0
    qtd_cont_ceft = 0
    qtd_div_silenciosa = 0
    qtd_red = 0
    qtd_cont_fora_gedai = 0

    # 1. Alterações detectadas no CESP (ST='S' ou mudança de UE entre snapshots CESP)
    if len(csec_por_arq) >= 1:
        base_map = csec_por_arq[0][1]
        for idx_s, (arq_s, map_s) in enumerate(csec_por_arq):
            for k, row_s in map_s.items():
                alt_snap = False
                ue_ant = ""
                if idx_s > 0:
                    row_ant = base_map.get(k)
                    if row_s["st"] in ("S", "*"):
                        alt_snap = True
                        ue_ant = row_ant["ue"] if row_ant else "(Nova)"
                    elif row_ant and row_ant["ue"] and row_s["ue"] and row_ant["ue"] != row_s["ue"]:
                        alt_snap = True
                        ue_ant = row_ant["ue"]
                if alt_snap:
                    qtd_alter_cesp += 1
                    cf = ceft_mapa.get(k, {})
                    no_gedai = (k in gedai_secoes_set) if gedai_disponivel else None
                    tp_oc = "ALTERACAO_CESP"
                    vistas_chaves_oc.add((tp_oc, k[0], k[1], k[2]))
                    ocorrencias.append({
                        "categoria": tp_oc,
                        "severidade": "ALERTA" if (cf.get("tp_div") == "" and row_s["dt_carga"].startswith("2026-10-04")) else "INFO",
                        "municipio_codigo": k[0],
                        "municipio_nome": row_s["mun_nome"],
                        "zona": k[1],
                        "secao": k[2],
                        "ue_esperada": ue_ant or row_s["ue"],
                        "ue_efetivada": cf.get("ue_efet") or row_s["ue"],
                        "dt_carga_esperada": row_s["dt_carga"],
                        "dt_carga_efetivada": cf.get("dt_carga_efet") or row_s["dt_carga"],
                        "flashcard": cf.get("mc_efet") or row_s["mc"],
                        "maquina": row_s["maq"],
                        "tpm": row_s["tpm"],
                        "tp_divergencia": cf.get("tp_div") or row_s["st"],
                        "presente_no_gedai": no_gedai,
                        "detalhe": (
                            f"CESP ({arq_s.dt_geracao} {arq_s.hh_geracao}) marcou ST={row_s['st']}: "
                            f"UE {ue_ant or '-'} → {row_s['ue']} em {row_s['dt_carga']}"
                            + (" (UE veio do pool CCONT Contingência)" if row_s["ue"] in ccont_ues else "")
                        ),
                    })

    # 2. Eventos do CEFT (Contingência C, Divergência Silenciosa, Origem RED, Ausente no GEDAI)
    secoes_base = ceft_mapa if ceft_mapa else (csec_por_arq[-1][1] if csec_por_arq else {})
    qtd_ausentes_gedai = 0
    maquinas_ausentes_gedai: set[str] = set()

    for k, row in secoes_base.items():
        no_gedai = (k in gedai_secoes_set) if gedai_disponivel else None
        if gedai_disponivel and not no_gedai:
            qtd_ausentes_gedai += 1
            if row.get("maq"):
                maquinas_ausentes_gedai.add(row["maq"])

        if not ceft_mapa:
            continue

        tp_div = row.get("tp_div") or ""
        cd_orig = row.get("cd_orig") or ""
        ue_esp = row.get("ue_esp") or ""
        ue_efet = row.get("ue_efet") or ""
        cg_esp = row.get("cg_esp") or ""
        cg_efet = row.get("cg_efet") or ""

        if cd_orig == "R":
            qtd_red += 1
            ocorrencias.append({
                "categoria": "RED_RECUPERACAO",
                "severidade": "ALERTA",
                "municipio_codigo": k[0], "municipio_nome": row["mun_nome"],
                "zona": k[1], "secao": k[2],
                "ue_esperada": ue_esp, "ue_efetivada": ue_efet,
                "dt_carga_esperada": row["dt_carga_esp"], "dt_carga_efetivada": row["dt_carga_efet"],
                "flashcard": row["mc_efet"], "maquina": row["maq"], "tpm": row["tpm"],
                "tp_divergencia": tp_div or "RED", "presente_no_gedai": no_gedai,
                "detalhe": f"{row['ds_orig']} (CD={cd_orig}, TP_DIV={tp_div or 'NULO'}).",
            })

        if tp_div == "C":
            qtd_cont_ceft += 1
            em_gedai_cont = (ue_efet in gedai_cont_ues_set) if gedai_disponivel else None
            if gedai_disponivel and not em_gedai_cont:
                qtd_cont_fora_gedai += 1
            ocorrencias.append({
                "categoria": "CONTINGENCIA_CEFT",
                "severidade": "INFO",
                "municipio_codigo": k[0], "municipio_nome": row["mun_nome"],
                "zona": k[1], "secao": k[2],
                "ue_esperada": ue_esp, "ue_efetivada": ue_efet,
                "dt_carga_esperada": row["dt_carga_esp"], "dt_carga_efetivada": row["dt_carga_efet"],
                "flashcard": row["mc_efet"], "maquina": row["maq"], "tpm": row["tpm"],
                "tp_divergencia": "C", "presente_no_gedai": em_gedai_cont,
                "detalhe": (
                    f"Contingência efetivada no CEFT: Titular #{ue_esp} → Reserva #{ue_efet}"
                    + ("" if em_gedai_cont is not False else " [Reserva ausente nos logs GEDAI carregados]")
                ),
            })
        elif (ue_esp and ue_efet and ue_esp != ue_efet) or (cg_esp and cg_efet and cg_esp != cg_efet):
            qtd_div_silenciosa += 1
            em_ccont = ue_efet in ccont_ues
            ocorrencias.append({
                "categoria": "DIVERGENCIA_SILENCIOSA",
                "severidade": "ALERTA",
                "municipio_codigo": k[0], "municipio_nome": row["mun_nome"],
                "zona": k[1], "secao": k[2],
                "ue_esperada": ue_esp, "ue_efetivada": ue_efet,
                "dt_carga_esperada": row["dt_carga_esp"], "dt_carga_efetivada": row["dt_carga_efet"],
                "flashcard": row["mc_efet"], "maquina": row["maq"], "tpm": row["tpm"],
                "tp_divergencia": tp_div or "VAZIO", "presente_no_gedai": no_gedai,
                "detalhe": (
                    f"CEFT sem flag de contingência (TP_DIVERGENCIA='{tp_div or 'VAZIO'}'), "
                    f"mas UE Esperada #{ue_esp} ≠ UE Efetivada #{ue_efet}"
                    + (" (UE efetivada consta no pool de Reserva CCONT!)" if em_ccont else "")
                ),
            })
        elif gedai_disponivel and not no_gedai:
            ocorrencias.append({
                "categoria": "AUSENTE_GEDAI",
                "severidade": "INFO",
                "municipio_codigo": k[0], "municipio_nome": row["mun_nome"],
                "zona": k[1], "secao": k[2],
                "ue_esperada": ue_esp, "ue_efetivada": ue_efet or ue_esp,
                "dt_carga_esperada": row["dt_carga_esp"], "dt_carga_efetivada": row.get("dt_carga_efet", ""),
                "flashcard": row.get("mc_efet", ""), "maquina": row["maq"], "tpm": row["tpm"],
                "tp_divergencia": tp_div or "OK", "presente_no_gedai": False,
                "detalhe": f"Seção presente no CEFT/CESP (máquina {row['maq'] or '-'} / TPM {row['tpm'] or '-'}), ausente dos logs .jez GEDAI importados.",
            })

    ocorrencias.sort(key=lambda o: (
        0 if o["categoria"] in ("DIVERGENCIA_SILENCIOSA", "RED_RECUPERACAO", "ALTERACAO_CESP") else 1,
        o["zona"],
        o["secao"],
    ))

    arqs_fmt = [
        {
            "id": a.id,
            "tipo_arquivo": a.tipo_arquivo,
            "nome_origem": a.nome_origem,
            "uf": a.uf,
            "turno": a.turno,
            "dt_geracao": a.dt_geracao,
            "hh_geracao": a.hh_geracao,
            "momento_geracao": a.momento_geracao,
            "total_registros": a.total_registros,
            "total_alteradas": a.total_alteradas,
            "total_contingencias_ceft": a.total_contingencias_ceft,
            "total_red": a.total_red,
        }
        for a in arqs
    ]

    return {
        "disponivel": True,
        "uf": uf,
        "turno": turno,
        "uf_nome": ESTADOS_E_REGIOES_BR.get(uf, {}).get("nome", uf),
        "arquivos": arqs_fmt,
        "resumo": {
            "total_arquivos": len(arqs_fmt),
            "total_secoes_ceft": len(ceft_mapa),
            "total_secoes_ultimo_cesp": len(csec_por_arq[-1][1]) if csec_por_arq else 0,
            "total_reservas_ccont": len(ccont_ues),
            "qtd_alteracoes_cesp": qtd_alter_cesp,
            "qtd_contingencias_ceft": qtd_cont_ceft,
            "qtd_divergencias_silenciosas": qtd_div_silenciosa,
            "qtd_red": qtd_red,
            "gedai_disponivel": gedai_disponivel,
            "qtd_secoes_gedai": len(gedai_secoes_set),
            "qtd_ausentes_gedai": qtd_ausentes_gedai,
            "qtd_cont_fora_gedai": qtd_cont_fora_gedai,
            "maquinas_ausentes_gedai": sorted(maquinas_ausentes_gedai)[:50],
        },
        "ocorrencias": ocorrencias,
    }


def listar_arquivos_e_painel_corresp(
    db,
    uf: Optional[str] = None,
    turno: Optional[int] = None,
    categoria: str = "TODAS",
    busca: str = "",
    limit: int = 200,
    offset: int = 0,
) -> dict[str, Any]:
    """Lista arquivos CESP/CEFT importados e retorna o painel cruzado com filtros e paginação."""
    todos_arqs = (
        db.query(TseCorrespArquivo)
        .order_by(TseCorrespArquivo.uf.asc(), TseCorrespArquivo.turno.asc(), TseCorrespArquivo.momento_geracao.asc())
        .all()
    )
    if not todos_arqs:
        return {"disponivel": False, "combos_disponiveis": [], "arquivos": [], "resumo": {}, "total_filtrado": 0, "ocorrencias": []}

    combos = sorted({(a.uf, int(a.turno or 1)) for a in todos_arqs})
    uf_alvo = (uf or combos[0][0]).upper().strip()
    turno_alvo = int(turno or combos[0][1])

    painel = _carregar_ocorrencias_cruzadas(db, uf_alvo, turno_alvo)
    oc = painel["ocorrencias"]

    cat_up = (categoria or "TODAS").upper().strip()
    if cat_up != "TODAS":
        oc = [o for o in oc if o["categoria"] == cat_up]

    termo = (busca or "").strip().lower()
    if termo:
        oc = [
            o for o in oc
            if termo in str(o.get("municipio_nome") or "").lower()
            or termo in str(o.get("municipio_codigo") or "").lower()
            or termo in str(o.get("ue_esperada") or "").lower()
            or termo in str(o.get("ue_efetivada") or "").lower()
            or termo in str(o.get("maquina") or "").lower()
            or termo in str(o.get("flashcard") or "").lower()
            or termo == str(o.get("zona"))
            or termo == str(o.get("secao"))
        ]

    total_filt = len(oc)
    off = max(int(offset or 0), 0)
    lim = min(max(int(limit or 200), 1), 500)

    return {
        "disponivel": painel["disponivel"],
        "combos_disponiveis": [{"uf": u, "turno": t} for (u, t) in combos],
        "uf": uf_alvo,
        "turno": turno_alvo,
        "arquivos": painel["arquivos"],
        "resumo": painel["resumo"],
        "total_filtrado": total_filt,
        "offset": off,
        "limit": lim,
        "ocorrencias": oc[off:off + lim],
    }


def buscar_custodia_corresp_secao(
    db,
    uf: str,
    mun_cod: str,
    zona: int,
    secao: int,
    turno: int,
    ue_candidata: Optional[str] = None,
) -> dict[str, Any]:
    """
    Consulta instantânea por seção (índice `idx_tse_corresp_reg_sec`) dos snapshots CESP e CEFT
    + verificação se a urna efetivada pertence ao pool CCONT (Reserva).
    """
    mun_z = str(mun_cod).strip().zfill(5)
    mun_cands = list({mun_z, mun_z.lstrip("0") or mun_z})
    rows = []
    tem_base_turno = False
    try:
        rows = (
            db.query(TseCorrespRegistro, TseCorrespArquivo)
            .join(TseCorrespArquivo, TseCorrespRegistro.arquivo_id == TseCorrespArquivo.id)
            .filter(
                TseCorrespRegistro.uf == uf,
                TseCorrespRegistro.turno == turno,
                TseCorrespRegistro.municipio_codigo.in_(mun_cands),
                TseCorrespRegistro.zona == int(zona),
                TseCorrespRegistro.secao == int(secao),
                TseCorrespRegistro.tipo_registro.in_(("CSEC", "CEFT")),
            )
            .order_by(TseCorrespArquivo.momento_geracao.asc(), TseCorrespArquivo.id.asc())
            .all()
        )

        tem_base_turno = (
            db.query(func.count(TseCorrespArquivo.id))
            .filter(TseCorrespArquivo.uf == uf, TseCorrespArquivo.turno == turno)
            .scalar() or 0
        ) > 0
    except Exception as exc_q:
        try:
            db.rollback()
        except Exception:
            pass
        print(f"[TSE-CORRESP] Aviso SQL em buscar_custodia_corresp_secao: {exc_q}")
        return {"disponivel": False, "base_turno_carregada": False, "csec_snapshots": [], "ceft": None, "alteracao_cesp": None, "ccont_match": None}

    csec_snaps: list[dict[str, Any]] = []
    ceft_reg: Optional[dict[str, Any]] = None

    for reg, arq in rows:
        item = {
            "arquivo": arq.nome_origem,
            "dt_geracao": arq.dt_geracao,
            "hh_geracao": arq.hh_geracao,
            "momento_geracao": arq.momento_geracao,
            "tipo": reg.tipo_registro,
            "nr_urna_esperada": reg.nr_urna_esperada,
            "cd_carga_esperada": reg.cd_carga_esperada,
            "cd_flashcard_esperada": reg.cd_flashcard_esperada,
            "dt_carga_esperada": reg.dt_carga_esperada,
            "dt_recbto_esperada": reg.dt_recbto_esperada,
            "st_corresp_alterada": reg.st_corresp_alterada,
            "nr_urna_efetivada": reg.nr_urna_efetivada,
            "cd_carga_efetivada": reg.cd_carga_efetivada,
            "cd_flashcard_efetivada": reg.cd_flashcard_efetivada,
            "dt_carga_efetivada": reg.dt_carga_efetivada,
            "dt_recbto_efetivada": reg.dt_recbto_efetivada,
            "cd_origem_voto": reg.cd_origem_voto,
            "ds_origem_voto": reg.ds_origem_voto,
            "tp_divergencia": reg.tp_divergencia or "",
            "maquina_geracao": reg.nm_maquina_geracao,
            "tpm_geracao": reg.nr_sri_tpm_geracao,
            "instal_geracao": reg.nr_sri_instal_geracao,
            "maquina_transm": reg.nm_maquina_transm,
        }
        if reg.tipo_registro == "CSEC":
            csec_snaps.append(item)
        elif reg.tipo_registro == "CEFT":
            ceft_reg = item

    # Detecta alteração entre snapshots CESP (ex.: 03/10 vs 04/10 12h59)
    alteracao_cesp = None
    if len(csec_snaps) >= 2:
        ue_ini = csec_snaps[0].get("nr_urna_esperada")
        for nxt in csec_snaps[1:]:
            if nxt.get("st_corresp_alterada") in ("S", "*") or (ue_ini and nxt.get("nr_urna_esperada") and ue_ini != nxt.get("nr_urna_esperada")):
                alteracao_cesp = {
                    "ue_anterior": ue_ini,
                    "ue_nova": nxt.get("nr_urna_esperada"),
                    "st": nxt.get("st_corresp_alterada"),
                    "dt_carga_nova": nxt.get("dt_carga_esperada"),
                    "snapshot_arquivo": nxt.get("arquivo"),
                    "snapshot_momento": f"{nxt.get('dt_geracao')} {nxt.get('hh_geracao')}".strip(),
                    "maquina": nxt.get("maquina_geracao"),
                    "tpm": nxt.get("tpm_geracao"),
                }

    ue_ref = _norm_ue_num(ue_candidata or (ceft_reg or {}).get("nr_urna_efetivada") or (csec_snaps[-1] if csec_snaps else {}).get("nr_urna_esperada"))
    ccont_match = None
    if ue_ref:
        try:
            cc_row = (
                db.query(TseCorrespRegistro, TseCorrespArquivo)
                .join(TseCorrespArquivo, TseCorrespRegistro.arquivo_id == TseCorrespArquivo.id)
                .filter(
                    TseCorrespRegistro.uf == uf,
                    TseCorrespRegistro.turno == turno,
                    TseCorrespRegistro.tipo_registro == "CCONT",
                    TseCorrespRegistro.nr_urna_esperada == ue_ref,
                )
                .order_by(TseCorrespArquivo.momento_geracao.desc())
                .first()
            )
            if cc_row:
                r_cc, a_cc = cc_row
                ccont_match = {
                    "arquivo": a_cc.nome_origem,
                    "zona_reserva": r_cc.zona,
                    "nr_urna": r_cc.nr_urna_esperada,
                    "cd_flashcard": r_cc.cd_flashcard_esperada,
                    "dt_carga": r_cc.dt_carga_esperada,
                    "maquina": r_cc.nm_maquina_geracao,
                    "tpm": r_cc.nr_sri_tpm_geracao,
                }
        except Exception:
            try:
                db.rollback()
            except Exception:
                pass

    return {
        "disponivel": tem_base_turno and (len(csec_snaps) > 0 or ceft_reg is not None),
        "base_turno_carregada": tem_base_turno,
        "csec_snapshots": csec_snaps,
        "ceft": ceft_reg,
        "alteracao_cesp": alteracao_cesp,
        "ccont_match": ccont_match,
    }


def obter_resumo_custodia_consolidado(
    db,
    uf_filtro: str = "TODAS",
    municipio_filtro: str = "TODAS",
    zona_filtro: str = "TODAS",
) -> dict[str, Any]:
    """
    Retorna o quadro consolidado ultrarrápido (<10ms via índices SQL) da Cadeia de Custódia
    (GEDAI-UE × CESP × CEFT) para o Estado, Município ou Zona selecionado.
    Se o Estado filtrado (ex: RS) não possuir pacotes GEDAI ou CESP/CEFT carregados, retorna `disponivel=False`.
    """
    uf_up = (uf_filtro or "TODAS").strip().upper()
    mun_raw = (municipio_filtro or "TODAS").strip()
    zona_raw = (zona_filtro or "TODAS").strip()

    if uf_up == "TODAS" and mun_raw == "TODAS" and zona_raw == "TODAS":
        return {"disponivel": False, "uf": "TODAS"}

    try:
        q_lotes = db.query(TseGedaiLote)
        q_arqs = db.query(TseCorrespArquivo)
        if uf_up != "TODAS":
            q_lotes = q_lotes.filter(TseGedaiLote.uf == uf_up)
            q_arqs = q_arqs.filter(TseCorrespArquivo.uf == uf_up)

        lotes_gedai = q_lotes.order_by(TseGedaiLote.id.desc()).all()
        arqs_corresp = q_arqs.order_by(TseCorrespArquivo.momento_geracao.asc(), TseCorrespArquivo.id.asc()).all()

        if not lotes_gedai and not arqs_corresp:
            return {"disponivel": False, "uf": uf_up}

        uf_efetiva = uf_up if uf_up != "TODAS" else (
            (arqs_corresp[0].uf if arqs_corresp else lotes_gedai[0].uf)
        )

        mun_cands = []
        if mun_raw != "TODAS" and mun_raw:
            mz = mun_raw.zfill(5) if mun_raw.isdigit() else mun_raw
            mun_cands = list({mz, mz.lstrip("0") or mz})

        zona_int = None
        if zona_raw != "TODAS" and zona_raw:
            m_z = re.search(r"\d+", zona_raw)
            if m_z:
                zona_int = int(m_z.group(0))

        # 1. Contagens GEDAI-UE no escopo
        gedai_estacoes = sum(int(l.total_estacoes or 0) for l in lotes_gedai if l.uf == uf_efetiva)
        gedai_secoes = 0
        gedai_contingencias = 0
        if lotes_gedai:
            lote_ids = [l.id for l in lotes_gedai if l.uf == uf_efetiva]
            if not mun_cands and zona_int is None:
                gedai_secoes = sum(int(l.total_secoes_unicas or l.total_corresp_secao or 0) for l in lotes_gedai if l.uf == uf_efetiva)
                gedai_contingencias = sum(int(l.total_contingencias or 0) for l in lotes_gedai if l.uf == uf_efetiva)
            elif lote_ids:
                qg = db.query(
                    TseGedaiCorrespondencia.tipo,
                    func.count(func.distinct(TseGedaiCorrespondencia.id_urna)),
                ).filter(TseGedaiCorrespondencia.lote_id.in_(lote_ids))
                if mun_cands:
                    qg = qg.filter(TseGedaiCorrespondencia.municipio_codigo.in_(mun_cands))
                if zona_int is not None:
                    qg = qg.filter(TseGedaiCorrespondencia.zona == zona_int)
                for tp_g, cnt_g in qg.group_by(TseGedaiCorrespondencia.tipo).all():
                    if tp_g == "SECAO":
                        gedai_secoes = int(cnt_g or 0)
                    elif tp_g == "CONTINGENCIA":
                        gedai_contingencias = int(cnt_g or 0)

        # 2. Contagens e Ocorrências CESP / CEFT no escopo
        csec_arqs = [a for a in arqs_corresp if a.uf == uf_efetiva and a.tipo_arquivo == "CESP_CSEC"]
        ccont_arqs = [a for a in arqs_corresp if a.uf == uf_efetiva and a.tipo_arquivo == "CESP_CCONT"]
        ceft_arq = max((a for a in arqs_corresp if a.uf == uf_efetiva and a.tipo_arquivo == "CEFT"), key=lambda a: (a.momento_geracao or "", a.id), default=None)

        total_secoes_ceft = 0
        titulares_confirmadas = 0
        contingencias_ceft = 0
        divergencias_silenciosas = 0
        ocorrencias_red = 0
        trocas_cesp = 0
        reservas_ccont = 0
        ocorrencias_amostra: list[dict[str, Any]] = []

        if ccont_arqs:
            ult_cc = ccont_arqs[-1]
            q_cc = db.query(func.count(TseCorrespRegistro.id)).filter(
                TseCorrespRegistro.arquivo_id == ult_cc.id,
                TseCorrespRegistro.tipo_registro == "CCONT",
            )
            if mun_cands:
                q_cc = q_cc.filter(TseCorrespRegistro.municipio_codigo.in_(mun_cands))
            if zona_int is not None:
                q_cc = q_cc.filter(TseCorrespRegistro.zona == zona_int)
            reservas_ccont = int(q_cc.scalar() or 0)

        if len(csec_arqs) >= 2:
            ult_csec = csec_arqs[-1]
            q_alt = db.query(TseCorrespRegistro).filter(
                TseCorrespRegistro.arquivo_id == ult_csec.id,
                TseCorrespRegistro.tipo_registro == "CSEC",
                TseCorrespRegistro.st_corresp_alterada.in_(("S", "*")),
            )
            if mun_cands:
                q_alt = q_alt.filter(TseCorrespRegistro.municipio_codigo.in_(mun_cands))
            if zona_int is not None:
                q_alt = q_alt.filter(TseCorrespRegistro.zona == zona_int)
            rows_alt = q_alt.order_by(TseCorrespRegistro.zona.asc(), TseCorrespRegistro.secao.asc()).all()
            trocas_cesp = len(rows_alt)
            for r in rows_alt[:20]:
                ocorrencias_amostra.append({
                    "categoria": "ALTERACAO_CESP",
                    "uf": uf_efetiva,
                    "municipio_codigo": r.municipio_codigo,
                    "municipio_nome": r.municipio_nome,
                    "zona": r.zona,
                    "secao": r.secao,
                    "ue_esperada": r.nr_urna_esperada,
                    "ue_efetivada": r.nr_urna_esperada,
                    "maquina": r.nm_maquina_geracao,
                    "flashcard": r.cd_flashcard_esperada,
                    "dt_evento": r.dt_carga_esperada,
                    "resumo": f"Troca CESP (ST={r.st_corresp_alterada}) • Carga em {r.dt_carga_esperada or '-'}",
                })

        if ceft_arq:
            q_tot = db.query(func.count(TseCorrespRegistro.id)).filter(
                TseCorrespRegistro.arquivo_id == ceft_arq.id,
                TseCorrespRegistro.tipo_registro == "CEFT",
            )
            if mun_cands:
                q_tot = q_tot.filter(TseCorrespRegistro.municipio_codigo.in_(mun_cands))
            if zona_int is not None:
                q_tot = q_tot.filter(TseCorrespRegistro.zona == zona_int)
            total_secoes_ceft = int(q_tot.scalar() or 0)

            q_oc = db.query(TseCorrespRegistro).filter(
                TseCorrespRegistro.arquivo_id == ceft_arq.id,
                TseCorrespRegistro.tipo_registro == "CEFT",
                (
                    (TseCorrespRegistro.tp_divergencia == "C")
                    | (TseCorrespRegistro.cd_origem_voto == "R")
                    | (TseCorrespRegistro.nr_urna_esperada != TseCorrespRegistro.nr_urna_efetivada)
                ),
            )
            if mun_cands:
                q_oc = q_oc.filter(TseCorrespRegistro.municipio_codigo.in_(mun_cands))
            if zona_int is not None:
                q_oc = q_oc.filter(TseCorrespRegistro.zona == zona_int)
            rows_oc_ceft = q_oc.order_by(TseCorrespRegistro.zona.asc(), TseCorrespRegistro.secao.asc()).all()

            for r in rows_oc_ceft:
                is_c = (r.tp_divergencia == "C")
                is_r = (r.cd_origem_voto == "R")
                is_diff = bool(r.nr_urna_esperada and r.nr_urna_efetivada and r.nr_urna_esperada != r.nr_urna_efetivada and not is_c)
                if is_c:
                    contingencias_ceft += 1
                if is_r:
                    ocorrencias_red += 1
                if is_diff:
                    divergencias_silenciosas += 1

                cat = "RED_RECUPERACAO" if is_r else ("DIVERGENCIA_SILENCIOSA" if is_diff else "CONTINGENCIA_CEFT")
                res_txt = (
                    f"RED ({r.ds_origem_voto}) • UE #{r.nr_urna_efetivada}"
                    if is_r else (
                        f"Div. Silenciosa (TP vazio): Esp #{r.nr_urna_esperada} → Efet #{r.nr_urna_efetivada}"
                        if is_diff else f"Urna Reserva Efetivada: Titular #{r.nr_urna_esperada} → Reserva #{r.nr_urna_efetivada}"
                    )
                )
                ocorrencias_amostra.append({
                    "categoria": cat,
                    "uf": uf_efetiva,
                    "municipio_codigo": r.municipio_codigo,
                    "municipio_nome": r.municipio_nome,
                    "zona": r.zona,
                    "secao": r.secao,
                    "ue_esperada": r.nr_urna_esperada,
                    "ue_efetivada": r.nr_urna_efetivada,
                    "maquina": r.nm_maquina_geracao,
                    "flashcard": r.cd_flashcard_efetivada,
                    "dt_evento": r.dt_carga_efetivada,
                    "resumo": res_txt,
                })

            titulares_confirmadas = max(0, total_secoes_ceft - contingencias_ceft - divergencias_silenciosas)
        elif gedai_secoes > 0:
            titulares_confirmadas = gedai_secoes

        ocorrencias_amostra.sort(key=lambda x: (
            0 if x["categoria"] in ("DIVERGENCIA_SILENCIOSA", "RED_RECUPERACAO", "ALTERACAO_CESP") else 1,
            x["zona"],
            x["secao"],
        ))

        return {
            "disponivel": True,
            "uf": uf_efetiva,
            "uf_nome": ESTADOS_E_REGIOES_BR.get(uf_efetiva, {}).get("nome", uf_efetiva),
            "gedai_estacoes": gedai_estacoes,
            "gedai_secoes": gedai_secoes,
            "gedai_contingencias": gedai_contingencias,
            "total_secoes_ceft": total_secoes_ceft,
            "titulares_confirmadas": titulares_confirmadas,
            "contingencias_ceft": contingencias_ceft,
            "divergencias_silenciosas": divergencias_silenciosas,
            "trocas_cesp": trocas_cesp,
            "ocorrencias_red": ocorrencias_red,
            "reservas_ccont": reservas_ccont or gedai_contingencias,
            "arquivos_carregados": [
                {"tipo": a.tipo_arquivo, "nome": a.nome_origem, "data_hora": f"{a.dt_geracao} {(a.hh_geracao or '')[:5]}".strip()}
                for a in arqs_corresp if a.uf == uf_efetiva
            ],
            "total_ocorrencias_escopo": len(ocorrencias_amostra),
            "amostra_ocorrencias": ocorrencias_amostra[:60],
        }
    except Exception as exc:
        try:
            db.rollback()
        except Exception:
            pass
        print(f"[TSE-CUSTODIA-CONS] Aviso ao compilar custódia consolidada: {exc}")
        return {"disponivel": False, "uf": uf_up}
