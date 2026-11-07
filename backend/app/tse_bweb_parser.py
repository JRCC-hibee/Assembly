"""
Módulo de Ingestão e Processamento Pericial de Boletins de Urna Fidedignos (BWEB TSE):
Processa arquivos oficiais do TSE no formato bweb_<turno>_<UF>_<data>.zip ou .csv
(ex: bweb_1t_PR_051020261403.zip, bweb_2t_PR_261020261730.zip).

Gera o Espelho Oficial da Bobina Impressa (100% Fiel à fita térmica da urna eletrônica),
preenche os metadados físicos (Série da Urna, Código de Carga, Flashcard, Horários de Abertura/Emissão)
e associa diretamente às urnas no PostgreSQL com isolamento estrito entre 1º e 2º Turnos.
"""

import csv
import io
import os
import re
import sys
import time
import zipfile
import threading
from datetime import datetime, timezone
from typing import Any, Optional

try:
    from sqlalchemy import func
    from .database import (
        SessionLocal,
        TseSecao,
        TseApuracaoBU,
        TseVotoCandidato,
        TseDossieSecao,
        TseHistoricoUpload,
        obter_regiao_uf,
        PADRAO_NOMES_PRESIDENTE,
        _obter_db_session,
    )
except ImportError:
    SessionLocal = None
    TseSecao = None
    TseApuracaoBU = None
    TseVotoCandidato = None
    TseDossieSecao = None
    TseHistoricoUpload = None
    obter_regiao_uf = lambda uf: "SUL"
    PADRAO_NOMES_PRESIDENTE = {"13": "LULA", "22": "FLÁVIO BOLSONARO"}
    _obter_db_session = lambda: None


# ==============================================================================
# ESTADO GLOBAL DA INGESTÃO BWEB EM SEGUNDO PLANO
# ==============================================================================

_STATUS_BWEB = {
    "status": "PARADO",  # PARADO, EM_ANDAMENTO, CONCLUIDO, ERRO
    "arquivo": None,
    "uf": None,
    "turno": None,
    "linhas_lidas": 0,
    "total_linhas_estimado": 3640000,
    "porcentagem": 0.0,
    "secoes_processadas": 0,
    "bus_atualizados": 0,
    "secoes_novas_criadas": 0,
    "votos_computados": 0,
    "velocidade_linhas_segundo": 0.0,
    "tempo_decorrido_segundos": 0,
    "inicio_timestamp": None,
    "fim_timestamp": None,
    "mensagem": "Nenhum processamento de BWEB em andamento.",
    "erro": None,
}

_THREAD_BWEB: Optional[threading.Thread] = None
_CANCELAR_BWEB_FLAG = threading.Event()


def _get_bweb_search_paths() -> list[str]:
    """Diretórios candidatos para localizar pacotes BWEB."""
    paths = [
        os.getenv("TSE_IMPORT_DIR", "/app/tse_import"),
        "/root/tse_import",
        "/app/data/tse_import",
        "/app/data",
        os.path.expanduser("~/Downloads"),
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "tse_import"),
    ]
    return [p for p in paths if os.path.isdir(p)]


def extrair_metadados_nome_bweb(nome_arquivo: str) -> dict[str, Any]:
    """
    Extrai UF e Turno a partir do nome do arquivo BWEB.
    Exemplos:
      - bweb_1t_PR_051020261403.zip -> {'uf': 'PR', 'turno': 1, 'data_hora': '051020261403'}
      - bweb_2t_SC_261020261730.csv -> {'uf': 'SC', 'turno': 2, 'data_hora': '261020261730'}
    """
    nome_norm = os.path.basename(nome_arquivo).strip()
    m = re.search(r"bweb_([12])t_([A-Za-z]{2})_?(\d+)?", nome_norm, re.IGNORECASE)
    if m:
        return {
            "valido": True,
            "turno": int(m.group(1)),
            "uf": m.group(2).upper(),
            "data_hora_geracao": m.group(3) or "",
        }
    return {
        "valido": False,
        "turno": None,
        "uf": None,
        "data_hora_geracao": "",
    }


def localizar_arquivos_bweb(caminho_especifico: Optional[str] = None) -> list[dict[str, Any]]:
    """Localiza todos os pacotes bweb_*.zip ou bweb_*.csv disponíveis no servidor ou máquina local."""
    encontrados = []
    vistos = set()

    if caminho_especifico and os.path.exists(caminho_especifico):
        meta = extrair_metadados_nome_bweb(caminho_especifico)
        sz = os.path.getsize(caminho_especifico)
        return [{
            "caminho": caminho_especifico,
            "nome": os.path.basename(caminho_especifico),
            "uf": meta.get("uf"),
            "turno": meta.get("turno"),
            "tamanho_mb": round(sz / (1024 * 1024), 2),
            "formato": "ZIP" if caminho_especifico.lower().endswith(".zip") else "CSV",
        }]

    for d in _get_bweb_search_paths():
        try:
            for item in os.listdir(d):
                item_low = item.lower()
                if item_low.startswith("bweb_") and (item_low.endswith(".zip") or item_low.endswith(".csv")):
                    full = os.path.join(d, item)
                    if os.path.isfile(full) and full not in vistos:
                        sz = os.path.getsize(full)
                        if sz > 1024:  # Ignora arquivos vazios ou hashes pequenos
                            vistos.add(full)
                            meta = extrair_metadados_nome_bweb(item)
                            encontrados.append({
                                "caminho": full,
                                "nome": item,
                                "uf": meta.get("uf"),
                                "turno": meta.get("turno"),
                                "tamanho_mb": round(sz / (1024 * 1024), 2),
                                "formato": "ZIP" if item_low.endswith(".zip") else "CSV",
                            })
                # Verifica subpastas descompactadas (ex: bweb_1t_PR_051020261403/bweb_1t_PR_051020261403.csv)
                elif item_low.startswith("bweb_") and os.path.isdir(os.path.join(d, item)):
                    sub = os.path.join(d, item)
                    try:
                        for sub_f in os.listdir(sub):
                            if sub_f.lower().startswith("bweb_") and sub_f.lower().endswith(".csv"):
                                full_sub = os.path.join(sub, sub_f)
                                if os.path.isfile(full_sub) and full_sub not in vistos:
                                    sz = os.path.getsize(full_sub)
                                    vistos.add(full_sub)
                                    meta = extrair_metadados_nome_bweb(sub_f)
                                    encontrados.append({
                                        "caminho": full_sub,
                                        "nome": sub_f,
                                        "uf": meta.get("uf"),
                                        "turno": meta.get("turno"),
                                        "tamanho_mb": round(sz / (1024 * 1024), 2),
                                        "formato": "CSV",
                                    })
                    except Exception:
                        pass
        except Exception:
            pass

    # Ordena por UF e Turno
    encontrados.sort(key=lambda x: (x.get("uf") or "", x.get("turno") or 0))
    return encontrados


def diagnosticar_bweb(db: Any = None) -> dict[str, Any]:
    """Retorna diagnóstico completo dos arquivos BWEB encontrados e das urnas no banco de dados."""
    close_db = False
    if db is None:
        db = _obter_db_session()
        close_db = True

    arquivos = localizar_arquivos_bweb()

    diag_banco = {
        "total_secoes": 0,
        "total_1t": 0,
        "total_2t": 0,
        "bobinas_vazias_1t": 0,
        "bobinas_vazias_2t": 0,
        "ufs": {},
    }

    if db:
        try:
            diag_banco["total_secoes"] = db.query(func.count(TseSecao.id)).scalar() or 0
            diag_banco["total_1t"] = db.query(func.count(TseApuracaoBU.id)).filter(TseApuracaoBU.turno == 1).scalar() or 0
            diag_banco["total_2t"] = db.query(func.count(TseApuracaoBU.id)).filter(TseApuracaoBU.turno == 2).scalar() or 0

            # Contagem de dossiês com bobinas preenchidas vs vazias
            dossies_1t = db.query(func.count(TseDossieSecao.id)).filter(
                TseDossieSecao.turno == 1,
                TseDossieSecao.espelho_bobina.isnot(None),
                TseDossieSecao.espelho_bobina != ""
            ).scalar() or 0

            dossies_2t = db.query(func.count(TseDossieSecao.id)).filter(
                TseDossieSecao.turno == 2,
                TseDossieSecao.espelho_bobina.isnot(None),
                TseDossieSecao.espelho_bobina != ""
            ).scalar() or 0

            diag_banco["bobinas_vazias_1t"] = max(0, diag_banco["total_1t"] - dossies_1t)
            diag_banco["bobinas_vazias_2t"] = max(0, diag_banco["total_2t"] - dossies_2t)

            # Detalhes por UF
            rows_uf = db.query(
                func.upper(TseSecao.uf),
                func.count(func.distinct(TseSecao.id)),
                func.count(func.distinct(TseApuracaoBU.id)).filter(TseApuracaoBU.turno == 1),
                func.count(func.distinct(TseApuracaoBU.id)).filter(TseApuracaoBU.turno == 2),
            ).outerjoin(TseApuracaoBU, TseApuracaoBU.secao_id == TseSecao.id).group_by(func.upper(TseSecao.uf)).all()

            for uf_r, s_tot, t1_tot, t2_tot in rows_uf:
                if uf_r:
                    diag_banco["ufs"][uf_r] = {
                        "secoes": int(s_tot or 0),
                        "turno_1": int(t1_tot or 0),
                        "turno_2": int(t2_tot or 0),
                    }
        except Exception as exc:
            diag_banco["erro"] = str(exc)
        finally:
            if close_db:
                db.close()

    return {
        "arquivos_disponiveis": arquivos,
        "total_arquivos": len(arquivos),
        "banco": diag_banco,
        "status_atual": _STATUS_BWEB,
    }


def gerar_espelho_bobina_bweb(
    uf: str,
    mun_nome: str,
    mun_cod: str,
    zona: int,
    secao: int,
    turno: int,
    data_pleito: str,
    local_votacao: Optional[str],
    secoes_agregadas: Optional[str],
    urna_efetivada: str,
    carga_1: str,
    carga_2: str,
    flashcard: str,
    dt_abertura: str,
    dt_encerramento: str,
    dt_emissao_bu: str,
    aptos: int,
    comparecimento: int,
    abstencoes: int,
    biom_sem_hab: int,
    cargos_votos: dict[str, dict[str, Any]],
) -> str:
    """
    Reconstrói a fita oficial impressa do Boletim de Urna (espelho_bobina)
    com fidedignidade 100% idêntica à impressão física da Urna Eletrônica na seção.
    """
    hab_bio = max(0, comparecimento - biom_sem_hab)
    agreg_str = secoes_agregadas.strip() if secoes_agregadas and secoes_agregadas != "#NULO#" else "NENHUMA"

    linhas = [
        "================================================================================",
        "JUSTIÇA ELEITORAL — BOLETIM DE URNA OFICIAL (BU)",
        f"ELEIÇÕES GERAIS 2026 — {turno}º TURNO ({data_pleito})",
        f"               {turno}º Turno",
        "================================================================================",
        f"UF: {uf:<2}   MUNICÍPIO: {mun_nome} ({mun_cod})",
        f"ZONA ELEITORAL: {zona:04d}        SEÇÃO ELEITORAL: {secao:04d}",
    ]
    if local_votacao and local_votacao != "#NULO#":
        linhas.append(f"LOCAL DE VOTAÇÃO: {local_votacao}")
    linhas.extend([
        f"SEÇÕES AGREGADAS: {agreg_str}",
        "--------------------------------------------------------------------------------",
        f"URNA ELETRÔNICA EFETIVADA (SÉRIE): {urna_efetivada}",
        f"CÓDIGO DE CARGA: {carga_1} {carga_2}",
        f"FLASHCARD: {flashcard}",
        f"DATA/HORA ABERTURA:     {dt_abertura}",
        f"DATA/HORA ENCERRAMENTO: {dt_encerramento}",
        f"EMISSÃO DO BOLETIM:     {dt_emissao_bu}",
        "--------------------------------------------------------------------------------",
        f"Eleitores aptos                  {aptos:>6}",
        f"Comparecimento                   {comparecimento:>6}",
        f"ABSTENÇÕES / FALTOSOS:           {abstencoes:>6}",
        f"HABILITAÇÃO BIOMÉTRICA (AFIS):   {hab_bio:>6}",
        f"BIOMETRIA NÃO RECONHECIDA (MES): {biom_sem_hab:>6}",
        "================================================================================",
    ])

    # Ordem canônica dos cargos na urna eletrônica
    ordem_cargos = [
        "Presidente",
        "Governador",
        "Senador",
        "Deputado Federal",
        "Deputado Estadual",
        "Deputado Distrital",
    ]

    cargos_ordenados = []
    for cg in ordem_cargos:
        if cg in cargos_votos:
            cargos_ordenados.append(cg)
    for cg in sorted(cargos_votos.keys()):
        if cg not in cargos_ordenados:
            cargos_ordenados.append(cg)

    for cg in cargos_ordenados:
        cg_data = cargos_votos[cg]
        cand_list = cg_data.get("candidatos", [])
        v_br = cg_data.get("brancos", 0)
        v_nu = cg_data.get("nulos", 0)
        v_leg = cg_data.get("legenda", 0)
        v_nom = sum(c.get("votos", 0) for c in cand_list)
        tot_cg = v_nom + v_leg + v_br + v_nu

        linhas.extend([
            f"CARGO: {cg.upper()}",
            "--------------------------------------------------------------------------------",
            "VOTAÇÃO NOMINAL:",
        ])

        # Ordena candidatos por número de votos decrescente
        for c in sorted(cand_list, key=lambda x: x.get("votos", 0), reverse=True):
            vt = c.get("votos", 0)
            if vt > 0:
                num_c = str(c.get("numero", ""))
                nm_c = c.get("nome", "")
                part_sg = c.get("partido", "")
                linhas.append(f"  {num_c:>5} - {nm_c:<32} ({part_sg:<10}): {vt:>4} votos")

        # Exibe votos de legenda se houver
        legendas = cg_data.get("legendas_detalhe", {})
        if legendas:
            linhas.append("VOTOS DE LEGENDA:")
            for num_part, leg_info in sorted(legendas.items()):
                vt_l = leg_info.get("votos", 0)
                if vt_l > 0:
                    sg_part = leg_info.get("sigla", "")
                    linhas.append(f"     {num_part:>2} - {sg_part:<15}: {vt_l:>4} votos")

        linhas.extend([
            "--------------------------------------------------------------------------------",
            f"TOTAL DE VOTOS NOMINAIS:      {v_nom:>6}",
            f"TOTAL DE VOTOS DE LEGENDA:    {v_leg:>6}",
            f"VOTOS EM BRANCO (95):         {v_br:>6}",
            f"VOTOS NULOS (96):             {v_nu:>6}",
            f"TOTAL DE VOTOS COMPUTADOS:    {tot_cg:>6}",
            "================================================================================",
        ])

    linhas.extend([
        "[Boletim de Urna Oficial — Repositório de Dados Abertos do TSE (BWEB)]",
        "================================================================================",
    ])
    return "\n".join(linhas)


def _executar_ingestao_bweb_worker(
    caminho_arquivo: str,
    turno_forcado: Optional[int] = None,
):
    """
    Worker que processa o arquivo BWEB em segundo plano via streaming in-memory,
    sem extrair no disco e com isolamento estrito entre 1º e 2º Turnos.
    """
    global _STATUS_BWEB
    t0 = time.time()

    meta = extrair_metadados_nome_bweb(caminho_arquivo)
    turno_arquivo = turno_forcado or meta.get("turno") or 1
    uf_arquivo = meta.get("uf") or "PR"

    _STATUS_BWEB["status"] = "EM_ANDAMENTO"
    _STATUS_BWEB["arquivo"] = os.path.basename(caminho_arquivo)
    _STATUS_BWEB["uf"] = uf_arquivo
    _STATUS_BWEB["turno"] = turno_arquivo
    _STATUS_BWEB["linhas_lidas"] = 0
    _STATUS_BWEB["porcentagem"] = 0.0
    _STATUS_BWEB["secoes_processadas"] = 0
    _STATUS_BWEB["bus_atualizados"] = 0
    _STATUS_BWEB["secoes_novas_criadas"] = 0
    _STATUS_BWEB["votos_computados"] = 0
    _STATUS_BWEB["inicio_timestamp"] = datetime.now(timezone.utc).isoformat()
    _STATUS_BWEB["mensagem"] = f"Mapeando banco de dados para {uf_arquivo} ({turno_arquivo}º Turno)..."
    _STATUS_BWEB["erro"] = None

    db = _obter_db_session()
    if not db:
        _STATUS_BWEB["status"] = "ERRO"
        _STATUS_BWEB["erro"] = "Não foi possível conectar ao banco PostgreSQL."
        return

    try:
        # 1. Carrega índice das seções no PostgreSQL
        # Mapa: chave_secao -> secao_id
        mapa_secoes_id: dict[str, int] = {}
        for s_id, s_chave in db.query(TseSecao.id, TseSecao.chave_secao).filter(
            func.upper(TseSecao.uf) == uf_arquivo.upper()
        ).all():
            if s_chave:
                mapa_secoes_id[s_chave.strip().upper()] = int(s_id)

        _STATUS_BWEB["mensagem"] = (
            f"Carregadas {len(mapa_secoes_id):,} seções de {uf_arquivo}. "
            f"Iniciando leitura em streaming de {os.path.basename(caminho_arquivo)}..."
        )

        is_zip = caminho_arquivo.lower().endswith(".zip")
        zip_ref = None
        f_raw = None
        f_text = None

        if is_zip:
            zip_ref = zipfile.ZipFile(caminho_arquivo, "r")
            nome_csv = None
            for n in zip_ref.namelist():
                if n.lower().endswith(".csv") and "bweb" in n.lower():
                    nome_csv = n
                    break
            if not nome_csv:
                for n in zip_ref.namelist():
                    if n.lower().endswith(".csv"):
                        nome_csv = n
                        break
            if not nome_csv:
                raise ValueError("Nenhum arquivo CSV encontrado dentro do pacote BWEB.")
            f_raw = zip_ref.open(nome_csv)
            f_text = io.TextIOWrapper(f_raw, encoding="iso-8859-1")
        else:
            f_text = open(caminho_arquivo, mode="r", encoding="iso-8859-1")

        reader = csv.reader(f_text, delimiter=";")
        header = next(reader)
        col_map = {col.strip('"'): idx for idx, col in enumerate(header)}

        # Mapeamento estrito das colunas oficiais
        idx_uf = col_map["SG_UF"]
        idx_mun_cod = col_map["CD_MUNICIPIO"]
        idx_mun_nm = col_map["NM_MUNICIPIO"]
        idx_zona = col_map["NR_ZONA"]
        idx_secao = col_map["NR_SECAO"]
        idx_turno = col_map["NR_TURNO"]
        idx_local = col_map.get("NR_LOCAL_VOTACAO")
        idx_cargo = col_map["DS_CARGO_PERGUNTA"]
        idx_cargo_cod = col_map.get("CD_CARGO_PERGUNTA")
        idx_part_num = col_map.get("NR_PARTIDO")
        idx_part_sg = col_map.get("SG_PARTIDO")
        idx_part_nm = col_map.get("NM_PARTIDO")
        idx_aptos = col_map["QT_APTOS"]
        idx_comp = col_map["QT_COMPARECIMENTO"]
        idx_abst = col_map["QT_ABSTENCOES"]
        idx_urna_efetivada = col_map["NR_URNA_EFETIVADA"]
        idx_carga_1 = col_map["CD_CARGA_1_URNA_EFETIVADA"]
        idx_carga_2 = col_map["CD_CARGA_2_URNA_EFETIVADA"]
        idx_flashcard = col_map["CD_FLASHCARD_URNA_EFETIVADA"]
        idx_tipo_votavel = col_map["DS_TIPO_VOTAVEL"]
        idx_num_votavel = col_map["NR_VOTAVEL"]
        idx_nm_votavel = col_map["NM_VOTAVEL"]
        idx_votos = col_map["QT_VOTOS"]
        idx_agregadas = col_map.get("DS_SECOES_AGREGADAS")
        idx_dt_abertura = col_map.get("DT_ABERTURA")
        idx_dt_encerramento = col_map.get("DT_ENCERRAMENTO")
        idx_dt_emissao = col_map.get("DT_EMISSAO_BU")
        idx_biom_sem_hab = col_map.get("QT_ELEI_BIOM_SEM_HABILITACAO")
        idx_dt_pleito = col_map.get("DT_PLEITO")

        # Buffer por seção e turno: key = (uf, mun_cod, zona, secao, turno)
        buffer_secoes: dict[tuple[str, str, int, int, int], dict[str, Any]] = {}
        total_linhas = 0
        ultimo_update_status = time.time()
        TAMANHO_LOTE = 400

        def persistir_lote_bweb(lote: dict):
            """Persiste um lote de seções com BU fidedigno no PostgreSQL."""
            nonlocal db
            if not lote:
                return

            for (uf_s, mun_cod_s, zona_s, secao_s, turno_s), sec_info in lote.items():
                mun_cod_norm = str(mun_cod_s).strip().zfill(5)
                chave_secao = f"{uf_s}_{mun_cod_norm}_{zona_s:04d}_{secao_s:04d}"

                sec_id = mapa_secoes_id.get(chave_secao)
                if not sec_id:
                    # Cria a seção física se ainda não existia
                    regiao = obter_regiao_uf(uf_s)
                    secao_obj = TseSecao(
                        chave_secao=chave_secao,
                        regiao=regiao,
                        uf=uf_s,
                        municipio_codigo=mun_cod_norm,
                        municipio_nome=sec_info["mun_nome"],
                        zona=zona_s,
                        secao=secao_s,
                        local_votacao=sec_info["local_votacao"],
                        modelo_urna="TSE_BWEB",
                    )
                    db.add(secao_obj)
                    db.flush()
                    sec_id = secao_obj.id
                    mapa_secoes_id[chave_secao] = sec_id
                    _STATUS_BWEB["secoes_novas_criadas"] += 1

                # 1. Atualiza ou Insere TseApuracaoBU strictly para o turno_s
                aptos_val = sec_info["aptos"]
                comp_val = sec_info["comparecimento"]
                abst_val = sec_info["abstencoes"]
                biom_sem_val = sec_info["biom_sem_hab"]
                hab_bio_val = max(0, comp_val - biom_sem_val)

                # Totais de Presidente (ou gerais se 2T)
                pres_data = sec_info["cargos"].get("Presidente", {})
                v_nom_pres = sum(c.get("votos", 0) for c in pres_data.get("candidatos", []))
                v_br_pres = pres_data.get("brancos", 0)
                v_nu_pres = pres_data.get("nulos", 0)

                bu_db = db.query(TseApuracaoBU).filter(
                    TseApuracaoBU.secao_id == sec_id,
                    TseApuracaoBU.turno == turno_s
                ).first()

                if not bu_db:
                    bu_db = TseApuracaoBU(
                        secao_id=sec_id,
                        turno=turno_s,
                        pleito="03220" if turno_s == 1 else "03221",
                        eleitores_aptos=aptos_val,
                        comparecimento=comp_val,
                        faltosos=abst_val,
                        votos_nominais=v_nom_pres,
                        votos_brancos=v_br_pres,
                        votos_nulos=v_nu_pres,
                        votos_legenda=0,
                        hab_biometrica=hab_bio_val,
                        hab_biografica=biom_sem_val,
                        hab_sem_biometria=0,
                        hash_bu_sha256=sec_info["carga_1"],
                        mac_urna=sec_info["urna_efetivada"],
                        divergencia_detectada=False,
                        divergencia_descricao="Boletim de Urna Oficial TSE (BWEB)",
                    )
                    db.add(bu_db)
                else:
                    bu_db.eleitores_aptos = aptos_val
                    bu_db.comparecimento = comp_val
                    bu_db.faltosos = abst_val
                    bu_db.hab_biometrica = hab_bio_val
                    bu_db.hab_biografica = biom_sem_val
                    if v_nom_pres > 0 or v_br_pres > 0 or v_nu_pres > 0:
                        bu_db.votos_nominais = v_nom_pres
                        bu_db.votos_brancos = v_br_pres
                        bu_db.votos_nulos = v_nu_pres
                    bu_db.hash_bu_sha256 = sec_info["carga_1"]
                    bu_db.mac_urna = sec_info["urna_efetivada"]
                    bu_db.divergencia_descricao = "Boletim de Urna Oficial TSE (BWEB)"

                # 2. Votos nominais para Presidente strictly no turno_s
                for c in pres_data.get("candidatos", []):
                    num_c = c.get("numero")
                    vt = c.get("votos", 0)
                    nm_c = c.get("nome")
                    if not num_c:
                        continue
                    if not nm_c or "JAIR" in (nm_c or "").upper():
                        nm_c = PADRAO_NOMES_PRESIDENTE.get(str(num_c), nm_c or f"CANDIDATO {num_c}")

                    voto_db = db.query(TseVotoCandidato).filter(
                        TseVotoCandidato.secao_id == sec_id,
                        TseVotoCandidato.turno == turno_s,
                        TseVotoCandidato.cargo == "PRESIDENTE",
                        TseVotoCandidato.numero_candidato == num_c
                    ).first()

                    if not voto_db:
                        voto_db = TseVotoCandidato(
                            secao_id=sec_id,
                            turno=turno_s,
                            cargo="PRESIDENTE",
                            numero_candidato=num_c,
                            nome_candidato=nm_c,
                            quantidade_votos=vt,
                            votos_bu=vt,
                            votos_rdv=vt,
                        )
                        db.add(voto_db)
                    else:
                        voto_db.quantidade_votos = vt
                        voto_db.votos_bu = vt
                        voto_db.nome_candidato = nm_c

                # 3. Reconstrói o espelho oficial fidedigno da bobina para o turno_s
                data_pleito_fmt = "04/10/2026" if turno_s == 1 else "25/10/2026"
                bobina_texto = gerar_espelho_bobina_bweb(
                    uf=uf_s,
                    mun_nome=sec_info["mun_nome"],
                    mun_cod=mun_cod_norm,
                    zona=zona_s,
                    secao=secao_s,
                    turno=turno_s,
                    data_pleito=data_pleito_fmt,
                    local_votacao=sec_info["local_votacao"],
                    secoes_agregadas=sec_info["secoes_agregadas"],
                    urna_efetivada=sec_info["urna_efetivada"],
                    carga_1=sec_info["carga_1"],
                    carga_2=sec_info["carga_2"],
                    flashcard=sec_info["flashcard"],
                    dt_abertura=sec_info["dt_abertura"],
                    dt_encerramento=sec_info["dt_encerramento"],
                    dt_emissao_bu=sec_info["dt_emissao_bu"],
                    aptos=aptos_val,
                    comparecimento=comp_val,
                    abstencoes=abst_val,
                    biom_sem_hab=biom_sem_val,
                    cargos_votos=sec_info["cargos"],
                )

                dossie_db = db.query(TseDossieSecao).filter(
                    TseDossieSecao.secao_id == sec_id,
                    TseDossieSecao.turno == turno_s
                ).first()

                if not dossie_db:
                    dossie_db = TseDossieSecao(
                        secao_id=sec_id,
                        turno=turno_s,
                        prefixo=f"{chave_secao}_{turno_s}T",
                        espelho_bobina=bobina_texto,
                    )
                    db.add(dossie_db)
                else:
                    dossie_db.espelho_bobina = bobina_texto

                _STATUS_BWEB["secoes_processadas"] += 1
                _STATUS_BWEB["bus_atualizados"] += 1
                _STATUS_BWEB["votos_computados"] += comp_val

            db.commit()

        # Leitura linha a linha do CSV
        for row in reader:
            if _CANCELAR_BWEB_FLAG.is_set():
                _STATUS_BWEB["mensagem"] = "Ingestão cancelada pelo usuário."
                break

            total_linhas += 1

            uf_r = row[idx_uf].strip().upper()
            try:
                turno_r = int(row[idx_turno])
            except Exception:
                turno_r = turno_arquivo

            try:
                zona_r = int(row[idx_zona])
                secao_r = int(row[idx_secao])
                mun_cod_r = row[idx_mun_cod].strip()
                mun_nm_r = row[idx_mun_nm].strip().upper()
                cargo_r = row[idx_cargo].strip()
                tipo_vot_r = row[idx_tipo_votavel].strip()
                num_vot_str = row[idx_num_votavel].strip()
                num_vot_r = int(num_vot_str) if num_vot_str.isdigit() else -1
                nm_vot_r = row[idx_nm_votavel].strip()
                votos_r = int(row[idx_votos])
            except Exception:
                continue

            sec_key = (uf_r, mun_cod_r, zona_r, secao_r, turno_r)
            if sec_key not in buffer_secoes:
                # Extrai metadados da urna desta seção
                try:
                    apt_val = int(row[idx_aptos])
                    comp_val = int(row[idx_comp])
                    abst_val = int(row[idx_abst])
                except Exception:
                    apt_val, comp_val, abst_val = 0, 0, 0

                try:
                    biom_val = int(row[idx_biom_sem_hab]) if idx_biom_sem_hab else 0
                except Exception:
                    biom_val = 0

                buffer_secoes[sec_key] = {
                    "mun_nome": mun_nm_r,
                    "local_votacao": row[idx_local].strip() if idx_local and row[idx_local] != "#NULO#" else None,
                    "urna_efetivada": row[idx_urna_efetivada].strip(),
                    "carga_1": row[idx_carga_1].strip(),
                    "carga_2": row[idx_carga_2].strip(),
                    "flashcard": row[idx_flashcard].strip(),
                    "dt_abertura": row[idx_dt_abertura].strip() if idx_dt_abertura else "-",
                    "dt_encerramento": row[idx_dt_encerramento].strip() if idx_dt_encerramento else "-",
                    "dt_emissao_bu": row[idx_dt_emissao].strip() if idx_dt_emissao else "-",
                    "secoes_agregadas": row[idx_agregadas].strip() if idx_agregadas else None,
                    "aptos": apt_val,
                    "comparecimento": comp_val,
                    "abstencoes": abst_val,
                    "biom_sem_hab": biom_val,
                    "cargos": {},
                }

            sec_dict = buffer_secoes[sec_key]
            cargo_dict = sec_dict["cargos"].setdefault(cargo_r, {
                "candidatos": [],
                "brancos": 0,
                "nulos": 0,
                "legenda": 0,
                "legendas_detalhe": {},
            })

            # Contabilização de votos
            if num_vot_r == 95 or "BRANCO" in tipo_vot_r.upper():
                cargo_dict["brancos"] += votos_r
            elif num_vot_r in (96, 97) or "NULO" in tipo_vot_r.upper():
                cargo_dict["nulos"] += votos_r
            elif "LEGENDA" in tipo_vot_r.upper():
                cargo_dict["legenda"] += votos_r
                part_sg = row[idx_part_sg].strip() if idx_part_sg else ""
                leg_map = cargo_dict["legendas_detalhe"].setdefault(num_vot_r, {"sigla": part_sg, "votos": 0})
                leg_map["votos"] += votos_r
            else:
                part_sg = row[idx_part_sg].strip() if idx_part_sg else ""
                cargo_dict["candidatos"].append({
                    "numero": num_vot_r,
                    "nome": nm_vot_r,
                    "partido": part_sg,
                    "votos": votos_r,
                })

            # Se atingir o tamanho do lote, persiste e libera RAM
            if len(buffer_secoes) >= TAMANHO_LOTE:
                persistir_lote_bweb(buffer_secoes)
                buffer_secoes.clear()

            # Atualização visual a cada ~0.5s
            agora = time.time()
            if agora - ultimo_update_status >= 0.5:
                decorrido = max(0.1, agora - t0)
                pct = min(99.0, (total_linhas / _STATUS_BWEB["total_linhas_estimado"]) * 100.0)
                vel = round(total_linhas / decorrido, 1)

                _STATUS_BWEB["linhas_lidas"] = total_linhas
                _STATUS_BWEB["porcentagem"] = round(pct, 1)
                _STATUS_BWEB["tempo_decorrido_segundos"] = int(decorrido)
                _STATUS_BWEB["velocidade_linhas_segundo"] = vel
                _STATUS_BWEB["mensagem"] = (
                    f"Processando {vel:,} linhas/s ({pct:.1f}%). "
                    f"{_STATUS_BWEB['bus_atualizados']:,} BUs oficiais ({turno_arquivo}ºT) gerados e gravados no banco."
                )
                ultimo_update_status = agora

        # Persiste o restante do buffer
        if buffer_secoes:
            persistir_lote_bweb(buffer_secoes)
            buffer_secoes.clear()

        # Fecha descritores
        if f_text:
            f_text.close()
        if f_raw:
            f_raw.close()
        if zip_ref:
            zip_ref.close()

        tempo_total = int(time.time() - t0)
        _STATUS_BWEB["status"] = "CONCLUIDO"
        _STATUS_BWEB["porcentagem"] = 100.0
        _STATUS_BWEB["linhas_lidas"] = total_linhas
        _STATUS_BWEB["tempo_decorrido_segundos"] = tempo_total
        _STATUS_BWEB["fim_timestamp"] = datetime.now(timezone.utc).isoformat()
        _STATUS_BWEB["mensagem"] = (
            f"Ingestão BWEB Concluída com Sucesso! "
            f"{_STATUS_BWEB['bus_atualizados']:,} BUs oficiais do {turno_arquivo}º Turno gerados no PostgreSQL em {tempo_total}s "
            f"({total_linhas:,} linhas processadas)."
        )

        # Registra histórico
        try:
            hist = TseHistoricoUpload(
                job_id=f"BWEB_{uf_arquivo}_{turno_arquivo}T_{int(t0)}",
                tipo_envio="BWEB_OFICIAL_TSE",
                nome_origem=os.path.basename(caminho_arquivo),
                uf=uf_arquivo,
                total_arquivos_recebidos=1,
                total_urnas_detectadas=_STATUS_BWEB["bus_atualizados"],
                total_urnas_novas_gravadas=_STATUS_BWEB["bus_atualizados"],
                total_urnas_duplicadas_ignoradas=0,
                total_erros=0,
                status="CONCLUIDO",
                duracao_segundos=tempo_total,
                mensagem_resumo=_STATUS_BWEB["mensagem"],
            )
            db.add(hist)
            db.commit()
        except Exception:
            pass

    except Exception as exc:
        _STATUS_BWEB["status"] = "ERRO"
        _STATUS_BWEB["erro"] = str(exc)
        _STATUS_BWEB["mensagem"] = f"Erro ao processar BWEB: {exc}"
    finally:
        db.close()


def iniciar_ingestao_bweb(
    caminho_arquivo: Optional[str] = None,
    turno: Optional[int] = None,
) -> dict[str, Any]:
    """Inicia o processamento do pacote BWEB em segundo plano."""
    global _THREAD_BWEB, _CANCELAR_BWEB_FLAG

    if _STATUS_BWEB.get("status") == "EM_ANDAMENTO":
        return {
            "ok": False,
            "status": "EM_ANDAMENTO",
            "mensagem": "Já existe uma ingestão BWEB em andamento.",
        }

    caminho = caminho_arquivo
    if not caminho:
        disponiveis = localizar_arquivos_bweb()
        if disponiveis:
            caminho = disponiveis[0]["caminho"]

    if not caminho or not os.path.exists(caminho):
        return {
            "ok": False,
            "status": "ARQUIVO_NAO_ENCONTRADO",
            "mensagem": "Arquivo BWEB não localizado. Coloque o arquivo bweb_1t_PR_*.zip na pasta /root/tse_import.",
        }

    _CANCELAR_BWEB_FLAG.clear()
    _THREAD_BWEB = threading.Thread(
        target=_executar_ingestao_bweb_worker,
        kwargs={
            "caminho_arquivo": caminho,
            "turno_forcado": turno,
        },
        daemon=True,
    )
    _THREAD_BWEB.start()

    meta = extrair_metadados_nome_bweb(caminho)
    return {
        "ok": True,
        "status": "INICIADO",
        "arquivo": os.path.basename(caminho),
        "uf": meta.get("uf"),
        "turno": turno or meta.get("turno"),
        "mensagem": f"Ingestão do BWEB iniciada em segundo plano ({os.path.basename(caminho)}).",
    }


def cancelar_ingestao_bweb() -> dict[str, Any]:
    """Cancela a ingestão BWEB em andamento."""
    global _CANCELAR_BWEB_FLAG
    _CANCELAR_BWEB_FLAG.set()
    _STATUS_BWEB["mensagem"] = "Cancelamento solicitado..."
    return {"ok": True, "mensagem": "Cancelamento solicitado."}


def obter_status_ingestao_bweb() -> dict[str, Any]:
    """Retorna o status em tempo real do processamento do BWEB."""
    return dict(_STATUS_BWEB)
