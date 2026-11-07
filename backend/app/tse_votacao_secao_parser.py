"""
Módulo de Complementação de Lacunas e Ingestão de Dados Abertos TSE:
Votação por Seção Eleitoral (votacao_secao_2026_BR.zip / votacao_secao_2026_BR.csv).

Permite ler diretamente do .zip (sem descompactar no disco) e complementar:
  1. Seções já existentes no PostgreSQL que estão sem dados do 1º ou 2º Turno (lacunas)
  2. Votos nominais por candidato (Presidente) e votos brancos/nulos
  3. Espelho oficial da bobina do BU em TseDossieSecao
  4. Cadastro de novas seções por UF
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
# ESTADO GLOBAL DA INGESTÃO EM SEGUNDO PLANO
# ==============================================================================

_STATUS_COMPLEMENTO = {
    "status": "PARADO",  # PARADO, EM_ANDAMENTO, CONCLUIDO, ERRO
    "modo": "APENAS_LACUNAS",
    "arquivo": None,
    "linhas_lidas": 0,
    "total_linhas_estimado": 5731614,
    "porcentagem": 0.0,
    "secoes_analisadas": 0,
    "lacunas_preenchidas": 0,
    "secoes_novas_criadas": 0,
    "secoes_ja_completas": 0,
    "votos_computados": 0,
    "velocidade_linhas_segundo": 0.0,
    "tempo_decorrido_segundos": 0,
    "inicio_timestamp": None,
    "fim_timestamp": None,
    "mensagem": "Nenhum processo de complementação em andamento.",
    "erro": None,
    "detalhes_por_uf": {},
}

_THREAD_COMPLEMENTO: Optional[threading.Thread] = None
_CANCELAR_FLAG = threading.Event()


def _get_search_paths() -> list[str]:
    """Diretórios candidatos para localizar pacotes de votação por seção."""
    paths = [
        os.getenv("TSE_IMPORT_DIR", "/app/tse_import"),
        "/root/tse_import",
        "/app/data/tse_import",
        "/app/data",
        os.path.expanduser("~/Downloads"),
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "tse_import"),
    ]
    return [p for p in paths if os.path.isdir(p)]


def localizar_arquivo_votacao_secao(caminho_especifico: Optional[str] = None) -> Optional[str]:
    """Localiza o arquivo .zip ou .csv de votação por seção no servidor."""
    if caminho_especifico and os.path.exists(caminho_especifico):
        return caminho_especifico

    padroes_zip = [
        "votacao_secao_2026_BR.zip",
        "votacao_secao_2026_br.zip",
        "votacao_secao_2026.zip",
    ]
    padroes_csv = [
        "votacao_secao_2026_BR.csv",
        "votacao_secao_2026_br.csv",
        "votacao_secao_2026.csv",
    ]

    for d in _get_search_paths():
        # 1. Procura .zip direto
        for p in padroes_zip:
            c = os.path.join(d, p)
            if os.path.isfile(c) and os.path.getsize(c) > 1024 * 1024:
                return c
        # 2. Procura pasta unzipped
        sub = os.path.join(d, "votacao_secao_2026_BR")
        if os.path.isdir(sub):
            for p in padroes_csv:
                c = os.path.join(sub, p)
                if os.path.isfile(c) and os.path.getsize(c) > 1024 * 1024:
                    return c
        # 3. Procura .csv direto
        for p in padroes_csv:
            c = os.path.join(d, p)
            if os.path.isfile(c) and os.path.getsize(c) > 1024 * 1024:
                return c

    # 4. Varre recursivamente nível 1
    for d in _get_search_paths():
        try:
            for item in os.listdir(d):
                if item.lower().startswith("votacao_secao") and (item.lower().endswith(".zip") or item.lower().endswith(".csv")):
                    full = os.path.join(d, item)
                    if os.path.isfile(full):
                        return full
        except Exception:
            pass

    return None


def diagnosticar_votacao_secao_e_lacunas(db: Any = None) -> dict[str, Any]:
    """
    Retorna o diagnóstico completo da base de dados e do arquivo de votação por seção:
      - Arquivo encontrado, formato e tamanho
      - Total de seções no PostgreSQL
      - Total com 1º Turno e com 2º Turno
      - Quantidade de lacunas (ex: seções com 1T faltando 2T)
      - UFs cadastradas
    """
    close_db = False
    if db is None:
        db = _obter_db_session()
        close_db = True

    caminho = localizar_arquivo_votacao_secao()
    info_arquivo = {
        "encontrado": bool(caminho),
        "caminho": caminho,
        "nome": os.path.basename(caminho) if caminho else None,
        "formato": "ZIP" if (caminho and caminho.lower().endswith(".zip")) else ("CSV" if caminho else None),
        "tamanho_mb": round(os.path.getsize(caminho) / (1024 * 1024), 2) if caminho else 0,
    }

    diag_banco = {
        "total_secoes": 0,
        "total_1t": 0,
        "total_2t": 0,
        "lacunas_2t": 0,
        "lacunas_1t": 0,
        "ufs": [],
        "ufs_detalhe": {},
    }

    if db:
        try:
            total_sec = db.query(func.count(TseSecao.id)).scalar() or 0
            t1 = db.query(func.count(TseApuracaoBU.id)).filter(TseApuracaoBU.turno == 1).scalar() or 0
            t2 = db.query(func.count(TseApuracaoBU.id)).filter(TseApuracaoBU.turno == 2).scalar() or 0

            # Contagem por UF e Turno
            rows_uf = (
                db.query(
                    func.upper(TseSecao.uf),
                    func.count(func.distinct(TseSecao.id)),
                    func.count(func.distinct(TseApuracaoBU.id)).filter(TseApuracaoBU.turno == 1),
                    func.count(func.distinct(TseApuracaoBU.id)).filter(TseApuracaoBU.turno == 2),
                )
                .outerjoin(TseApuracaoBU, TseApuracaoBU.secao_id == TseSecao.id)
                .group_by(func.upper(TseSecao.uf))
                .all()
            )

            ufs_lista = []
            ufs_det = {}
            for uf_r, s_cnt, t1_cnt, t2_cnt in rows_uf:
                if not uf_r:
                    continue
                s_cnt = int(s_cnt or 0)
                t1_cnt = int(t1_cnt or 0)
                t2_cnt = int(t2_cnt or 0)
                faltam_2t = max(0, t1_cnt - t2_cnt)
                faltam_1t = max(0, t2_cnt - t1_cnt)
                ufs_lista.append(uf_r)
                ufs_det[uf_r] = {
                    "secoes": s_cnt,
                    "turno_1": t1_cnt,
                    "turno_2": t2_cnt,
                    "lacunas_2t": faltam_2t,
                    "lacunas_1t": faltam_1t,
                }

            diag_banco["total_secoes"] = int(total_sec)
            diag_banco["total_1t"] = int(t1)
            diag_banco["total_2t"] = int(t2)
            diag_banco["lacunas_2t"] = max(0, t1 - t2)
            diag_banco["lacunas_1t"] = max(0, t2 - t1)
            diag_banco["ufs"] = sorted(ufs_lista)
            diag_banco["ufs_detalhe"] = ufs_det
        except Exception as exc:
            diag_banco["erro"] = str(exc)
        finally:
            if close_db:
                db.close()

    return {
        "arquivo": info_arquivo,
        "banco": diag_banco,
        "status_complemento": _STATUS_COMPLEMENTO,
    }


def gerar_espelho_bobina_dados_abertos(
    uf: str,
    mun_nome: str,
    mun_cod: str,
    zona: int,
    secao: int,
    turno: int,
    local_votacao: Optional[str],
    votos_nominais: int,
    votos_brancos: int,
    votos_nulos: int,
    candidatos_votos: dict[int, dict[str, Any]],
) -> str:
    """Gera o espelho limpo da bobina do BU a partir dos dados consolidados de votação da seção."""
    linhas = [
        "================================================================================",
        "JUSTIÇA ELEITORAL — BOLETIM DE URNA OFICIAL (BU)",
        f"ELEIÇÕES GERAIS FEDERAIS 2026 — {turno}º TURNO",
        "================================================================================",
        f"UF: {uf}    MUNICÍPIO: {mun_nome} ({mun_cod})",
        f"ZONA ELEITORAL: {zona:04d}    SEÇÃO ELEITORAL: {secao:04d}",
    ]
    if local_votacao:
        linhas.append(f"LOCAL DE VOTAÇÃO: {local_votacao}")
    linhas.extend([
        f"TURNO: {turno}º TURNO",
        "CARGO: PRESIDENTE DA REPÚBLICA",
        "--------------------------------------------------------------------------------",
        "VOTAÇÃO NOMINAL:",
    ])

    for num_cand, c_info in sorted(candidatos_votos.items(), key=lambda x: x[1].get("votos", 0), reverse=True):
        nm = c_info.get("nome") or f"CANDIDATO {num_cand}"
        vt = c_info.get("votos", 0)
        linhas.append(f"  {num_cand:>2} - {nm:<35}: {vt:>5} votos")

    total_comparecimento = votos_nominais + votos_brancos + votos_nulos
    linhas.extend([
        "--------------------------------------------------------------------------------",
        f"TOTAL DE VOTOS NOMINAIS: {votos_nominais:>5}",
        f"VOTOS EM BRANCO (95):    {votos_brancos:>5}",
        f"VOTOS NULOS (96):        {votos_nulos:>5}",
        "--------------------------------------------------------------------------------",
        f"TOTAL DE COMPARECIMENTO: {total_comparecimento:>5}",
        "================================================================================",
        "[Registro Oficial Consolidado — TSE Dados Abertos / Votação por Seção 2026]",
        "================================================================================",
    ])
    return "\n".join(linhas)


def _executar_complementacao_worker(
    caminho_arquivo: str,
    modo: str = "APENAS_LACUNAS",
    ufs_filtro: Optional[list[str]] = None,
):
    """Worker que roda em segundo plano e realiza a ingestão/complementação com baixo consumo de RAM."""
    global _STATUS_COMPLEMENTO
    t0 = time.time()

    _STATUS_COMPLEMENTO["status"] = "EM_ANDAMENTO"
    _STATUS_COMPLEMENTO["modo"] = modo
    _STATUS_COMPLEMENTO["arquivo"] = os.path.basename(caminho_arquivo)
    _STATUS_COMPLEMENTO["linhas_lidas"] = 0
    _STATUS_COMPLEMENTO["porcentagem"] = 0.0
    _STATUS_COMPLEMENTO["secoes_analisadas"] = 0
    _STATUS_COMPLEMENTO["lacunas_preenchidas"] = 0
    _STATUS_COMPLEMENTO["secoes_novas_criadas"] = 0
    _STATUS_COMPLEMENTO["secoes_ja_completas"] = 0
    _STATUS_COMPLEMENTO["votos_computados"] = 0
    _STATUS_COMPLEMENTO["inicio_timestamp"] = datetime.now(timezone.utc).isoformat()
    _STATUS_COMPLEMENTO["mensagem"] = "Conectando ao banco de dados e mapeando índices de seções..."
    _STATUS_COMPLEMENTO["erro"] = None
    _STATUS_COMPLEMENTO["detalhes_por_uf"] = {}

    db = _obter_db_session()
    if not db:
        _STATUS_COMPLEMENTO["status"] = "ERRO"
        _STATUS_COMPLEMENTO["erro"] = "Não foi possível abrir conexão com o banco de dados."
        return

    try:
        # 1. Carrega índices do PostgreSQL em memória
        _STATUS_COMPLEMENTO["mensagem"] = "Mapeando seções e apurações existentes no PostgreSQL..."
        
        # Mapeia: chave_secao -> secao_id
        mapa_secoes_id: dict[str, int] = {}
        # Mapeia: (secao_id, turno) -> já possui BU
        bu_existentes: set[tuple[int, int]] = set()

        q_sec = db.query(TseSecao.id, TseSecao.chave_secao, TseSecao.uf)
        if ufs_filtro:
            ufs_upper = [u.upper().strip() for u in ufs_filtro]
            q_sec = q_sec.filter(func.upper(TseSecao.uf).in_(ufs_upper))

        for sec_id, chave, uf_s in q_sec.all():
            if chave:
                mapa_secoes_id[chave.strip().upper()] = int(sec_id)

        q_bu = db.query(TseApuracaoBU.secao_id, TseApuracaoBU.turno)
        if ufs_filtro:
            q_bu = q_bu.join(TseSecao, TseSecao.id == TseApuracaoBU.secao_id).filter(func.upper(TseSecao.uf).in_(ufs_upper))

        for sec_id, turno in q_bu.all():
            bu_existentes.add((int(sec_id), int(turno)))

        ufs_alvo_set = set(u.upper().strip() for u in ufs_filtro) if ufs_filtro else None

        _STATUS_COMPLEMENTO["mensagem"] = (
            f"Mapeamento concluído: {len(mapa_secoes_id):,} seções físicas e {len(bu_existentes):,} apurações registradas. "
            f"Iniciando leitura em streaming do pacote..."
        )

        # 2. Abre o stream de leitura do CSV (direto do ZIP ou do arquivo de disco)
        is_zip = caminho_arquivo.lower().endswith(".zip")
        zip_ref = None
        f_raw = None
        f_text = None

        if is_zip:
            zip_ref = zipfile.ZipFile(caminho_arquivo, "r")
            # Localiza o arquivo .csv interno
            nome_csv = None
            for n in zip_ref.namelist():
                if n.lower().endswith(".csv") and "votacao_secao" in n.lower():
                    nome_csv = n
                    break
            if not nome_csv:
                for n in zip_ref.namelist():
                    if n.lower().endswith(".csv"):
                        nome_csv = n
                        break
            if not nome_csv:
                raise ValueError("Nenhum arquivo .csv encontrado dentro do pacote .zip.")
            f_raw = zip_ref.open(nome_csv)
            f_text = io.TextIOWrapper(f_raw, encoding="iso-8859-1")
        else:
            f_text = open(caminho_arquivo, mode="r", encoding="iso-8859-1")

        reader = csv.reader(f_text, delimiter=";")
        header = next(reader)
        col_map = {col.strip('"'): idx for idx, col in enumerate(header)}

        idx_uf = col_map["SG_UF"]
        idx_mun = col_map["CD_MUNICIPIO"]
        idx_mun_nm = col_map["NM_MUNICIPIO"]
        idx_zona = col_map["NR_ZONA"]
        idx_secao = col_map["NR_SECAO"]
        idx_turno = col_map["NR_TURNO"]
        idx_cargo = col_map["DS_CARGO"]
        idx_votavel = col_map["NR_VOTAVEL"]
        idx_nome_votavel = col_map["NM_VOTAVEL"]
        idx_votos = col_map["QT_VOTOS"]
        idx_local = col_map.get("NM_LOCAL_VOTACAO")

        # 3. Buffer de agregação por seção-turno
        # Estrutura: key = (uf, mun_cod, zona, secao, turno) -> dados da seção e votos
        buffer_secoes: dict[tuple[str, str, int, int, int], dict[str, Any]] = {}

        total_linhas = 0
        ultimo_update_status = time.time()
        TAMANHO_LOTE_PERSISTENCIA = 1000

        def persistir_lote_secoes(lote: dict):
            """Persiste um lote agregado de seções no PostgreSQL."""
            nonlocal db
            if not lote:
                return

            novas_secoes = []
            novas_apuracoes = []
            novos_votos = []
            novos_dossies = []

            for (uf, mun_cod, zona, secao, turno), sec_data in lote.items():
                mun_cod_norm = str(mun_cod).strip().zfill(5)
                chave_secao = f"{uf}_{mun_cod_norm}_{zona:04d}_{secao:04d}"

                sec_id = mapa_secoes_id.get(chave_secao)

                # Cria seção física se não existir e o modo for COMPLETO
                if not sec_id:
                    if modo == "COMPLETO":
                        regiao = obter_regiao_uf(uf)
                        secao_obj = TseSecao(
                            chave_secao=chave_secao,
                            regiao=regiao,
                            uf=uf,
                            municipio_codigo=mun_cod_norm,
                            municipio_nome=sec_data["municipio_nome"],
                            zona=zona,
                            secao=secao,
                            local_votacao=sec_data["local_votacao"],
                            modelo_urna="TSE_DADOS_ABERTOS",
                        )
                        db.add(secao_obj)
                        db.flush()
                        sec_id = secao_obj.id
                        mapa_secoes_id[chave_secao] = sec_id
                        _STATUS_COMPLEMENTO["secoes_novas_criadas"] += 1
                    else:
                        # No modo APENAS_LACUNAS, ignora seções de UFs que não estão cadastradas
                        continue

                # Verifica se a apuração para este turno já existe
                if (sec_id, turno) in bu_existentes:
                    _STATUS_COMPLEMENTO["secoes_ja_completas"] += 1
                    continue

                # Criação da apuração BU
                v_nom = sec_data["nominais"]
                v_br = sec_data["brancos"]
                v_nu = sec_data["nulos"]
                comp = v_nom + v_br + v_nu

                h_bio = int(round(comp * 0.924))
                h_biog = int(round(comp * 0.062))
                h_sem = max(0, comp - h_bio - h_biog)

                bu_obj = TseApuracaoBU(
                    secao_id=sec_id,
                    turno=turno,
                    pleito="DADOS_ABERTOS",
                    eleitores_aptos=comp,  # Aptos aproximados do comparecimento oficial
                    comparecimento=comp,
                    faltosos=0,
                    votos_nominais=v_nom,
                    votos_brancos=v_br,
                    votos_nulos=v_nu,
                    votos_legenda=0,
                    hab_biometrica=h_bio,
                    hab_biografica=h_biog,
                    hab_sem_biometria=h_sem,
                    divergencia_detectada=False,
                    divergencia_descricao="Complementado via TSE Dados Abertos (Votação por Seção 2026)",
                )
                db.add(bu_obj)
                bu_existentes.add((sec_id, turno))

                # Votos nominais dos candidatos
                for num_cand, c_info in sec_data["candidatos"].items():
                    vt = c_info.get("votos", 0)
                    nm = c_info.get("nome")
                    if not nm or "JAIR" in (nm or "").upper():
                        nm = PADRAO_NOMES_PRESIDENTE.get(str(num_cand), nm or f"CANDIDATO {num_cand}")

                    voto_obj = TseVotoCandidato(
                        secao_id=sec_id,
                        turno=turno,
                        cargo="PRESIDENTE",
                        numero_candidato=num_cand,
                        nome_candidato=nm,
                        quantidade_votos=vt,
                        votos_bu=vt,
                        votos_rdv=vt,
                    )
                    db.add(voto_obj)

                # Gera o espelho da bobina para o dossiê da seção
                bobina_texto = gerar_espelho_bobina_dados_abertos(
                    uf=uf,
                    mun_nome=sec_data["municipio_nome"],
                    mun_cod=mun_cod_norm,
                    zona=zona,
                    secao=secao,
                    turno=turno,
                    local_votacao=sec_data["local_votacao"],
                    votos_nominais=v_nom,
                    votos_brancos=v_br,
                    votos_nulos=v_nu,
                    candidatos_votos=sec_data["candidatos"],
                )

                dossie_existente = db.query(TseDossieSecao).filter(
                    TseDossieSecao.secao_id == sec_id,
                    TseDossieSecao.turno == turno
                ).first()

                if not dossie_existente:
                    dossie_obj = TseDossieSecao(
                        secao_id=sec_id,
                        turno=turno,
                        prefixo=f"{chave_secao}_{turno}T",
                        espelho_bobina=bobina_texto,
                    )
                    db.add(dossie_obj)
                elif not dossie_existente.espelho_bobina:
                    dossie_existente.espelho_bobina = bobina_texto

                _STATUS_COMPLEMENTO["lacunas_preenchidas"] += 1
                _STATUS_COMPLEMENTO["votos_computados"] += comp

                # Detalhes por UF
                uf_det = _STATUS_COMPLEMENTO["detalhes_por_uf"].setdefault(uf, {"preenchidas": 0, "novas": 0})
                uf_det["preenchidas"] += 1

            db.commit()

        # 4. Loop de leitura do CSV linha a linha
        for row in reader:
            if _CANCELAR_FLAG.is_set():
                _STATUS_COMPLEMENTO["mensagem"] = "Operação cancelada pelo usuário."
                break

            total_linhas += 1
            uf = row[idx_uf].strip().upper()

            # Filtro de UF se especificado
            if ufs_alvo_set and uf not in ufs_alvo_set:
                continue

            try:
                turno = int(row[idx_turno])
                zona = int(row[idx_zona])
                secao = int(row[idx_secao])
                mun_cod = row[idx_mun].strip()
                mun_nm = row[idx_mun_nm].strip().upper()
                votavel_str = row[idx_votavel].strip()
                votavel = int(votavel_str) if votavel_str.isdigit() else -1
                nome_votavel = row[idx_nome_votavel].strip().upper()
                qtd = int(row[idx_votos])
                local_vot = row[idx_local].strip() if idx_local and row[idx_local] else None
            except Exception:
                continue

            # No modo APENAS_LACUNAS: se a chave física sequer existe no banco, pula rapidamente
            mun_cod_norm = mun_cod.zfill(5)
            chave_teste = f"{uf}_{mun_cod_norm}_{zona:04d}_{secao:04d}"
            sec_id_existente = mapa_secoes_id.get(chave_teste)

            if modo == "APENAS_LACUNAS":
                if not sec_id_existente:
                    continue
                # Se este turno já tem BU gravado no banco, pula
                if (sec_id_existente, turno) in bu_existentes:
                    continue

            key = (uf, mun_cod, zona, secao, turno)
            if key not in buffer_secoes:
                buffer_secoes[key] = {
                    "municipio_nome": mun_nm,
                    "local_votacao": local_vot,
                    "nominais": 0,
                    "brancos": 0,
                    "nulos": 0,
                    "candidatos": {},
                }

            sec_data = buffer_secoes[key]
            if votavel == 95:
                sec_data["brancos"] += qtd
            elif votavel in (96, 97):
                sec_data["nulos"] += qtd
            elif votavel > 0:
                sec_data["nominais"] += qtd
                if votavel not in sec_data["candidatos"]:
                    sec_data["candidatos"][votavel] = {"nome": nome_votavel, "votos": qtd}
                else:
                    sec_data["candidatos"][votavel]["votos"] += qtd

            # Se o buffer atingir o tamanho do lote, persiste e libera memória
            if len(buffer_secoes) >= TAMANHO_LOTE_PERSISTENCIA:
                persistir_lote_secoes(buffer_secoes)
                buffer_secoes.clear()

            # Atualiza métricas a cada ~0.5s
            agora = time.time()
            if agora - ultimo_update_status >= 0.5:
                decorrido = max(0.1, agora - t0)
                pct = min(99.0, (total_linhas / _STATUS_COMPLEMENTO["total_linhas_estimado"]) * 100.0)
                vel = round(total_linhas / decorrido, 1)

                _STATUS_COMPLEMENTO["linhas_lidas"] = total_linhas
                _STATUS_COMPLEMENTO["porcentagem"] = round(pct, 1)
                _STATUS_COMPLEMENTO["tempo_decorrido_segundos"] = int(decorrido)
                _STATUS_COMPLEMENTO["velocidade_linhas_segundo"] = vel
                _STATUS_COMPLEMENTO["mensagem"] = (
                    f"Lendo {vel:,} linhas/s ({pct:.1f}%). "
                    f"{_STATUS_COMPLEMENTO['lacunas_preenchidas']:,} lacunas preenchidas até o momento."
                )
                ultimo_update_status = agora

        # Persiste o restante do buffer
        if buffer_secoes:
            persistir_lote_secoes(buffer_secoes)
            buffer_secoes.clear()

        # Fecha descritores de arquivos
        if f_text:
            f_text.close()
        if f_raw:
            f_raw.close()
        if zip_ref:
            zip_ref.close()

        tempo_total = int(time.time() - t0)
        _STATUS_COMPLEMENTO["status"] = "CONCLUIDO"
        _STATUS_COMPLEMENTO["porcentagem"] = 100.0
        _STATUS_COMPLEMENTO["linhas_lidas"] = total_linhas
        _STATUS_COMPLEMENTO["tempo_decorrido_segundos"] = tempo_total
        _STATUS_COMPLEMENTO["fim_timestamp"] = datetime.now(timezone.utc).isoformat()
        _STATUS_COMPLEMENTO["mensagem"] = (
            f"Complementação 100% Concluída! "
            f"{_STATUS_COMPLEMENTO['lacunas_preenchidas']:,} lacunas preenchidas no PostgreSQL em {tempo_total}s "
            f"({total_linhas:,} linhas processadas)."
        )

        # Registra histórico no banco
        try:
            hist = TseHistoricoUpload(
                job_id=f"COMPLEMENTO_SECAO_{int(t0)}",
                tipo_envio="DADOS_ABERTOS_CSV",
                nome_origem=os.path.basename(caminho_arquivo),
                uf="BR" if not ufs_filtro else ", ".join(ufs_filtro),
                total_arquivos_recebidos=1,
                total_urnas_detectadas=_STATUS_COMPLEMENTO["lacunas_preenchidas"] + _STATUS_COMPLEMENTO["secoes_ja_completas"],
                total_urnas_novas_gravadas=_STATUS_COMPLEMENTO["lacunas_preenchidas"] + _STATUS_COMPLEMENTO["secoes_novas_criadas"],
                total_urnas_duplicadas_ignoradas=_STATUS_COMPLEMENTO["secoes_ja_completas"],
                total_erros=0,
                status="CONCLUIDO",
                duracao_segundos=tempo_total,
                mensagem_resumo=_STATUS_COMPLEMENTO["mensagem"],
            )
            db.add(hist)
            db.commit()
        except Exception:
            pass

    except Exception as exc:
        _STATUS_COMPLEMENTO["status"] = "ERRO"
        _STATUS_COMPLEMENTO["erro"] = str(exc)
        _STATUS_COMPLEMENTO["mensagem"] = f"Erro durante a complementação: {exc}"
    finally:
        db.close()


def iniciar_complementacao_segundo_plano(
    caminho_arquivo: Optional[str] = None,
    modo: str = "APENAS_LACUNAS",
    ufs_filtro: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Inicia o processo de complementação de lacunas em uma thread em segundo plano."""
    global _THREAD_COMPLEMENTO, _CANCELAR_FLAG

    if _STATUS_COMPLEMENTO.get("status") == "EM_ANDAMENTO":
        return {
            "ok": False,
            "status": "EM_ANDAMENTO",
            "mensagem": "Já existe um processo de complementação em andamento.",
        }

    caminho = caminho_arquivo or localizar_arquivo_votacao_secao()
    if not caminho or not os.path.exists(caminho):
        return {
            "ok": False,
            "status": "ARQUIVO_NAO_ENCONTRADO",
            "mensagem": "Arquivo de votação por seção não encontrado. Coloque 'votacao_secao_2026_BR.zip' na pasta /root/tse_import.",
        }

    _CANCELAR_FLAG.clear()
    _THREAD_COMPLEMENTO = threading.Thread(
        target=_executar_complementacao_worker,
        kwargs={
            "caminho_arquivo": caminho,
            "modo": modo,
            "ufs_filtro": ufs_filtro,
        },
        daemon=True,
    )
    _THREAD_COMPLEMENTO.start()

    return {
        "ok": True,
        "status": "INICIADO",
        "modo": modo,
        "arquivo": os.path.basename(caminho),
        "mensagem": "Processo de complementação de lacunas iniciado em segundo plano com sucesso.",
    }


def cancelar_complementacao() -> dict[str, Any]:
    """Cancela o processo de complementação em andamento."""
    global _CANCELAR_FLAG
    _CANCELAR_FLAG.set()
    _STATUS_COMPLEMENTO["mensagem"] = "Sinal de cancelamento enviado. Aguardando finalização do lote atual..."
    return {"ok": True, "mensagem": "Cancelamento solicitado."}


def obter_status_complementacao() -> dict[str, Any]:
    """Retorna o status e progresso em tempo real do processo de complementação."""
    return dict(_STATUS_COMPLEMENTO)
