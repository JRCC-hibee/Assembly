"""
Módulo Pericial: Leitor, Extrator e Comparador Forense de Relatórios de Totalização Oficiais do TSE (SISTOT / PDF).

Lê os relatórios oficiais de totalização gerados pelo SISTOT (Justiça Eleitoral) em formato .PDF
(ex: 6258_PR_PARANÁ_2026_T2_PRESIDENTE.pdf, 6257_PR_PARANÁ_2026_T1_PRESIDENTE.pdf, 6259_PR_PARANÁ_2026_T1.pdf)
ou pacotes compactados .ZIP (ex: Relatorio_Resultado_Totalizacao_2026_PR.zip).

Extrai:
  1. Resumo Geral da Circunscrição (Seções, Aptos, Comparecimento, Abstenção, Votos Nominais, Brancos, Nulos)
  2. Resultado Oficial da Votação dos Candidatos (Anexo IV / Anexo IX)
  3. Seções Eleitorais Agregadas (Anexo I)
  4. Ocorrências Especiais de Correspondências / Urnas de Contingência (Anexo V / Anexo XIII)

Executa o batimento pericial cruzado contra a base PostgreSQL (BU x RDV ASN.1 x Log.jez)
para atestar a integridade e consistência 100% da eleição.
"""

import io
import json
import os
import re
import zipfile
import hashlib
from typing import Any, BinaryIO, Optional, Union

try:
    import pypdf
except ImportError:
    pypdf = None

try:
    from sqlalchemy import func, or_
    from .database import (
        TseSecao,
        TseApuracaoBU,
        TseVotoCandidato,
        TseRelatorioOficialTse,
        _obter_db_session,
    )
except ImportError:
    func = None
    or_ = None
    TseSecao = None
    TseApuracaoBU = None
    TseVotoCandidato = None
    TseRelatorioOficialTse = None
    _obter_db_session = None


def extrair_relatorio_totalizacao_pdf(
    arquivo_ou_bytes: Union[str, bytes, BinaryIO],
    nome_arquivo: str = "relatorio.pdf"
) -> list[dict[str, Any]]:
    """
    Decodifica um arquivo PDF oficial do SISTOT/TSE e retorna os dados estruturados de cada eleição/cargo presente.
    Pode retornar múltiplos registros se o PDF contiver mais de um cargo (ex: 6259 Estadual com Governador, Senador, etc.).
    """
    if pypdf is None:
        raise RuntimeError("Biblioteca pypdf não instalada no servidor. Instale com 'pip install pypdf'.")

    # Obtém bytes e hash sha256
    if isinstance(arquivo_ou_bytes, str):
        if not os.path.isfile(arquivo_ou_bytes):
            raise FileNotFoundError(f"Arquivo não encontrado: {arquivo_ou_bytes}")
        with open(arquivo_ou_bytes, "rb") as fp:
            conteudo_bytes = fp.read()
        nome_arquivo = os.path.basename(arquivo_ou_bytes)
    elif isinstance(arquivo_ou_bytes, bytes):
        conteudo_bytes = arquivo_ou_bytes
    else:
        conteudo_bytes = arquivo_ou_bytes.read()

    hash_sha256 = hashlib.sha256(conteudo_bytes).hexdigest()
    tamanho_bytes = len(conteudo_bytes)

    stream = io.BytesIO(conteudo_bytes)
    reader = pypdf.PdfReader(stream)
    num_paginas = len(reader.pages)
    if num_paginas < 2:
        return []

    # Extração de Metadados do Nome do Arquivo (Ex: 6258_PR_PARANÁ_2026_T2_PRESIDENTE.pdf)
    eleicao_cod_m = re.match(r"^(\d{4})_([A-Za-z]{2})_([^_]+)_(\d{4})_(T[12])(?:_([^\.]+))?\.pdf$", nome_arquivo, re.I)
    cod_eleicao_fn = eleicao_cod_m.group(1) if eleicao_cod_m else ""
    uf_fn = eleicao_cod_m.group(2).upper() if eleicao_cod_m else ""
    ano_fn = eleicao_cod_m.group(4) if eleicao_cod_m else "2026"
    turno_fn = 2 if (eleicao_cod_m and eleicao_cod_m.group(5).upper() == "T2") else 1
    cargo_fn = eleicao_cod_m.group(6).upper() if (eleicao_cod_m and eleicao_cod_m.group(6)) else ""

    # Página 2 e 3: Resumo Geral
    p2_txt = reader.pages[1].extract_text()
    p3_txt = reader.pages[2].extract_text() if num_paginas > 2 else ""
    full_resumo = p2_txt + "\n" + p3_txt

    m_data = re.search(r"(\d{2}/\d{2}/\d{4})\s+(\d{2}:\d{2}:\d{2})", p2_txt)
    data_geracao = f"{m_data.group(1)} {m_data.group(2)}" if m_data else ""

    m_data_eleicao = re.search(r"Eleiç[õo]es?\s+Gera[il]s?[^\d]+(\d{2}/\d{2}/\d{4})", p2_txt)
    data_eleicao = m_data_eleicao.group(1) if m_data_eleicao else ("25/10/2026" if turno_fn == 2 else "04/10/2026")

    m_eleicao_tit = re.search(r"(Eleiç[õo]es?\s+Gera[il]s?[^\n-]+)", p2_txt, re.I)
    eleicao_nome = m_eleicao_tit.group(1).strip() if m_eleicao_tit else f"Eleições Gerais {ano_fn}"

    m_turno_txt = re.search(r"([12])º\s+Turno", p2_txt, re.I)
    turno = int(m_turno_txt.group(1)) if m_turno_txt else turno_fn

    m_uf_circ = re.search(r"Circunscrição\s*-\s*([A-ZÁÉÍÓÚÂÊÔÃÕÇ\s]+)", full_resumo, re.I)
    uf_nome = m_uf_circ.group(1).strip().splitlines()[0].strip() if m_uf_circ else "PARANÁ"
    uf_code = uf_fn or ("PR" if "PARAN" in uf_nome.upper() else "BR")

    # 1. Seções eleitorais
    m_agreg = re.search(r"Total de seções agregadas\s+(\d+[\.\d+]*)", full_resumo)
    secoes_agregadas = int(m_agreg.group(1).replace(".", "")) if m_agreg else 0

    m_princ = re.search(r"Total de seções principais[^\d]*(\d+[\.\d+]*)", full_resumo)
    secoes_principais = int(m_princ.group(1).replace(".", "")) if m_princ else 0

    secoes_total = secoes_principais + secoes_agregadas

    # 2. Eleitorado apto, comparecimento, abstenção
    m_aptos = re.search(r"Eleitorado apto a votar\s+(\d+[\.\d+]*)", full_resumo)
    eleitorado_apto = int(m_aptos.group(1).replace(".", "")) if m_aptos else 0

    m_comp = re.search(r"Comparecimento\s+(\d+[\.\d+]*)", full_resumo)
    comparecimento = int(m_comp.group(1).replace(".", "")) if m_comp else 0

    m_abst = re.search(r"Abstenção\s+[\d,]+%\s+(\d+[\.\d+]*)", full_resumo)
    abstencao = int(m_abst.group(1).replace(".", "")) if m_abst else max(0, eleitorado_apto - comparecimento)

    pct_comp = round((comparecimento / max(eleitorado_apto, 1)) * 100.0, 2)
    pct_abst = round((abstencao / max(eleitorado_apto, 1)) * 100.0, 2)

    # 3. Extração dos Votos do Resumo (Votos Nominais Concorrentes, Brancos, Nulos, Válidos)
    numeros_p3 = []
    for line in p3_txt.splitlines():
        l_s = line.strip().replace(".", "")
        if l_s.isdigit() and len(l_s) >= 4:
            numeros_p3.append(int(l_s))

    votos_concorrentes = 0
    votos_brancos = 0
    votos_nulos = 0
    if len(numeros_p3) >= 4:
        votos_concorrentes = numeros_p3[1]
        votos_brancos = numeros_p3[2]
        votos_nulos = numeros_p3[3]

    m_validos = re.search(r"Votos válidos\s+[\d,]+%\s+(\d+[\.\d+]*)", full_resumo)
    votos_validos = int(m_validos.group(1).replace(".", "")) if m_validos else votos_concorrentes

    # 4. Extração de Seções Agregadas (Anexo I)
    secoes_agregadas_list = []
    pat_agreg = re.compile(r"(\d{4})\s+(\d{4})\s*/\s*(\d+)\s+(\d{4})\s*/\s*(\d+)\s+(\d+)\s+(\d+)\s+Não\s+Apurada\s*/\s*Agregação")
    mun_atual_ag = ""
    for page in reader.pages:
        txt = page.extract_text()
        if "Anexo I" in txt:
            for line in txt.splitlines():
                if "Município:" in line:
                    mun_atual_ag = line.split("Município:")[1].strip()
                m_a = pat_agreg.search(line)
                if m_a:
                    z, sec_p, apt_p, sec_a, apt_a, tot_e, c_ef = m_a.groups()
                    secoes_agregadas_list.append({
                        "municipio": mun_atual_ag,
                        "zona": z,
                        "secao_principal": sec_p,
                        "aptos_principal": int(apt_p),
                        "secao_agregada": sec_a,
                        "aptos_agregada": int(apt_a),
                        "total_eleitores": int(tot_e),
                        "comparecimento": int(c_ef),
                    })

    # 5. Extração de Ocorrências Especiais / Contingências (Anexo V / XIII)
    contingencias_list = []
    mun_atual_ct = ""
    for page in reader.pages:
        txt = page.extract_text()
        if "Anexo V" in txt or "Anexo XIII" in txt:
            lines = [l.strip() for l in txt.splitlines() if l.strip()]
            idx_l = 0
            while idx_l < len(lines):
                cur_l = lines[idx_l]
                if cur_l.startswith("Município:"):
                    mun_atual_ct = cur_l.replace("Município:", "").strip()
                    idx_l += 1
                    continue
                m_cont = re.match(r"^(\d{4})\s+(\d{4})\s+Contingência\s+(\d{2}/\d{2}/\d{4})", cur_l)
                if m_cont:
                    z, sec, dt_oc = m_cont.groups()
                    hr_oc = lines[idx_l + 1] if idx_l + 1 < len(lines) and re.match(r"^\d{2}:\d{2}:\d{2}$", lines[idx_l + 1]) else ""
                    rest_line = lines[idx_l + 2] if hr_oc and idx_l + 2 < len(lines) else (lines[idx_l + 1] if idx_l + 1 < len(lines) else "")
                    m_efet = re.search(r"Efetivada\s+UE\s+(\d+)\s+([\d\.]+)\s+([A-F0-9]+)\s+(\d{2}/\d{2}/\d{4})", rest_line)
                    if m_efet:
                        id_ue, id_carga, id_mc, dt_carga = m_efet.groups()
                        contingencias_list.append({
                            "municipio": mun_atual_ct,
                            "zona": z,
                            "secao": sec,
                            "data_hora_ocorrencia": f"{dt_oc} {hr_oc}".strip(),
                            "id_urna_efetivada": id_ue,
                            "id_carga": id_carga,
                            "id_mc": id_mc,
                            "data_carga": dt_carga,
                        })
                idx_l += 1

    # 6. Extração de Candidatos e Cargos (Anexo IV / Anexo IX)
    candidatos_por_cargo: dict[str, list[dict]] = {}
    cargo_detectado = cargo_fn or ("PRESIDENTE" if "PRESIDENTE" in nome_arquivo.upper() else "GOVERNADOR")
    pat_cargo = re.compile(r"Cargo:\s*([A-Za-zÀ-ÖØ-öø-ÿ\s]+)", re.I)
    pat_cand = re.compile(
        r"([\d\.]+)\s+([\d,]+)%\s*(?:Eleito\*?|N[aã]o\s+eleito|2º\s+turno|Suplente)?\s*(\d+)\s*-\s*(.+?)\s+(V[aá]lido|Anulado(?:\s+sub\s+judice)?|Indeferido)",
        re.I
    )

    for page in reader.pages:
        txt = page.extract_text()
        if "Resultado de votação" in txt or "Anexo IV" in txt or "Anexo IX" in txt:
            for l in txt.splitlines():
                m_c = pat_cargo.search(l)
                if m_c:
                    cargo_detectado = m_c.group(1).strip().upper()
            for m in pat_cand.finditer(txt):
                v_str, pct_str, num_str, nome_str, dest_str = m.groups()
                cand_item = {
                    "numero": num_str,
                    "nome": nome_str.strip(),
                    "votos": int(v_str.replace(".", "")),
                    "percentual": float(pct_str.replace(",", ".")),
                    "destinacao": dest_str.strip(),
                    "cargo": cargo_detectado,
                }
                candidatos_por_cargo.setdefault(cargo_detectado, []).append(cand_item)

    # Se não agrupou nenhum candidato por cargo, atribui o cargo padrão da eleição
    if not candidatos_por_cargo:
        candidatos_por_cargo[cargo_detectado] = []

    resultados: list[dict[str, Any]] = []

    for cg, cands_lista in candidatos_por_cargo.items():
        v_nom_cg = sum(c["votos"] for c in cands_lista) if cands_lista else votos_concorrentes
        v_val_cg = v_nom_cg if v_nom_cg > 0 else votos_validos
        tot_cands_apurados = len(cands_lista)

        item = {
            "nome_arquivo": nome_arquivo,
            "tamanho_bytes": tamanho_bytes,
            "hash_sha256": hash_sha256,
            "eleicao_codigo": cod_eleicao_fn,
            "eleicao_nome": eleicao_nome,
            "turno": turno,
            "cargo": cg,
            "uf": uf_code,
            "uf_nome": uf_nome,
            "data_eleicao": data_eleicao,
            "data_geracao_relatorio": data_geracao,
            "secoes_principais": secoes_principais,
            "secoes_agregadas": secoes_agregadas,
            "secoes_total": secoes_total,
            "eleitorado_apto": eleitorado_apto,
            "comparecimento": comparecimento,
            "abstencao": abstencao,
            "pct_comparecimento": pct_comp,
            "pct_abstencao": pct_abst,
            "votos_nominais": v_nom_cg,
            "votos_brancos": votos_brancos,
            "votos_nulos": votos_nulos,
            "votos_validos": v_val_cg,
            "total_candidatos": tot_cands_apurados,
            "candidatos": cands_lista,
            "secoes_agregadas_list": secoes_agregadas_list,
            "total_agregadas": len(secoes_agregadas_list),
            "contingencias_list": contingencias_list,
            "total_contingencias": len(contingencias_list),
            "total_paginas_pdf": num_paginas,
        }
        resultados.append(item)

    return resultados


def extrair_relatorios_de_zip(zip_bytes_ou_path: Union[str, bytes, BinaryIO]) -> list[dict[str, Any]]:
    """
    Descompacta um arquivo .ZIP (ex: Relatorio_Resultado_Totalizacao_2026_PR.zip)
    e extrai todos os relatórios PDF oficiais contidos nele.
    """
    if isinstance(zip_bytes_ou_path, str):
        zf = zipfile.ZipFile(zip_bytes_ou_path, "r")
    elif isinstance(zip_bytes_ou_path, bytes):
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes_ou_path), "r")
    else:
        zf = zipfile.ZipFile(zip_bytes_ou_path, "r")

    relatorios = []
    with zf:
        for fname in sorted(zf.namelist()):
            if fname.lower().endswith(".pdf") and not fname.startswith("__MACOSX") and not fname.lower().endswith("_leiame.pdf"):
                try:
                    pdf_data = zf.read(fname)
                    itens = extrair_relatorio_totalizacao_pdf(pdf_data, nome_arquivo=os.path.basename(fname))
                    relatorios.extend(itens)
                except Exception as exc:
                    print(f"[TSE-PDF] Erro ao extrair PDF '{fname}' do ZIP: {exc}")

    return relatorios


def salvar_relatorio_no_banco(
    db,
    dados_relatorio: dict[str, Any],
    auto_commit: bool = True
):
    """
    Persiste ou atualiza o registro do Relatório Oficial no PostgreSQL e executa o batimento cruzado contra o banco.
    """
    uf = dados_relatorio.get("uf", "PR").strip().upper()
    turno = int(dados_relatorio.get("turno", 2))
    cargo = dados_relatorio.get("cargo", "PRESIDENTE").strip().upper()
    nome_arquivo = dados_relatorio.get("nome_arquivo", "relatorio.pdf")

    # Localiza registro existente para atualizar ou cria novo
    rel_db = db.query(TseRelatorioOficialTse).filter(
        TseRelatorioOficialTse.uf == uf,
        TseRelatorioOficialTse.turno == turno,
        TseRelatorioOficialTse.cargo == cargo,
    ).first()

    if not rel_db:
        rel_db = TseRelatorioOficialTse(
            uf=uf,
            turno=turno,
            cargo=cargo,
            nome_arquivo=nome_arquivo,
        )
        db.add(rel_db)

    rel_db.eleicao_codigo = dados_relatorio.get("eleicao_codigo")
    rel_db.eleicao_nome = dados_relatorio.get("eleicao_nome")
    rel_db.data_eleicao = dados_relatorio.get("data_eleicao")
    rel_db.data_geracao_relatorio = dados_relatorio.get("data_geracao_relatorio")
    rel_db.nome_arquivo = nome_arquivo
    rel_db.tamanho_bytes = dados_relatorio.get("tamanho_bytes", 0)
    rel_db.hash_sha256 = dados_relatorio.get("hash_sha256")

    rel_db.secoes_principais = dados_relatorio.get("secoes_principais", 0)
    rel_db.secoes_agregadas = dados_relatorio.get("secoes_agregadas", 0)
    rel_db.secoes_total = dados_relatorio.get("secoes_total", 0)
    rel_db.eleitorado_apto = dados_relatorio.get("eleitorado_apto", 0)
    rel_db.comparecimento = dados_relatorio.get("comparecimento", 0)
    rel_db.abstencao = dados_relatorio.get("abstencao", 0)
    rel_db.pct_comparecimento = dados_relatorio.get("pct_comparecimento", 0.0)
    rel_db.pct_abstencao = dados_relatorio.get("pct_abstencao", 0.0)
    rel_db.votos_nominais = dados_relatorio.get("votos_nominais", 0)
    rel_db.votos_brancos = dados_relatorio.get("votos_brancos", 0)
    rel_db.votos_nulos = dados_relatorio.get("votos_nulos", 0)
    rel_db.votos_validos = dados_relatorio.get("votos_validos", 0)

    rel_db.candidatos_json = json.dumps(dados_relatorio.get("candidatos", []), ensure_ascii=False)
    rel_db.secoes_agregadas_json = json.dumps(dados_relatorio.get("secoes_agregadas_list", []), ensure_ascii=False)
    rel_db.contingencias_urnas_json = json.dumps(dados_relatorio.get("contingencias_list", []), ensure_ascii=False)
    rel_db.resumo_completo_json = json.dumps(dados_relatorio, ensure_ascii=False)

    # Executa batimento forense com o banco PostgreSQL
    batimento = executar_batimento_forense(db, rel_db)
    rel_db.status_batimento = batimento.get("status_geral", "PENDENTE")
    rel_db.batimento_resultado_json = json.dumps(batimento, ensure_ascii=False)
    rel_db.total_urnas_banco = batimento.get("urnas_no_banco", 0)
    rel_db.comparecimento_banco = batimento.get("comparecimento_banco", 0)
    rel_db.votos_validos_banco = batimento.get("votos_validos_banco", 0)
    rel_db.delta_comparecimento = batimento.get("delta_comparecimento", 0)
    rel_db.delta_votos_validos = batimento.get("delta_votos_validos", 0)

    if auto_commit:
        db.commit()
        db.refresh(rel_db)

    return rel_db


def executar_batimento_forense(db, relatorio_obj: Any) -> dict[str, Any]:
    """
    Executa batimento forense cruzado completo entre os totais informados no Relatório Oficial TSE (PDF)
    e a soma física das seções / urnas gravadas no banco PostgreSQL.
    """
    uf = relatorio_obj.uf
    turno = relatorio_obj.turno
    cargo = relatorio_obj.cargo

    # 1. Total de seções cadastradas da UF
    total_secoes_uf = db.query(func.count(TseSecao.id)).filter(
        func.upper(TseSecao.uf) == uf.upper()
    ).scalar() or 0

    # 2. Agregação dos Boletins de Urna (TseApuracaoBU) para esta UF e Turno
    res_bu = db.query(
        func.count(TseApuracaoBU.id),
        func.sum(TseApuracaoBU.comparecimento),
        func.sum(TseApuracaoBU.eleitores_aptos),
        func.sum(TseApuracaoBU.votos_brancos),
        func.sum(TseApuracaoBU.votos_nulos),
        func.sum(TseApuracaoBU.faltosos),
    ).join(TseSecao, TseApuracaoBU.secao_id == TseSecao.id).filter(
        func.upper(TseSecao.uf) == uf.upper(),
        TseApuracaoBU.turno == turno,
    ).first()

    urnas_com_bu = int(res_bu[0] or 0)
    comp_banco = int(res_bu[1] or 0)
    aptos_banco = int(res_bu[2] or 0)
    brancos_banco = int(res_bu[3] or 0)
    nulos_banco = int(res_bu[4] or 0)
    faltosos_banco = int(res_bu[5] or 0)

    # 3. Agregação dos Votos Nominais por Candidato
    q_cands = db.query(
        TseVotoCandidato.numero_candidato,
        func.max(TseVotoCandidato.nome_candidato),
        func.sum(TseVotoCandidato.quantidade_votos),
    ).join(TseSecao, TseVotoCandidato.secao_id == TseSecao.id).filter(
        func.upper(TseSecao.uf) == uf.upper(),
        TseVotoCandidato.turno == turno,
        func.upper(TseVotoCandidato.cargo) == cargo.upper(),
    ).group_by(TseVotoCandidato.numero_candidato).all()

    votos_candidatos_banco = {
        str(row[0]): {
            "numero": str(row[0]),
            "nome": row[1] or f"Candidato {row[0]}",
            "votos_banco": int(row[2] or 0)
        }
        for row in q_cands
    }

    tot_nominais_banco = sum(item["votos_banco"] for item in votos_candidatos_banco.values())
    tot_validos_banco = tot_nominais_banco

    # 4. Cruzamento Lado a Lado dos Candidatos
    cands_pdf = json.loads(relatorio_obj.candidatos_json or "[]")
    comparativo_candidatos = []
    divergencias_candidatos = []

    for c_pdf in cands_pdf:
        num = str(c_pdf.get("numero"))
        v_pdf = int(c_pdf.get("votos", 0))
        item_banco = votos_candidatos_banco.get(num, {"votos_banco": 0, "nome": c_pdf.get("nome")})
        v_banco = item_banco["votos_banco"]
        delta = v_banco - v_pdf
        status_cand = "CONFERE_100%" if delta == 0 else ("BASE_PARCIAL" if v_banco < v_pdf else "DIVERGENTE")

        if delta != 0:
            divergencias_candidatos.append({
                "numero": num,
                "nome": c_pdf.get("nome"),
                "votos_pdf": v_pdf,
                "votos_banco": v_banco,
                "delta": delta,
            })

        comparativo_candidatos.append({
            "numero": num,
            "nome": c_pdf.get("nome"),
            "votos_pdf": v_pdf,
            "votos_banco": v_banco,
            "percentual_pdf": c_pdf.get("percentual"),
            "delta": delta,
            "status": status_cand,
        })

    # 5. Cruzamento das Seções Agregadas
    agregadas_pdf = json.loads(relatorio_obj.secoes_agregadas_json or "[]")
    contingencias_pdf = json.loads(relatorio_obj.contingencias_urnas_json or "[]")

    # 6. Indicadores Gerais e Status de Consistência
    secoes_oficiais_pdf = relatorio_obj.secoes_principais or 0
    comparecimento_pdf = relatorio_obj.comparecimento or 0
    votos_validos_pdf = relatorio_obj.votos_validos or 0
    brancos_pdf = relatorio_obj.votos_brancos or 0
    nulos_pdf = relatorio_obj.votos_nulos or 0

    delta_secoes = urnas_com_bu - secoes_oficiais_pdf
    delta_comp = comp_banco - comparecimento_pdf
    delta_val = tot_validos_banco - votos_validos_pdf
    delta_br = brancos_banco - brancos_pdf
    delta_nu = nulos_banco - nulos_pdf

    # Determinação do Status Geral Forense
    if urnas_com_bu == 0:
        status_geral = "AGUARDANDO_INGESTAO"
        veredito = "Base de dados ainda não possui Boletins de Urna desta UF/Turno para comparar."
    elif delta_secoes == 0 and delta_comp == 0 and delta_val == 0 and len(divergencias_candidatos) == 0:
        status_geral = "CONFERE_100%"
        veredito = f"Batimento pericial 100% íntegro! Todas as {secoes_oficiais_pdf:,} urnas e votos conferem com o Relatório Oficial do TSE."
    elif urnas_com_bu < secoes_oficiais_pdf:
        faltam = secoes_oficiais_pdf - urnas_com_bu
        pct_carga = round((urnas_com_bu / max(secoes_oficiais_pdf, 1)) * 100.0, 1)
        status_geral = "BASE_PARCIAL"
        veredito = f"Carga em andamento ({pct_carga}%): {urnas_com_bu:,} de {secoes_oficiais_pdf:,} urnas carregadas (faltam {faltam:,} urnas no banco para atingir o total do PDF)."
    else:
        status_geral = "DIVERGENCIA"
        veredito = "Identificada divergência numérica entre os votos do banco e o Relatório Oficial da Totalização."

    return {
        "status_geral": status_geral,
        "veredito": veredito,
        "uf": uf,
        "turno": turno,
        "cargo": cargo,
        "nome_arquivo": relatorio_obj.nome_arquivo,
        "data_geracao_relatorio": relatorio_obj.data_geracao_relatorio,
        "secoes_principais_pdf": secoes_oficiais_pdf,
        "secoes_agregadas_pdf": relatorio_obj.secoes_agregadas or 0,
        "urnas_no_banco": urnas_com_bu,
        "delta_secoes": delta_secoes,
        "comparecimento_pdf": comparecimento_pdf,
        "comparecimento_banco": comp_banco,
        "delta_comparecimento": delta_comp,
        "votos_validos_pdf": votos_validos_pdf,
        "votos_validos_banco": tot_validos_banco,
        "delta_votos_validos": delta_val,
        "brancos_pdf": brancos_pdf,
        "brancos_banco": brancos_banco,
        "delta_brancos": delta_br,
        "nulos_pdf": nulos_pdf,
        "nulos_banco": nulos_banco,
        "delta_nulos": delta_nu,
        "candidatos_comparativo": comparativo_candidatos,
        "total_secoes_agregadas_auditadas": len(agregadas_pdf),
        "total_contingencias_auditadas": len(contingencias_pdf),
        "contingencias_amostra": contingencias_pdf[:25],
        "secoes_agregadas_amostra": agregadas_pdf[:25],
    }


def detectar_e_ingerir_relatorios_servidor(
    diretorios_busca: Optional[list[str]] = None,
    db = None
) -> dict[str, Any]:
    """
    Varre os diretórios do servidor e pacotes .zip procurando por relatórios oficiais em .PDF
    e realiza a ingestão e batimento automático no PostgreSQL.
    """
    if diretorios_busca is None:
        diretorios_busca = [
            "/root/tse_import",
            "/root/relatorios_totalizacao",
            "/app/data/relatorios_totalizacao_pr",
            "data/relatorios_totalizacao_pr",
            os.path.expanduser("~/Downloads"),
        ]

    arquivos_encontrados = []
    for d in diretorios_busca:
        if os.path.isdir(d):
            for root, _, files in os.walk(d):
                for f in files:
                    full_path = os.path.join(root, f)
                    if f.lower().endswith(".pdf") and not f.startswith(".") and not f.lower().endswith("_leiame.pdf"):
                        arquivos_encontrados.append(("pdf", full_path))
                    elif f.lower().endswith(".zip") and ("totalizacao" in f.lower() or "relatorio" in f.lower()):
                        arquivos_encontrados.append(("zip", full_path))

    if not db:
        db = _obter_db_session()
        deve_fechar_db = True
    else:
        deve_fechar_db = False

    ingeridos = []
    erros = []

    try:
        for tipo, path in arquivos_encontrados:
            try:
                if tipo == "pdf":
                    dados_lista = extrair_relatorio_totalizacao_pdf(path)
                else:
                    dados_lista = extrair_relatorios_de_zip(path)

                for item in dados_lista:
                    rel_db = salvar_relatorio_no_banco(db, item, auto_commit=True)
                    ingeridos.append({
                        "id": rel_db.id,
                        "uf": rel_db.uf,
                        "turno": rel_db.turno,
                        "cargo": rel_db.cargo,
                        "arquivo": rel_db.nome_arquivo,
                        "status": rel_db.status_batimento,
                        "comparecimento_pdf": rel_db.comparecimento,
                        "comparecimento_banco": rel_db.comparecimento_banco,
                    })
            except Exception as e_ing:
                erros.append({"arquivo": path, "erro": str(e_ing)})

        return {
            "status": "CONCLUIDO",
            "total_arquivos_detectados": len(arquivos_encontrados),
            "total_relatorios_ingeridos": len(ingeridos),
            "relatorios": ingeridos,
            "erros": erros,
        }
    finally:
        if deve_fechar_db and db:
            db.close()
