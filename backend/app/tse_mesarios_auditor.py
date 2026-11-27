from __future__ import annotations

import io
import os
import re
import json
import math
import time
import zipfile
import threading
from collections import defaultdict
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import func, distinct
from sqlalchemy.orm import Session

from .database import (
    SessionLocal,
    TseSecao,
    TseApuracaoBU,
    TseEventoMesario,
    ESTADOS_E_REGIOES_BR,
    garantir_tabelas_custodia_tse,
)

# Tabela oficial TSE de códigos estaduais nos dígitos 9 e 10 do Título de Eleitor
UF_POR_CODIGO_TITULO = {
    "01": "SP", "02": "MG", "03": "RJ", "04": "RS", "05": "BA",
    "06": "PR", "07": "CE", "08": "PE", "09": "SC", "10": "GO",
    "11": "MA", "12": "PB", "13": "PA", "14": "ES", "15": "PI",
    "16": "RN", "17": "AL", "18": "MT", "19": "MS", "20": "DF",
    "21": "SE", "22": "AM", "23": "RO", "24": "AC", "25": "AP",
    "26": "RR", "27": "TO", "28": "ZZ",
}

_STATUS_REINDEX_MESARIOS: dict[str, Any] = {
    "em_andamento": False,
    "progresso_pct": 0,
    "arquivos_encontrados": 0,
    "arquivos_processados": 0,
    "logs_jez_lidos": 0,
    "secoes_com_mesarios": 0,
    "registros_gravados": 0,
    "velocidade_logs_s": 0.0,
    "iniciado_em": None,
    "finalizado_em": None,
    "mensagem": "Aguardando indexação de logs .jez disponíveis.",
    "erros": [],
}
_LOCK_REINDEX_MESARIOS = threading.Lock()


def validar_titulo_eleitor_tse(titulo_raw: str) -> dict[str, Any]:
    """
    Normaliza o número do título de eleitor (12 dígitos), extrai a UF emissora (dígitos 9–10)
    e valida matematicamente os dígitos verificadores Módulo-11 segundo a regra oficial do TSE.
    """
    digs = "".join(ch for ch in str(titulo_raw or "") if ch.isdigit())
    if not digs:
        return {"titulo": "", "valido": False, "uf_origem": ""}
    s = digs.zfill(12) if len(digs) <= 12 else digs
    if len(s) != 12 or s == "000000000000":
        return {"titulo": s[:20], "valido": False, "uf_origem": ""}

    uf_cod = s[8:10]
    uf_sigla = UF_POR_CODIGO_TITULO.get(uf_cod, "")
    if not uf_sigla:
        return {"titulo": s, "valido": False, "uf_origem": ""}

    pesos1 = (2, 3, 4, 5, 6, 7, 8, 9)
    soma1 = sum(int(s[i]) * pesos1[i] for i in range(8))
    r1 = soma1 % 11
    if r1 == 10:
        dv1 = 0
    elif r1 == 0 and uf_cod in ("01", "02"):
        dv1 = 1
    else:
        dv1 = r1

    soma2 = int(s[8]) * 7 + int(s[9]) * 8 + dv1 * 9
    r2 = soma2 % 11
    if r2 == 10:
        dv2 = 0
    elif r2 == 0 and uf_cod in ("01", "02"):
        dv2 = 1
    else:
        dv2 = r2

    valido = (int(s[10]) == dv1 and int(s[11]) == dv2)
    return {
        "titulo": s,
        "valido": valido,
        "uf_origem": uf_sigla,
    }


def calcular_distancia_haversine_km(
    lat1: Optional[float],
    lon1: Optional[float],
    lat2: Optional[float],
    lon2: Optional[float],
) -> float:
    """Calcula a distância geodésica em quilômetros entre duas coordenadas (Haversine)."""
    if lat1 is None or lon1 is None or lat2 is None or lon2 is None:
        return 0.0
    try:
        rlat1, rlon1 = math.radians(float(lat1)), math.radians(float(lon1))
        rlat2, rlon2 = math.radians(float(lat2)), math.radians(float(lon2))
    except (TypeError, ValueError):
        return 0.0
    dlat = rlat2 - rlat1
    dlon = rlon2 - rlon1
    a = math.sin(dlat / 2.0) ** 2 + math.cos(rlat1) * math.cos(rlat2) * (math.sin(dlon / 2.0) ** 2)
    c = 2.0 * math.atan2(math.sqrt(max(0.0, a)), math.sqrt(max(0.0, 1.0 - a)))
    return 6371.0088 * c


def classificar_escala_alerta_distancia(dist_max_km: float) -> dict[str, str]:
    """
    Aplica a escala objetiva de alertas por distância entre locais de votação:
      - AZUL:     < 300 metros (< 0.3 km)
      - AMARELO:  300 metros até 80 km (0.3 km <= d <= 80.0 km)
      - VERMELHO: > 80 km (Crítico)
    """
    d = float(dist_max_km or 0.0)
    if d > 80.0:
        return {
            "escala": "VERMELHO",
            "severidade": "CRITICO",
            "rotulo": "Alerta Vermelho (> 80 km)",
            "faixa_distancia": "> 80 km",
        }
    if d >= 0.3:
        return {
            "escala": "AMARELO",
            "severidade": "ATENCAO",
            "rotulo": "Alerta Amarelo (> 300 m a 80 km)",
            "faixa_distancia": "300 m – 80 km",
        }
    return {
        "escala": "AZUL",
        "severidade": "INFORMATIVO",
        "rotulo": "Alerta Azul (< 300 m / Mesmo Local)",
        "faixa_distancia": "< 300 m",
    }


def _hora_para_segundos(hora_str: Optional[str]) -> Optional[int]:
    if not hora_str:
        return None
    s = str(hora_str).strip()
    m = re.match(r"^(\d{2}):(\d{2})(?::(\d{2}))?", s)
    if not m:
        return None
    hh = int(m.group(1))
    mm = int(m.group(2))
    ss = int(m.group(3) or 0)
    return hh * 3600 + mm * 60 + ss


def _resolver_geolocalizacao_secao(
    uf: str,
    municipio_codigo: str,
    municipio_nome: str,
    zona: int,
    local_votacao: str,
) -> dict[str, Any]:
    """Obtém coordenadas e endereço do local de votação usando a base oficial 2026 do sistema."""
    try:
        from .tse_reverse_analyzer import _obter_dados_local_oficial
        loc_id = (local_votacao or "").strip()
        if not loc_id or loc_id == "-":
            loc_id = f"Z{int(zona or 0):04d}"
        return _obter_dados_local_oficial(
            uf=uf,
            mun_cod=municipio_codigo,
            mun_nome=municipio_nome,
            zona=int(zona or 0),
            loc_id=loc_id,
        )
    except Exception:
        return {
            "latitude": None,
            "longitude": None,
            "nome_local": local_votacao or "",
            "endereco": "",
            "coord_exata": False,
        }


def persistir_lista_mesarios_turno(
    db: Session,
    secao_db: TseSecao,
    turno: int,
    mesarios_detalhados: list[dict],
    serial_ue: str = "",
    data_eleicao: str = "",
    hora_zeresima: str = "",
    hora_pronta_votos: str = "",
    hora_encerramento_urna: str = "",
    titulos_invalidos: int = 0,
) -> int:
    """
    Faz upsert em lote dos registros de mesários de uma seção e turno específicos em `tse_eventos_mesarios`.
    Retorna a quantidade de linhas inseridas ou atualizadas.
    """
    if not secao_db or not secao_db.id or not mesarios_detalhados:
        return 0

    garantir_tabelas_custodia_tse()

    uf_up = (secao_db.uf or "PR").strip().upper()
    mun_cod = str(secao_db.municipio_codigo or "00000").strip().zfill(5)
    mun_nome = (secao_db.municipio_nome or "").strip()
    zona_int = int(secao_db.zona or 0)
    secao_int = int(secao_db.secao or 0)
    loc_vot = (secao_db.local_votacao or "").strip()

    geo = _resolver_geolocalizacao_secao(
        uf=uf_up,
        municipio_codigo=mun_cod,
        municipio_nome=mun_nome,
        zona=zona_int,
        local_votacao=loc_vot,
    )

    existentes = {
        r.titulo_mesario: r
        for r in db.query(TseEventoMesario).filter(
            TseEventoMesario.secao_id == secao_db.id,
            TseEventoMesario.turno == int(turno),
        ).all()
    }

    gravados = 0
    for item in mesarios_detalhados:
        tit_info = validar_titulo_eleitor_tse(item.get("titulo", ""))
        tit_norm = tit_info["titulo"]
        if not tit_norm:
            continue

        ev_json = json.dumps(item.get("eventos", []), ensure_ascii=False) if item.get("eventos") else None
        row = existentes.get(tit_norm)
        if row is None:
            row = TseEventoMesario(
                secao_id=secao_db.id,
                turno=int(turno),
                titulo_mesario=tit_norm,
            )
            db.add(row)
            existentes[tit_norm] = row

        row.uf_origem_titulo = tit_info["uf_origem"] or None
        row.dv_titulo_valido = bool(tit_info["valido"])
        row.uf = uf_up[:4]
        row.municipio_codigo = mun_cod[:10]
        row.municipio_nome = mun_nome[:120] if mun_nome else None
        row.zona = zona_int
        row.secao = secao_int
        row.local_votacao = loc_vot[:120] if loc_vot else None
        row.nome_local = (geo.get("nome_local") or loc_vot or "")[:160] or None
        row.endereco_local = (geo.get("endereco") or "")[:220] or None
        row.latitude = geo.get("latitude")
        row.longitude = geo.get("longitude")
        row.coord_exata = bool(geo.get("coord_exata", False))

        row.serial_ue = (serial_ue or "")[:32] or row.serial_ue
        row.data_eleicao = (data_eleicao or "")[:16] or row.data_eleicao
        row.hora_zeresima = (hora_zeresima or "")[:12] or row.hora_zeresima
        row.hora_urna_pronta = (hora_pronta_votos or "")[:12] or row.hora_urna_pronta
        row.hora_urna_encerrada = (hora_encerramento_urna or "")[:12] or row.hora_urna_encerrada

        row.abriu_secao = bool(item.get("abriu_secao")) or bool(row.abriu_secao)
        if item.get("ordem_abertura"):
            row.ordem_abertura = int(item["ordem_abertura"])
        if item.get("hora_abertura"):
            row.hora_abertura = str(item["hora_abertura"])[:12]
        if item.get("mac_abertura"):
            row.mac_abertura = str(item["mac_abertura"])[:24]

        row.registrou_durante = bool(item.get("registrou_durante")) or bool(row.registrou_durante)
        if item.get("hora_durante"):
            row.hora_durante = str(item["hora_durante"])[:12]
        row.qtd_habilitacoes_bio = max(int(row.qtd_habilitacoes_bio or 0), int(item.get("qtd_habilitacoes_bio") or 0))

        row.encerrou_secao = bool(item.get("digitou_encerramento")) or bool(row.encerrou_secao)
        if item.get("hora_encerramento"):
            row.hora_encerramento = str(item["hora_encerramento"])[:12]
        if item.get("mac_encerramento"):
            row.mac_encerramento = str(item["mac_encerramento"])[:24]

        row.registrou_pos_votacao = bool(item.get("registrou_pos_votacao")) or bool(row.registrou_pos_votacao)
        if item.get("hora_pos_votacao"):
            row.hora_pos_votacao = str(item["hora_pos_votacao"])[:12]

        p_hora = str(item.get("primeira_acao_hora") or "")[:12]
        u_hora = str(item.get("ultima_acao_hora") or "")[:12]
        if p_hora and (not row.primeira_acao_hora or p_hora < row.primeira_acao_hora):
            row.primeira_acao_hora = p_hora
        if u_hora and (not row.ultima_acao_hora or u_hora > row.ultima_acao_hora):
            row.ultima_acao_hora = u_hora

        if item.get("eleitor_da_secao") is not None:
            row.eleitor_da_secao = bool(item["eleitor_da_secao"])
        if item.get("biometria_conferida") is not None:
            row.biometria_conferida = bool(item["biometria_conferida"])
        row.titulos_invalidos_urna = max(int(row.titulos_invalidos_urna or 0), int(titulos_invalidos or 0))
        if ev_json:
            row.eventos_json = ev_json
        gravados += 1

    return gravados


def persistir_mesarios_pacote_no_banco(
    db: Session,
    secao_db: TseSecao,
    turno_pacote: int,
    resumo: dict,
    relatorio_completo: Optional[dict] = None,
) -> int:
    """
    Extrai os eventos de mesários de `relatorio_completo` / `resumo` (1ºT e 2ºT acumulados na MI)
    e os persiste automaticamente em `tse_eventos_mesarios`.
    """
    if not secao_db or not secao_db.id:
        return 0

    total = 0
    log_rep = (relatorio_completo or {}).get("log_jez") or {}
    serial_ue = str(
        resumo.get("serial_ue")
        or (log_rep.get("metadados_urna") or {}).get("serial_ue")
        or ""
    ).strip()

    # Turno principal do pacote
    res_princ = log_rep.get("resumo_votacao_log") or {}
    mes_princ = res_princ.get("mesarios_detalhados") or resumo.get("mesarios_detalhados_t2") or []
    if mes_princ:
        total += persistir_lista_mesarios_turno(
            db=db,
            secao_db=secao_db,
            turno=int(turno_pacote),
            mesarios_detalhados=mes_princ,
            serial_ue=serial_ue,
            data_eleicao=res_princ.get("data_eleicao", ""),
            hora_zeresima=res_princ.get("hora_zeresima") or resumo.get("hora_zeresima_t2", ""),
            hora_pronta_votos=res_princ.get("hora_pronta_votos") or resumo.get("hora_pronta_votos_t2", ""),
            hora_encerramento_urna=res_princ.get("hora_encerramento") or resumo.get("hora_encerramento_t2", ""),
            titulos_invalidos=int(res_princ.get("titulos_invalidos_mesario") or resumo.get("titulos_invalidos_mesario_t2") or 0),
        )

    # 1º Turno acumulado na Mídia Interna de pacotes do 2º Turno
    res_1t = log_rep.get("resumo_1_turno_log") or {}
    mes_1t = res_1t.get("mesarios_detalhados") or resumo.get("mesarios_detalhados_t1") or []
    if mes_1t and int(turno_pacote) != 1:
        total += persistir_lista_mesarios_turno(
            db=db,
            secao_db=secao_db,
            turno=1,
            mesarios_detalhados=mes_1t,
            serial_ue=serial_ue,
            data_eleicao=res_1t.get("data_eleicao", ""),
            hora_zeresima=res_1t.get("hora_zeresima") or resumo.get("hora_zeresima_t1", ""),
            hora_pronta_votos=res_1t.get("hora_pronta_votos") or resumo.get("hora_pronta_votos_t1", ""),
            hora_encerramento_urna=res_1t.get("hora_encerramento") or resumo.get("hora_encerramento_t1", ""),
            titulos_invalidos=int(res_1t.get("titulos_invalidos_mesario") or resumo.get("titulos_invalidos_mesario_t1") or 0),
        )

    return total


def extrair_mesarios_rapido_de_log_jez(log_jez_bytes: bytes, filename: str = "") -> Optional[dict[str, Any]]:
    """
    Extrator ultrarrápido de `logd.dat` focado exclusivamente em metadados de seção e eventos de mesários
    (abertura, operação biométrica e encerramento) para 1º e 2º turnos.
    Ignora os milhares de eventos de cabine para processar grandes lotes de `log.jez` em alta velocidade.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(log_jez_bytes), "r") as zf:
            names = [n for n in zf.namelist() if not n.endswith("/")]
            # Ignora arquivos GEDAI (que não contêm logd.dat da urna de votação)
            log_names = [n for n in names if os.path.basename(n).lower() == "logd.dat"]
            if not log_names:
                log_names = [n for n in names if n.lower().endswith(".dat") and "gedai" not in n.lower()]
            if not log_names:
                return None
            raw_logd = b"\n".join(zf.read(n) for n in sorted(log_names))
    except Exception:
        return None

    text_logd = raw_logd.decode("iso-8859-1", errors="ignore")
    if "VOTA\t" not in text_logd and "Mesário " not in text_logd and "Título digitado para encerramento" not in text_logd:
        return None

    from .tse_reverse_analyzer import (
        _novo_estado_dia_log,
        _garantir_item_mesario_log,
        _registrar_evento_mesario_log,
        _compilar_resumo_dia_log,
        extrair_identificacao_arquivo_tse,
    )

    id_info = extrair_identificacao_arquivo_tse(filename or "o03221pr0000000000000-log.jez")
    meta = {
        "serial_ue": "",
        "modelo_ue": "",
        "municipio": id_info.get("municipio_codigo", "00000"),
        "zona": id_info.get("zona", "0000"),
        "secao": id_info.get("secao", "0000"),
        "uf": id_info.get("uf", "PR"),
        "turno_arquivo": int(id_info.get("turno") or 2),
    }

    datas_votacao: dict[str, int] = defaultdict(int)
    estados_por_data: dict[str, dict] = {}

    KEYWORDS_RAPIDAS = (
        "Mesário ",
        "mesário",
        "mesários",
        "encerramento",
        "ZERÉSIMA",
        "pronta para receber votos",
        "Município:",
        "Zona Eleitoral:",
        "Seção Eleitoral:",
        "Modelo de Urna:",
        "O voto do eleitor foi computado",
    )

    for line in text_logd.splitlines():
        if not any(k in line for k in KEYWORDS_RAPIDAS):
            continue
        parts = line.split("\t")
        if len(parts) < 5:
            continue

        ts_str = parts[0].strip()
        data_cur = ts_str[:10]
        hora_cur = ts_str[11:19] if len(ts_str) >= 19 else ""
        serial_ue = parts[2].strip()
        msg = parts[4].strip()
        mac_hex = parts[5].strip() if len(parts) >= 6 else ""

        if not meta["serial_ue"] and serial_ue:
            meta["serial_ue"] = serial_ue

        if "Identificação do Modelo de Urna:" in msg:
            meta["modelo_ue"] = msg.split(":", 1)[1].strip()
            continue
        if msg.startswith("Município:"):
            meta["municipio"] = msg.split(":", 1)[1].strip().zfill(5)
            continue
        if msg.startswith("Zona Eleitoral:"):
            meta["zona"] = msg.split(":", 1)[1].strip()
            continue
        if msg.startswith("Seção Eleitoral:"):
            meta["secao"] = msg.split(":", 1)[1].strip()
            continue
        if "O voto do eleitor foi computado" in msg:
            if len(data_cur) == 10:
                datas_votacao[data_cur] += 1
            continue

        if len(data_cur) != 10:
            continue
        est = estados_por_data.get(data_cur)
        if est is None:
            est = _novo_estado_dia_log(data_cur)
            estados_por_data[data_cur] = est

        if "Gerando relatório [ZERÉSIMA] [TÉRMINO]" in msg and not est["hora_zeresima"]:
            est["hora_zeresima"] = hora_cur
        elif "Registrando mesários antes da votação" in msg:
            est["fase_mesa"] = "ANTES_VOTACAO"
        elif "Registrando mesários durante a votação" in msg:
            est["fase_mesa"] = "DURANTE_VOTACAO"
        elif "Registrando mesários após a votação" in msg:
            est["fase_mesa"] = "APOS_VOTACAO"
        elif "Urna pronta para receber votos" in msg:
            if not est["hora_pronta_votos"]:
                est["hora_pronta_votos"] = hora_cur
            est["fase_mesa"] = "DURANTE_VOTACAO"
        elif "Procedimento de encerramento confirmado" in msg:
            est["hora_encerramento"] = hora_cur
            est["fase_mesa"] = "APOS_VOTACAO"
        elif "Digitado título inválido para o registro de mesário" in msg:
            est["titulos_invalidos_mesario"] = est.get("titulos_invalidos_mesario", 0) + 1
        elif "Pedido de leitura da biometria do mesário" in msg:
            m_p = re.search(r"mesário\s+(\d+)", msg, re.IGNORECASE)
            if m_p:
                det_m = _garantir_item_mesario_log(est, m_p.group(1))
                if det_m:
                    est["ultimo_titulo_bio_pendente"] = det_m["titulo"]
                    _registrar_evento_mesario_log(det_m, hora_cur, "PEDIDO_BIOMETRIA_MESARIO", mac_hex)
        elif "Realizada a conferência da biometria do mesário" in msg:
            tit_pend = est.get("ultimo_titulo_bio_pendente")
            if tit_pend and tit_pend in est["mesarios_detalhes"]:
                est["mesarios_detalhes"][tit_pend]["biometria_conferida"] = True
        elif "Digital capturada não corresponde a digital do eleitor" in msg and est.get("ultimo_titulo_bio_pendente"):
            tit_pend = est.get("ultimo_titulo_bio_pendente")
            if tit_pend in est["mesarios_detalhes"] and est["mesarios_detalhes"][tit_pend]["biometria_conferida"] is None:
                est["mesarios_detalhes"][tit_pend]["biometria_conferida"] = False
        elif "é eleitor da seção" in msg and msg.startswith("Mesário "):
            m_el = re.search(r"^Mesário\s+(\d+)\s+(não\s+)?é eleitor da seção", msg)
            if m_el:
                det_m = _garantir_item_mesario_log(est, m_el.group(1))
                if det_m:
                    det_m["eleitor_da_secao"] = (m_el.group(2) is None)
        elif "Título digitado para encerramento:" in msg:
            tit_raw_enc = msg.split(":", 1)[1].strip()
            det_m = _garantir_item_mesario_log(est, tit_raw_enc)
            if det_m:
                est["titulo_encerramento"] = det_m["titulo"]
                est["hora_titulo_encerramento"] = hora_cur
                est["mac_encerramento"] = mac_hex
                det_m["digitou_encerramento"] = True
                det_m["hora_encerramento"] = hora_cur
                det_m["mac_encerramento"] = mac_hex
                _registrar_evento_mesario_log(det_m, hora_cur, "DIGITOU_TITULO_ENCERRAMENTO", mac_hex)
        elif re.match(r"^Mesário\s+\d+\s+registrado$", msg):
            m_mes = re.search(r"Mesário\s+(\d+)\s+registrado", msg)
            if m_mes:
                det_m = _garantir_item_mesario_log(est, m_mes.group(1))
                est["ultimo_titulo_bio_pendente"] = ""
                if det_m:
                    tit_n = det_m["titulo"]
                    if tit_n not in est["mesarios_registrados"]:
                        est["mesarios_registrados"].append(tit_n)
                    fase_m = est.get("fase_mesa", "ANTES_VOTACAO")
                    if fase_m == "ANTES_VOTACAO":
                        if not det_m["abriu_secao"]:
                            est["contador_ordem_abertura"] = est.get("contador_ordem_abertura", 0) + 1
                            det_m["abriu_secao"] = True
                            det_m["ordem_abertura"] = est["contador_ordem_abertura"]
                            det_m["hora_abertura"] = hora_cur
                            det_m["mac_abertura"] = mac_hex
                            if est["contador_ordem_abertura"] == 1:
                                est["titulo_abertura"] = tit_n
                                est["hora_abertura_mesario"] = hora_cur
                        _registrar_evento_mesario_log(det_m, hora_cur, "REGISTRO_ABERTURA", mac_hex)
                    elif fase_m == "APOS_VOTACAO":
                        det_m["registrou_pos_votacao"] = True
                        det_m["hora_pos_votacao"] = hora_cur
                        if not det_m["mac_encerramento"]:
                            det_m["mac_encerramento"] = mac_hex
                        _registrar_evento_mesario_log(det_m, hora_cur, "REGISTRO_POS_ENCERRAMENTO", mac_hex)
                    else:
                        det_m["registrou_durante"] = True
                        if not det_m["hora_durante"]:
                            det_m["hora_durante"] = hora_cur
                        _registrar_evento_mesario_log(det_m, hora_cur, "REGISTRO_DURANTE_VOTACAO", mac_hex)
        elif msg.startswith("Mesário ") and "habilitou o eleitor" in msg:
            m_hb = re.search(r"^Mesário\s+(\d+)\s+habilitou o eleitor", msg)
            if m_hb:
                det_m = _garantir_item_mesario_log(est, m_hb.group(1))
                if det_m:
                    det_m["qtd_habilitacoes_bio"] += 1
                    _registrar_evento_mesario_log(det_m, hora_cur, "HABILITOU_ELEITOR_BIO", mac_hex)

    datas_validas = sorted(
        [d for d, est in estados_por_data.items() if est.get("mesarios_detalhes") or d in datas_votacao],
        key=lambda d: datetime.strptime(d, "%d/%m/%Y") if re.match(r"^\d{2}/\d{2}/\d{4}$", d) else datetime.min,
    )
    if not datas_validas:
        return None

    turnos_extraidos: dict[int, dict] = {}
    for d in datas_validas:
        est = estados_por_data.get(d)
        if not est or not est.get("mesarios_detalhes"):
            continue
        if d.startswith(("04/10", "02/10", "06/10")):
            t_num = 1
        elif d.startswith(("25/10", "30/10", "27/10")):
            t_num = 2
        elif len(datas_validas) >= 2:
            t_num = 1 if d == datas_validas[0] else 2
        else:
            t_num = meta["turno_arquivo"]
        turnos_extraidos[t_num] = _compilar_resumo_dia_log(est)

    if not turnos_extraidos:
        return None

    return {
        "metadados": meta,
        "turnos": turnos_extraidos,
    }


def _descobrir_fontes_log_jez_disponiveis() -> list[str]:
    """Localiza todos os pacotes .zip/.7z e arquivos -log.jez já disponíveis no servidor."""
    from .tse_reverse_analyzer import _get_tse_import_dir, _get_tse_storage_dir

    dirs_candidatos = []
    for d in (
        _get_tse_import_dir(),
        _get_tse_storage_dir(),
        os.path.join(os.path.dirname(__file__), "samples_tse_pr"),
    ):
        if d and os.path.isdir(d) and d not in dirs_candidatos:
            dirs_candidatos.append(d)

    arquivos: list[str] = []
    vistos: set[str] = set()
    for base_dir in dirs_candidatos:
        for root, _dirs, files in os.walk(base_dir):
            for f in sorted(files):
                low = f.lower()
                # Ignora pacotes exclusivos de CSV BWEB, eleitorado ou GEDAI
                if any(ign in low for ign in ("bweb_", "votacao_secao", "eleitorado_local", "gedai", "cesp", "ceft")):
                    continue
                if low.endswith(("-log.jez", ".logjez", ".jez", ".zip", ".7z")):
                    full = os.path.abspath(os.path.join(root, f))
                    if full not in vistos:
                        vistos.add(full)
                        arquivos.append(full)
    return arquivos


def obter_status_reindexacao_mesarios() -> dict[str, Any]:
    fontes = _descobrir_fontes_log_jez_disponiveis()
    st = dict(_STATUS_REINDEX_MESARIOS)
    st["fontes_disponiveis_disco"] = len(fontes)
    st["nomes_fontes"] = [os.path.basename(p) for p in fontes[:25]]
    return st


def iniciar_reindexacao_mesarios_background(forcar_reprocessamento: bool = False) -> dict[str, Any]:
    """Dispara em background a indexação exclusiva dos arquivos `log.jez` já disponíveis."""
    with _LOCK_REINDEX_MESARIOS:
        if _STATUS_REINDEX_MESARIOS["em_andamento"]:
            return {
                "ok": True,
                "ja_em_andamento": True,
                "status": obter_status_reindexacao_mesarios(),
            }
        fontes = _descobrir_fontes_log_jez_disponiveis()
        _STATUS_REINDEX_MESARIOS.update({
            "em_andamento": True,
            "progresso_pct": 1,
            "arquivos_encontrados": len(fontes),
            "arquivos_processados": 0,
            "logs_jez_lidos": 0,
            "secoes_com_mesarios": 0,
            "registros_gravados": 0,
            "velocidade_logs_s": 0.0,
            "iniciado_em": datetime.utcnow().isoformat(),
            "finalizado_em": None,
            "mensagem": f"Iniciando varredura de {len(fontes)} pacote(s)/arquivo(s) com log.jez disponíveis...",
            "erros": [],
        })

    t = threading.Thread(
        target=_worker_reindexar_mesarios,
        args=(fontes, forcar_reprocessamento),
        daemon=True,
    )
    t.start()
    return {
        "ok": True,
        "ja_em_andamento": False,
        "status": obter_status_reindexacao_mesarios(),
    }


def _obter_ou_criar_secao_para_log(
    db: Session,
    cache_secoes: dict[str, TseSecao],
    uf: str,
    mun_cod: str,
    zona_str: str,
    secao_str: str,
    modelo_urna: str = "",
) -> Optional[TseSecao]:
    from .tse_reverse_analyzer import MUNICIPIOS_PR_TSE

    uf_up = (uf or "PR").strip().upper()[:2]
    m_cod = str(mun_cod or "00000").strip().zfill(5)
    try:
        z_int = int(zona_str or 0)
        s_int = int(secao_str or 0)
    except Exception:
        return None
    if m_cod == "00000" or z_int <= 0 or s_int <= 0:
        return None

    chave = f"{uf_up}_{m_cod}_{z_int:04d}_{s_int:04d}"
    sec = cache_secoes.get(chave)
    if sec is not None:
        return sec

    sec = db.query(TseSecao).filter(TseSecao.chave_secao == chave).first()
    if sec is None:
        sec = db.query(TseSecao).filter(
            TseSecao.uf == uf_up,
            TseSecao.municipio_codigo == m_cod,
            TseSecao.zona == z_int,
            TseSecao.secao == s_int,
        ).first()
    if sec is None:
        regiao = ESTADOS_E_REGIOES_BR.get(uf_up, {}).get("regiao", "SUL")
        mun_nm = MUNICIPIOS_PR_TSE.get(m_cod, f"MUNICÍPIO {m_cod}")
        sec = TseSecao(
            chave_secao=chave,
            regiao=regiao,
            uf=uf_up,
            municipio_codigo=m_cod,
            municipio_nome=mun_nm,
            zona=z_int,
            secao=s_int,
            local_votacao="-",
            modelo_urna=(modelo_urna or "UE2020")[:10],
        )
        db.add(sec)
        db.flush()

    cache_secoes[chave] = sec
    return sec


def _worker_reindexar_mesarios(fontes: list[str], forcar_reprocessamento: bool = False) -> None:
    from .tse_reverse_analyzer import extrair_uf_turno_de_nome_arquivo, extrair_identificacao_arquivo_tse

    garantir_tabelas_custodia_tse()
    t0 = time.time()
    db = SessionLocal()
    cache_secoes: dict[str, TseSecao] = {}
    logs_lidos = 0
    secoes_ok = 0
    regs_gravados = 0
    lote_pendente = 0

    try:
        # Pré-carrega índice rápido de seções já cadastradas para zero round-trips por urna
        for s in db.query(TseSecao).all():
            cache_secoes[s.chave_secao] = s
            ch_alt = f"{(s.uf or '').upper()}_{str(s.municipio_codigo or '').zfill(5)}_{int(s.zona or 0):04d}_{int(s.secao or 0):04d}"
            cache_secoes.setdefault(ch_alt, s)

        secoes_ja_indexadas: set[tuple[int, int]] = set()
        if not forcar_reprocessamento:
            for r_sid, r_t in db.query(TseEventoMesario.secao_id, TseEventoMesario.turno).distinct().all():
                secoes_ja_indexadas.add((int(r_sid), int(r_t)))

        def _processar_membro_jez(raw_bytes: bytes, member_name: str, default_uf: str) -> None:
            nonlocal logs_lidos, secoes_ok, regs_gravados, lote_pendente, db, cache_secoes

            logs_lidos += 1
            base_name = os.path.basename(member_name)
            id_f = extrair_identificacao_arquivo_tse(base_name, default_uf=default_uf or "PR")

            # Checagem rápida de pulo se ambos os turnos já estiverem indexados
            if not forcar_reprocessamento and id_f.get("municipio_codigo") != "00000":
                try:
                    ch_fast = f"{id_f['uf']}_{id_f['municipio_codigo']}_{int(id_f['zona']):04d}_{int(id_f['secao']):04d}"
                    s_fast = cache_secoes.get(ch_fast)
                    t_est = int(id_f.get("turno") or 2)
                    if s_fast and (s_fast.id, t_est) in secoes_ja_indexadas:
                        if t_est == 1 or (s_fast.id, 1) in secoes_ja_indexadas:
                            return
                except Exception:
                    pass

            parsed = extrair_mesarios_rapido_de_log_jez(raw_bytes, filename=base_name)
            if not parsed:
                return

            meta = parsed["metadados"]
            uf_sec = id_f.get("uf") if id_f.get("uf") and id_f.get("uf") != "PR" else (default_uf or meta.get("uf") or "PR")
            sec_db = _obter_ou_criar_secao_para_log(
                db=db,
                cache_secoes=cache_secoes,
                uf=uf_sec,
                mun_cod=meta.get("municipio") or id_f.get("municipio_codigo", "00000"),
                zona_str=meta.get("zona") or id_f.get("zona", "0000"),
                secao_str=meta.get("secao") or id_f.get("secao", "0000"),
                modelo_urna=meta.get("modelo_ue", ""),
            )
            if not sec_db:
                return

            gravou_algum = False
            for t_num, res_dia in parsed["turnos"].items():
                mes_lista = res_dia.get("mesarios_detalhados") or []
                if not mes_lista:
                    continue
                qtd = persistir_lista_mesarios_turno(
                    db=db,
                    secao_db=sec_db,
                    turno=int(t_num),
                    mesarios_detalhados=mes_lista,
                    serial_ue=meta.get("serial_ue", ""),
                    data_eleicao=res_dia.get("data_eleicao", ""),
                    hora_zeresima=res_dia.get("hora_zeresima", ""),
                    hora_pronta_votos=res_dia.get("hora_pronta_votos", ""),
                    hora_encerramento_urna=res_dia.get("hora_encerramento", ""),
                    titulos_invalidos=int(res_dia.get("titulos_invalidos_mesario") or 0),
                )
                if qtd > 0:
                    regs_gravados += qtd
                    secoes_ja_indexadas.add((sec_db.id, int(t_num)))
                    gravou_algum = True

            if gravou_algum:
                secoes_ok += 1
                lote_pendente += 1

            if lote_pendente >= 100:
                db.commit()
                lote_pendente = 0

            if logs_lidos % 25 == 0:
                dt_s = max(0.1, time.time() - t0)
                _STATUS_REINDEX_MESARIOS.update({
                    "logs_jez_lidos": logs_lidos,
                    "secoes_com_mesarios": secoes_ok,
                    "registros_gravados": regs_gravados,
                    "velocidade_logs_s": round(logs_lidos / dt_s, 1),
                    "mensagem": f"Lidos {logs_lidos:,} logs .jez ({secoes_ok:,} seções, {regs_gravados:,} registros de mesários)...",
                })

        total_fontes = max(1, len(fontes))
        for idx_f, fpath in enumerate(fontes, start=1):
            low = fpath.lower()
            uf_hint, _ = extrair_uf_turno_de_nome_arquivo(os.path.basename(fpath))
            default_uf = uf_hint or "PR"

            try:
                if low.endswith(("-log.jez", ".logjez", ".jez")):
                    with open(fpath, "rb") as fp:
                        _processar_membro_jez(fp.read(), fpath, default_uf)
                elif low.endswith(".zip"):
                    with zipfile.ZipFile(fpath, "r") as zf:
                        jez_members = [
                            m for m in zf.namelist()
                            if not m.endswith("/") and m.lower().endswith(("-log.jez", ".logjez", ".jez"))
                            and "wsq" not in m.lower() and "gedai" not in m.lower()
                        ]
                        for m_idx, m_name in enumerate(jez_members, start=1):
                            try:
                                _processar_membro_jez(zf.read(m_name), m_name, default_uf)
                            except Exception:
                                pass
                            if m_idx % 50 == 0:
                                pct_sub = int(((idx_f - 1 + (m_idx / max(1, len(jez_members)))) / total_fontes) * 95) + 2
                                _STATUS_REINDEX_MESARIOS["progresso_pct"] = min(98, pct_sub)
                elif low.endswith(".7z"):
                    try:
                        import py7zr
                        with py7zr.SevenZipFile(fpath, mode="r") as sz:
                            jez_targets = [
                                m for m in sz.getnames()
                                if m.lower().endswith(("-log.jez", ".logjez", ".jez"))
                                and "wsq" not in m.lower() and "gedai" not in m.lower()
                            ]
                            if jez_targets:
                                bio_dict = sz.read(targets=jez_targets)
                                for m_name, bio in bio_dict.items():
                                    _processar_membro_jez(bio.read(), m_name, default_uf)
                    except Exception as exc_7z:
                        _STATUS_REINDEX_MESARIOS["erros"].append(f"{os.path.basename(fpath)}: {exc_7z}")
            except Exception as exc_arq:
                _STATUS_REINDEX_MESARIOS["erros"].append(f"{os.path.basename(fpath)}: {exc_arq}")

            if lote_pendente > 0:
                db.commit()
                lote_pendente = 0

            _STATUS_REINDEX_MESARIOS["arquivos_processados"] = idx_f
            _STATUS_REINDEX_MESARIOS["progresso_pct"] = min(99, int((idx_f / total_fontes) * 98) + 1)

        if lote_pendente > 0:
            db.commit()
            lote_pendente = 0

        # Passo complementar: recupera também resumos de log.jez já salvos em catalogo_secoes.jsonl
        # (cobre urnas cujo arquivo .zip original já foi removido da VPS após ingestão)
        try:
            from .tse_reverse_analyzer import _get_tse_storage_dir
            jsonl_cat = os.path.join(_get_tse_storage_dir(), "catalogo_secoes.jsonl")
            if os.path.isfile(jsonl_cat):
                with open(jsonl_cat, "r", encoding="utf-8") as fp_cat:
                    for line_cat in fp_cat:
                        line_cat = line_cat.strip()
                        if not line_cat or "mesarios_registrados" not in line_cat:
                            continue
                        try:
                            rc = json.loads(line_cat)
                        except Exception:
                            continue
                        sec_c = _obter_ou_criar_secao_para_log(
                            db=db,
                            cache_secoes=cache_secoes,
                            uf=rc.get("uf", "PR"),
                            mun_cod=rc.get("municipio_codigo", "00000"),
                            zona_str=rc.get("zona", "0000"),
                            secao_str=rc.get("secao", "0000"),
                            modelo_urna=rc.get("modelo_ue", ""),
                        )
                        if not sec_c:
                            continue
                        t_pac = int(rc.get("turno_pacote") or 2)
                        pares_cat = [
                            (t_pac, rc.get("mesarios_registrados_t2") or [], rc.get("titulo_encerramento_t2") or "", rc.get("hora_zeresima_t2") or "", rc.get("hora_pronta_votos_t2") or "", rc.get("hora_encerramento_t2") or ""),
                            (1, rc.get("mesarios_registrados_t1") or [], rc.get("titulo_encerramento_t1") or "", rc.get("hora_zeresima_t1") or "", rc.get("hora_pronta_votos_t1") or "", rc.get("hora_encerramento_t1") or ""),
                        ]
                        for t_c, m_regs, tit_enc, h_zer, h_pro, h_enc in pares_cat:
                            if (sec_c.id, t_c) in secoes_ja_indexadas and not forcar_reprocessamento:
                                continue
                            todos_tits = list(dict.fromkeys([t for t in m_regs if t] + ([tit_enc] if tit_enc else [])))
                            if not todos_tits:
                                continue
                            sint_list = []
                            for idx_m, t_str in enumerate(todos_tits, start=1):
                                sint_list.append({
                                    "titulo": t_str,
                                    "abriu_secao": idx_m <= len(m_regs),
                                    "ordem_abertura": idx_m if idx_m <= len(m_regs) else 0,
                                    "hora_abertura": h_zer or h_pro or "",
                                    "digitou_encerramento": (t_str == tit_enc and bool(tit_enc)),
                                    "hora_encerramento": h_enc if (t_str == tit_enc and bool(tit_enc)) else "",
                                    "primeira_acao_hora": h_zer or h_pro or "",
                                    "ultima_acao_hora": h_enc or h_pro or "",
                                })
                            q_cat = persistir_lista_mesarios_turno(
                                db=db,
                                secao_db=sec_c,
                                turno=t_c,
                                mesarios_detalhados=sint_list,
                                serial_ue=str(rc.get("serial_ue") or ""),
                                hora_zeresima=h_zer,
                                hora_pronta_votos=h_pro,
                                hora_encerramento_urna=h_enc,
                            )
                            if q_cat > 0:
                                regs_gravados += q_cat
                                secoes_ok += 1
                                secoes_ja_indexadas.add((sec_c.id, t_c))
                                lote_pendente += 1
                                if lote_pendente >= 200:
                                    db.commit()
                                    lote_pendente = 0
                if lote_pendente > 0:
                    db.commit()
                    lote_pendente = 0
        except Exception as exc_cat:
            _STATUS_REINDEX_MESARIOS["erros"].append(f"Catálogo complementar: {exc_cat}")

        # Atualiza também coordenadas de registros existentes caso o local_votacao da seção tenha sido enriquecido depois
        atualizar_coordenadas_mesarios_pendentes(db)

        dt_final = max(0.1, time.time() - t0)
        _STATUS_REINDEX_MESARIOS.update({
            "em_andamento": False,
            "progresso_pct": 100,
            "logs_jez_lidos": logs_lidos,
            "secoes_com_mesarios": secoes_ok,
            "registros_gravados": regs_gravados,
            "velocidade_logs_s": round(logs_lidos / dt_final, 1),
            "finalizado_em": datetime.utcnow().isoformat(),
            "mensagem": f"Indexação concluída: {logs_lidos:,} logs .jez inspecionados, {regs_gravados:,} registros de mesários consolidados.",
        })
    except Exception as exc_geral:
        try:
            db.rollback()
        except Exception:
            pass
        _STATUS_REINDEX_MESARIOS.update({
            "em_andamento": False,
            "finalizado_em": datetime.utcnow().isoformat(),
            "mensagem": f"Erro durante reindexação: {exc_geral}",
        })
        _STATUS_REINDEX_MESARIOS["erros"].append(str(exc_geral))
    finally:
        try:
            db.close()
        except Exception:
            pass


def atualizar_coordenadas_mesarios_pendentes(db: Session) -> int:
    """Sincroniza local_votacao e coordenadas de `TseSecao` para `TseEventoMesario` quando enriquecidos posteriormente."""
    atualizados = 0
    rows_sem_loc = (
        db.query(TseEventoMesario, TseSecao)
        .join(TseSecao, TseEventoMesario.secao_id == TseSecao.id)
        .filter(
            (TseEventoMesario.latitude.is_(None))
            | (
                ((TseEventoMesario.local_votacao.is_(None)) | (TseEventoMesario.local_votacao == "-"))
                & TseSecao.local_votacao.isnot(None)
                & (TseSecao.local_votacao != "-")
            )
        )
        .limit(5000)
        .all()
    )
    for ev, sec in rows_sem_loc:
        loc_v = (sec.local_votacao or ev.local_votacao or "").strip()
        geo = _resolver_geolocalizacao_secao(
            uf=sec.uf,
            municipio_codigo=sec.municipio_codigo,
            municipio_nome=sec.municipio_nome or "",
            zona=sec.zona,
            local_votacao=loc_v,
        )
        ev.local_votacao = loc_v[:120] if loc_v else ev.local_votacao
        ev.nome_local = (geo.get("nome_local") or loc_v or "")[:160] or ev.nome_local
        ev.endereco_local = (geo.get("endereco") or "")[:220] or ev.endereco_local
        ev.latitude = geo.get("latitude")
        ev.longitude = geo.get("longitude")
        ev.coord_exata = bool(geo.get("coord_exata", False))
        atualizados += 1
    if atualizados > 0:
        db.commit()
    return atualizados


def _serializar_ocorrencia_mesario(r: TseEventoMesario) -> dict[str, Any]:
    papeis = []
    if r.abriu_secao:
        papeis.append(f"Abriu ({r.ordem_abertura}º)" if r.ordem_abertura else "Abriu Seção")
    if r.registrou_durante:
        papeis.append("Entrou Durante")
    if (r.qtd_habilitacoes_bio or 0) > 0:
        papeis.append(f"Habilitou {r.qtd_habilitacoes_bio} el.")
    if r.encerrou_secao:
        papeis.append("Digitou Encerramento")
    elif r.registrou_pos_votacao:
        papeis.append("Assinou Pós-Votação")

    loc_cod = (r.local_votacao or "").strip()
    chave_predio = (
        f"{r.uf}_{r.municipio_codigo}_{r.zona:04d}_{loc_cod}"
        if (loc_cod and loc_cod != "-")
        else f"{r.uf}_{r.municipio_codigo}_{r.zona:04d}_SEC{r.secao:04d}"
    )

    return {
        "id": r.id,
        "secao_id": r.secao_id,
        "turno": r.turno,
        "titulo": r.titulo_mesario,
        "uf_origem_titulo": r.uf_origem_titulo or "",
        "dv_titulo_valido": bool(r.dv_titulo_valido),
        "uf": r.uf,
        "municipio_codigo": r.municipio_codigo,
        "municipio_nome": r.municipio_nome or f"Município {r.municipio_codigo}",
        "zona": int(r.zona or 0),
        "zona_fmt": f"{int(r.zona or 0):04d}",
        "secao": int(r.secao or 0),
        "secao_fmt": f"{int(r.secao or 0):04d}",
        "local_votacao": loc_cod or "-",
        "nome_local": r.nome_local or (f"Local {loc_cod}" if loc_cod and loc_cod != "-" else f"Zona {int(r.zona or 0):04d} - Seção {int(r.secao or 0):04d}"),
        "endereco_local": r.endereco_local or "",
        "chave_predio": chave_predio,
        "latitude": r.latitude,
        "longitude": r.longitude,
        "coord_exata": bool(r.coord_exata),
        "serial_ue": r.serial_ue or "-",
        "data_eleicao": r.data_eleicao or "",
        "hora_zeresima": r.hora_zeresima or "",
        "hora_urna_pronta": r.hora_urna_pronta or "",
        "hora_urna_encerrada": r.hora_urna_encerrada or "",
        "abriu_secao": bool(r.abriu_secao),
        "ordem_abertura": int(r.ordem_abertura or 0),
        "hora_abertura": r.hora_abertura or "",
        "mac_abertura": r.mac_abertura or "",
        "registrou_durante": bool(r.registrou_durante),
        "hora_durante": r.hora_durante or "",
        "qtd_habilitacoes_bio": int(r.qtd_habilitacoes_bio or 0),
        "encerrou_secao": bool(r.encerrou_secao),
        "hora_encerramento": r.hora_encerramento or "",
        "mac_encerramento": r.mac_encerramento or "",
        "registrou_pos_votacao": bool(r.registrou_pos_votacao),
        "hora_pos_votacao": r.hora_pos_votacao or "",
        "primeira_acao_hora": r.primeira_acao_hora or r.hora_abertura or r.hora_encerramento or "",
        "ultima_acao_hora": r.ultima_acao_hora or r.hora_pos_votacao or r.hora_encerramento or r.hora_abertura or "",
        "eleitor_da_secao": r.eleitor_da_secao,
        "biometria_conferida": r.biometria_conferida,
        "papeis": papeis,
        "papeis_resumo": " • ".join(papeis) if papeis else "Registrado",
    }


def _avaliar_grupo_multi_secao(turno: int, titulo: str, ocorrencias: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Avalia um título que apareceu em 2+ seções no mesmo turno:
      - Calcula a distância máxima Haversine entre todas as seções envolvidas;
      - Aplica a escala exata de alertas: AZUL (< 300m), AMARELO (300m a 80km), VERMELHO (> 80km);
      - Detecta conflito/sobreposição de janelas de horário e velocidade implícita de deslocamento.
    """
    ocs_ord = sorted(
        ocorrencias,
        key=lambda o: (o.get("primeira_acao_hora") or "99:99:99", o["uf"], o["zona"], o["secao"]),
    )

    dist_max_km = 0.0
    par_mais_distante: Optional[tuple[dict, dict]] = None
    sobreposicao_horaria = False
    menor_intervalo_min: Optional[float] = None
    velocidade_max_kmh: Optional[float] = None

    n = len(ocs_ord)
    for i in range(n):
        a = ocs_ord[i]
        ini_a = _hora_para_segundos(a.get("primeira_acao_hora"))
        fim_a = _hora_para_segundos(a.get("ultima_acao_hora")) or ini_a
        for j in range(i + 1, n):
            b = ocs_ord[j]
            if a["chave_predio"] == b["chave_predio"] and a["local_votacao"] != "-":
                d_km = 0.0
            else:
                d_km = calcular_distancia_haversine_km(
                    a.get("latitude"), a.get("longitude"),
                    b.get("latitude"), b.get("longitude"),
                )

            if d_km >= dist_max_km:
                dist_max_km = d_km
                par_mais_distante = (a, b)

            ini_b = _hora_para_segundos(b.get("primeira_acao_hora"))
            fim_b = _hora_para_segundos(b.get("ultima_acao_hora")) or ini_b
            if ini_a is not None and fim_a is not None and ini_b is not None and fim_b is not None:
                if max(ini_a, ini_b) <= min(fim_a, fim_b):
                    if d_km >= 0.3:
                        sobreposicao_horaria = True
                    menor_intervalo_min = 0.0
                else:
                    gap_s = max(0, max(ini_a, ini_b) - min(fim_a, fim_b))
                    gap_min = round(gap_s / 60.0, 1)
                    if menor_intervalo_min is None or gap_min < menor_intervalo_min:
                        menor_intervalo_min = gap_min
                    if d_km >= 0.3 and gap_s > 0:
                        vel = round(d_km / (gap_s / 3600.0), 1)
                        if velocidade_max_kmh is None or vel > velocidade_max_kmh:
                            velocidade_max_kmh = vel

    escala_info = classificar_escala_alerta_distancia(dist_max_km)
    ufs = sorted({o["uf"] for o in ocs_ord})
    municipios = sorted({f"{o['municipio_nome']}/{o['uf']}" for o in ocs_ord})
    zonas_chaves = sorted({f"{o['uf']}-Z{o['zona_fmt']}" for o in ocs_ord})
    locais_chaves = {o["chave_predio"] for o in ocs_ord}

    qtd_aberturas = sum(1 for o in ocs_ord if o["abriu_secao"])
    qtd_encerramentos = sum(1 for o in ocs_ord if o["encerrou_secao"] or o["registrou_pos_votacao"])
    qtd_cmd_encerramento = sum(1 for o in ocs_ord if o["encerrou_secao"])
    qtd_hab_total = sum(int(o.get("qtd_habilitacoes_bio") or 0) for o in ocs_ord)

    primeiro = ocs_ord[0]
    return {
        "turno": int(turno),
        "titulo": titulo,
        "uf_origem_titulo": primeiro.get("uf_origem_titulo") or "",
        "dv_titulo_valido": bool(primeiro.get("dv_titulo_valido", True)),
        "escala": escala_info["escala"],           # VERMELHO | AMARELO | AZUL
        "severidade": escala_info["severidade"],
        "rotulo_escala": escala_info["rotulo"],
        "faixa_distancia": escala_info["faixa_distancia"],
        "distancia_max_km": round(dist_max_km, 2),
        "distancia_max_metros": int(round(dist_max_km * 1000.0)),
        "sobreposicao_horaria": sobreposicao_horaria,
        "menor_intervalo_min": menor_intervalo_min,
        "velocidade_impl_kmh": velocidade_max_kmh,
        "qtd_secoes": len(ocs_ord),
        "qtd_locais_distintos": len(locais_chaves),
        "qtd_zonas_distintas": len(zonas_chaves),
        "qtd_municipios_distintos": len(municipios),
        "qtd_ufs_distintas": len(ufs),
        "multi_zona": len(zonas_chaves) > 1,
        "multi_municipio": len(municipios) > 1,
        "multi_uf": len(ufs) > 1,
        "qtd_aberturas": qtd_aberturas,
        "qtd_encerramentos": qtd_encerramentos,
        "qtd_cmd_encerramento": qtd_cmd_encerramento,
        "qtd_habilitacoes_bio_total": qtd_hab_total,
        "ufs": ufs,
        "municipios": municipios,
        "zonas": zonas_chaves,
        "par_extremo": {
            "origem": f"{par_mais_distante[0]['municipio_nome']} Z{par_mais_distante[0]['zona_fmt']} S{par_mais_distante[0]['secao_fmt']}",
            "destino": f"{par_mais_distante[1]['municipio_nome']} Z{par_mais_distante[1]['zona_fmt']} S{par_mais_distante[1]['secao_fmt']}",
        } if par_mais_distante else None,
        "secoes": ocs_ord,
    }


def consultar_auditoria_mesarios_bi(
    db: Session,
    turno: str = "TODOS",
    uf: str = "TODAS",
    municipio: str = "TODAS",
    zona: str = "TODAS",
    escala: str = "TODAS",
    papel: str = "TODOS",
    busca_titulo: str = "",
    limit: int = 250,
) -> dict[str, Any]:
    """
    Motor principal da Segmentação de Auditoria de Mesários no BI:
      1. Calcula KPIs globais das seções com `log.jez` auditado;
      2. Identifica todos os títulos inseridos em >= 2 seções no mesmo turno e classifica na escala:
         - VERMELHO (> 80 km)
         - AMARELO (> 300 m até 80 km)
         - AZUL (< 300 m / mesmo prédio)
      3. Compila os Subtotais por Zona Eleitoral e Seções envolvidas para o filtro ativo
         (ex.: "50 alertas críticos -> quais zonas e seções concentram esses alertas e seus subtotais");
      4. Permite busca individual direta por qualquer número de título de eleitor.
    """
    garantir_tabelas_custodia_tse()

    turno_norm = (turno or "TODOS").strip().upper()
    uf_norm = (uf or "TODAS").strip().upper()
    mun_norm = (municipio or "TODAS").strip()
    zona_norm = (zona or "TODAS").strip()
    escala_norm = (escala or "TODAS").strip().upper()
    papel_norm = (papel or "TODOS").strip().upper()
    busca_clean = "".join(ch for ch in (busca_titulo or "") if ch.isdigit())

    # Se o banco estiver completamente vazio de mesários, mas houver amostras/logs rápidos locais e nenhum job ativo,
    # informa quantos pacotes estão prontos para indexação
    total_registros_global = int(db.query(func.count(TseEventoMesario.id)).scalar() or 0)
    if total_registros_global == 0:
        sample_jez = os.path.join(os.path.dirname(__file__), "samples_tse_pr", "o03221pr7407101710017-log.jez")
        if os.path.isfile(sample_jez):
            try:
                with open(sample_jez, "rb") as fp:
                    parsed_s = extrair_mesarios_rapido_de_log_jez(fp.read(), filename=os.path.basename(sample_jez))
                if parsed_s:
                    cache_s: dict[str, TseSecao] = {}
                    sec_s = _obter_ou_criar_secao_para_log(
                        db=db,
                        cache_secoes=cache_s,
                        uf="PR",
                        mun_cod=parsed_s["metadados"]["municipio"],
                        zona_str=parsed_s["metadados"]["zona"],
                        secao_str=parsed_s["metadados"]["secao"],
                        modelo_urna=parsed_s["metadados"]["modelo_ue"],
                    )
                    if sec_s:
                        for t_n, r_d in parsed_s["turnos"].items():
                            persistir_lista_mesarios_turno(
                                db=db,
                                secao_db=sec_s,
                                turno=t_n,
                                mesarios_detalhados=r_d.get("mesarios_detalhados", []),
                                serial_ue=parsed_s["metadados"]["serial_ue"],
                                data_eleicao=r_d.get("data_eleicao", ""),
                                hora_zeresima=r_d.get("hora_zeresima", ""),
                                hora_pronta_votos=r_d.get("hora_pronta_votos", ""),
                                hora_encerramento_urna=r_d.get("hora_encerramento", ""),
                                titulos_invalidos=int(r_d.get("titulos_invalidos_mesario") or 0),
                            )
                        db.commit()
                        total_registros_global = int(db.query(func.count(TseEventoMesario.id)).scalar() or 0)
            except Exception:
                db.rollback()

    # Filtros de escopo para estatísticas gerais
    filtros_escopo = []
    if turno_norm in ("1", "1T"):
        filtros_escopo.append(TseEventoMesario.turno == 1)
    elif turno_norm in ("2", "2T"):
        filtros_escopo.append(TseEventoMesario.turno == 2)
    if uf_norm != "TODAS":
        filtros_escopo.append(TseEventoMesario.uf == uf_norm)
    if mun_norm != "TODAS":
        filtros_escopo.append(TseEventoMesario.municipio_codigo == mun_norm)
    if zona_norm != "TODAS":
        try:
            filtros_escopo.append(TseEventoMesario.zona == int(zona_norm))
        except Exception:
            pass

    urnas_auditadas = int(
        db.query(func.count(distinct(TseEventoMesario.secao_id))).filter(*filtros_escopo).scalar() or 0
    )
    titulos_unicos = int(
        db.query(func.count(distinct(TseEventoMesario.titulo_mesario))).filter(*filtros_escopo).scalar() or 0
    )
    titulos_dv_invalido = int(
        db.query(func.count(distinct(TseEventoMesario.titulo_mesario)))
        .filter(*filtros_escopo, TseEventoMesario.dv_titulo_valido == False)
        .scalar() or 0
    )
    encerramentos_sem_abertura = int(
        db.query(func.count(TseEventoMesario.id))
        .filter(
            *filtros_escopo,
            TseEventoMesario.encerrou_secao == True,
            TseEventoMesario.abriu_secao == False,
            TseEventoMesario.registrou_durante == False,
        )
        .scalar() or 0
    )

    # 1. Localiza todos os pares (turno, titulo_mesario) com atuação em >= 2 seções no mesmo turno
    q_dup = db.query(
        TseEventoMesario.turno,
        TseEventoMesario.titulo_mesario,
    )
    if turno_norm in ("1", "1T"):
        q_dup = q_dup.filter(TseEventoMesario.turno == 1)
    elif turno_norm in ("2", "2T"):
        q_dup = q_dup.filter(TseEventoMesario.turno == 2)

    if busca_clean:
        q_dup = q_dup.filter(TseEventoMesario.titulo_mesario.like(f"%{busca_clean}%"))
        pares_alvo = q_dup.group_by(TseEventoMesario.turno, TseEventoMesario.titulo_mesario).limit(500).all()
    else:
        pares_alvo = (
            q_dup.group_by(TseEventoMesario.turno, TseEventoMesario.titulo_mesario)
            .having(func.count(distinct(TseEventoMesario.secao_id)) >= 2)
            .all()
        )

    titulos_alvo_set = {p[1] for p in pares_alvo}
    turnos_alvo_set = {int(p[0]) for p in pares_alvo}

    grupos_avaliados: list[dict[str, Any]] = []
    if titulos_alvo_set:
        rows_det = (
            db.query(TseEventoMesario)
            .filter(
                TseEventoMesario.turno.in_(turnos_alvo_set),
                TseEventoMesario.titulo_mesario.in_(titulos_alvo_set),
            )
            .all()
        )
        agrupado: dict[tuple[int, str], list[dict[str, Any]]] = defaultdict(list)
        pares_validos = {(int(p[0]), p[1]) for p in pares_alvo}
        for r in rows_det:
            chave_par = (int(r.turno), r.titulo_mesario)
            if chave_par in pares_validos:
                agrupado[chave_par].append(_serializar_ocorrencia_mesario(r))

        for (t_val, tit_val), ocs in agrupado.items():
            # Se não for busca nominal explícita, exige >= 2 seções distintas
            if not busca_clean and len(ocs) < 2:
                continue

            # Se houver filtro geográfico (UF, Município, Zona), exige que ao menos 1 das seções pertença ao escopo!
            if uf_norm != "TODAS" and not any(o["uf"] == uf_norm for o in ocs):
                continue
            if mun_norm != "TODAS" and not any(o["municipio_codigo"] == mun_norm for o in ocs):
                continue
            if zona_norm != "TODAS":
                try:
                    z_f = int(zona_norm)
                    if not any(o["zona"] == z_f for o in ocs):
                        continue
                except Exception:
                    pass

            aval = _avaliar_grupo_multi_secao(t_val, tit_val, ocs)
            if len(ocs) == 1:
                aval["escala"] = "UNICA"
                aval["rotulo_escala"] = "Seção Única (Regular)"
                aval["faixa_distancia"] = "0 m"
            grupos_avaliados.append(aval)

    # Contadores por escala ANTES do filtro de escala (para manter os cards do topo sempre com os totais reais!)
    contagem_escalas = {
        "VERMELHO": sum(1 for g in grupos_avaliados if g["escala"] == "VERMELHO"),
        "AMARELO": sum(1 for g in grupos_avaliados if g["escala"] == "AMARELO"),
        "AZUL": sum(1 for g in grupos_avaliados if g["escala"] == "AZUL"),
        "CONFLITO_TEMPORAL": sum(1 for g in grupos_avaliados if g["sobreposicao_horaria"]),
        "MULTI_ZONA": sum(1 for g in grupos_avaliados if g["multi_zona"]),
        "TOTAL_MULTI": sum(1 for g in grupos_avaliados if g["qtd_secoes"] >= 2),
    }

    # Aplica filtros de escala e papel solicitados pelo usuário
    filtrados: list[dict[str, Any]] = []
    for g in grupos_avaliados:
        if escala_norm in ("VERMELHO", "AMARELO", "AZUL") and g["escala"] != escala_norm:
            continue
        if escala_norm == "ACIMA_300M" and g["escala"] not in ("VERMELHO", "AMARELO"):
            continue
        if papel_norm == "ABERTURA" and g["qtd_aberturas"] == 0:
            continue
        if papel_norm == "ENCERRAMENTO" and g["qtd_encerramentos"] == 0:
            continue
        if papel_norm == "AMBOS" and not (g["qtd_aberturas"] > 0 and g["qtd_encerramentos"] > 0):
            continue
        if papel_norm == "CONFLITO_TEMPORAL" and not g["sobreposicao_horaria"]:
            continue
        if papel_norm == "MULTI_ZONA" and not g["multi_zona"]:
            continue
        filtrados.append(g)

    # Ordenação: Vermelhos primeiro (> 80km), depois Amarelos (> 300m), depois Azuis (< 300m), por maior distância
    ordem_peso = {"VERMELHO": 0, "AMARELO": 1, "AZUL": 2, "UNICA": 3}
    filtrados.sort(
        key=lambda g: (
            ordem_peso.get(g["escala"], 9),
            0 if g["sobreposicao_horaria"] else 1,
            -float(g["distancia_max_km"]),
            -int(g["qtd_secoes"]),
            g["titulo"],
        )
    )

    # 2. Compilação dos Subtotais por Zona Eleitoral e Seções para TODOS os alertas do filtro ativo
    zonas_agg: dict[tuple[str, str, int], dict[str, Any]] = {}
    secoes_afetadas_global: set[tuple[str, str, int, int]] = set()

    for g in filtrados:
        escala_g = g["escala"]
        zonas_vistas_neste_alerta: set[tuple[str, str, int]] = set()
        for o in g["secoes"]:
            z_key = (o["uf"], o["municipio_codigo"], o["zona"])
            secoes_afetadas_global.add((o["uf"], o["municipio_codigo"], o["zona"], o["secao"]))
            z_entry = zonas_agg.get(z_key)
            if z_entry is None:
                z_entry = {
                    "uf": o["uf"],
                    "municipio_codigo": o["municipio_codigo"],
                    "municipio_nome": o["municipio_nome"],
                    "zona": o["zona"],
                    "zona_fmt": o["zona_fmt"],
                    "subtotal_alertas": 0,
                    "subtotal_vermelhos": 0,
                    "subtotal_amarelos": 0,
                    "subtotal_azuis": 0,
                    "subtotal_aberturas": 0,
                    "subtotal_encerramentos": 0,
                    "distancia_max_zona_km": 0.0,
                    "_secoes_map": {},
                }
                zonas_agg[z_key] = z_entry

            if z_key not in zonas_vistas_neste_alerta:
                zonas_vistas_neste_alerta.add(z_key)
                z_entry["subtotal_alertas"] += 1
                if escala_g == "VERMELHO":
                    z_entry["subtotal_vermelhos"] += 1
                elif escala_g == "AMARELO":
                    z_entry["subtotal_amarelos"] += 1
                elif escala_g == "AZUL":
                    z_entry["subtotal_azuis"] += 1

            if o["abriu_secao"]:
                z_entry["subtotal_aberturas"] += 1
            if o["encerrou_secao"] or o["registrou_pos_votacao"]:
                z_entry["subtotal_encerramentos"] += 1
            if g["distancia_max_km"] > z_entry["distancia_max_zona_km"]:
                z_entry["distancia_max_zona_km"] = g["distancia_max_km"]

            sec_m = z_entry["_secoes_map"].get(o["secao"])
            if sec_m is None:
                sec_m = {
                    "secao": o["secao"],
                    "secao_fmt": o["secao_fmt"],
                    "local_votacao": o["local_votacao"],
                    "nome_local": o["nome_local"],
                    "qtd_ocorrencias": 0,
                    "titulos": [],
                }
                z_entry["_secoes_map"][o["secao"]] = sec_m
            sec_m["qtd_ocorrencias"] += 1
            if g["titulo"] not in sec_m["titulos"] and len(sec_m["titulos"]) < 8:
                sec_m["titulos"].append(g["titulo"])

    subtotais_por_zona = []
    for z_entry in zonas_agg.values():
        sec_list = sorted(z_entry.pop("_secoes_map").values(), key=lambda x: x["secao"])
        z_entry["subtotal_secoes"] = len(sec_list)
        z_entry["secoes"] = sec_list
        subtotais_por_zona.append(z_entry)

    subtotais_por_zona.sort(
        key=lambda z: (
            -z["subtotal_vermelhos"],
            -z["subtotal_amarelos"],
            -z["subtotal_alertas"],
            -z["subtotal_secoes"],
            z["uf"],
            z["zona"],
        )
    )

    # Lista de UFs disponíveis na tabela de mesários para o seletor rápido
    ufs_disponiveis = [
        r[0] for r in db.query(TseEventoMesario.uf).distinct().order_by(TseEventoMesario.uf).all() if r[0]
    ]

    return {
        "kpis": {
            "total_registros_banco": total_registros_global,
            "urnas_com_log_auditado": urnas_auditadas,
            "titulos_unicos_escopo": titulos_unicos,
            "total_alertas_multi_secao": contagem_escalas["TOTAL_MULTI"],
            "alertas_vermelhos": contagem_escalas["VERMELHO"],
            "alertas_amarelos": contagem_escalas["AMARELO"],
            "alertas_azuis": contagem_escalas["AZUL"],
            "conflitos_temporais": contagem_escalas["CONFLITO_TEMPORAL"],
            "alertas_multi_zona": contagem_escalas["MULTI_ZONA"],
            "encerramentos_sem_abertura": encerramentos_sem_abertura,
            "titulos_dv_invalido": titulos_dv_invalido,
            "total_filtrado": len(filtrados),
            "zonas_afetadas_no_filtro": len(subtotais_por_zona),
            "secoes_afetadas_no_filtro": len(secoes_afetadas_global),
        },
        "filtros_aplicados": {
            "turno": turno_norm,
            "uf": uf_norm,
            "municipio": mun_norm,
            "zona": zona_norm,
            "escala": escala_norm,
            "papel": papel_norm,
            "busca_titulo": busca_clean,
        },
        "ufs_disponiveis": ufs_disponiveis,
        "subtotais_por_zona": subtotais_por_zona,
        "alertas": filtrados[: max(1, min(int(limit or 250), 1000))],
        "reindexacao": obter_status_reindexacao_mesarios(),
    }


def obter_dossie_titulo_mesario(db: Session, titulo: str, turno: Optional[int] = None) -> dict[str, Any]:
    """Retorna a linha do tempo completa, códigos MAC e coordenadas de mapa para um título específico."""
    garantir_tabelas_custodia_tse()
    digs = "".join(ch for ch in str(titulo or "") if ch.isdigit())
    if not digs:
        raise ValueError("Informe um número de título válido.")
    tit_norm = digs.zfill(12) if len(digs) <= 12 else digs

    q = db.query(TseEventoMesario).filter(TseEventoMesario.titulo_mesario == tit_norm)
    if turno in (1, 2):
        q = q.filter(TseEventoMesario.turno == int(turno))

    rows = q.order_by(TseEventoMesario.turno, TseEventoMesario.primeira_acao_hora).all()
    if not rows:
        raise ValueError(f"Título {tit_norm} não encontrado nos logs .jez indexados.")

    por_turno: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        item = _serializar_ocorrencia_mesario(r)
        try:
            item["eventos"] = json.loads(r.eventos_json) if r.eventos_json else []
        except Exception:
            item["eventos"] = []
        por_turno[int(r.turno)].append(item)

    turnos_dossie = {}
    for t_num, ocs in sorted(por_turno.items()):
        if len(ocs) >= 2:
            aval = _avaliar_grupo_multi_secao(t_num, tit_norm, ocs)
        else:
            aval = {
                "turno": t_num,
                "titulo": tit_norm,
                "escala": "UNICA",
                "rotulo_escala": "Atuação em Seção Única (Regular)",
                "distancia_max_km": 0.0,
                "distancia_max_metros": 0,
                "sobreposicao_horaria": False,
                "menor_intervalo_min": None,
                "velocidade_impl_kmh": None,
                "qtd_secoes": len(ocs),
                "secoes": ocs,
            }
        turnos_dossie[str(t_num)] = aval

    val_info = validar_titulo_eleitor_tse(tit_norm)
    return {
        "titulo": tit_norm,
        "uf_origem_titulo": val_info["uf_origem"],
        "dv_titulo_valido": val_info["valido"],
        "turnos": turnos_dossie,
    }


def obter_mesarios_secao_individual(db: Session, secao_id: int) -> dict[str, Any]:
    """
    Retorna os mesários registrados na seção individual (1ºT e 2ºT) já enriquecidos
    com eventual alerta caso qualquer um deles tenha aparecido em outra seção no mesmo turno.
    """
    garantir_tabelas_custodia_tse()
    rows = (
        db.query(TseEventoMesario)
        .filter(TseEventoMesario.secao_id == int(secao_id))
        .order_by(TseEventoMesario.turno, TseEventoMesario.ordem_abertura, TseEventoMesario.primeira_acao_hora)
        .all()
    )
    if not rows:
        return {"disponivel": False, "turno_1": [], "turno_2": []}

    titulos_secao = {r.titulo_mesario for r in rows}
    outros_rows = (
        db.query(TseEventoMesario)
        .filter(TseEventoMesario.titulo_mesario.in_(titulos_secao))
        .all()
    )
    agrup: dict[tuple[int, str], list[dict[str, Any]]] = defaultdict(list)
    for r in outros_rows:
        agrup[(int(r.turno), r.titulo_mesario)].append(_serializar_ocorrencia_mesario(r))

    alertas_por_chave: dict[tuple[int, str], dict[str, Any]] = {}
    for chave, lista_ocs in agrup.items():
        if len(lista_ocs) >= 2:
            alertas_por_chave[chave] = _avaliar_grupo_multi_secao(chave[0], chave[1], lista_ocs)

    res = {"disponivel": True, "turno_1": [], "turno_2": []}
    for r in rows:
        item = _serializar_ocorrencia_mesario(r)
        al = alertas_por_chave.get((int(r.turno), r.titulo_mesario))
        if al:
            item["alerta_multi_secao"] = {
                "escala": al["escala"],
                "rotulo_escala": al["rotulo_escala"],
                "distancia_max_km": al["distancia_max_km"],
                "qtd_secoes": al["qtd_secoes"],
                "sobreposicao_horaria": al["sobreposicao_horaria"],
            }
        else:
            item["alerta_multi_secao"] = None
        res[f"turno_{int(r.turno)}"].append(item)

    return res
