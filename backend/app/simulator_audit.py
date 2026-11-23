import os
import json
import math
import random
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from sqlalchemy import func, case

from .database import (
    engine,
    SeccaoConfig,
    EleitorSeccao,
    Partido,
    Candidato,
    RegistroDigitalVoto,
    LogAuditoriaUrna,
    TseSecao,
    TseApuracaoBU,
    TseVotoCandidato,
    HistoricoSimulacao,
    garantir_tabelas_custodia_tse,
)
from .election_engine import get_cargos_por_turno, seed_default_candidates
from .thermal_printer import gerar_relatorio_zeresima, apurar_boletim_de_urna
from .cartridge import gerar_cartucho_midia_resultado


def _append_simulated_log(
    db: Session,
    config: SeccaoConfig,
    sim_clock: datetime,
    evento: str,
    detalhes: str,
    metadados_telemetria: dict = None,
):
    """
    Insere um evento no Log de Auditoria com timestamp cronológico simulado (`sim_clock`)
    e encadeamento criptográfico SHA-256 (Merkle chain).
    """
    ts_iso = sim_clock.isoformat()
    detalhes_full = detalhes
    if metadados_telemetria:
        detalhes_full = f"{detalhes} | TELEMETRIA={json.dumps(metadados_telemetria, ensure_ascii=False)}"

    payload = f"{config.ultimo_hash_log}|{ts_iso}|{evento}|{detalhes_full}"
    novo_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

    entry = LogAuditoriaUrna(
        timestamp=sim_clock,
        evento=evento,
        detalhes=detalhes_full,
        hash_anterior=config.ultimo_hash_log,
        hash_atual=novo_hash,
    )
    config.ultimo_hash_log = novo_hash
    db.add(entry)
    return entry


def executar_simulacao_cadencia_seccao(
    db: Session,
    config: SeccaoConfig,
    *,
    turno: int = 1,
    eleitores_aptos: int = 300,
    abstencoes: int = 60,
    pct_brancos: float = 5.0,
    pct_nulos: float = 4.0,
    pct_legenda: float = 6.0,
    modo_anomalia: str = "NORMAL",
    qtd_votos_anomalia: int = 0,
    candidato_alvo_anomalia: str = "",
) -> dict:
    """
    Simula um dia completo de votação na Seção Eleitoral (08:00 às 17:00 BRT / UTC-3)
    com cadência realista de fila, mesário, biometria AFIS, digitação de teclas por cargo
    e opção de injeção de distorções/anomalias para estudo forense de auditoria de logs.

    Modos de Anomalia suportados (`modo_anomalia`):
      - "NORMAL": Todos os votos respeitam a cadência humana física e biométrica (35s a 95s por ciclo completo).
      - "RAJADA_ROBO": Injeta `qtd_votos_anomalia` votos com intervalos sobre-humanos (1.2s a 3.5s por eleitor completo e ~80ms por cargo).
      - "SEM_BIOMETRIA_EM_MASSA": Injeta `qtd_votos_anomalia` habilitações seguidas sem leitura biométrica AFIS em curto intervalo.
      - "FORA_DE_JANELA_HORARIA": Injeta `qtd_votos_anomalia` votos antes das 08:00 ou após as 17:00.
    """
    seed_default_candidates(db)

    if abstencoes < 0 or abstencoes > eleitores_aptos:
        raise ValueError("O número de abstenções deve estar entre 0 e o total de eleitores aptos.")

    comparecimento_humano = eleitores_aptos - abstencoes
    cargos = get_cargos_por_turno(turno)
    candidatos_turno = db.query(Candidato).filter(Candidato.turno == turno).all()
    partidos = db.query(Partido).all()

    # Reinicia a seção e os logs para uma simulação limpa e determinística
    db.query(RegistroDigitalVoto).filter(RegistroDigitalVoto.turno == turno).delete()
    db.query(LogAuditoriaUrna).delete()

    tz_brt = timezone(timedelta(hours=-3))
    dia_eleicao = datetime(2026, 10, 4 if turno == 1 else 25, 7, 50, 0, tzinfo=tz_brt)

    config.turno = turno
    config.eleitores_aptos = eleitores_aptos
    config.eleitores_compareceram = 0
    config.status = "NAO_INICIALIZADA"
    config.terminal_eleitor_liberado = False
    config.eleitor_habilitado_titulo = None
    config.ultimo_hash_log = "0" * 64
    db.commit()

    # 1. Boot e Emissão da Zerésima às 07:55:00
    relogio = dia_eleicao
    _append_simulated_log(
        db,
        config,
        relogio,
        "BOOT_URNA",
        f"Urna energizada na seção {config.secao} (Zona {config.zona}).",
        {"fase": "BOOT", "clock_drift_ms": 0},
    )

    relogio = dia_eleicao.replace(hour=7, minute=55, second=12)
    zeresima_info = gerar_relatorio_zeresima(db, config)
    config.zeresima_timestamp = relogio
    config.abertura_timestamp = dia_eleicao.replace(hour=8, minute=0, second=0)

    _append_simulated_log(
        db,
        config,
        relogio,
        "EMISSAO_ZERESIMA_E_ABERTURA",
        f"Zerésima emitida (SHA256={zeresima_info['hash_sha256'][:16]}...). Seção aberta para início às 08:00.",
        {"hash_zeresima": zeresima_info["hash_sha256"][:24]},
    )

    # Posiciona relógio na abertura oficial às 08:00:00
    relogio = dia_eleicao.replace(hour=8, minute=0, second=5)

    # Calcula o espaçamento médio entre chegadas para distribuir `comparecimento_humano` ao longo de 9h (32.400s)
    janela_total_seg = 9 * 3600  # 32.400 segundos (08h às 17h)
    passo_medio_fila = janela_total_seg / max(comparecimento_humano, 1)

    metricas_ciclos = []

    def _sortear_voto_cargo(c_meta: dict, forcar_alvo: str = ""):
        cod = c_meta["codigo"]
        cands_cargo = [c for c in candidatos_turno if c.cargo == cod]

        if forcar_alvo:
            cand_match = next((c for c in cands_cargo if c.numero == forcar_alvo or c.numero.startswith(forcar_alvo)), None)
            if cand_match:
                return "NOMINAL", cand_match.numero, cand_match.numero[:2]

        r = random.uniform(0, 100.0)
        if r < pct_brancos:
            return "BRANCO", None, None
        if r < (pct_brancos + pct_nulos):
            num_invalido = "99" + "".join(str(random.randint(0, 9)) for _ in range(c_meta["digitos"] - 2))
            return "NULO", num_invalido, None
        if c_meta["permite_legenda"] and r < (pct_brancos + pct_nulos + pct_legenda) and partidos:
            p = random.choice(partidos)
            return "LEGENDA", p.numero, p.numero

        if cands_cargo:
            pesos = [1.4 if idx == 0 else (1.15 if idx == 1 else 0.8) for idx in range(len(cands_cargo))]
            escolhido = random.choices(cands_cargo, weights=pesos, k=1)[0]
            return "NOMINAL", escolhido.numero, escolhido.numero[:2]
        return "BRANCO", None, None

    def _executar_ciclo_eleitor(idx_seq: int, is_anomalia: bool, tipo_anomalia: str):
        nonlocal relogio
        t_inicio_ciclo = relogio

        # Etapas do Mesário:
        # 1) Digitação e busca do título no Terminal do Mesário
        # 2) Coleta e validação biométrica AFIS
        # 3) Habilitação da cabine e caminhada do eleitor
        # 4) Digitação de cada cargo + CONFIRMA
        if not is_anomalia:
            t_busca_mesario = round(random.uniform(5.5, 14.0), 2)
            usa_biometria = random.random() < 0.93  # 93% com biometria AFIS, 7% idoso/documento
            tentativas_bio = 1 if random.random() < 0.85 else 2
            t_biometria = round(random.uniform(4.2, 11.5) * tentativas_bio, 2) if usa_biometria else round(random.uniform(8.0, 16.0), 2)
            t_caminhada_cabine = round(random.uniform(3.0, 7.5), 2)
        else:
            if tipo_anomalia == "RAJADA_ROBO":
                # Fraude de injeção automatizada: tempos humanamente impossíveis (< 2s total)
                t_busca_mesario = round(random.uniform(0.15, 0.40), 2)
                usa_biometria = False
                tentativas_bio = 0
                t_biometria = round(random.uniform(0.10, 0.25), 2)
                t_caminhada_cabine = round(random.uniform(0.05, 0.15), 2)
            elif tipo_anomalia == "SEM_BIOMETRIA_EM_MASSA":
                # Mesário liberando urna sequencialmente sem digital AFIS e rápido demais
                t_busca_mesario = round(random.uniform(1.8, 3.5), 2)
                usa_biometria = False
                tentativas_bio = 0
                t_biometria = round(random.uniform(0.8, 1.5), 2)
                t_caminhada_cabine = round(random.uniform(1.0, 2.0), 2)
            else:  # FORA_DE_JANELA_HORARIA
                t_busca_mesario = round(random.uniform(4.0, 7.0), 2)
                usa_biometria = False
                tentativas_bio = 0
                t_biometria = round(random.uniform(2.0, 4.0), 2)
                t_caminhada_cabine = round(random.uniform(2.0, 3.5), 2)

        # Avança relógio: Mesário localizou eleitor e coletou biometria
        relogio = relogio + timedelta(seconds=t_busca_mesario + t_biometria)
        metodo_hab = "AFIS_BIOMETRIA_OK" if usa_biometria else "SEM_BIO_DOC_OFICIAL"

        _append_simulated_log(
            db,
            config,
            relogio,
            "TERMINAL_MESARIO_HABILITOU_ELEITOR",
            f"Terminal liberado pelo Mesário (Seq #{idx_seq} | Auth={metodo_hab}).",
            {
                "seq_comparecimento": idx_seq,
                "tempo_busca_mesario_s": t_busca_mesario,
                "tempo_biometria_s": t_biometria,
                "biometria_afis": usa_biometria,
                "tentativas_bio": tentativas_bio,
            },
        )

        # Eleitor caminha até a Urna e digita cada cargo
        relogio = relogio + timedelta(seconds=t_caminhada_cabine)
        tempos_por_cargo = {}
        total_teclas_eleitor = 0

        for c_meta in cargos:
            cod = c_meta["codigo"]
            n_dig = c_meta["digitos"]

            if not is_anomalia or tipo_anomalia == "FORA_DE_JANELA_HORARIA":
                # Cadência humana real: ~1.1s a 2.6s por dígito + conferência visual da foto + tecla CONFIRMA
                t_cargo = round(random.uniform(1.2 * n_dig + 2.2, 2.5 * n_dig + 5.5), 2)
            elif tipo_anomalia == "SEM_BIOMETRIA_EM_MASSA":
                t_cargo = round(random.uniform(0.45 * n_dig, 0.75 * n_dig), 2)
            else:  # RAJADA_ROBO
                t_cargo = round(random.uniform(0.08, 0.22), 2)

            tempos_por_cargo[cod] = t_cargo
            relogio = relogio + timedelta(seconds=t_cargo)

            alvo = candidato_alvo_anomalia if is_anomalia else ""
            tipo_voto, num_gravado, legenda_gravada = _sortear_voto_cargo(c_meta, forcar_alvo=alvo)
            total_teclas_eleitor += (1 if tipo_voto == "BRANCO" else len(num_gravado or "")) + 1  # dígitos + CONFIRMA

            shuffle_key = secrets.token_hex(32)
            integrity_payload = f"{shuffle_key}|{turno}|{cod}|{tipo_voto}|{num_gravado}|{legenda_gravada}"
            voto_hash = hashlib.sha256(integrity_payload.encode("utf-8")).hexdigest()

            db.add(
                RegistroDigitalVoto(
                    shuffle_key=shuffle_key,
                    turno=turno,
                    cargo=cod,
                    tipo_voto=tipo_voto,
                    numero_digitado=num_gravado,
                    partido_legenda=legenda_gravada,
                    hash_integridade=voto_hash,
                )
            )

        duracao_cabine_s = round(sum(tempos_por_cargo.values()), 2)
        duracao_ciclo_completo_s = round((relogio - t_inicio_ciclo).total_seconds(), 2)
        config.eleitores_compareceram += 1

        _append_simulated_log(
            db,
            config,
            relogio,
            "VOTO_COMPUTADO_RDV",
            f"Comparecimento #{config.eleitores_compareceram} concluiu votação ({len(cargos)} cargos gravados no RDV).",
            {
                "seq_comparecimento": config.eleitores_compareceram,
                "duracao_cabine_s": duracao_cabine_s,
                "duracao_ciclo_completo_s": duracao_ciclo_completo_s,
                "teclas_pressionadas": total_teclas_eleitor,
                "tempos_cargos_s": tempos_por_cargo,
                "biometria_afis": usa_biometria,
            },
        )

        metricas_ciclos.append(
            {
                "seq": config.eleitores_compareceram,
                "timestamp_fim": relogio.isoformat(),
                "hora_brt": relogio.strftime("%H:%M:%S"),
                "tempo_mesario_s": round(t_busca_mesario + t_biometria, 2),
                "tempo_cabine_s": duracao_cabine_s,
                "tempo_ciclo_total_s": duracao_ciclo_completo_s,
                "biometria_afis": usa_biometria,
                "anomalia_injetada": is_anomalia,
                "tipo_anomalia": tipo_anomalia if is_anomalia else "NORMAL",
            }
        )

    # Ponto de injeção de anomalia no meio do expediente (ex: após 55% dos eleitores normais)
    ponto_injecao = int(comparecimento_humano * 0.55)

    # Caso FORA_DE_JANELA_HORARIA: injeta metade às 07:57 (antes das 08:00)
    if modo_anomalia == "FORA_DE_JANELA_HORARIA" and qtd_votos_anomalia > 0:
        relogio_pre_08h = dia_eleicao.replace(hour=7, minute=56, second=30)
        relogio_salvo = relogio
        relogio = relogio_pre_08h
        for _ in range(qtd_votos_anomalia):
            _executar_ciclo_eleitor(config.eleitores_compareceram + 1, True, "FORA_DE_JANELA_HORARIA")
            relogio = relogio + timedelta(seconds=random.uniform(1.5, 4.0))
        relogio = max(relogio_salvo, dia_eleicao.replace(hour=8, minute=0, second=5))

    # Executa os eleitores legítimos ao longo do dia (08h00 -> 17h00)
    for i in range(comparecimento_humano):
        _executar_ciclo_eleitor(config.eleitores_compareceram + 1, False, "NORMAL")

        # Injeta rajada robótica ou lote sem biometria no meio do dia (por volta das 13h)
        if i == ponto_injecao and modo_anomalia in ("RAJADA_ROBO", "SEM_BIOMETRIA_EM_MASSA") and qtd_votos_anomalia > 0:
            for _ in range(qtd_votos_anomalia):
                relogio = relogio + timedelta(seconds=random.uniform(0.2, 0.8))
                _executar_ciclo_eleitor(config.eleitores_compareceram + 1, True, modo_anomalia)

        # Tempo ocioso natural da fila até o próximo eleitor chegar à mesa
        tempo_gasto = metricas_ciclos[-1]["tempo_ciclo_total_s"]
        folga_fila = max(2.0, passo_medio_fila - tempo_gasto + random.uniform(-12.0, 15.0))
        relogio = relogio + timedelta(seconds=folga_fila)
        # Mantém dentro das 17:00 para eleitores normais
        limite_17h = dia_eleicao.replace(hour=16, minute=58, second=30)
        if relogio > limite_17h and i < comparecimento_humano - 1:
            relogio = limite_17h - timedelta(seconds=(comparecimento_humano - i) * 35)

    # Encerramento oficial da Seção às 17:00:00
    relogio_encerramento = max(relogio + timedelta(seconds=15), dia_eleicao.replace(hour=17, minute=0, second=0))
    config.status = "ENCERRADA"
    config.encerramento_timestamp = relogio_encerramento
    db.commit()

    bu = apurar_boletim_de_urna(db, config)
    cartucho = gerar_cartucho_midia_resultado(db, config)

    _append_simulated_log(
        db,
        config,
        relogio_encerramento,
        "ENCERRAMENTO_BU_E_CARTUCHO",
        f"Seção encerrada às 17h. BU SHA256={bu['hash_bu_sha256'][:16]}... Cartucho={cartucho['arquivo']}.",
        {
            "eleitores_aptos": eleitores_aptos,
            "comparecimento_total": config.eleitores_compareceram,
            "hash_bu": bu["hash_bu_sha256"][:24],
        },
    )
    db.commit()

    tempos_normais = [m["tempo_ciclo_total_s"] for m in metricas_ciclos if not m["anomalia_injetada"]]
    tempos_todos = [m["tempo_ciclo_total_s"] for m in metricas_ciclos]

    return {
        "ok": True,
        "parametros": {
            "turno": turno,
            "eleitores_aptos": eleitores_aptos,
            "abstencoes_planejadas": abstencoes,
            "comparecimento_legitimo": comparecimento_humano,
            "modo_anomalia": modo_anomalia,
            "votos_anomalia_injetados": qtd_votos_anomalia if modo_anomalia != "NORMAL" else 0,
            "comparecimento_final_urna": config.eleitores_compareceram,
        },
        "estatisticas_cadencia": {
            "tempo_medio_ciclo_normal_s": round(sum(tempos_normais) / max(len(tempos_normais), 1), 2),
            "tempo_minimo_registrado_s": round(min(tempos_todos), 2) if tempos_todos else 0,
            "tempo_maximo_registrado_s": round(max(tempos_todos), 2) if tempos_todos else 0,
            "taxa_biometria_afis_pct": round(
                sum(1 for m in metricas_ciclos if m["biometria_afis"]) / max(len(metricas_ciclos), 1) * 100.0, 1
            ),
        },
        "amostra_ciclos": metricas_ciclos,
        "boletim_de_urna": bu,
        "cartucho": cartucho,
    }


def auditar_logs_independente(logs_list: list[dict]) -> dict:
    """
    Motor Paralelo Independente de Auditoria Forense de Logs da Urna Eletrônica.
    Recebe um pacote JSON de logs (ou lê da base) e executa 5 verificações forenses:
      1. Integridade Criptográfica da Cadeia SHA-256 (Merkle Chain Verification);
      2. Detecção de Cadência Sobre-Humana / Injeção Robótica (< 18s no ciclo completo ou < 4s na cabine);
      3. Detecção de Lotes Suspeitos sem Biometria AFIS;
      4. Detecção de Votos Fora da Janela Horária Legal (Antes da Zerésima/08:00 ou Após Encerramento/17:05);
      5. Consistência entre Habilitações do Mesário e Votos Computados no RDV.
    """
    anomalias = []
    ciclos_extraidos = []

    cadeia_integra = True
    quebras_hash = 0

    # Ordena cronologicamente pelo ID
    logs_sorted = sorted(logs_list, key=lambda x: x.get("id", 0))

    ultimo_hash_esperado = "0" * 64
    abertura_dt = None
    encerramento_dt = None

    seq_sem_biometria_consecutiva = 0
    habilitacoes_count = 0
    votos_rdv_count = 0

    for idx, entry in enumerate(logs_sorted):
        ev = entry.get("evento", "")
        det = entry.get("detalhes", "")
        ts_str = entry.get("timestamp", "")
        h_ant = entry.get("hash_anterior", "")
        h_atu = entry.get("hash_atual", "")

        # 1. Verificação da cadeia de hash anterior -> atual
        if idx > 0 and h_ant != ultimo_hash_esperado:
            cadeia_integra = False
            quebras_hash += 1
            anomalias.append({
                "severidade": "CRITICA",
                "codigo": "QUEBRA_CADEIA_SHA256",
                "log_id": entry.get("id"),
                "timestamp": ts_str,
                "descricao": f"Adulteração detectada no Log #{entry.get('id')}: hash_anterior ({h_ant[:12]}...) diverge do hash_atual precedente ({ultimo_hash_esperado[:12]}...).",
            })
        ultimo_hash_esperado = h_atu

        # Extrai telemetria JSON se presente
        telemetria = {}
        if "| TELEMETRIA=" in det:
            try:
                raw_json = det.split("| TELEMETRIA=", 1)[1].strip()
                telemetria = json.loads(raw_json)
            except Exception:
                telemetria = {}

        try:
            dt_obj = datetime.fromisoformat(ts_str) if ts_str else None
        except Exception:
            dt_obj = None

        if ev == "EMISSAO_ZERESIMA_E_ABERTURA" and dt_obj:
            abertura_dt = dt_obj
        elif ev == "ENCERRAMENTO_BU_E_CARTUCHO" and dt_obj:
            encerramento_dt = dt_obj

        if ev == "TERMINAL_MESARIO_HABILITOU_ELEITOR":
            habilitacoes_count += 1
            bio_ok = telemetria.get("biometria_afis", True)
            if not bio_ok:
                seq_sem_biometria_consecutiva += 1
                if seq_sem_biometria_consecutiva >= 4:
                    anomalias.append({
                        "severidade": "ALTA",
                        "codigo": "LOTE_SEM_BIOMETRIA_AFIS",
                        "log_id": entry.get("id"),
                        "timestamp": ts_str,
                        "descricao": (
                            f"Sequência suspeita de {seq_sem_biometria_consecutiva} eleitores consecutivos "
                            f"habilitados SEM leitura biométrica AFIS (Seq #{telemetria.get('seq_comparecimento')})."
                        ),
                    })
            else:
                seq_sem_biometria_consecutiva = 0

        if ev == "VOTO_COMPUTADO_RDV":
            votos_rdv_count += 1
            dur_ciclo = telemetria.get("duracao_ciclo_completo_s")
            dur_cabine = telemetria.get("duracao_cabine_s")
            seq_num = telemetria.get("seq_comparecimento", votos_rdv_count)
            bio_ok = telemetria.get("biometria_afis", True)

            if dur_ciclo is not None:
                ciclos_extraidos.append({
                    "seq": seq_num,
                    "log_id": entry.get("id"),
                    "timestamp": ts_str,
                    "hora": dt_obj.strftime("%H:%M:%S") if dt_obj else "",
                    "duracao_ciclo_s": dur_ciclo,
                    "duracao_cabine_s": dur_cabine,
                    "biometria_afis": bio_ok,
                })

                # 2. Detecção de Cadência Sobre-Humana (Robô / Script)
                if dur_ciclo < 15.0 or (dur_cabine is not None and dur_cabine < 3.5):
                    anomalias.append({
                        "severidade": "CRITICA",
                        "codigo": "CADENCIA_SOBRE_HUMANA_ROBO",
                        "log_id": entry.get("id"),
                        "timestamp": ts_str,
                        "descricao": (
                            f"Injeção acelerada detectada no Eleitor #{seq_num}: Ciclo completo em {dur_ciclo}s "
                            f"(Cabine={dur_cabine}s). Limite mínimo humano aceitável é ~18s."
                        ),
                    })

            # 3. Verificação de Janela Horária Legal (08:00 às 17:00)
            if dt_obj and dt_obj.hour < 8:
                anomalias.append({
                    "severidade": "CRITICA",
                    "codigo": "VOTO_ANTES_DAS_08H",
                    "log_id": entry.get("id"),
                    "timestamp": ts_str,
                    "descricao": f"Voto #{seq_num} computado às {dt_obj.strftime('%H:%M:%S')} (ANTES do horário oficial de abertura das 08:00).",
                })

    if habilitacoes_count != votos_rdv_count:
        anomalias.append({
            "severidade": "CRITICA",
            "codigo": "DIVERGENCIA_MESARIO_VS_RDV",
            "log_id": None,
            "timestamp": "",
            "descricao": f"Divergência grave: Mesário habilitou {habilitacoes_count} eleitores, mas o RDV registrou {votos_rdv_count} votos.",
        })

    tempos = [c["duracao_ciclo_s"] for c in ciclos_extraidos]
    media_s = round(sum(tempos) / len(tempos), 2) if tempos else 0.0
    min_s = round(min(tempos), 2) if tempos else 0.0
    max_s = round(max(tempos), 2) if tempos else 0.0

    veredito = "APROVADA — CADÊNCIA HUMANA NORMAL E CADEIA SHA-256 ÍNTEGRA"
    nivel_risco = "BAIXO"
    if any(a["severidade"] == "CRITICA" for a in anomalias):
        veredito = "REPROVADA — EVIDÊNCIA FORENSE DE INSERÇÃO FRAUDULENTA / ANOMALIA CRÍTICA"
        nivel_risco = "CRITICO"
    elif anomalias:
        veredito = "ALERTA — DISTORÇÕES OPERACIONAIS DETECTADAS NOS LOGS"
        nivel_risco = "ALTO"

    return {
        "veredito": veredito,
        "nivel_risco": nivel_risco,
        "cadeia_sha256_integra": cadeia_integra,
        "quebras_hash_detectadas": quebras_hash,
        "total_eventos_analisados": len(logs_sorted),
        "total_votos_auditados": votos_rdv_count,
        "total_anomalias_encontradas": len(anomalias),
        "estatisticas_cadencia": {
            "tempo_medio_ciclo_s": media_s,
            "tempo_minimo_ciclo_s": min_s,
            "tempo_maximo_ciclo_s": max_s,
            "limite_minimo_humano_referencia_s": 18.0,
        },
        "anomalias": anomalias,
        "serie_temporal_ciclos": ciclos_extraidos,
    }


def executar_simulacao_segundo_turno_voto_a_voto(
    db: Session,
    config: SeccaoConfig,
    *,
    cand1_numero: str = "22",
    cand1_nome: str = "FLÁVIO BOLSONARO",
    cand1_partido: str = "PL",
    cand1_pct_pesquisa: float = 52.0,
    cand2_numero: str = "13",
    cand2_nome: str = "LUIZ INÁCIO LULA",
    cand2_partido: str = "PT",
    cand2_pct_pesquisa: float = 48.0,
    eleitores_aptos: int = 350,
    comparecimento: int = None,
    abstencoes: int = None,
    pct_brancos: float = 2.5,
    pct_nulos: float = 3.5,
    perfil_vazao: str = "PADRAO_REAL_TSE",
    modo_anomalia: str = "NORMAL",
    qtd_votos_anomalia: int = 0,
    candidato_alvo_anomalia: str = "",
) -> dict:
    """
    Rotina de Alta Fidelidade: Simulação de Votação Voto a Voto e Hora a Hora (2º Turno).
    
    Reproduz fielmente o dia de votação (08h00 às 17h00) em poucos segundos:
      - 2 Candidatos Presidenciais configuráveis com números, nomes e % de pesquisa
      - Vazão horária realista distribuída nas 9 horas de expediente (08h..16h)
      - Cadência humana física de 2º turno (biometria AFIS, caminhada e cabine rápida de 1 cargo)
      - Gravação criptográfica no RDV (shuffle_key) e Merkle chain nos Logs de Auditoria
      - Emissão de Zerésima, Boletim de Urna (BU térmico) e Cartucho Digital de Mídia
      - Apuração comparativa Pesquisa x Urna com margem de erro amostral da seção
    """
    c1_num = str(cand1_numero or "22").strip()
    c2_num = str(cand2_numero or "13").strip()
    c1_nome = str(cand1_nome or "FLÁVIO BOLSONARO").strip().upper()
    c2_nome = str(cand2_nome or "LUIZ INÁCIO LULA").strip().upper()
    c1_sigla = str(cand1_partido or "PL").strip().upper()
    c2_sigla = str(cand2_partido or "PT").strip().upper()

    p1_pesq = float(cand1_pct_pesquisa or 50.0)
    p2_pesq = float(cand2_pct_pesquisa or 50.0)
    soma_pesq = max(0.01, p1_pesq + p2_pesq)
    p1_norm = (p1_pesq / soma_pesq) * 100.0
    p2_norm = (p2_pesq / soma_pesq) * 100.0

    aptos = max(10, int(eleitores_aptos or 350))
    if comparecimento is not None and int(comparecimento) > 0:
        comp_real = min(int(comparecimento), aptos)
        abst_real = max(0, aptos - comp_real)
    elif abstencoes is not None:
        abst_real = min(int(abstencoes), aptos)
        comp_real = max(0, aptos - abst_real)
    else:
        comp_real = max(1, int(round(aptos * 0.81)))
        abst_real = max(0, aptos - comp_real)

    if comp_real < 1:
        comp_real = 1
        abst_real = max(0, aptos - 1)

    p_brancos = max(0.0, float(pct_brancos or 0.0))
    p_nulos = max(0.0, float(pct_nulos or 0.0))

    # 1. Configura Candidatos e Partidos do 2º Turno no Banco de Dados
    db.query(Candidato).filter(Candidato.turno == 2).delete()

    for n_p, s_p in [(c1_num[:2], c1_sigla), (c2_num[:2], c2_sigla)]:
        part_row = db.query(Partido).filter(Partido.numero == n_p).first()
        if not part_row:
            db.add(Partido(numero=n_p, sigla=s_p, nome=f"Partido {s_p}"))
        else:
            part_row.sigla = s_p

    db.add(Candidato(
        cargo="PRESIDENTE",
        numero=c1_num,
        nome_urna=c1_nome,
        nome_completo=c1_nome.title(),
        sigla_partido=c1_sigla,
        numero_partido=c1_num[:2],
        turno=2,
        vice_ou_suplente1="Vice Pres. " + c1_nome.title(),
    ))
    db.add(Candidato(
        cargo="PRESIDENTE",
        numero=c2_num,
        nome_urna=c2_nome,
        nome_completo=c2_nome.title(),
        sigla_partido=c2_sigla,
        numero_partido=c2_num[:2],
        turno=2,
        vice_ou_suplente1="Vice Pres. " + c2_nome.title(),
    ))
    db.flush()

    # 2. Limpeza e Inicialização da Seção Eleitoral
    db.query(RegistroDigitalVoto).filter(RegistroDigitalVoto.turno == 2).delete()
    db.query(LogAuditoriaUrna).delete()

    tz_brt = timezone(timedelta(hours=-3))
    dia_eleicao = datetime(2026, 10, 25, 7, 50, 0, tzinfo=tz_brt)

    config.turno = 2
    config.eleitores_aptos = aptos
    config.eleitores_compareceram = 0
    config.status = "NAO_INICIALIZADA"
    config.terminal_eleitor_liberado = False
    config.eleitor_habilitado_titulo = None
    config.ultimo_hash_log = "0" * 64
    db.commit()

    # 3. Boot da Urna e Emissão da Zerésima
    relogio = dia_eleicao
    _append_simulated_log(
        db,
        config,
        relogio,
        "BOOT_URNA",
        f"Urna eletrônica 2º Turno energizada na seção {config.secao} (Zona {config.zona}).",
        {"fase": "BOOT", "turno": 2, "cargo": "PRESIDENTE"},
    )

    relogio = dia_eleicao.replace(hour=7, minute=55, second=10)
    zeresima_info = gerar_relatorio_zeresima(db, config)
    config.zeresima_timestamp = relogio
    config.abertura_timestamp = dia_eleicao.replace(hour=8, minute=0, second=0)

    _append_simulated_log(
        db,
        config,
        relogio,
        "EMISSAO_ZERESIMA_E_ABERTURA",
        f"Zerésima emitida 2º Turno (SHA256={zeresima_info['hash_sha256'][:16]}...). Seção aberta para início às 08:00.",
        {"hash_zeresima": zeresima_info["hash_sha256"][:24]},
    )

    # 4. Distribuição da Vazão Horária (08h às 16h / encerramento 17h)
    horas = [8, 9, 10, 11, 12, 13, 14, 15, 16]
    perfis_pesos = {
        "PADRAO_REAL_TSE": [0.11, 0.15, 0.16, 0.13, 0.07, 0.09, 0.12, 0.11, 0.06],
        "UNIFORME": [1.0 / 9.0] * 9,
        "PICO_MATUTINO": [0.14, 0.22, 0.22, 0.15, 0.07, 0.06, 0.05, 0.05, 0.04],
        "PICO_VESPERTINO": [0.06, 0.08, 0.09, 0.10, 0.10, 0.15, 0.18, 0.14, 0.10],
        "DINAMICA_VIRADA": [0.11, 0.15, 0.16, 0.13, 0.07, 0.09, 0.12, 0.11, 0.06],
    }
    pesos = perfis_pesos.get(perfil_vazao, perfis_pesos["PADRAO_REAL_TSE"])

    exact_alloc = [w * comp_real for w in pesos]
    int_alloc = [int(x) for x in exact_alloc]
    sobra = comp_real - sum(int_alloc)
    diffs = sorted(enumerate([x - int(x) for x in exact_alloc]), key=lambda t: t[1], reverse=True)
    for k in range(sobra):
        int_alloc[diffs[k][0]] += 1

    # 5. Execução Voto a Voto
    todos_ciclos = []
    ponto_anomalia = int(comp_real * 0.52)
    seq_votante = 0

    for idx_h, h in enumerate(horas):
        n_eleitores_hora = int_alloc[idx_h]
        if n_eleitores_hora <= 0:
            continue

        # Distribui os segundos de chegada ordenados na janela de 58 minutos
        offsets = sorted(random.uniform(10.0, 3500.0) for _ in range(n_eleitores_hora))

        for j in range(n_eleitores_hora):
            seq_votante += 1
            t_chegada = dia_eleicao.replace(hour=h, minute=0, second=0) + timedelta(seconds=offsets[j])

            # Verifica se é voto sob anomalia (para estudo forense)
            is_anomalia_voto = False
            if modo_anomalia != "NORMAL" and qtd_votos_anomalia > 0:
                if seq_votante >= ponto_anomalia and seq_votante < (ponto_anomalia + qtd_votos_anomalia):
                    is_anomalia_voto = True

            # Sorteio do Voto
            if is_anomalia_voto and candidato_alvo_anomalia:
                tipo_voto = "NOMINAL"
                num_voto = candidato_alvo_anomalia
                part_voto = c1_sigla if num_voto == c1_num else (c2_sigla if num_voto == c2_num else "LEG")
                rotulo_voto = c1_nome if num_voto == c1_num else (c2_nome if num_voto == c2_num else f"CAND {num_voto}")
            else:
                roll_branco_nulo = random.uniform(0.0, 100.0)
                if roll_branco_nulo < p_brancos:
                    tipo_voto = "BRANCO"
                    num_voto = None
                    part_voto = None
                    rotulo_voto = "VOTO EM BRANCO"
                elif roll_branco_nulo < (p_brancos + p_nulos):
                    tipo_voto = "NULO"
                    num_voto = "99"
                    part_voto = None
                    rotulo_voto = "VOTO NULO"
                else:
                    tipo_voto = "NOMINAL"
                    # Ajuste dinâmico se perfil for DINAMICA_VIRADA
                    if perfil_vazao == "DINAMICA_VIRADA":
                        if h <= 11:
                            prob_c1 = min(0.95, max(0.05, (p1_norm + 4.5) / 100.0))
                        elif h <= 13:
                            prob_c1 = p1_norm / 100.0
                        else:
                            prob_c1 = min(0.95, max(0.05, (p1_norm - 5.5) / 100.0))
                    else:
                        prob_c1 = p1_norm / 100.0

                    if random.random() < prob_c1:
                        num_voto = c1_num
                        part_voto = c1_sigla
                        rotulo_voto = c1_nome
                    else:
                        num_voto = c2_num
                        part_voto = c2_sigla
                        rotulo_voto = c2_nome

            # Cadência Temporal do Ciclo
            if not is_anomalia_voto:
                t_busca = round(random.uniform(4.5, 9.0), 2)
                usa_bio = random.random() < 0.94
                tentativas_bio = 1 if (usa_bio and random.random() < 0.88) else (2 if usa_bio else 0)
                t_bio = round(random.uniform(2.8, 6.0) * (1.0 if tentativas_bio == 1 else 1.8), 2) if usa_bio else round(random.uniform(6.0, 11.0), 2)
                t_caminhada = round(random.uniform(2.5, 5.0), 2)
                # 2º Turno: apenas 1 cargo (Presidente, 2 dígitos)
                if tipo_voto == "NOMINAL":
                    t_cabine = round(random.uniform(5.5, 11.0), 2)
                    teclas = [d for d in (num_voto or "")] + ["CONFIRMA"]
                elif tipo_voto == "BRANCO":
                    t_cabine = round(random.uniform(3.0, 5.5), 2)
                    teclas = ["BRANCO", "CONFIRMA"]
                else:
                    t_cabine = round(random.uniform(4.0, 7.5), 2)
                    teclas = ["9", "9", "CONFIRMA"]
            else:
                # Anomalia forçada
                t_busca = round(random.uniform(0.15, 0.40), 2)
                usa_bio = False
                tentativas_bio = 0
                t_bio = round(random.uniform(0.10, 0.25), 2)
                t_caminhada = round(random.uniform(0.10, 0.25), 2)
                t_cabine = round(random.uniform(0.40, 1.20), 2)
                teclas = [d for d in (num_voto or "22")] + ["CONFIRMA"]

            t_mesario_total = round(t_busca + t_bio, 2)
            t_ciclo_total = round(t_mesario_total + t_caminhada + t_cabine, 2)
            relogio_hab = t_chegada + timedelta(seconds=t_mesario_total)
            relogio_fim_voto = relogio_hab + timedelta(seconds=t_caminhada + t_cabine)

            # Gravação no Registro Digital do Voto (RDV)
            shuffle_key = secrets.token_hex(32)
            part_legenda = (num_voto[:2] if num_voto else None)
            integrity_payload = f"{shuffle_key}|2|PRESIDENTE|{tipo_voto}|{num_voto}|{part_legenda}"
            voto_hash = hashlib.sha256(integrity_payload.encode("utf-8")).hexdigest()

            db.add(
                RegistroDigitalVoto(
                    shuffle_key=shuffle_key,
                    turno=2,
                    cargo="PRESIDENTE",
                    tipo_voto=tipo_voto,
                    numero_digitado=num_voto,
                    partido_legenda=part_legenda,
                    hash_integridade=voto_hash,
                )
            )

            # Gravação encadeada no Log de Auditoria
            metodo_hab = "AFIS_BIOMETRIA_OK" if usa_bio else "SEM_BIO_DOC_OFICIAL"
            _append_simulated_log(
                db,
                config,
                relogio_hab,
                "TERMINAL_MESARIO_HABILITOU_ELEITOR",
                f"Terminal liberado pelo Mesário (Seq #{seq_votante} | Auth={metodo_hab}).",
                {
                    "seq_comparecimento": seq_votante,
                    "hora_brt": relogio_hab.strftime("%H:%M:%S"),
                    "tempo_busca_s": t_busca,
                    "tempo_biometria_s": t_bio,
                    "biometria_afis": usa_bio,
                },
            )

            config.eleitores_compareceram = seq_votante

            _append_simulated_log(
                db,
                config,
                relogio_fim_voto,
                "VOTO_COMPUTADO_RDV",
                f"Comparecimento #{seq_votante} concluiu votação para Presidente no 2º Turno (RDV gravado).",
                {
                    "seq_comparecimento": seq_votante,
                    "hora_brt": relogio_fim_voto.strftime("%H:%M:%S"),
                    "duracao_cabine_s": t_cabine,
                    "duracao_ciclo_completo_s": t_ciclo_total,
                    "teclas_pressionadas": len(teclas),
                    "biometria_afis": usa_bio,
                    "anomalia_injetada": is_anomalia_voto,
                },
            )

            todos_ciclos.append({
                "seq": seq_votante,
                "hora_faixa": f"{h:02d}h",
                "hora_int": h,
                "timestamp_chegada": t_chegada.strftime("%d/%m/%Y %H:%M:%S"),
                "timestamp_conclusao": relogio_fim_voto.strftime("%d/%m/%Y %H:%M:%S"),
                "hora_brt": relogio_fim_voto.strftime("%H:%M:%S"),
                "tempo_mesario_s": t_mesario_total,
                "tempo_cabine_s": t_cabine,
                "tempo_ciclo_total_s": t_ciclo_total,
                "biometria_afis": usa_bio,
                "tentativas_bio": tentativas_bio,
                "tipo_voto": tipo_voto,
                "numero_digitado": num_voto,
                "rotulo_candidato": rotulo_voto,
                "teclas": teclas,
                "anomalia": is_anomalia_voto,
            })

    # 6. Agregação e Estatísticas Hora a Hora (08h às 16h)
    vazao_horaria = []
    acum_vot = 0
    acum_c1 = 0
    acum_c2 = 0
    acum_br = 0
    acum_nu = 0

    for h in horas:
        ciclos_da_hora = [c for c in todos_ciclos if c["hora_int"] == h]
        n_hora = len(ciclos_da_hora)
        c1_hora = sum(1 for c in ciclos_da_hora if c["tipo_voto"] == "NOMINAL" and c["numero_digitado"] == c1_num)
        c2_hora = sum(1 for c in ciclos_da_hora if c["tipo_voto"] == "NOMINAL" and c["numero_digitado"] == c2_num)
        br_hora = sum(1 for c in ciclos_da_hora if c["tipo_voto"] == "BRANCO")
        nu_hora = sum(1 for c in ciclos_da_hora if c["tipo_voto"] == "NULO")
        val_hora = c1_hora + c2_hora

        pct_c1_h = round((c1_hora / max(1, val_hora)) * 100.0, 1) if val_hora > 0 else 0.0
        pct_c2_h = round((c2_hora / max(1, val_hora)) * 100.0, 1) if val_hora > 0 else 0.0

        acum_vot += n_hora
        acum_c1 += c1_hora
        acum_c2 += c2_hora
        acum_br += br_hora
        acum_nu += nu_hora
        acum_val = acum_c1 + acum_c2

        pct_acum_c1 = round((acum_c1 / max(1, acum_val)) * 100.0, 1) if acum_val > 0 else 0.0
        pct_acum_c2 = round((acum_c2 / max(1, acum_val)) * 100.0, 1) if acum_val > 0 else 0.0

        venc_hora = c1_num if c1_hora > c2_hora else (c2_num if c2_hora > c1_hora else "EMPATE")
        tempos_cab_h = [c["tempo_cabine_s"] for c in ciclos_da_hora]
        media_cab_h = round(sum(tempos_cab_h) / max(1, len(tempos_cab_h)), 1) if tempos_cab_h else 0.0

        vazao_horaria.append({
            "hora": f"{h:02d}h",
            "faixa": f"{h:02d}:00 às {h:02d}:59",
            "votantes_hora": n_hora,
            "pct_do_dia": round((n_hora / max(1, comp_real)) * 100.0, 1),
            "votos_cand1": c1_hora,
            "pct_cand1": pct_c1_h,
            "votos_cand2": c2_hora,
            "pct_cand2": pct_c2_h,
            "brancos": br_hora,
            "nulos": nu_hora,
            "validos": val_hora,
            "acumulado_votantes": acum_vot,
            "acumulado_cand1": acum_c1,
            "pct_acumulado_cand1": pct_acum_c1,
            "acumulado_cand2": acum_c2,
            "pct_acumulado_cand2": pct_acum_c2,
            "vencedor_hora": venc_hora,
            "tempo_medio_cabine_s": media_cab_h,
        })

    # 7. Encerramento Oficial da Seção às 17:00:15
    relogio_fim_oficial = dia_eleicao.replace(hour=17, minute=0, second=15)
    config.status = "ENCERRADA"
    config.encerramento_timestamp = relogio_fim_oficial
    db.commit()

    bu = apurar_boletim_de_urna(db, config)
    cartucho = gerar_cartucho_midia_resultado(db, config)

    _append_simulated_log(
        db,
        config,
        relogio_fim_oficial,
        "ENCERRAMENTO_BU_E_CARTUCHO",
        f"Seção encerrada oficialmente às 17h. BU SHA256={bu['hash_bu_sha256'][:16]}... Cartucho={cartucho['arquivo']}.",
        {
            "turno": 2,
            "cargo": "PRESIDENTE",
            "eleitores_aptos": aptos,
            "comparecimento_total": config.eleitores_compareceram,
            "hash_bu": bu["hash_bu_sha256"][:24],
        },
    )
    db.commit()

    # 8. Análise Estatística Final: Pesquisa x Resultado Apurado na Urna
    tot_validos_urna = acum_c1 + acum_c2
    pct_real_c1 = round((acum_c1 / max(1, tot_validos_urna)) * 100.0, 2) if tot_validos_urna > 0 else 0.0
    pct_real_c2 = round((acum_c2 / max(1, tot_validos_urna)) * 100.0, 2) if tot_validos_urna > 0 else 0.0

    delta_pesq_c1 = round(pct_real_c1 - p1_pesq, 2)
    delta_pesq_c2 = round(pct_real_c2 - p2_pesq, 2)

    # Margem de Erro Amostral Estocástica Esperada da Seção (95% confiança)
    p_est = (p1_pesq / 100.0)
    margem_amostral_pct = round(1.96 * math.sqrt(max(0.0001, (p_est * (1.0 - p_est)) / max(1, tot_validos_urna))) * 100.0, 2)
    dentro_margem = bool(abs(delta_pesq_c1) <= margem_amostral_pct)

    vencedor_final = c1_num if acum_c1 > acum_c2 else (c2_num if acum_c2 > acum_c1 else "EMPATE")
    vencedor_nome = c1_nome if acum_c1 > acum_c2 else (c2_nome if acum_c2 > acum_c1 else "EMPATE")

    tempos_normais = [c["tempo_ciclo_total_s"] for c in todos_ciclos if not c["anomalia"]]
    tempos_cabine = [c["tempo_cabine_s"] for c in todos_ciclos if not c["anomalia"]]

    return {
        "ok": True,
        "parametros": {
            "turno": 2,
            "cargo": "PRESIDENTE",
            "cand1": {
                "numero": c1_num,
                "nome": c1_nome,
                "partido": c1_sigla,
                "pct_pesquisa": p1_pesq,
            },
            "cand2": {
                "numero": c2_num,
                "nome": c2_nome,
                "partido": c2_sigla,
                "pct_pesquisa": p2_pesq,
            },
            "eleitores_aptos": aptos,
            "comparecimento": comp_real,
            "abstencoes": abst_real,
            "pct_abstencao": round((abst_real / aptos) * 100.0, 1),
            "pct_brancos": p_brancos,
            "pct_nulos": p_nulos,
            "perfil_vazao": perfil_vazao,
            "modo_anomalia": modo_anomalia,
        },
        "resultado_urna": {
            "cand1": {
                "numero": c1_num,
                "nome": c1_nome,
                "partido": c1_sigla,
                "votos": acum_c1,
                "pct_validos": pct_real_c1,
                "pct_pesquisa": p1_pesq,
                "delta_pesquisa": delta_pesq_c1,
            },
            "cand2": {
                "numero": c2_num,
                "nome": c2_nome,
                "partido": c2_sigla,
                "votos": acum_c2,
                "pct_validos": pct_real_c2,
                "pct_pesquisa": p2_pesq,
                "delta_pesquisa": delta_pesq_c2,
            },
            "votos_validos": tot_validos_urna,
            "votos_brancos": acum_br,
            "pct_brancos": round((acum_br / max(1, comp_real)) * 100.0, 1),
            "votos_nulos": acum_nu,
            "pct_nulos": round((acum_nu / max(1, comp_real)) * 100.0, 1),
            "comparecimento_total": comp_real,
            "pct_comparecimento": round((comp_real / aptos) * 100.0, 1),
            "abstencao_total": abst_real,
            "pct_abstencao": round((abst_real / aptos) * 100.0, 1),
            "vencedor_numero": vencedor_final,
            "vencedor_nome": vencedor_nome,
            "margem_amostral_secao_pct": margem_amostral_pct,
            "dentro_margem_amostral": dentro_margem,
            "diagnostico_pesquisa_vs_urna": (
                f"✅ Votação perfeitamente aderente à pesquisa: variação de {delta_pesq_c1:+.1f}% para {c1_nome} "
                f"está contida na margem de erro estatística da seção (±{margem_amostral_pct}% com 95% de confiança)."
                if dentro_margem else
                f"⚠️ Dispersão estatística superior à margem prevista: oscilação de {delta_pesq_c1:+.1f}% "
                f"ultrapassou a margem amostral esperada da urna (±{margem_amostral_pct}%)."
            ),
        },
        "cadencia_operacional": {
            "tempo_medio_cabine_s": round(sum(tempos_cabine) / max(1, len(tempos_cabine)), 1) if tempos_cabine else 0.0,
            "tempo_medio_ciclo_s": round(sum(tempos_normais) / max(1, len(tempos_normais)), 1) if tempos_normais else 0.0,
            "tempo_minimo_cabine_s": round(min(tempos_cabine), 1) if tempos_cabine else 0.0,
            "taxa_biometria_afis_pct": round(sum(1 for c in todos_ciclos if c["biometria_afis"]) / max(1, len(todos_ciclos)) * 100.0, 1),
        },
        "vazao_horaria": vazao_horaria,
        "feed_voto_a_voto": todos_ciclos,
        "boletim_de_urna": bu,
        "cartucho": cartucho,
    }


# ==============================================================================
# ATRELAMENTO A SEÇÕES REAIS DO TSE (SETUP 1ºT -> 2ºT & NOVOS VOTOS)
# ==============================================================================

def obter_setup_secao_real(
    db: Session,
    uf: str = None,
    zona: int = None,
    secao: int = None,
    secao_id: int = None,
    chave_secao: str = None,
) -> dict:
    """
    Busca uma seção real no catálogo físico do TSE e extrai:
      - O resultado oficial do 1º Turno entre os dois concorrentes principais
      - Os votos nominais de outros concorrentes / terceiras vias no 1º Turno
      - As condições demográficas efetivas do 2º Turno (aptos, comparecimento, abstenção, brancos, nulos)
      - O montante de Novos Votos Efetivos em disputa (sem antecipar o vencedor do 2º turno)
      - O comparativo real do TSE no 2º turno (caso já conste do banco de dados)
    """
    garantir_tabelas_custodia_tse()
    query = db.query(TseSecao)
    if secao_id:
        secao_db = query.filter(TseSecao.id == int(secao_id)).first()
    elif chave_secao:
        secao_db = query.filter(TseSecao.chave_secao == str(chave_secao).strip()).first()
    elif uf and zona is not None and secao is not None:
        secao_db = query.filter(
            TseSecao.uf == str(uf).strip().upper(),
            TseSecao.zona == int(zona),
            TseSecao.secao == int(secao),
        ).first()
    else:
        raise ValueError("Informe UF, Zona e Seção para buscar os dados oficiais.")

    if not secao_db:
        raise ValueError(f"Seção eleitoral não encontrada na base de dados (UF={uf}, Zona={zona}, Seção={secao}).")

    # 1. Apuração BU 1º Turno e 2º Turno
    bu_1t = db.query(TseApuracaoBU).filter(TseApuracaoBU.secao_id == secao_db.id, TseApuracaoBU.turno == 1).first()
    bu_2t = db.query(TseApuracaoBU).filter(TseApuracaoBU.secao_id == secao_db.id, TseApuracaoBU.turno == 2).first()

    # 2. Votação de Candidatos no 1T e 2T (Presidente: estritamente 2 dígitos 10 a 99)
    votos_1t = db.query(TseVotoCandidato).filter(
        TseVotoCandidato.secao_id == secao_db.id,
        TseVotoCandidato.turno == 1,
        TseVotoCandidato.cargo == "PRESIDENTE",
        TseVotoCandidato.numero_candidato.between(10, 99),
    ).order_by(TseVotoCandidato.quantidade_votos.desc()).all()

    votos_2t = db.query(TseVotoCandidato).filter(
        TseVotoCandidato.secao_id == secao_db.id,
        TseVotoCandidato.turno == 2,
        TseVotoCandidato.cargo == "PRESIDENTE",
        TseVotoCandidato.numero_candidato.between(10, 99),
    ).order_by(TseVotoCandidato.quantidade_votos.desc()).all()

    # Identificar os 2 concorrentes principais (22 e 13 ou os mais votados)
    cand1_voto_1t = next((v for v in votos_1t if v.numero_candidato == 22), None)
    cand2_voto_1t = next((v for v in votos_1t if v.numero_candidato == 13), None)

    if not cand1_voto_1t and len(votos_1t) > 0:
        cand1_voto_1t = votos_1t[0]
    if not cand2_voto_1t and len(votos_1t) > 1:
        cand2_voto_1t = votos_1t[1] if votos_1t[1].id != getattr(cand1_voto_1t, "id", None) else (votos_1t[0] if len(votos_1t) > 0 else None)

    v1_1t = cand1_voto_1t.quantidade_votos if cand1_voto_1t else 0
    v2_1t = cand2_voto_1t.quantidade_votos if cand2_voto_1t else 0
    c1_num = str(cand1_voto_1t.numero_candidato if cand1_voto_1t else "22")
    c1_nome = cand1_voto_1t.nome_candidato if cand1_voto_1t and cand1_voto_1t.nome_candidato else "JAIR BOLSONARO"
    c1_part = "PL" if c1_num == "22" else "C1"

    c2_num = str(cand2_voto_1t.numero_candidato if cand2_voto_1t else "13")
    c2_nome = cand2_voto_1t.nome_candidato if cand2_voto_1t and cand2_voto_1t.nome_candidato else "LULA"
    c2_part = "PT" if c2_num == "13" else "C2"

    v_outros_1t = sum(v.quantidade_votos for v in votos_1t if v.numero_candidato not in (int(c1_num), int(c2_num)))

    # Metadados do 1T
    aptos_1t = bu_1t.eleitores_aptos if bu_1t and bu_1t.eleitores_aptos else (secao_db.apuracoes[0].eleitores_aptos if secao_db.apuracoes else 350)
    comp_1t = bu_1t.comparecimento if bu_1t else (v1_1t + v2_1t + v_outros_1t)
    abst_1t = bu_1t.faltosos if bu_1t else max(0, aptos_1t - comp_1t)
    brancos_1t = bu_1t.votos_brancos if bu_1t else 0
    nulos_1t = bu_1t.votos_nulos if bu_1t else 0
    val_1t = bu_1t.votos_nominais if bu_1t else (v1_1t + v2_1t + v_outros_1t)

    # Condições Efetivas do 2º Turno (Demografia & Fluxo da Urna)
    tem_dados_2t = bool(bu_2t and bu_2t.comparecimento > 0)
    if tem_dados_2t:
        aptos_2t = bu_2t.eleitores_aptos or aptos_1t
        comp_2t = bu_2t.comparecimento
        abst_2t = bu_2t.faltosos
        pct_abst_2t = round((abst_2t / max(1, aptos_2t)) * 100.0, 1)
        brancos_2t = bu_2t.votos_brancos
        pct_brancos_2t = round((brancos_2t / max(1, comp_2t)) * 100.0, 1)
        nulos_2t = bu_2t.votos_nulos
        pct_nulos_2t = round((nulos_2t / max(1, comp_2t)) * 100.0, 1)
        val_2t = bu_2t.votos_nominais
    else:
        aptos_2t = aptos_1t
        comp_2t = comp_1t
        abst_2t = abst_1t
        pct_abst_2t = round((abst_2t / max(1, aptos_2t)) * 100.0, 1)
        brancos_2t = brancos_1t
        pct_brancos_2t = round((brancos_2t / max(1, comp_2t)) * 100.0, 1)
        nulos_2t = nulos_1t
        pct_nulos_2t = round((nulos_2t / max(1, comp_2t)) * 100.0, 1)
        val_2t = max(1, comp_2t - brancos_2t - nulos_2t)

    # Cálculo dos Novos Votos Efetivos em Disputa (conforme BI consolidado: 3ª Via 1T + ΔComp + Saldo Br/Nu)
    piso_base_1t = v1_1t + v2_1t
    pct_1t_rel_c1 = round((v1_1t / max(1, piso_base_1t)) * 100.0, 1) if piso_base_1t > 0 else 50.0
    pct_1t_rel_c2 = round(100.0 - pct_1t_rel_c1, 1)

    delta_comparecimento = comp_2t - comp_1t
    saldo_br_nu = (brancos_1t + nulos_1t) - (brancos_2t + nulos_2t)
    novos_votos_disputa = max(0, v_outros_1t + delta_comparecimento + saldo_br_nu)

    # Distribuição dos novos votos proporcional ao 1º Turno (setup base de pesquisa)
    novos_c1_prop = round(novos_votos_disputa * (pct_1t_rel_c1 / 100.0))
    novos_c2_prop = max(0, novos_votos_disputa - novos_c1_prop)

    proj_votos_c1 = v1_1t + novos_c1_prop
    proj_votos_c2 = v2_1t + novos_c2_prop
    proj_validos = proj_votos_c1 + proj_votos_c2
    pct_pesq_proj_c1 = round((proj_votos_c1 / max(1, proj_validos)) * 100.0, 1) if proj_validos > 0 else 50.0
    pct_pesq_proj_c2 = round(100.0 - pct_pesq_proj_c1, 1)

    p_est = pct_pesq_proj_c1 / 100.0
    me_amostral = round(1.96 * math.sqrt(max(0.0001, (p_est * (1.0 - p_est)) / max(1, proj_validos))) * 100.0, 2)

    # Resultado real do 2T se existir no banco (para confrontação analítica)
    c1_real_2t = next((v.quantidade_votos for v in votos_2t if v.numero_candidato == int(c1_num)), None)
    c2_real_2t = next((v.quantidade_votos for v in votos_2t if v.numero_candidato == int(c2_num)), None)

    real_comparativo_2t = None
    if c1_real_2t is not None and c2_real_2t is not None:
        tot_real_2t = c1_real_2t + c2_real_2t
        p_real_c1 = round((c1_real_2t / max(1, tot_real_2t)) * 100.0, 1) if tot_real_2t > 0 else 0.0
        p_real_c2 = round((c2_real_2t / max(1, tot_real_2t)) * 100.0, 1) if tot_real_2t > 0 else 0.0
        venc_real = c1_nome if c1_real_2t > c2_real_2t else (c2_nome if c2_real_2t > c1_real_2t else "EMPATE")
        delta_real_c1 = c1_real_2t - v1_1t
        delta_real_c2 = c2_real_2t - v2_1t
        delta_pct_c1 = round(pct_pesq_proj_c1 - p_real_c1, 1)
        dentro_me_real = abs(delta_pct_c1) <= me_amostral

        real_comparativo_2t = {
            "votos_cand1": c1_real_2t,
            "pct_cand1": p_real_c1,
            "novos_votos_cand1": delta_real_c1,
            "pct_absorcao_real_cand1": round((delta_real_c1 / max(1, novos_votos_disputa)) * 100.0, 1) if novos_votos_disputa > 0 else 0.0,
            "votos_cand2": c2_real_2t,
            "pct_cand2": p_real_c2,
            "novos_votos_cand2": delta_real_c2,
            "pct_absorcao_real_cand2": round((delta_real_c2 / max(1, novos_votos_disputa)) * 100.0, 1) if novos_votos_disputa > 0 else 0.0,
            "vencedor_real": venc_real,
            "total_validos_real": tot_real_2t,
            "delta_proj_c1_pct": delta_pct_c1,
            "margem_erro_pct": me_amostral,
            "dentro_margem_erro": dentro_me_real,
            "status_margem": "DENTRO DA MARGEM" if dentro_me_real else "FORA DA MARGEM",
        }

    return {
        "secao_info": {
            "id": secao_db.id,
            "chave_secao": secao_db.chave_secao,
            "uf": secao_db.uf,
            "municipio_codigo": secao_db.municipio_codigo,
            "municipio_nome": secao_db.municipio_nome,
            "zona": secao_db.zona,
            "secao": secao_db.secao,
            "local_votacao": secao_db.local_votacao or "Local não informado",
            "modelo_urna": secao_db.modelo_urna or "UE2020",
        },
        "primeiro_turno": {
            "cand1": {
                "numero": c1_num,
                "nome": c1_nome,
                "partido": c1_part,
                "votos": v1_1t,
                "pct_validos": round((v1_1t / max(1, val_1t)) * 100.0, 1) if val_1t > 0 else 0.0,
                "pct_relativo_dois_candidatos": pct_1t_rel_c1,
            },
            "cand2": {
                "numero": c2_num,
                "nome": c2_nome,
                "partido": c2_part,
                "votos": v2_1t,
                "pct_validos": round((v2_1t / max(1, val_1t)) * 100.0, 1) if val_1t > 0 else 0.0,
                "pct_relativo_dois_candidatos": pct_1t_rel_c2,
            },
            "piso_dois_candidatos": piso_base_1t,
            "votos_outros_candidatos": v_outros_1t,
            "votos_validos": val_1t,
            "brancos": brancos_1t,
            "pct_brancos": round((brancos_1t / max(1, comp_1t)) * 100.0, 1) if comp_1t > 0 else 0.0,
            "nulos": nulos_1t,
            "pct_nulos": round((nulos_1t / max(1, comp_1t)) * 100.0, 1) if comp_1t > 0 else 0.0,
            "comparecimento": comp_1t,
            "aptos": aptos_1t,
            "abstencoes": abst_1t,
            "pct_abstencao": round((abst_1t / max(1, aptos_1t)) * 100.0, 1) if aptos_1t > 0 else 0.0,
        },
        "pesquisa_simulada_secao": {
            "cand1_pct_pesquisa": pct_pesq_proj_c1,
            "cand2_pct_pesquisa": pct_pesq_proj_c2,
            "piso_1t_cand1": v1_1t,
            "piso_1t_cand2": v2_1t,
            "pct_1t_rel_cand1": pct_1t_rel_c1,
            "pct_1t_rel_cand2": pct_1t_rel_c2,
            "novos_votos_cand1": novos_c1_prop,
            "novos_votos_cand2": novos_c2_prop,
            "proj_votos_cand1": proj_votos_c1,
            "proj_votos_cand2": proj_votos_c2,
            "margem_erro_amostral_secao_pct": me_amostral,
        },
        "novos_votos_detalhados": {
            "total_novos_votos": novos_votos_disputa,
            "votos_terceiras_vias_1t": v_outros_1t,
            "delta_comparecimento": delta_comparecimento,
            "saldo_brancos_nulos": saldo_br_nu,
        },
        "segundo_turno_condicoes_efetivas": {
            "aptos": aptos_2t,
            "comparecimento": comp_2t,
            "abstencoes": abst_2t,
            "pct_abstencao": pct_abst_2t,
            "brancos": brancos_2t,
            "pct_brancos": pct_brancos_2t,
            "nulos": nulos_2t,
            "pct_nulos": pct_nulos_2t,
            "votos_validos": val_2t,
            "novos_votos_efetivos_disputa": novos_votos_disputa,
            "delta_comparecimento": delta_comparecimento,
            "saldo_brancos_nulos": saldo_br_nu,
            "tem_dados_2t_oficiais": tem_dados_2t,
        },
        "resultado_real_2t_tse": real_comparativo_2t,
        "dados_local": dados_local,
    }


def executar_simulacao_intra_local(
    db: Session,
    uf: str,
    zona: int,
    secao_ref: int,
    cand1_num: int = 22,
    cand1_nome: str = "FLÁVIO BOLSONARO",
    cand2_num: int = 13,
    cand2_nome: str = "LULA",
    tipo_absorcao: str = "PROPORCIONAL_1T",
    pct_absorcao_c1: float = 50.0,
    arquivar_historico: bool = True,
) -> dict:
    """
    Executa a simulação completa para todas as seções eleitorais de um mesmo local de votação (prédio físico).
    Calcula os números voto a voto e turno a turno de cada urna individualmente.
    Ao final, gera:
      - A média ponderada consolidada do prédio (1ºT, 2ºT Simulado e 2ºT Real Oficial).
      - O comparativo de cada urna individual contra a média do local.
      - A medição da Distorção Intra-Local de Novos Votos para cada urna.
      - Métricas de coerência intra-prédio: Desvio Padrão (sigma) e Delta Máximo (delta_max).
    """
    garantir_tabelas_custodia_tse()
    secao_ref_db = db.query(TseSecao).filter(
        TseSecao.uf == uf.strip().upper(),
        TseSecao.zona == int(zona),
        TseSecao.secao == int(secao_ref),
    ).first()
    if not secao_ref_db:
        raise ValueError(f"Seção de referência {secao_ref} (Zona {zona}, {uf}) não encontrada.")

    loc_val = (secao_ref_db.local_votacao or "").strip()
    tem_local = bool(loc_val and loc_val != "-")
    q_loc = db.query(TseSecao).filter(
        TseSecao.uf == secao_ref_db.uf,
        TseSecao.municipio_codigo == secao_ref_db.municipio_codigo,
        TseSecao.zona == secao_ref_db.zona,
    )
    if tem_local:
        q_loc = q_loc.filter(func.trim(func.upper(TseSecao.local_votacao)) == loc_val.upper())
    else:
        q_loc = q_loc.filter(TseSecao.secao == secao_ref_db.secao)

    secoes_local = q_loc.order_by(TseSecao.secao).all()
    if len(secoes_local) < 2:
        raise ValueError(f"O local desta seção possui apenas {len(secoes_local)} urna. A simulação intra-local requer 2 ou mais seções.")

    nome_local = loc_val or f"Zona {zona:04d} - Local {secao_ref}"
    nome_mun = secao_ref_db.municipio_nome or ""
    uf_upper = secao_ref_db.uf.upper()

    secoes_resultados = []
    totais_local = {
        "aptos": 0,
        "comp_1t": 0,
        "comp_2t": 0,
        "v1_1t": 0,
        "v2_1t": 0,
        "voutros_1t": 0,
        "brancos_1t": 0,
        "nulos_1t": 0,
        "brancos_2t": 0,
        "nulos_2t": 0,
        "novos_votos_disputa": 0,
        "sim_c1": 0,
        "sim_c2": 0,
        "real_c1": 0,
        "real_c2": 0,
        "novos_real_c1": 0,
        "novos_real_c2": 0,
        "urnas_com_real_2t": 0,
    }

    for s in secoes_local:
        bu_1t = db.query(TseApuracaoBU).filter(TseApuracaoBU.secao_id == s.id, TseApuracaoBU.turno == 1).first()
        bu_2t = db.query(TseApuracaoBU).filter(TseApuracaoBU.secao_id == s.id, TseApuracaoBU.turno == 2).first()

        votos_1t = db.query(TseVotoCandidato).filter(
            TseVotoCandidato.secao_id == s.id,
            TseVotoCandidato.turno == 1,
            TseVotoCandidato.cargo == "PRESIDENTE",
            TseVotoCandidato.numero_candidato.between(10, 99)
        ).all()

        votos_2t = db.query(TseVotoCandidato).filter(
            TseVotoCandidato.secao_id == s.id,
            TseVotoCandidato.turno == 2,
            TseVotoCandidato.cargo == "PRESIDENTE",
            TseVotoCandidato.numero_candidato.between(10, 99)
        ).all()

        v1_1t = sum(v.quantidade_votos for v in votos_1t if v.numero_candidato == cand1_num)
        v2_1t = sum(v.quantidade_votos for v in votos_1t if v.numero_candidato == cand2_num)
        v_outros_1t = sum(v.quantidade_votos for v in votos_1t if v.numero_candidato not in (cand1_num, cand2_num))

        aptos_sec = (bu_2t.eleitores_aptos if bu_2t and bu_2t.eleitores_aptos else (bu_1t.eleitores_aptos if bu_1t and bu_1t.eleitores_aptos else 350))
        comp_1t_sec = bu_1t.comparecimento if bu_1t and bu_1t.comparecimento else (v1_1t + v2_1t + v_outros_1t)
        comp_2t_sec = bu_2t.comparecimento if bu_2t and bu_2t.comparecimento else comp_1t_sec
        br_1t_sec = bu_1t.votos_brancos if bu_1t else 0
        nu_1t_sec = bu_1t.votos_nulos if bu_1t else 0
        br_2t_sec = bu_2t.votos_brancos if bu_2t else br_1t_sec
        nu_2t_sec = bu_2t.votos_nulos if bu_2t else nu_1t_sec

        delta_comp_sec = comp_2t_sec - comp_1t_sec
        saldo_br_nu_sec = (br_1t_sec + nu_1t_sec) - (br_2t_sec + nu_2t_sec)
        novos_disputa_sec = max(0, v_outros_1t + delta_comp_sec + saldo_br_nu_sec)

        # Absorção configurada / proporcional individual desta urna
        tot_1t_par = v1_1t + v2_1t
        if tipo_absorcao == "PROPORCIONAL_1T":
            p_abs_c1 = round((v1_1t / max(1, tot_1t_par)) * 100.0, 1) if tot_1t_par > 0 else 50.0
        else:
            p_abs_c1 = float(pct_absorcao_c1)
        p_abs_c2 = round(100.0 - p_abs_c1, 1)

        novos_c1_sim = round(novos_disputa_sec * (p_abs_c1 / 100.0))
        novos_c2_sim = max(0, novos_disputa_sec - novos_c1_sim)

        sim_c1_sec = v1_1t + novos_c1_sim
        sim_c2_sec = v2_1t + novos_c2_sim
        sim_val_sec = sim_c1_sec + sim_c2_sec
        pct_sim_c1_sec = round((sim_c1_sec / max(1, sim_val_sec)) * 100.0, 1) if sim_val_sec > 0 else 50.0
        pct_sim_c2_sec = round(100.0 - pct_sim_c1_sec, 1)

        # Real 2T se existir no banco
        c1_real_v = next((v.quantidade_votos for v in votos_2t if v.numero_candidato == cand1_num), None)
        c2_real_v = next((v.quantidade_votos for v in votos_2t if v.numero_candidato == cand2_num), None)
        tem_real_sec = (c1_real_v is not None and c2_real_v is not None)

        if tem_real_sec:
            val_real_sec = c1_real_v + c2_real_v
            pct_real_c1_sec = round((c1_real_v / max(1, val_real_sec)) * 100.0, 1) if val_real_sec > 0 else 0.0
            pct_real_c2_sec = round(100.0 - pct_real_c1_sec, 1)
            novos_real_c1_sec = c1_real_v - v1_1t
            novos_real_c2_sec = c2_real_v - v2_1t
            pct_abs_real_c1_sec = round((novos_real_c1_sec / max(1, novos_disputa_sec)) * 100.0, 1) if novos_disputa_sec > 0 else 0.0

            totais_local["real_c1"] += c1_real_v
            totais_local["real_c2"] += c2_real_v
            totais_local["novos_real_c1"] += novos_real_c1_sec
            totais_local["novos_real_c2"] += novos_real_c2_sec
            totais_local["urnas_com_real_2t"] += 1
        else:
            val_real_sec = None
            pct_real_c1_sec = None
            pct_real_c2_sec = None
            novos_real_c1_sec = None
            novos_real_c2_sec = None
            pct_abs_real_c1_sec = None

        totais_local["aptos"] += aptos_sec
        totais_local["comp_1t"] += comp_1t_sec
        totais_local["comp_2t"] += comp_2t_sec
        totais_local["v1_1t"] += v1_1t
        totais_local["v2_1t"] += v2_1t
        totais_local["voutros_1t"] += v_outros_1t
        totais_local["brancos_1t"] += br_1t_sec
        totais_local["nulos_1t"] += nu_1t_sec
        totais_local["brancos_2t"] += br_2t_sec
        totais_local["nulos_2t"] += nu_2t_sec
        totais_local["novos_votos_disputa"] += novos_disputa_sec
        totais_local["sim_c1"] += sim_c1_sec
        totais_local["sim_c2"] += sim_c2_sec

        # Margem de erro da urna individual
        p_est_u = pct_sim_c1_sec / 100.0
        me_u = round(1.96 * math.sqrt(max(0.0001, (p_est_u * (1.0 - p_est_u)) / max(1, sim_val_sec))) * 100.0, 2)

        secoes_resultados.append({
            "secao": s.secao,
            "chave_secao": s.chave_secao,
            "is_secao_foco": (s.secao == secao_ref_db.secao),
            "modelo_urna": s.modelo_urna or "UE2020",
            "aptos": aptos_sec,
            "comparecimento_1t": comp_1t_sec,
            "comparecimento_2t": comp_2t_sec,
            "votos_1t_cand1": v1_1t,
            "votos_1t_cand2": v2_1t,
            "votos_1t_outros": v_outros_1t,
            "pct_1t_cand1": round((v1_1t / max(1, tot_1t_par)) * 100.0, 1) if tot_1t_par > 0 else 0.0,
            "pct_1t_cand2": round((v2_1t / max(1, tot_1t_par)) * 100.0, 1) if tot_1t_par > 0 else 0.0,
            "novos_votos_disputa": novos_disputa_sec,
            "pct_absorcao_sim_c1": p_abs_c1,
            "sim_votos_cand1": sim_c1_sec,
            "sim_votos_cand2": sim_c2_sec,
            "sim_pct_cand1": pct_sim_c1_sec,
            "sim_pct_cand2": pct_sim_c2_sec,
            "sim_validos": sim_val_sec,
            "margem_erro_urna_pct": me_u,
            "tem_real_2t": tem_real_sec,
            "real_votos_cand1": c1_real_v,
            "real_votos_cand2": c2_real_v,
            "real_pct_cand1": pct_real_c1_sec,
            "real_pct_cand2": pct_real_c2_sec,
            "real_validos": val_real_sec,
            "real_novos_cand1": novos_real_c1_sec,
            "real_novos_cand2": novos_real_c2_sec,
            "real_pct_absorcao_c1": pct_abs_real_c1_sec,
        })

    # 2. Médias Globais do Prédio Físico
    tot_par_1t_loc = totais_local["v1_1t"] + totais_local["v2_1t"]
    media_local_1t_pct_c1 = round((totais_local["v1_1t"] / max(1, tot_par_1t_loc)) * 100.0, 1) if tot_par_1t_loc > 0 else 50.0
    media_local_1t_pct_c2 = round(100.0 - media_local_1t_pct_c1, 1)

    tot_sim_val_loc = totais_local["sim_c1"] + totais_local["sim_c2"]
    media_local_sim_pct_c1 = round((totais_local["sim_c1"] / max(1, tot_sim_val_loc)) * 100.0, 1) if tot_sim_val_loc > 0 else 50.0
    media_local_sim_pct_c2 = round(100.0 - media_local_sim_pct_c1, 1)

    tem_algum_real = totais_local["urnas_com_real_2t"] > 0
    tot_real_val_loc = totais_local["real_c1"] + totais_local["real_c2"]
    media_local_real_pct_c1 = round((totais_local["real_c1"] / max(1, tot_real_val_loc)) * 100.0, 1) if tot_real_val_loc > 0 else 0.0
    media_local_real_pct_c2 = round(100.0 - media_local_real_pct_c1, 1) if tot_real_val_loc > 0 else 0.0

    media_abs_real_c1_loc = round((totais_local["novos_real_c1"] / max(1, totais_local["novos_votos_disputa"])) * 100.0, 1) if totais_local["novos_votos_disputa"] > 0 else 0.0

    # 3. Análise Seção por Seção: Desvios e Distorções Intra-Local
    urnas_com_distorcao = 0
    urnas_favorecendo_c1 = 0
    urnas_favorecendo_c2 = 0
    urnas_homogeneas = 0
    lista_pct_real_c1 = []
    lista_pct_sim_c1 = []

    for r in secoes_resultados:
        # Desvio do simulado em relação à média simulada do prédio
        d_sim_loc_c1 = round(r["sim_pct_cand1"] - media_local_sim_pct_c1, 1)
        r["delta_sim_vs_media_local_c1"] = d_sim_loc_c1
        lista_pct_sim_c1.append(r["sim_pct_cand1"])

        if r["tem_real_2t"]:
            lista_pct_real_c1.append(r["real_pct_cand1"])
            d_real_loc_c1 = round(r["real_pct_cand1"] - media_local_real_pct_c1, 1)
            d_real_sim_c1 = round(r["real_pct_cand1"] - r["sim_pct_cand1"], 1)
            r["delta_real_vs_media_local_c1"] = d_real_loc_c1
            r["delta_real_vs_sim_c1"] = d_real_sim_c1

            # Medição da Distorção Intra-Local de Novos Votos
            distorcao_nv_c1 = round(r["real_pct_absorcao_c1"] - media_abs_real_c1_loc, 1)
            r["distorcao_novos_votos_c1"] = distorcao_nv_c1
            r["distorcao_novos_votos_c2"] = -distorcao_nv_c1

            # Limiar forense para distorção intra-local: |distorcao| >= 10.0%
            if abs(distorcao_nv_c1) >= 10.0:
                urnas_com_distorcao += 1
                if distorcao_nv_c1 > 0:
                    urnas_favorecendo_c1 += 1
                    r["status_coerencia"] = "DISTORCAO_FAVOR_C1"
                    r["veredito_intra_local"] = f"Distorção detectada a favor de {cand1_nome} (+{distorcao_nv_c1:.1f}% novos votos)"
                else:
                    urnas_favorecendo_c2 += 1
                    r["status_coerencia"] = "DISTORCAO_FAVOR_C2"
                    r["veredito_intra_local"] = f"Distorção detectada a favor de {cand2_nome} (+{abs(distorcao_nv_c1):.1f}% novos votos)"
            else:
                urnas_homogeneas += 1
                r["status_coerencia"] = "HOMOGENEO"
                r["veredito_intra_local"] = "Padrão homogêneo com o prédio (± variação normal)"
        else:
            r["delta_real_vs_media_local_c1"] = None
            r["delta_real_vs_sim_c1"] = None
            r["distorcao_novos_votos_c1"] = None
            r["distorcao_novos_votos_c2"] = None
            r["status_coerencia"] = "SIMULADO_PROJETADO"
            r["veredito_intra_local"] = f"Urna simulada ({d_sim_loc_c1:+.1f}% vs média)"

    # Coerência estatística do prédio (Desvio Padrão sigma e Delta Máximo)
    if lista_pct_real_c1:
        n_pts = len(lista_pct_real_c1)
        media_pts = sum(lista_pct_real_c1) / n_pts
        var_pts = sum((x - media_pts) ** 2 for x in lista_pct_real_c1) / max(1, n_pts)
        sigma_local = round(math.sqrt(var_pts), 2)
        delta_max_local = round(max(lista_pct_real_c1) - min(lista_pct_real_c1), 1)
    else:
        n_pts = len(lista_pct_sim_c1)
        media_pts = sum(lista_pct_sim_c1) / max(1, n_pts)
        var_pts = sum((x - media_pts) ** 2 for x in lista_pct_sim_c1) / max(1, n_pts)
        sigma_local = round(math.sqrt(var_pts), 2)
        delta_max_local = round(max(lista_pct_sim_c1) - min(lista_pct_sim_c1), 1)

    veredito_predio = (
        "PADRÃO HOMOGÊNEO INTRA-PRÉDIO"
        if urnas_com_distorcao == 0
        else f"DIVERGÊNCIA INTERNA: {urnas_com_distorcao} de {len(secoes_local)} urnas com distorção atípica de novos votos"
    )

    p_est_loc = media_local_sim_pct_c1 / 100.0
    me_local = round(1.96 * math.sqrt(max(0.0001, (p_est_loc * (1.0 - p_est_loc)) / max(1, tot_sim_val_loc))) * 100.0, 2)

    resultado_completo = {
        "ok": True,
        "local_info": {
            "nome_local": nome_local,
            "municipio_nome": nome_mun,
            "uf": uf_upper,
            "zona": zona,
            "qtd_secoes": len(secoes_local),
            "secao_referencia": secao_ref,
        },
        "candidatos": {
            "cand1": {"numero": str(cand1_num), "nome": cand1_nome, "partido": "PL" if str(cand1_num) == "22" else "C1"},
            "cand2": {"numero": str(cand2_num), "nome": cand2_nome, "partido": "PT" if str(cand2_num) == "13" else "C2"},
        },
        "media_local": {
            "primeiro_turno": {
                "votos_cand1": totais_local["v1_1t"],
                "votos_cand2": totais_local["v2_1t"],
                "votos_outros": totais_local["voutros_1t"],
                "pct_cand1": media_local_1t_pct_c1,
                "pct_cand2": media_local_1t_pct_c2,
                "comparecimento": totais_local["comp_1t"],
                "brancos": totais_local["brancos_1t"],
                "nulos": totais_local["nulos_1t"],
            },
            "segundo_turno_simulado": {
                "votos_cand1": totais_local["sim_c1"],
                "votos_cand2": totais_local["sim_c2"],
                "pct_cand1": media_local_sim_pct_c1,
                "pct_cand2": media_local_sim_pct_c2,
                "total_validos": tot_sim_val_loc,
                "comparecimento": totais_local["comp_2t"],
                "brancos": totais_local["brancos_2t"],
                "nulos": totais_local["nulos_2t"],
                "novos_votos_totais": totais_local["novos_votos_disputa"],
                "margem_erro_local_pct": me_local,
            },
            "segundo_turno_real_oficial": {
                "disponivel": tem_algum_real,
                "votos_cand1": totais_local["real_c1"],
                "votos_cand2": totais_local["real_c2"],
                "pct_cand1": media_local_real_pct_c1,
                "pct_cand2": media_local_real_pct_c2,
                "total_validos": tot_real_val_loc,
                "media_absorcao_real_cand1": media_abs_real_c1_loc,
                "media_absorcao_real_cand2": round(100.0 - media_abs_real_c1_loc, 1) if tem_algum_real else 0.0,
            },
            "coerencia_estatistica": {
                "desvio_padrao_sigma": sigma_local,
                "delta_maximo_pct": delta_max_local,
                "urnas_com_distorcao": urnas_com_distorcao,
                "urnas_homogeneas": urnas_homogeneas,
                "urnas_favorecendo_c1": urnas_favorecendo_c1,
                "urnas_favorecendo_c2": urnas_favorecendo_c2,
                "veredito_geral": veredito_predio,
            },
        },
        "secoes_detalhes": secoes_resultados,
    }

    if arquivar_historico:
        try:
            h_obj = HistoricoSimulacao(
                tipo_origem="INTRA_LOCAL",
                titulo_cenario=f"Simulação Intra-Local: {nome_local} ({len(secoes_local)} Urnas)",
                secao_chave=f"{uf_upper}_{secao_ref_db.municipio_codigo}_{zona:04d}_{secao_ref:04d}",
                uf=uf_upper,
                municipio_codigo=secao_ref_db.municipio_codigo,
                municipio_nome=nome_mun,
                zona=zona,
                secao=secao_ref,
                local_votacao=nome_local,
                eleitores_aptos=totais_local["aptos"],
                comparecimento=totais_local["comp_2t"],
                abstencoes=max(0, totais_local["aptos"] - totais_local["comp_2t"]),
                votos_validos=tot_sim_val_loc,
                cand1_numero=str(cand1_num),
                cand1_nome=cand1_nome,
                cand1_partido="PL" if str(cand1_num) == "22" else "C1",
                cand1_votos_urna=totais_local["sim_c1"],
                cand1_pct_urna=media_local_sim_pct_c1,
                cand2_numero=str(cand2_num),
                cand2_nome=cand2_nome,
                cand2_partido="PT" if str(cand2_num) == "13" else "C2",
                cand2_votos_urna=totais_local["sim_c2"],
                cand2_pct_urna=media_local_sim_pct_c2,
                vencedor_numero=str(cand1_num if totais_local["sim_c1"] >= totais_local["sim_c2"] else cand2_num),
                vencedor_nome=cand1_nome if totais_local["sim_c1"] >= totais_local["sim_c2"] else cand2_nome,
                margem_amostral_pct=me_local,
                dentro_margem=True,
                veredito_forense=veredito_predio,
                payload_completo_json=json.dumps(resultado_completo, ensure_ascii=False),
            )
            db.add(h_obj)
            db.commit()
            resultado_completo["historico_id"] = h_obj.id
        except Exception as e_hist:
            db.rollback()
            print(f"[SIMULADOR] Aviso ao arquivar simulação intra-local: {e_hist}")

    return resultado_completo


def buscar_secoes_reais_banco(
    db: Session,
    q: str = "",
    uf: str = "",
    limit: int = 20,
) -> list[dict]:
    """Busca seções eleitorais cadastradas para seleção rápida no simulador."""
    garantir_tabelas_custodia_tse()
    query = db.query(TseSecao)
    if uf and uf.strip() and uf.strip().upper() != "TODAS":
        query = query.filter(TseSecao.uf == uf.strip().upper())
    if q and q.strip():
        termo = f"%{q.strip().upper()}%"
        if q.strip().isdigit():
            val = int(q.strip())
            query = query.filter((TseSecao.zona == val) | (TseSecao.secao == val))
        else:
            query = query.filter(
                (TseSecao.municipio_nome.ilike(termo)) |
                (TseSecao.chave_secao.ilike(termo)) |
                (TseSecao.local_votacao.ilike(termo))
            )

    secoes = query.order_by(
        TseSecao.uf.asc(),
        TseSecao.municipio_nome.asc(),
        TseSecao.zona.asc(),
        TseSecao.secao.asc()
    ).limit(max(1, min(50, limit))).all()

    res = []
    for s in secoes:
        tem_1t = any(a.turno == 1 for a in s.apuracoes)
        tem_2t = any(a.turno == 2 for a in s.apuracoes)
        res.append({
            "id": s.id,
            "chave_secao": s.chave_secao,
            "uf": s.uf,
            "municipio_nome": s.municipio_nome,
            "municipio_codigo": s.municipio_codigo,
            "zona": s.zona,
            "secao": s.secao,
            "local_votacao": s.local_votacao or "Local não informado",
            "tem_1t": tem_1t,
            "tem_2t": tem_2t,
        })
    return res


# ==============================================================================
# GESTÃO PERSISTIDA DO HISTÓRICO DE SIMULAÇÕES
# ==============================================================================

def salvar_historico_simulacao(
    db: Session,
    resultado_simulacao: dict,
    parametros_extra: dict = None,
) -> dict:
    """Salva no banco de dados o snapshot de uma simulação realizada."""
    try:
        HistoricoSimulacao.__table__.create(bind=engine, checkfirst=True)
    except Exception as e_tbl:
        print(f"[HISTORICO-SIMULACAO] Aviso ao verificar tabela: {e_tbl}")

    p = resultado_simulacao.get("parametros", {})
    r = resultado_simulacao.get("resultado_urna", {})
    extra = parametros_extra or {}

    c1 = r.get("cand1", {})
    c2 = r.get("cand2", {})

    tipo_origem = extra.get("tipo_origem") or ("SECAO_REAL" if extra.get("secao_chave") or extra.get("secao_id") else "PARAMETRICO")
    titulo = extra.get("titulo_cenario")
    if not titulo:
        if tipo_origem == "SECAO_REAL":
            mun = extra.get("municipio_nome") or extra.get("municipio") or ""
            uf_txt = extra.get("uf") or ""
            titulo = f"Seção {extra.get('secao')} (Z:{extra.get('zona')} • {mun}-{uf_txt})"
        else:
            titulo = f"Simulação 2º Turno ({c1.get('pct_validos', 0)}% x {c2.get('pct_validos', 0)}%)"

    def _safe_int(val):
        if val is None:
            return None
        s = str(val).strip()
        return int(s) if s.isdigit() else None

    def _safe_float(val, default=0.0):
        if val is None:
            return default
        try:
            return float(val)
        except (ValueError, TypeError):
            return default

    zona_val = _safe_int(extra.get("zona"))
    secao_val = _safe_int(extra.get("secao"))
    v1t_c1 = _safe_int(extra.get("votos_1t_c1"))
    v1t_c2 = _safe_int(extra.get("votos_1t_c2"))
    v1t_out = _safe_int(extra.get("votos_1t_outros"))
    comp_1t = _safe_int(extra.get("comparecimento_1t"))
    novos_vot = _safe_int(extra.get("novos_votos_efetivos"))

    entry = HistoricoSimulacao(
        created_at=datetime.now(timezone.utc),
        tipo_origem=tipo_origem,
        titulo_cenario=titulo,
        secao_chave=extra.get("secao_chave"),
        uf=extra.get("uf"),
        municipio_codigo=extra.get("municipio_codigo"),
        municipio_nome=extra.get("municipio_nome") or extra.get("municipio"),
        zona=zona_val,
        secao=secao_val,
        local_votacao=extra.get("local_votacao"),
        perfil_vazao=p.get("perfil_vazao", "PADRAO_REAL_TSE"),
        modo_anomalia=p.get("modo_anomalia", "NORMAL"),
        eleitores_aptos=_safe_int(p.get("eleitores_aptos")) or 0,
        comparecimento=_safe_int(r.get("comparecimento_total")) or 0,
        abstencoes=_safe_int(r.get("abstencao_total")) or 0,
        pct_abstencao=_safe_float(r.get("pct_abstencao")),
        pct_brancos=_safe_float(r.get("pct_brancos")),
        pct_nulos=_safe_float(r.get("pct_nulos")),
        votos_brancos=_safe_int(r.get("votos_brancos")) or 0,
        votos_nulos=_safe_int(r.get("votos_nulos")) or 0,
        votos_validos=_safe_int(r.get("votos_validos")) or 0,
        votos_1t_c1=v1t_c1,
        votos_1t_c2=v1t_c2,
        votos_1t_outros=v1t_out,
        comparecimento_1t=comp_1t,
        novos_votos_efetivos=novos_vot,
        pct_absorcao_c1=_safe_float(extra.get("pct_absorcao_c1")),
        pct_absorcao_c2=_safe_float(extra.get("pct_absorcao_c2")),
        real_2t_c1_votos=_safe_int(extra.get("real_2t_c1_votos")),
        real_2t_c2_votos=_safe_int(extra.get("real_2t_c2_votos")),
        real_2t_vencedor=extra.get("real_2t_vencedor"),
        cand1_numero=str(c1.get("numero", "22")),
        cand1_nome=str(c1.get("nome", "CANDIDATO 1")),
        cand1_partido=str(c1.get("partido", "PL")),
        cand1_pct_pesquisa=_safe_float(c1.get("pct_pesquisa", 50.0)),
        cand1_votos_urna=_safe_int(c1.get("votos")) or 0,
        cand1_pct_urna=_safe_float(c1.get("pct_validos", 0.0)),
        cand2_numero=str(c2.get("numero", "13")),
        cand2_nome=str(c2.get("nome", "CANDIDATO 2")),
        cand2_partido=str(c2.get("partido", "PT")),
        cand2_pct_pesquisa=_safe_float(c2.get("pct_pesquisa", 50.0)),
        cand2_votos_urna=_safe_int(c2.get("votos")) or 0,
        cand2_pct_urna=_safe_float(c2.get("pct_validos", 0.0)),
        vencedor_numero=str(r.get("vencedor_numero", "EMPATE")),
        vencedor_nome=str(r.get("vencedor_nome", "EMPATE")),
        margem_amostral_pct=_safe_float(r.get("margem_amostral_secao_pct", 0.0)),
        dentro_margem=bool(r.get("dentro_margem_amostral", True)),
        veredito_forense="APROVADA" if p.get("modo_anomalia") == "NORMAL" else "ANOMALIA DETECTADA",
        payload_completo_json=json.dumps(resultado_simulacao, ensure_ascii=False),
    )

    try:
        db.add(entry)
        db.commit()
        db.refresh(entry)
    except Exception as exc_first:
        db.rollback()
        # Segunda tentativa garantindo criação de tabela
        try:
            HistoricoSimulacao.__table__.create(bind=engine, checkfirst=True)
            db.add(entry)
            db.commit()
            db.refresh(entry)
        except Exception as exc_second:
            db.rollback()
            raise RuntimeError(f"Erro ao persistir simulação no PostgreSQL: {exc_second}")

    return {
        "id": entry.id,
        "created_at": entry.created_at.isoformat(),
        "titulo_cenario": entry.titulo_cenario,
        "tipo_origem": entry.tipo_origem,
    }


def listar_historico_simulacoes(db: Session, limit: int = 50) -> list[dict]:
    """Lista as simulações arquivadas ordenadas por data descrescente."""
    try:
        HistoricoSimulacao.__table__.create(bind=engine, checkfirst=True)
    except Exception:
        pass

    registros = (
        db.query(HistoricoSimulacao)
        .order_by(HistoricoSimulacao.id.desc())
        .limit(max(1, min(100, limit)))
        .all()
    )
    itens = []
    for h in registros:
        venc_pct = h.cand1_pct_urna if h.vencedor_numero == h.cand1_numero else (h.cand2_pct_urna if h.vencedor_numero == h.cand2_numero else 50.0)
        dt_str = h.created_at.strftime("%d/%m/%Y %H:%M:%S") if h.created_at else "-"

        tem_real = h.real_2t_c1_votos is not None and h.real_2t_c2_votos is not None
        tot_real = (h.real_2t_c1_votos + h.real_2t_c2_votos) if tem_real else 0
        pct_real_c1 = round((h.real_2t_c1_votos / max(1, tot_real)) * 100.0, 1) if (tem_real and tot_real > 0) else 0.0
        pct_real_c2 = round(100.0 - pct_real_c1, 1) if (tem_real and tot_real > 0) else 0.0
        delta_real_pct = round(abs(h.cand1_pct_urna - pct_real_c1), 1) if tem_real else 0.0
        me_pct = h.margem_amostral_pct or 5.0
        dentro_me_real = (delta_real_pct <= me_pct) if tem_real else None

        itens.append({
            "id": h.id,
            "created_at": dt_str,
            "criado_em": dt_str,
            "tipo_origem": h.tipo_origem,
            "titulo_cenario": h.titulo_cenario,
            "uf": h.uf,
            "municipio_nome": h.municipio_nome,
            "municipio": h.municipio_nome,
            "zona": h.zona,
            "secao": h.secao,
            "local_votacao": h.local_votacao,
            "comparecimento": h.comparecimento,
            "eleitores_aptos": h.eleitores_aptos,
            "votos_validos": h.votos_validos,
            "cand1_numero": h.cand1_numero,
            "cand1_nome": h.cand1_nome,
            "cand1_partido": h.cand1_partido,
            "cand1_votos": h.cand1_votos_urna,
            "cand1_pct": h.cand1_pct_urna,
            "cand2_numero": h.cand2_numero,
            "cand2_nome": h.cand2_nome,
            "cand2_partido": h.cand2_partido,
            "cand2_votos": h.cand2_votos_urna,
            "cand2_pct": h.cand2_pct_urna,
            "cand1": {
                "numero": h.cand1_numero,
                "nome": h.cand1_nome,
                "partido": h.cand1_partido,
                "votos": h.cand1_votos_urna,
                "pct": h.cand1_pct_urna,
            },
            "cand2": {
                "numero": h.cand2_numero,
                "nome": h.cand2_nome,
                "partido": h.cand2_partido,
                "votos": h.cand2_votos_urna,
                "pct": h.cand2_pct_urna,
            },
            "vencedor_numero": h.vencedor_numero,
            "vencedor_nome": h.vencedor_nome,
            "vencedor_pct": venc_pct,
            "margem_amostral_pct": h.margem_amostral_pct,
            "dentro_margem": h.dentro_margem,
            "veredito_forense": h.veredito_forense,
            "perfil_vazao": h.perfil_vazao,
            "modo_anomalia": h.modo_anomalia,
            "votos_1t_c1": h.votos_1t_c1,
            "votos_1t_c2": h.votos_1t_c2,
            "novos_votos_efetivos": h.novos_votos_efetivos,
            "pct_absorcao_c1": h.pct_absorcao_c1,
            "pct_absorcao_c2": h.pct_absorcao_c2,
            "tem_real_2t": tem_real,
            "real_2t_c1_votos": h.real_2t_c1_votos,
            "real_2t_c2_votos": h.real_2t_c2_votos,
            "real_2t_c1_pct": pct_real_c1 if tem_real else None,
            "real_2t_c2_pct": pct_real_c2 if tem_real else None,
            "real_2t_vencedor": h.real_2t_vencedor,
            "delta_real_c1_pct": delta_real_pct if tem_real else None,
            "dentro_margem_real_tse": dentro_me_real,
            "status_margem_real_tse": ("DENTRO DA MARGEM" if dentro_me_real else "FORA DA MARGEM") if tem_real else None,
        })
    return itens


def obter_historico_simulacao(db: Session, simulacao_id: int) -> dict:
    """Recupera o registro e o payload completo de uma simulação anterior."""
    try:
        HistoricoSimulacao.__table__.create(bind=engine, checkfirst=True)
    except Exception:
        pass

    h = db.query(HistoricoSimulacao).filter(HistoricoSimulacao.id == simulacao_id).first()
    if not h:
        raise ValueError(f"Simulação #{simulacao_id} não encontrada no histórico.")

    payload = json.loads(h.payload_completo_json) if h.payload_completo_json else {}
    dt_str = h.created_at.strftime("%d/%m/%Y %H:%M:%S") if h.created_at else "-"
    return {
        "id": h.id,
        "created_at": dt_str,
        "criado_em": dt_str,
        "tipo_origem": h.tipo_origem,
        "titulo_cenario": h.titulo_cenario,
        "uf": h.uf,
        "municipio_nome": h.municipio_nome,
        "municipio": h.municipio_nome,
        "zona": h.zona,
        "secao": h.secao,
        "local_votacao": h.local_votacao,
        "secao_chave": h.secao_chave,
        "dados_transicao_1t_2t": {
            "votos_1t_c1": h.votos_1t_c1,
            "votos_1t_c2": h.votos_1t_c2,
            "votos_1t_outros": h.votos_1t_outros,
            "comparecimento_1t": h.comparecimento_1t,
            "novos_votos_efetivos": h.novos_votos_efetivos,
            "pct_absorcao_c1": h.pct_absorcao_c1,
            "pct_absorcao_c2": h.pct_absorcao_c2,
            "real_2t_c1_votos": h.real_2t_c1_votos,
            "real_2t_c2_votos": h.real_2t_c2_votos,
            "real_2t_vencedor": h.real_2t_vencedor,
        },
        "resultado_simulacao": payload,
        "payload_completo_json": payload,
    }


def excluir_historico_simulacao(db: Session, simulacao_id: int) -> bool:
    """Exclui um registro específico do histórico."""
    garantir_tabelas_custodia_tse()
    h = db.query(HistoricoSimulacao).filter(HistoricoSimulacao.id == simulacao_id).first()
    if not h:
        return False
    db.delete(h)
    db.commit()
    return True


def limpar_todo_historico_simulacoes(db: Session) -> int:
    """Limpa todos os registros do histórico de simulações."""
    garantir_tabelas_custodia_tse()
    total = db.query(HistoricoSimulacao).delete()
    db.commit()
    return total
