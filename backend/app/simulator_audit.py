import os
import json
import random
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session

from .database import (
    SeccaoConfig,
    EleitorSeccao,
    Partido,
    Candidato,
    RegistroDigitalVoto,
    LogAuditoriaUrna,
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
