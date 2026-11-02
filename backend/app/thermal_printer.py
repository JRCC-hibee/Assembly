import hashlib
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from .database import SeccaoConfig, Candidato, Partido, RegistroDigitalVoto
from .election_engine import get_cargos_por_turno


def gerar_relatorio_zeresima(db: Session, config: SeccaoConfig) -> dict:
    """
    Emite a Zerésima Oficial da Seção Eleitoral, comprovando que existem 0 votos
    computados para todos os candidatos e cargos antes da abertura da urna.
    """
    total_votos = db.query(RegistroDigitalVoto).filter(RegistroDigitalVoto.turno == config.turno).count()
    if total_votos > 0:
        raise ValueError("Violação de Zerésima: A urna já possui votos registrados neste turno!")

    cargos = get_cargos_por_turno(config.turno)
    candidatos = (
        db.query(Candidato)
        .filter(Candidato.turno == config.turno)
        .order_by(Candidato.cargo, Candidato.numero)
        .all()
    )

    now = datetime.now(timezone.utc)
    config.zeresima_timestamp = now
    config.abertura_timestamp = now
    config.status = "EM_VOTACAO"
    db.commit()

    linhas = [
        "================================================",
        "           JUSTICA ELEITORAL DO BRASIL          ",
        "       RELATORIO DE ZERESIMA DA SECAO (TSE)     ",
        "================================================",
        f"MUNICIPIO : {config.municipio}",
        f"ZONA      : {config.zona}      SECAO: {config.secao}",
        f"TURNO     : {config.turno}o TURNO NACIONAL",
        f"EMISSAO   : {now.strftime('%d/%m/%Y %H:%M:%S')} UTC",
        f"APTOS     : {config.eleitores_aptos}",
        "------------------------------------------------",
        "COMPROVACAO DE ZERAGEM ANTES DA VOTACAO:",
    ]

    for c_meta in cargos:
        linhas.append(f"\n>>> CARGO: {c_meta['titulo'].upper()}")
        cands_cargo = [c for c in candidatos if c.cargo == c_meta["codigo"]]
        for cand in cands_cargo:
            linhas.append(f"  {cand.numero.ljust(6)} {cand.nome_urna[:22].ljust(22)} ({cand.sigla_partido}) : 0000")
        linhas.append("  VOTOS EM BRANCO                       : 0000")
        linhas.append("  VOTOS NULOS                           : 0000")

    payload_assinatura = "\n".join(linhas)
    assinatura_sha256 = hashlib.sha256(payload_assinatura.encode("utf-8")).hexdigest().upper()

    linhas.extend([
        "------------------------------------------------",
        "TOTAL GERAL DE VOTOS COMPUTADOS NA URNA : 0000",
        "------------------------------------------------",
        "ASSINATURA DIGITAL SHA-256 DA ZERESIMA:",
        assinatura_sha256[:32],
        assinatura_sha256[32:],
        "================================================",
        "     PRESIDENTE DA MESA / MESARIOS / FISCAIS    ",
        "================================================",
    ])

    return {
        "tipo": "ZERESIMA",
        "timestamp": now.isoformat(),
        "hash_sha256": assinatura_sha256,
        "cupom_termico": "\n".join(linhas),
    }


def apurar_boletim_de_urna(db: Session, config: SeccaoConfig) -> dict:
    """
    Calcula a totalização completa da Seção e formata o Boletim de Urna (BU)
    em estilo bobina térmica de 48 colunas + estrutura JSON para o Cartucho.
    """
    cargos = get_cargos_por_turno(config.turno)
    votos = db.query(RegistroDigitalVoto).filter(RegistroDigitalVoto.turno == config.turno).all()
    candidatos = (
        db.query(Candidato)
        .filter(Candidato.turno == config.turno)
        .order_by(Candidato.numero)
        .all()
    )
    partidos = db.query(Partido).order_by(Partido.numero).all()

    now = config.encerramento_timestamp or datetime.now(timezone.utc)
    faltosos = max(0, config.eleitores_aptos - config.eleitores_compareceram)

    resumo_cargos = []
    linhas = [
        "================================================",
        "           JUSTICA ELEITORAL DO BRASIL          ",
        "             BOLETIM DE URNA (BU)               ",
        "================================================",
        f"MUNICIPIO      : {config.municipio}",
        f"ZONA ELEITORAL : {config.zona}       SECAO: {config.secao}",
        f"ELEICAO GERAL  : {config.turno}o TURNO NACIONAL",
        f"ENCERRAMENTO   : {now.strftime('%d/%m/%Y %H:%M:%S')} UTC",
        "------------------------------------------------",
        f"ELEITORES APTOS         : {str(config.eleitores_aptos).rjust(6)}",
        f"COMPARECIMENTO          : {str(config.eleitores_compareceram).rjust(6)}",
        f"ELEITORES FALTOSOS      : {str(faltosos).rjust(6)}",
        "================================================",
    ]

    for c_meta in cargos:
        cod = c_meta["codigo"]
        votos_cargo = [v for v in votos if v.cargo == cod]
        cands_cargo = [c for c in candidatos if c.cargo == cod]

        contagem_nominal = {}
        for cand in cands_cargo:
            contagem_nominal[cand.numero] = 0

        contagem_legenda = {p.numero: 0 for p in partidos}
        brancos = 0
        nulos = 0

        for v in votos_cargo:
            if v.tipo_voto == "NOMINAL" and v.numero_digitado in contagem_nominal:
                contagem_nominal[v.numero_digitado] += 1
            elif v.tipo_voto == "LEGENDA" and v.partido_legenda in contagem_legenda:
                contagem_legenda[v.partido_legenda] += 1
            elif v.tipo_voto == "BRANCO":
                brancos += 1
            else:
                nulos += 1

        total_nominais = sum(contagem_nominal.values())
        total_legenda = sum(contagem_legenda.values())
        total_validos = total_nominais + total_legenda
        total_apurado = total_validos + brancos + nulos

        linhas.append(f"\n>>> CARGO: {c_meta['titulo'].upper()}")
        linhas.append("------------------------------------------------")
        linhas.append("NUM   CANDIDATO / PARTIDO                  VOTOS")
        linhas.append("------------------------------------------------")

        lista_candidatos_bu = []
        for cand in cands_cargo:
            qtd = contagem_nominal.get(cand.numero, 0)
            pct = (qtd / total_validos * 100.0) if total_validos > 0 else 0.0
            linhas.append(
                f"{cand.numero.ljust(5)} {cand.nome_urna[:22].ljust(22)} ({cand.sigla_partido[:4].ljust(4)}) {str(qtd).rjust(6)}"
            )
            lista_candidatos_bu.append({
                "numero": cand.numero,
                "nome_urna": cand.nome_urna,
                "sigla_partido": cand.sigla_partido,
                "votos": qtd,
                "percentual_validos": round(pct, 2),
            })

        lista_legendas_bu = []
        if c_meta["permite_legenda"]:
            linhas.append("  --- VOTOS DE LEGENDA ---                      ")
            for p in partidos:
                qtd_leg = contagem_legenda.get(p.numero, 0)
                if qtd_leg > 0:
                    linhas.append(f"  {p.numero}  LEGENDA {p.sigla.ljust(26)} {str(qtd_leg).rjust(6)}")
                lista_legendas_bu.append({"numero_partido": p.numero, "sigla": p.sigla, "votos_legenda": qtd_leg})

        linhas.extend([
            "------------------------------------------------",
            f"VOTOS NOMINAIS          : {str(total_nominais).rjust(6)}",
            f"VOTOS DE LEGENDA        : {str(total_legenda).rjust(6)}",
            f"TOTAL DE VOTOS VALIDOS  : {str(total_validos).rjust(6)}",
            f"VOTOS EM BRANCO         : {str(brancos).rjust(6)}",
            f"VOTOS NULOS             : {str(nulos).rjust(6)}",
            f"TOTAL APURADO NO CARGO  : {str(total_apurado).rjust(6)}",
            "------------------------------------------------",
        ])

        resumo_cargos.append({
            "cargo": cod,
            "titulo": c_meta["titulo"],
            "votos_nominais": total_nominais,
            "votos_legenda": total_legenda,
            "votos_validos": total_validos,
            "votos_brancos": brancos,
            "votos_nulos": nulos,
            "total_apurado": total_apurado,
            "candidatos": lista_candidatos_bu,
            "legendas": lista_legendas_bu,
        })

    corpo_bu = "\n".join(linhas)
    hash_bu = hashlib.sha256(corpo_bu.encode("utf-8")).hexdigest().upper()

    qr_payload = f"TSE-BU|Z:{config.zona}|S:{config.secao}|T:{config.turno}|APT:{config.eleitores_aptos}|CMP:{config.eleitores_compareceram}|HASH:{hash_bu[:24]}"

    linhas.extend([
        "\n================================================",
        "CODIGO DE AUTENTICACAO DO BOLETIM DE URNA (SHA256)",
        hash_bu[:32],
        hash_bu[32:],
        "------------------------------------------------",
        "QRPAYLOAD DE CONFERENCIA PUBLICA:",
        qr_payload,
        "================================================",
        "              FIM DO BOLETIM DE URNA            ",
        "================================================",
    ])

    return {
        "zona": config.zona,
        "secao": config.secao,
        "municipio": config.municipio,
        "turno": config.turno,
        "eleitores_aptos": config.eleitores_aptos,
        "comparecimento": config.eleitores_compareceram,
        "faltosos": faltosos,
        "encerramento_utc": now.isoformat(),
        "hash_bu_sha256": hash_bu,
        "qr_payload": qr_payload,
        "cargos": resumo_cargos,
        "cupom_termico": "\n".join(linhas),
    }
