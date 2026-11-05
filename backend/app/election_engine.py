import hashlib
import secrets
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from .database import (
    SeccaoConfig,
    EleitorSeccao,
    Partido,
    Candidato,
    RegistroDigitalVoto,
    LogAuditoriaUrna,
)

# Definição Oficial dos Cargos por Turno na Eleição Geral Brasileira
CARGOS_TURNO_1 = [
    {"codigo": "DEPUTADO_FEDERAL", "titulo": "Deputado Federal", "digitos": 4, "permite_legenda": True},
    {"codigo": "DEPUTADO_ESTADUAL", "titulo": "Deputado Estadual", "digitos": 5, "permite_legenda": True},
    {"codigo": "SENADOR", "titulo": "Senador", "digitos": 3, "permite_legenda": False},
    {"codigo": "GOVERNADOR", "titulo": "Governador", "digitos": 2, "permite_legenda": False},
    {"codigo": "PRESIDENTE", "titulo": "Presidente", "digitos": 2, "permite_legenda": False},
]

CARGOS_TURNO_2 = [
    {"codigo": "GOVERNADOR", "titulo": "Governador", "digitos": 2, "permite_legenda": False},
    {"codigo": "PRESIDENTE", "titulo": "Presidente", "digitos": 2, "permite_legenda": False},
]


def get_cargos_por_turno(turno: int):
    return CARGOS_TURNO_2 if turno == 2 else CARGOS_TURNO_1


def registrar_log_encadeado(db: Session, config: SeccaoConfig, evento: str, detalhes: str):
    ts_iso = datetime.now(timezone.utc).isoformat()
    payload = f"{config.ultimo_hash_log}|{ts_iso}|{evento}|{detalhes}"
    novo_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

    entry = LogAuditoriaUrna(
        evento=evento,
        detalhes=detalhes,
        hash_anterior=config.ultimo_hash_log,
        hash_atual=novo_hash,
    )
    config.ultimo_hash_log = novo_hash
    db.add(entry)
    db.commit()
    return entry


def get_or_create_seccao(db: Session) -> SeccaoConfig:
    config = db.query(SeccaoConfig).first()
    if not config:
        config = SeccaoConfig()
        db.add(config)
        db.commit()
        db.refresh(config)
        registrar_log_encadeado(db, config, "BOOT_URNA", "Urna energizada na seção eleitoral.")
    return config


def seed_default_voters(db: Session):
    """Popula o Caderno de Votação da Seção (Terminal do Mesário) com eleitores e templates biométricos."""
    if db.query(EleitorSeccao).count() > 0:
        return

    eleitores_demo = [
        (
            "014285930116",
            "123.456.789-01",
            "JOÃO CARLOS DA SILVA",
            "14/05/1984",
            "MARIA APARECIDA DA SILVA",
            True,
        ),
        (
            "029384750124",
            "234.567.890-12",
            "ANA PAULA FERREIRA ROCHA",
            "22/09/1991",
            "VERA LÚCIA FERREIRA",
            True,
        ),
        (
            "038475610132",
            "345.678.901-23",
            "MARCOS VINÍCIUS SANTOS",
            "03/11/1978",
            "HELENA PEREIRA SANTOS",
            True,
        ),
        (
            "047586920140",
            "456.789.012-34",
            "CAMILA MENDES OLIVEIRA",
            "19/02/1998",
            "SANDRA REGINA MENDES",
            True,
        ),
        (
            "056192830159",
            "567.890.123-45",
            "ANTÔNIO JOSÉ NOGUEIRA",
            "08/07/1955",
            "FRANCISCA ALVES NOGUEIRA",
            False,  # Sem biometria cadastrada (exige liberação com código do mesário)
        ),
    ]

    for titulo, cpf, nome, nasc, mae, bio in eleitores_demo:
        bio_hash = hashlib.sha256(f"BIO-TSE|{titulo}|{cpf}".encode("utf-8")).hexdigest()
        db.add(
            EleitorSeccao(
                titulo=titulo,
                cpf=cpf,
                nome=nome,
                data_nascimento=nasc,
                nome_mae=mae,
                biometria_cadastrada=bio,
                hash_template_biometrico=bio_hash,
            )
        )
    db.commit()


def seed_default_candidates(db: Session):
    """Popula partidos, candidatos de demonstração e caderno de eleitores."""
    seed_default_voters(db)

    if db.query(Partido).count() > 0:
        return

    partidos_demo = [
        Partido(numero="10", sigla="PRB", nome="Partido Republicano Brasileiro Demo"),
        Partido(numero="13", sigla="PTD", nome="Partido Trabalhista Democrático Demo"),
        Partido(numero="22", sigla="PLD", nome="Partido Liberal Democrático Demo"),
        Partido(numero="45", sigla="PSD", nome="Partido Social Democrata Demo"),
        Partido(numero="55", sigla="PUD", nome="Partido União Digital Demo"),
    ]
    db.add_all(partidos_demo)

    candidatos_demo = [
        # 1º Turno - Deputado Federal (4 dígitos)
        Candidato(cargo="DEPUTADO_FEDERAL", numero="1010", nome_urna="CARLOS ALMEIDA", nome_completo="Carlos Eduardo Almeida", sigla_partido="PRB", numero_partido="10", turno=1),
        Candidato(cargo="DEPUTADO_FEDERAL", numero="1313", nome_urna="MARIA FERNANDA", nome_completo="Maria Fernanda Souza", sigla_partido="PTD", numero_partido="13", turno=1),
        Candidato(cargo="DEPUTADO_FEDERAL", numero="2222", nome_urna="ROBERTO SANTOS", nome_completo="Roberto Santos Lima", sigla_partido="PLD", numero_partido="22", turno=1),
        # 1º Turno - Deputado Estadual (5 dígitos)
        Candidato(cargo="DEPUTADO_ESTADUAL", numero="10123", nome_urna="DR. HENRIQUE", nome_completo="Henrique Vasconcelos", sigla_partido="PRB", numero_partido="10", turno=1),
        Candidato(cargo="DEPUTADO_ESTADUAL", numero="13456", nome_urna="PROFESSORA LUCIA", nome_completo="Lúcia Helena Martins", sigla_partido="PTD", numero_partido="13", turno=1),
        Candidato(cargo="DEPUTADO_ESTADUAL", numero="22333", nome_urna="CAPITÃO MARCOS", nome_completo="Marcos Vinícius Oliveira", sigla_partido="PLD", numero_partido="22", turno=1),
        # 1º Turno - Senador (3 dígitos)
        Candidato(cargo="SENADOR", numero="100", nome_urna="SENADOR OTÁVIO", nome_completo="Otávio Augusto Medeiros", sigla_partido="PRB", numero_partido="10", vice_ou_suplente1="1º Sup: Ana Clara", suplente2="2º Sup: João Pedro", turno=1),
        Candidato(cargo="SENADOR", numero="133", nome_urna="BEATRIZ ROCHA", nome_completo="Beatriz Rocha Cavalcanti", sigla_partido="PTD", numero_partido="13", vice_ou_suplente1="1º Sup: Paulo Sérgio", suplente2="2º Sup: Helena Costa", turno=1),
        Candidato(cargo="SENADOR", numero="222", nome_urna="RICARDO NOGUEIRA", nome_completo="Ricardo Nogueira Filho", sigla_partido="PLD", numero_partido="22", vice_ou_suplente1="1º Sup: Cláudio Silva", suplente2="2º Sup: Sandra Luz", turno=1),
        # 1º Turno - Governador (2 dígitos)
        Candidato(cargo="GOVERNADOR", numero="10", nome_urna="TARCÍSIO MENDES", nome_completo="Tarcísio Mendes Prado", sigla_partido="PRB", numero_partido="10", vice_ou_suplente1="Vice: Celso Arantes", turno=1),
        Candidato(cargo="GOVERNADOR", numero="13", nome_urna="FERNANDO CASTRO", nome_completo="Fernando Castro Neto", sigla_partido="PTD", numero_partido="13", vice_ou_suplente1="Vice: Marina Alves", turno=1),
        Candidato(cargo="GOVERNADOR", numero="45", nome_urna="RODRIGO GARCIA", nome_completo="Rodrigo Garcia Lopes", sigla_partido="PSD", numero_partido="45", vice_ou_suplente1="Vice: Geninho Silva", turno=1),
        # 1º Turno - Presidente (2 dígitos)
        Candidato(cargo="PRESIDENTE", numero="13", nome_urna="LUIZ INÁCIO", nome_completo="Luiz Inácio Demo", sigla_partido="PTD", numero_partido="13", vice_ou_suplente1="Vice: Geraldo José", turno=1),
        Candidato(cargo="PRESIDENTE", numero="22", nome_urna="FLÁVIO BOLSONARO", nome_completo="Flávio Bolsonaro", sigla_partido="PLD", numero_partido="22", vice_ou_suplente1="Vice: Walter Braga", turno=1),
        Candidato(cargo="PRESIDENTE", numero="45", nome_urna="SIMONE TEBET", nome_completo="Simone Nassar Demo", sigla_partido="PSD", numero_partido="45", vice_ou_suplente1="Vice: Mara Gabrilli", turno=1),
        # 2º Turno - Governador e Presidente
        Candidato(cargo="GOVERNADOR", numero="10", nome_urna="TARCÍSIO MENDES", nome_completo="Tarcísio Mendes Prado", sigla_partido="PRB", numero_partido="10", vice_ou_suplente1="Vice: Celso Arantes", turno=2),
        Candidato(cargo="GOVERNADOR", numero="13", nome_urna="FERNANDO CASTRO", nome_completo="Fernando Castro Neto", sigla_partido="PTD", numero_partido="13", vice_ou_suplente1="Vice: Marina Alves", turno=2),
        Candidato(cargo="PRESIDENTE", numero="13", nome_urna="LUIZ INÁCIO", nome_completo="Luiz Inácio Demo", sigla_partido="PTD", numero_partido="13", vice_ou_suplente1="Vice: Geraldo José", turno=2),
        Candidato(cargo="PRESIDENTE", numero="22", nome_urna="FLÁVIO BOLSONARO", nome_completo="Flávio Bolsonaro", sigla_partido="PLD", numero_partido="22", vice_ou_suplente1="Vice: Walter Braga", turno=2),
    ]
    db.add_all(candidatos_demo)
    db.commit()


def consultar_digitos_urna(db: Session, turno: int, cargo: str, numero_digitado: str):
    """
    Simula a validação instantânea da Urna Eletrônica enquanto o eleitor digita os números.
    """
    prefixo_partido = numero_digitado[:2] if len(numero_digitado) >= 2 else ""
    partido = None
    if len(prefixo_partido) == 2:
        partido = db.query(Partido).filter(Partido.numero == prefixo_partido).first()

    candidato = (
        db.query(Candidato)
        .filter(
            Candidato.cargo == cargo,
            Candidato.numero == numero_digitado,
            Candidato.turno == turno,
        )
        .first()
    )

    cargo_meta = next((c for c in get_cargos_por_turno(turno) if c["codigo"] == cargo), None)
    max_digitos = cargo_meta["digitos"] if cargo_meta else 2
    permite_legenda = cargo_meta["permite_legenda"] if cargo_meta else False

    if candidato and len(numero_digitado) == max_digitos:
        return {
            "tipo": "NOMINAL",
            "valido": True,
            "candidato": {
                "numero": candidato.numero,
                "nome_urna": candidato.nome_urna,
                "sigla_partido": candidato.sigla_partido,
                "vice_ou_suplente1": candidato.vice_ou_suplente1,
                "suplente2": candidato.suplente2,
            },
            "partido": {"numero": partido.numero, "sigla": partido.sigla, "nome": partido.nome} if partido else None,
        }

    if permite_legenda and len(numero_digitado) >= 2 and partido and not candidato:
        return {
            "tipo": "LEGENDA" if len(numero_digitado) == 2 else "LEGENDA_CANDIDATO_INEXISTENTE",
            "valido": True,
            "candidato": None,
            "partido": {"numero": partido.numero, "sigla": partido.sigla, "nome": partido.nome},
            "mensagem": "VOTO NA LEGENDA",
        }

    if len(numero_digitado) >= 2 and not partido:
        return {
            "tipo": "NULO",
            "valido": False,
            "candidato": None,
            "partido": None,
            "mensagem": "NÚMERO ERRADO — VOTO NULO",
        }

    if len(numero_digitado) == max_digitos and not candidato:
        return {
            "tipo": "NULO",
            "valido": False,
            "candidato": None,
            "partido": {"numero": partido.numero, "sigla": partido.sigla, "nome": partido.nome} if partido else None,
            "mensagem": "CANDIDATO INEXISTENTE — VOTO NULO",
        }

    return {
        "tipo": "DIGITANDO",
        "valido": True,
        "candidato": None,
        "partido": {"numero": partido.numero, "sigla": partido.sigla, "nome": partido.nome} if partido else None,
    }


def computar_cesta_votos_eleitor(db: Session, config: SeccaoConfig, votos_eleitor: list[dict]):
    """
    Grava no RDV todos os votos dos cargos de 1 eleitor utilizando chave de embaralhamento CSPRNG
    (garantindo que a ordem de armazenamento no RDV não revele a identidade do eleitor) e
    bloqueia novamente o terminal da urna até que o mesário habilite o próximo eleitor via biometria.
    """
    if config.status != "EM_VOTACAO":
        raise ValueError(f"A urna não está aberta para votação (Status atual: {config.status}).")

    if not config.terminal_eleitor_liberado or not config.eleitor_habilitado_titulo:
        raise ValueError(
            "Terminal da Urna bloqueado! O mesário precisa identificar o eleitor (Título/CPF) e validar a Biometria antes de liberar o voto."
        )

    eleitor = (
        db.query(EleitorSeccao)
        .filter(EleitorSeccao.titulo == config.eleitor_habilitado_titulo)
        .first()
    )
    if not eleitor:
        raise ValueError("Eleitor habilitado não encontrado no caderno da seção.")

    if config.turno == 1 and eleitor.votou_turno_1:
        raise ValueError("Este eleitor já registrou voto no 1º Turno!")
    if config.turno == 2 and eleitor.votou_turno_2:
        raise ValueError("Este eleitor já registrou voto no 2º Turno!")

    cargos_esperados = get_cargos_por_turno(config.turno)
    for item in votos_eleitor:
        cargo = item["cargo"]
        branco = item.get("branco", False)
        numero = (item.get("numero") or "").strip()

        if branco:
            tipo_voto = "BRANCO"
            num_gravado = None
            legenda_gravada = None
        else:
            consulta = consultar_digitos_urna(db, config.turno, cargo, numero)
            if consulta["tipo"] == "NOMINAL":
                tipo_voto = "NOMINAL"
                num_gravado = numero
                legenda_gravada = numero[:2]
            elif consulta["tipo"] in ("LEGENDA", "LEGENDA_CANDIDATO_INEXISTENTE"):
                tipo_voto = "LEGENDA"
                num_gravado = numero[:2]
                legenda_gravada = numero[:2]
            else:
                tipo_voto = "NULO"
                num_gravado = numero
                legenda_gravada = None

        shuffle_key = secrets.token_hex(32)
        integrity_payload = f"{shuffle_key}|{config.turno}|{cargo}|{tipo_voto}|{num_gravado}|{legenda_gravada}"
        voto_hash = hashlib.sha256(integrity_payload.encode("utf-8")).hexdigest()

        rdv_row = RegistroDigitalVoto(
            shuffle_key=shuffle_key,
            turno=config.turno,
            cargo=cargo,
            tipo_voto=tipo_voto,
            numero_digitado=num_gravado,
            partido_legenda=legenda_gravada,
            hash_integridade=voto_hash,
        )
        db.add(rdv_row)

    # Marca presença no caderno de votação (sem qualquer chave estrangeira ou timestamp cruzado com o RDV!)
    if config.turno == 1:
        eleitor.votou_turno_1 = True
    else:
        eleitor.votou_turno_2 = True

    # Trava novamente o terminal da urna para aguardar o próximo eleitor no Terminal do Mesário
    config.terminal_eleitor_liberado = False
    config.eleitor_habilitado_titulo = None
    config.eleitores_compareceram += 1
    db.commit()

    # Nota de sigilo: o log de auditoria registra apenas o evento anônimo de conclusão de voto na urna
    registrar_log_encadeado(
        db,
        config,
        "VOTO_COMPUTADO_RDV",
        f"Comparecimento #{config.eleitores_compareceram} concluiu votação ({len(cargos_esperados)} cargos gravados no RDV embaralhado). Terminal bloqueado para próximo eleitor.",
    )
