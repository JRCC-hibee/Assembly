import os
import hashlib
from datetime import datetime, timezone
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .database import (
    SessionLocal,
    init_db,
    SeccaoConfig,
    EleitorSeccao,
    Partido,
    Candidato,
    RegistroDigitalVoto,
    LogAuditoriaUrna,
)
from .election_engine import (
    get_cargos_por_turno,
    get_or_create_seccao,
    seed_default_candidates,
    consultar_digitos_urna,
    computar_cesta_votos_eleitor,
    registrar_log_encadeado,
)
from .thermal_printer import gerar_relatorio_zeresima, apurar_boletim_de_urna
from .cartridge import gerar_cartucho_midia_resultado
from .esp32_protocol import decode_esp32_vote_frame
from .simulator_audit import executar_simulacao_cadencia_seccao, auditar_logs_independente

app = FastAPI(
    title="Urna Eletrônica Brasileira (ESP32 RISC-V Assembly + Python Core)",
    version="1.1.0",
    description="Motor Eleitoral de 1º e 2º Turnos, Terminal do Mesário com Biometria, Zerésima, Boletim de Urna, Cartucho RDV Assinado e Interface ESP32 RISC-V.",
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.on_event("startup")
def on_startup():
    init_db()
    db = SessionLocal()
    try:
        get_or_create_seccao(db)
        seed_default_candidates(db)
    finally:
        db.close()


# ==============================================================================
# Schemas Pydantic
# ==============================================================================
class PartidoCreate(BaseModel):
    numero: str
    sigla: str
    nome: str


class CandidatoCreate(BaseModel):
    cargo: str
    numero: str
    nome_urna: str
    nome_completo: Optional[str] = None
    sigla_partido: str
    numero_partido: str
    vice_ou_suplente1: Optional[str] = None
    suplente2: Optional[str] = None
    turno: int = 1


class EleitorCreate(BaseModel):
    titulo: str
    cpf: str
    nome: str
    data_nascimento: str
    nome_mae: Optional[str] = ""
    biometria_cadastrada: bool = True


class MesarioLiberarEleitorSchema(BaseModel):
    documento: str  # Título ou CPF
    biometria_validada: bool = False
    justificativa_sem_biometria: Optional[str] = None


class SeccaoSetupUpdate(BaseModel):
    zona: str
    secao: str
    municipio: str
    turno: int
    eleitores_aptos: int
    forcar_reinicio: bool = False


class VotoItemSchema(BaseModel):
    cargo: str
    branco: bool = False
    numero: Optional[str] = ""


class CestaVotosEleitorSchema(BaseModel):
    votos: list[VotoItemSchema]


class Esp32HexPacketSchema(BaseModel):
    frames_hex: list[str]


class SimulacaoSeccaoSchema(BaseModel):
    turno: int = 1
    eleitores_aptos: int = 250
    abstencoes: int = 45
    pct_brancos: float = 4.0
    pct_nulos: float = 3.0
    pct_legenda: float = 5.0
    modo_anomalia: str = "NORMAL"  # NORMAL, RAJADA_ROBO, SEM_BIOMETRIA_EM_MASSA, FORA_DE_JANELA_HORARIA
    qtd_votos_anomalia: int = 0
    candidato_alvo_anomalia: Optional[str] = ""


class AuditoriaExternaLogsSchema(BaseModel):
    logs: Optional[list[dict]] = None



# ==============================================================================
# Rotas de Interface Web e API Eleitoral
# ==============================================================================
@app.get("/", response_class=HTMLResponse)
def index_page(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/api/status")
def api_get_status(db: Session = Depends(get_db)):
    config = get_or_create_seccao(db)
    cargos = get_cargos_por_turno(config.turno)
    total_rdv = db.query(RegistroDigitalVoto).filter(RegistroDigitalVoto.turno == config.turno).count()

    eleitor_atual = None
    if config.terminal_eleitor_liberado and config.eleitor_habilitado_titulo:
        el = db.query(EleitorSeccao).filter(EleitorSeccao.titulo == config.eleitor_habilitado_titulo).first()
        if el:
            eleitor_atual = {
                "titulo": el.titulo,
                "nome": el.nome,
                "cpf": el.cpf,
            }

    return {
        "zona": config.zona,
        "secao": config.secao,
        "municipio": config.municipio,
        "turno": config.turno,
        "status": config.status,
        "terminal_eleitor_liberado": bool(config.terminal_eleitor_liberado),
        "eleitor_habilitado": eleitor_atual,
        "eleitores_aptos": config.eleitores_aptos,
        "eleitores_compareceram": config.eleitores_compareceram,
        "total_registros_rdv": total_rdv,
        "zeresima_timestamp": config.zeresima_timestamp.isoformat() if config.zeresima_timestamp else None,
        "abertura_timestamp": config.abertura_timestamp.isoformat() if config.abertura_timestamp else None,
        "encerramento_timestamp": config.encerramento_timestamp.isoformat() if config.encerramento_timestamp else None,
        "ultimo_hash_log": config.ultimo_hash_log,
        "cargos_turno": cargos,
    }


@app.post("/api/seccao/configurar")
def api_configurar_seccao(payload: SeccaoSetupUpdate, db: Session = Depends(get_db)):
    config = get_or_create_seccao(db)
    if payload.turno not in (1, 2):
        raise HTTPException(status_code=400, detail="Turno deve ser 1 ou 2.")

    # Trava de Segurança TSE: Impede trocar de turno ou reconfigurar seção enquanto EM_VOTACAO!
    if config.status == "EM_VOTACAO" and not payload.forcar_reinicio:
        raise HTTPException(
            status_code=409,
            detail=(
                f"BLOQUEIO DE SEGURANÇA TSE: A seção está EM VOTAÇÃO ATIVA no {config.turno}º Turno! "
                "Não é permitido preparar outro turno ou reiniciar a urna antes de ENCERRAR a votação e emitir o Boletim de Urna (BU)."
            ),
        )

    config.zona = payload.zona
    config.secao = payload.secao
    config.municipio = payload.municipio.upper()
    config.turno = payload.turno
    config.eleitores_aptos = payload.eleitores_aptos
    config.status = "NAO_INICIALIZADA"
    config.terminal_eleitor_liberado = False
    config.eleitor_habilitado_titulo = None
    config.eleitores_compareceram = 0
    config.zeresima_timestamp = None
    config.abertura_timestamp = None
    config.encerramento_timestamp = None

    # Limpa os votos do turno que está sendo preparado e reseta a flag de presença daquele turno no caderno
    db.query(RegistroDigitalVoto).filter(RegistroDigitalVoto.turno == payload.turno).delete()
    for el in db.query(EleitorSeccao).all():
        if payload.turno == 1:
            el.votou_turno_1 = False
        else:
            el.votou_turno_2 = False

    db.commit()

    registrar_log_encadeado(
        db,
        config,
        "CONFIGURACAO_SECAO",
        f"Seção configurada para {payload.turno}º Turno (Zona {payload.zona}, Seção {payload.secao}) e pronta para emissão da Zerésima.",
    )
    return {"ok": True, "mensagem": f"Seção preparada para o {payload.turno}º Turno. Pronta para emitir Zerésima."}


# ==============================================================================
# Rotas do Terminal do Mesário (Busca de Eleitor, Biometria e Habilitação da Urna)
# ==============================================================================
@app.get("/api/mesario/eleitores")
def api_listar_eleitores_seccao(db: Session = Depends(get_db)):
    config = get_or_create_seccao(db)
    eleitores = db.query(EleitorSeccao).order_by(EleitorSeccao.nome).all()
    return [
        {
            "id": e.id,
            "titulo": e.titulo,
            "cpf": e.cpf,
            "nome": e.nome,
            "data_nascimento": e.data_nascimento,
            "nome_mae": e.nome_mae,
            "biometria_cadastrada": e.biometria_cadastrada,
            "hash_template_biometrico": e.hash_template_biometrico[:16] + "...",
            "ja_votou_turno_atual": e.votou_turno_1 if config.turno == 1 else e.votou_turno_2,
            "votou_turno_1": e.votou_turno_1,
            "votou_turno_2": e.votou_turno_2,
        }
        for e in eleitores
    ]


@app.post("/api/mesario/eleitores")
def api_cadastrar_eleitor(payload: EleitorCreate, db: Session = Depends(get_db)):
    titulo_limpo = "".join(ch for ch in payload.titulo if ch.isdigit())
    if len(titulo_limpo) < 8:
        raise HTTPException(status_code=400, detail="Título de Eleitor inválido (mínimo 8 dígitos).")

    existente = db.query(EleitorSeccao).filter(EleitorSeccao.titulo == titulo_limpo).first()
    bio_hash = hashlib.sha256(f"BIO-TSE|{titulo_limpo}|{payload.cpf}".encode("utf-8")).hexdigest()
    if existente:
        existente.cpf = payload.cpf.strip()
        existente.nome = payload.nome.upper().strip()
        existente.data_nascimento = payload.data_nascimento.strip()
        existente.nome_mae = (payload.nome_mae or "").upper().strip()
        existente.biometria_cadastrada = payload.biometria_cadastrada
        existente.hash_template_biometrico = bio_hash
    else:
        db.add(
            EleitorSeccao(
                titulo=titulo_limpo,
                cpf=payload.cpf.strip(),
                nome=payload.nome.upper().strip(),
                data_nascimento=payload.data_nascimento.strip(),
                nome_mae=(payload.nome_mae or "").upper().strip(),
                biometria_cadastrada=payload.biometria_cadastrada,
                hash_template_biometrico=bio_hash,
            )
        )
    db.commit()
    return {"ok": True}


@app.get("/api/mesario/buscar")
def api_buscar_eleitor_mesario(documento: str, db: Session = Depends(get_db)):
    config = get_or_create_seccao(db)
    doc_raw = documento.strip()
    doc_digits = "".join(ch for ch in doc_raw if ch.isdigit())

    eleitor = (
        db.query(EleitorSeccao)
        .filter(
            (EleitorSeccao.titulo == doc_raw)
            | (EleitorSeccao.titulo == doc_digits)
            | (EleitorSeccao.cpf == doc_raw)
        )
        .first()
    )
    if not eleitor:
        # Tenta comparar CPF sem pontuação
        for e in db.query(EleitorSeccao).all():
            cpf_digits = "".join(ch for ch in e.cpf if ch.isdigit())
            if doc_digits and (e.titulo == doc_digits or cpf_digits == doc_digits):
                eleitor = e
                break

    if not eleitor:
        raise HTTPException(status_code=404, detail="Eleitor não encontrado no caderno desta Seção Eleitoral.")

    ja_votou = eleitor.votou_turno_1 if config.turno == 1 else eleitor.votou_turno_2
    return {
        "titulo": eleitor.titulo,
        "cpf": eleitor.cpf,
        "nome": eleitor.nome,
        "data_nascimento": eleitor.data_nascimento,
        "nome_mae": eleitor.nome_mae,
        "biometria_cadastrada": eleitor.biometria_cadastrada,
        "hash_template_biometrico": eleitor.hash_template_biometrico,
        "ja_votou_turno_atual": ja_votou,
        "turno_atual": config.turno,
    }


@app.post("/api/mesario/liberar-urna")
def api_mesario_liberar_urna(payload: MesarioLiberarEleitorSchema, db: Session = Depends(get_db)):
    config = get_or_create_seccao(db)
    if config.status != "EM_VOTACAO":
        raise HTTPException(
            status_code=400,
            detail=f"A seção não está aberta para votação (Status: {config.status}). Emita a Zerésima primeiro!",
        )

    if config.terminal_eleitor_liberado:
        raise HTTPException(
            status_code=409,
            detail="A urna já está liberada para um eleitor na cabine! Aguarde a conclusão do voto ou cancele a liberação.",
        )

    busca = api_buscar_eleitor_mesario(payload.documento, db)
    if busca["ja_votou_turno_atual"]:
        raise HTTPException(
            status_code=409,
            detail=f"BLOQUEIO TSE: O eleitor {busca['nome']} (Título {busca['titulo']}) JÁ VOTOU neste {config.turno}º Turno!",
        )

    if busca["biometria_cadastrada"] and not payload.biometria_validada:
        raise HTTPException(
            status_code=400,
            detail="O eleitor possui biometria cadastrada. Realize a coleta da impressão digital no sensor biométrico do Terminal do Mesário.",
        )

    if not busca["biometria_cadastrada"] and not payload.biometria_validada and not payload.justificativa_sem_biometria:
        raise HTTPException(
            status_code=400,
            detail="Eleitor sem biometria exige confirmação de documento oficial com foto pelo Mesário.",
        )

    config.terminal_eleitor_liberado = True
    config.eleitor_habilitado_titulo = busca["titulo"]
    db.commit()

    metodo_auth = "BIOMETRIA AFIS/TSE VALIDADA" if payload.biometria_validada else "HABILITAÇÃO POR DOCUMENTO COM FOTO (SEM BIO)"
    registrar_log_encadeado(
        db,
        config,
        "TERMINAL_MESARIO_HABILITOU_ELEITOR",
        f"Terminal da Urna liberado pelo Mesário ({metodo_auth}). Cabine pronta para receber voto.",
    )
    return {
        "ok": True,
        "eleitor": busca,
        "metodo": metodo_auth,
    }


@app.post("/api/mesario/cancelar-liberacao")
def api_mesario_cancelar_liberacao(db: Session = Depends(get_db)):
    config = get_or_create_seccao(db)
    config.terminal_eleitor_liberado = False
    config.eleitor_habilitado_titulo = None
    db.commit()
    registrar_log_encadeado(
        db,
        config,
        "TERMINAL_MESARIO_CANCELOU_LIBERACAO",
        "Liberação do terminal da urna cancelada pelo Presidente da Mesa.",
    )
    return {"ok": True}


# ==============================================================================
# Rotas de Partidos e Candidatos
# ==============================================================================
@app.get("/api/partidos")
def api_listar_partidos(db: Session = Depends(get_db)):
    partidos = db.query(Partido).order_by(Partido.numero).all()
    return [{"id": p.id, "numero": p.numero, "sigla": p.sigla, "nome": p.nome} for p in partidos]


@app.post("/api/partidos")
def api_criar_partido(payload: PartidoCreate, db: Session = Depends(get_db)):
    numero = payload.numero.strip()
    if len(numero) != 2 or not numero.isdigit():
        raise HTTPException(status_code=400, detail="Número do partido deve conter exatamente 2 dígitos.")
    existente = db.query(Partido).filter(Partido.numero == numero).first()
    if existente:
        existente.sigla = payload.sigla.upper().strip()
        existente.nome = payload.nome.strip()
    else:
        db.add(Partido(numero=numero, sigla=payload.sigla.upper().strip(), nome=payload.nome.strip()))
    db.commit()
    return {"ok": True}


@app.get("/api/candidatos")
def api_listar_candidatos(turno: Optional[int] = None, db: Session = Depends(get_db)):
    q = db.query(Candidato)
    if turno in (1, 2):
        q = q.filter(Candidato.turno == turno)
    cands = q.order_by(Candidato.turno, Candidato.cargo, Candidato.numero).all()
    return [
        {
            "id": c.id,
            "cargo": c.cargo,
            "numero": c.numero,
            "nome_urna": c.nome_urna,
            "nome_completo": c.nome_completo,
            "sigla_partido": c.sigla_partido,
            "numero_partido": c.numero_partido,
            "vice_ou_suplente1": c.vice_ou_suplente1,
            "suplente2": c.suplente2,
            "turno": c.turno,
        }
        for c in cands
    ]


@app.post("/api/candidatos")
def api_cadastrar_candidato(payload: CandidatoCreate, db: Session = Depends(get_db)):
    config = get_or_create_seccao(db)
    if config.status == "EM_VOTACAO":
        raise HTTPException(
            status_code=409,
            detail="BLOQUEIO TSE: Não é permitido alterar a carga de candidatos enquanto a seção está EM VOTAÇÃO!",
        )

    numero = payload.numero.strip()
    num_partido = payload.numero_partido.strip()

    if not db.query(Partido).filter(Partido.numero == num_partido).first():
        db.add(Partido(numero=num_partido, sigla=payload.sigla_partido.upper().strip(), nome=f"Partido {payload.sigla_partido.upper()}"))

    existente = (
        db.query(Candidato)
        .filter(
            Candidato.cargo == payload.cargo,
            Candidato.numero == numero,
            Candidato.turno == payload.turno,
        )
        .first()
    )
    if existente:
        existente.nome_urna = payload.nome_urna.upper().strip()
        existente.nome_completo = payload.nome_completo
        existente.sigla_partido = payload.sigla_partido.upper().strip()
        existente.numero_partido = num_partido
        existente.vice_ou_suplente1 = payload.vice_ou_suplente1
        existente.suplente2 = payload.suplente2
    else:
        novo = Candidato(
            cargo=payload.cargo,
            numero=numero,
            nome_urna=payload.nome_urna.upper().strip(),
            nome_completo=payload.nome_completo,
            sigla_partido=payload.sigla_partido.upper().strip(),
            numero_partido=num_partido,
            vice_ou_suplente1=payload.vice_ou_suplente1,
            suplente2=payload.suplente2,
            turno=payload.turno,
        )
        db.add(novo)

    db.commit()
    registrar_log_encadeado(
        db,
        config,
        "CADASTRO_CANDIDATO",
        f"Candidato {payload.nome_urna.upper()} ({numero} - {payload.cargo} - {payload.turno}ºT) registrado.",
    )
    return {"ok": True}


@app.delete("/api/candidatos/{candidato_id}")
def api_remover_candidato(candidato_id: int, db: Session = Depends(get_db)):
    config = get_or_create_seccao(db)
    if config.status == "EM_VOTACAO":
        raise HTTPException(
            status_code=409,
            detail="BLOQUEIO TSE: Não é permitido excluir candidatos enquanto a seção está EM VOTAÇÃO!",
        )
    cand = db.query(Candidato).filter(Candidato.id == candidato_id).first()
    if not cand:
        raise HTTPException(status_code=404, detail="Candidato não encontrado.")
    db.delete(cand)
    db.commit()
    return {"ok": True}


@app.get("/api/urna/consulta")
def api_consultar_digitos(cargo: str, numero: str, db: Session = Depends(get_db)):
    config = get_or_create_seccao(db)
    return consultar_digitos_urna(db, config.turno, cargo, numero)


@app.post("/api/seccao/zeresima")
def api_emitir_zeresima(db: Session = Depends(get_db)):
    config = get_or_create_seccao(db)
    if config.status == "EM_VOTACAO":
        raise HTTPException(
            status_code=409,
            detail="A Zerésima já foi emitida e a seção já está EM VOTAÇÃO! Não é permitido reemitir Zerésima com a urna aberta.",
        )
    if config.status == "ENCERRADA":
        raise HTTPException(
            status_code=409,
            detail="Esta seção já foi ENCERRADA. Para iniciar o próximo turno, clique em Preparar 1º ou 2º Turno.",
        )
    try:
        relatorio = gerar_relatorio_zeresima(db, config)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    registrar_log_encadeado(
        db,
        config,
        "EMISSAO_ZERESIMA_E_ABERTURA",
        f"Zerésima emitida com sucesso (SHA256: {relatorio['hash_sha256'][:16]}...). Seção aberta aguardando liberação de eleitores pelo Mesário.",
    )
    return relatorio


@app.post("/api/urna/votar")
def api_computar_votos_eleitor(payload: CestaVotosEleitorSchema, db: Session = Depends(get_db)):
    config = get_or_create_seccao(db)
    try:
        computar_cesta_votos_eleitor(
            db,
            config,
            [{"cargo": v.cargo, "branco": v.branco, "numero": v.numero} for v in payload.votos],
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return {
        "ok": True,
        "eleitores_compareceram": config.eleitores_compareceram,
        "mensagem": "FIM",
    }


@app.post("/api/esp32/pacote-binario")
def api_receber_pacote_esp32(payload: Esp32HexPacketSchema, db: Session = Depends(get_db)):
    config = get_or_create_seccao(db)
    votos_decodificados = []
    try:
        for hex_str in payload.frames_hex:
            raw_bytes = bytes.fromhex(hex_str.replace(" ", ""))
            voto = decode_esp32_vote_frame(raw_bytes, turno=config.turno)
            votos_decodificados.append(voto)
        computar_cesta_votos_eleitor(db, config, votos_decodificados)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return {
        "ok": True,
        "votos_processados": votos_decodificados,
        "eleitores_compareceram": config.eleitores_compareceram,
    }


@app.post("/api/seccao/encerrar")
def api_encerrar_votacao(db: Session = Depends(get_db)):
    config = get_or_create_seccao(db)
    if config.status != "EM_VOTACAO":
        raise HTTPException(status_code=400, detail=f"A seção precisa estar EM_VOTACAO para ser encerrada (Status atual: {config.status}).")

    if config.terminal_eleitor_liberado:
        raise HTTPException(
            status_code=409,
            detail="Há um eleitor habilitado na cabine de votação! Aguarde ele concluir o voto ou cancele a liberação no Terminal do Mesário antes de encerrar a urna.",
        )

    config.status = "ENCERRADA"
    config.encerramento_timestamp = datetime.now(timezone.utc)
    db.commit()

    bu = apurar_boletim_de_urna(db, config)
    cartucho = gerar_cartucho_midia_resultado(db, config)

    registrar_log_encadeado(
        db,
        config,
        "ENCERRAMENTO_BU_E_CARTUCHO",
        f"Seção encerrada. BU SHA256={bu['hash_bu_sha256'][:16]}... Cartucho={cartucho['arquivo']}.",
    )
    return {
        "boletim_de_urna": bu,
        "cartucho": cartucho,
    }


@app.get("/api/seccao/boletim")
def api_obter_boletim(db: Session = Depends(get_db)):
    config = get_or_create_seccao(db)
    if config.status != "ENCERRADA":
        raise HTTPException(status_code=400, detail="O Boletim de Urna só pode ser emitido após o encerramento da votação.")
    return apurar_boletim_de_urna(db, config)


@app.get("/api/seccao/cartucho/download")
def api_download_cartucho(db: Session = Depends(get_db)):
    config = get_or_create_seccao(db)
    if config.status != "ENCERRADA":
        raise HTTPException(status_code=400, detail="Encerre a votação na seção antes de exportar o Cartucho de Mídia de Resultado.")
    cartucho = gerar_cartucho_midia_resultado(db, config)
    return FileResponse(
        path=cartucho["caminho"],
        filename=cartucho["arquivo"],
        media_type="application/zip",
    )


@app.get("/api/seccao/logs")
def api_listar_logs(limit: int = 500, db: Session = Depends(get_db)):
    logs = db.query(LogAuditoriaUrna).order_by(LogAuditoriaUrna.id.desc()).limit(limit).all()
    return [
        {
            "id": l.id,
            "timestamp": l.timestamp.isoformat() if l.timestamp else None,
            "evento": l.evento,
            "detalhes": l.detalhes,
            "hash_anterior": l.hash_anterior,
            "hash_atual": l.hash_atual,
        }
        for l in logs
    ]


@app.get("/api/seccao/logs/export")
def api_exportar_logs_json(db: Session = Depends(get_db)):
    """Exporta todos os logs cronológicos da seção em formato JSON independente para auditoria paralela."""
    config = get_or_create_seccao(db)
    logs = db.query(LogAuditoriaUrna).order_by(LogAuditoriaUrna.id.asc()).all()
    return {
        "cabecalho": {
            "zona": config.zona,
            "secao": config.secao,
            "municipio": config.municipio,
            "turno": config.turno,
            "eleitores_aptos": config.eleitores_aptos,
            "comparecimento": config.eleitores_compareceram,
            "ultimo_hash_log": config.ultimo_hash_log,
            "total_eventos": len(logs),
        },
        "logs": [
            {
                "id": l.id,
                "timestamp": l.timestamp.isoformat() if l.timestamp else None,
                "evento": l.evento,
                "detalhes": l.detalhes,
                "hash_anterior": l.hash_anterior,
                "hash_atual": l.hash_atual,
            }
            for l in logs
        ],
    }


@app.post("/api/simulacao/executar")
def api_executar_simulacao(payload: SimulacaoSeccaoSchema, db: Session = Depends(get_db)):
    config = get_or_create_seccao(db)
    try:
        resultado = executar_simulacao_cadencia_seccao(
            db,
            config,
            turno=payload.turno,
            eleitores_aptos=payload.eleitores_aptos,
            abstencoes=payload.abstencoes,
            pct_brancos=payload.pct_brancos,
            pct_nulos=payload.pct_nulos,
            pct_legenda=payload.pct_legenda,
            modo_anomalia=payload.modo_anomalia,
            qtd_votos_anomalia=payload.qtd_votos_anomalia,
            candidato_alvo_anomalia=(payload.candidato_alvo_anomalia or "").strip(),
        )
        return resultado
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/auditoria/analisar-logs")
def api_auditar_logs_independente(payload: AuditoriaExternaLogsSchema, db: Session = Depends(get_db)):
    """
    Sistema Paralelo de Auditoria Forense:
    Analisa uma lista de logs enviada via JSON externo OU lê diretamente os logs da seção atual.
    """
    if payload.logs is not None and len(payload.logs) > 0:
        logs_input = payload.logs
    else:
        logs_db = db.query(LogAuditoriaUrna).order_by(LogAuditoriaUrna.id.asc()).all()
        logs_input = [
            {
                "id": l.id,
                "timestamp": l.timestamp.isoformat() if l.timestamp else None,
                "evento": l.evento,
                "detalhes": l.detalhes,
                "hash_anterior": l.hash_anterior,
                "hash_atual": l.hash_atual,
            }
            for l in logs_db
        ]
    return auditar_logs_independente(logs_input)

