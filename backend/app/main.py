import os
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

app = FastAPI(
    title="Urna Eletrônica Brasileira (ESP32 RISC-V Assembly + Python Core)",
    version="1.0.0",
    description="Motor Eleitoral de 1º e 2º Turnos, Zerésima, Boletim de Urna, Cartucho RDV Assinado e Interface ESP32 RISC-V.",
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


class SeccaoSetupUpdate(BaseModel):
    zona: str
    secao: str
    municipio: str
    turno: int
    eleitores_aptos: int


class VotoItemSchema(BaseModel):
    cargo: str
    branco: bool = False
    numero: Optional[str] = ""


class CestaVotosEleitorSchema(BaseModel):
    votos: list[VotoItemSchema]


class Esp32HexPacketSchema(BaseModel):
    frames_hex: list[str]


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
    return {
        "zona": config.zona,
        "secao": config.secao,
        "municipio": config.municipio,
        "turno": config.turno,
        "status": config.status,
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

    # Ao trocar de turno ou reconfigurar seção, reinicia a seção para permitir nova Zerésima
    config.zona = payload.zona
    config.secao = payload.secao
    config.municipio = payload.municipio.upper()
    config.turno = payload.turno
    config.eleitores_aptos = payload.eleitores_aptos
    config.status = "NAO_INICIALIZADA"
    config.eleitores_compareceram = 0
    config.zeresima_timestamp = None
    config.abertura_timestamp = None
    config.encerramento_timestamp = None
    db.query(RegistroDigitalVoto).filter(RegistroDigitalVoto.turno == payload.turno).delete()
    db.commit()

    registrar_log_encadeado(
        db,
        config,
        "CONFIGURACAO_SECAO",
        f"Seção configurada para {payload.turno}º Turno (Zona {payload.zona}, Seção {payload.secao}) e RDV do turno limpo para Zerésima.",
    )
    return {"ok": True, "mensagem": f"Seção preparada para o {payload.turno}º Turno. Pronta para emitir Zerésima."}


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
    try:
        relatorio = gerar_relatorio_zeresima(db, config)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    registrar_log_encadeado(
        db,
        config,
        "EMISSAO_ZERESIMA_E_ABERTURA",
        f"Zerésima emitida com sucesso (SHA256: {relatorio['hash_sha256'][:16]}...). Seção aberta para votação.",
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
    """
    Endpoint para ingestão direta dos frames binários de 10 bytes gerados
    pelo firmware Assembly RISC-V (`urna_fsm_riscv.S`: 0xAA ... 0x55).
    """
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
def api_listar_logs(db: Session = Depends(get_db)):
    logs = db.query(LogAuditoriaUrna).order_by(LogAuditoriaUrna.id.desc()).limit(100).all()
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
