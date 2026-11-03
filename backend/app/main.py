import os
import glob
import time
import zipfile
import hashlib
import uuid
import tempfile
from datetime import datetime, timezone
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, Request, UploadFile, File, BackgroundTasks
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
from .tse_reverse_analyzer import (
    analisar_pacote_seccao_tse,
    processar_lote_arquivos_tse,
    consolidar_secoes_tse,
    obter_secao_individual_tse,
    obter_indice_secoes_carregadas,
    reauditar_urnas_divergentes_catalogo,
    limpar_catalogo_tse,
    extrair_prefixo_seccao,
    sincronizar_catalogo_com_banco,
    _CATALOGO_MEMORIA,
)

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


@app.post("/api/tse-reverso/upload")
async def api_tse_reverso_upload(request: Request):
    """
    Recebe o upload dos arquivos oficiais do TSE de uma ou mais seções eleitorais
    (`-log.jez`, `-imgbu.dat`, `-rdv.dat`, `-bu.dat`, `-vota.vsc`),
    registra no catálogo multi-urna e retorna o resultado.
    """
    form = await request.form(max_files=5000, max_fields=5000)
    files = form.getlist("files")
    if not files:
        raise HTTPException(status_code=400, detail="Nenhum arquivo enviado para análise reversa.")

    arquivos_dict = {}
    for f in files:
        if hasattr(f, "read") and getattr(f, "filename", None):
            content = await f.read()
            arquivos_dict[f.filename] = content

    if not arquivos_dict:
        raise HTTPException(status_code=400, detail="Nenhum arquivo válido encontrado no envio.")

    try:
        lote_res = processar_lote_arquivos_tse(arquivos_dict)
        if lote_res.get("secoes_processadas_neste_lote") == 1 and lote_res.get("ultimo_relatorio_individual"):
            return lote_res["ultimo_relatorio_individual"]
        return consolidar_secoes_tse("TODAS", "TODAS", "CONSOLIDADO")
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Erro ao processar pacote TSE: {exc}")


@app.get("/api/tse-reverso/indice-ja-carregados")
def api_tse_reverso_indice_ja_carregados():
    """
    Retorna a máscara de bits de todas as seções já carregadas no servidor
    para que o navegador pule 100% dos arquivos já processados em uploads anteriores.
    """
    return obter_indice_secoes_carregadas()


@app.post("/api/tse-reverso/upload-lote")
async def api_tse_reverso_upload_lote(request: Request):
    """
    Endpoint otimizado para ingestão em lote (chunked) de dezenas, centenas ou milhares
    de seções/urnas do estado (ex: Paraná inteiro). Agrupa por prefixo da seção,
    ignora arquivos duplicados, persiste no catálogo e retorna o progresso.
    """
    form = await request.form(max_files=5000, max_fields=5000)
    files = form.getlist("files")
    if not files:
        raise HTTPException(status_code=400, detail="Nenhum arquivo enviado no lote.")

    arquivos_dict = {}
    for f in files:
        if hasattr(f, "read") and getattr(f, "filename", None):
            content = await f.read()
            arquivos_dict[f.filename] = content

    try:
        lote_res = processar_lote_arquivos_tse(arquivos_dict)
        return {
            "ok": True,
            "secoes_processadas_neste_lote": lote_res["secoes_processadas_neste_lote"],
            "secoes_ignoradas_duplicadas": lote_res.get("secoes_ignoradas_duplicadas", 0),
            "prefixos_processados": lote_res["prefixos_processados"],
            "total_secoes_no_catalogo": lote_res["total_secoes_no_catalogo"],
        }
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Erro ao processar lote TSE: {exc}")


# Gerenciador persistente de jobs em background para importação massiva de arquivos .ZIP
# (Garante resiliência com fallback em disco caso o worker recarregue ou existam múltiplos processos)
_JOBS_IMPORTACAO_TSE: dict[str, dict] = {}


def _get_jobs_dir() -> str:
    p = "/app/data/jobs" if os.path.exists("/app/data") else os.path.join(tempfile.gettempdir(), "tse_jobs")
    os.makedirs(p, exist_ok=True)
    return p


def _salvar_job_status(job_id: str, data: dict):
    _JOBS_IMPORTACAO_TSE[job_id] = data
    try:
        fpath = os.path.join(_get_jobs_dir(), f"{job_id}.json")
        with open(fpath, "w", encoding="utf-8") as fp:
            json.dump(data, fp)
    except Exception:
        pass


def _obter_job_status(job_id: str) -> dict | None:
    if job_id in _JOBS_IMPORTACAO_TSE:
        return _JOBS_IMPORTACAO_TSE[job_id]
    try:
        fpath = os.path.join(_get_jobs_dir(), f"{job_id}.json")
        if os.path.exists(fpath):
            with open(fpath, "r", encoding="utf-8") as fp:
                data = json.load(fp)
                _JOBS_IMPORTACAO_TSE[job_id] = data
                return data
    except Exception:
        pass
    return None


def _executar_job_importacao_zip(job_id: str, temp_paths: list[str]):
    t0 = time.time()
    job = _obter_job_status(job_id) or {
        "job_id": job_id,
        "status": "PROCESSANDO",
        "concluido": False,
        "total_secoes_estimadas": 0,
        "secoes_gravadas": 0,
        "progresso_pct": 2.0,
        "mensagem": "Iniciando varredura das urnas...",
        "erro": None,
        "tempo_inicio": t0,
        "tempo_segundos": 0.0,
    }

    total_secoes_gravadas = 0
    try:
        total_secoes_estimadas = 0
        zips_info = []
        for p in temp_paths:
            if not os.path.exists(p):
                continue
            try:
                zf = zipfile.ZipFile(p, "r")
                infolist = [
                    info
                    for info in zf.infolist()
                    if not info.is_dir()
                    and any(info.filename.lower().endswith(ext) for ext in (".jez", ".dat", ".vsc"))
                ]
                grupos = {}
                for info in infolist:
                    base = os.path.basename(info.filename)
                    pref = extrair_prefixo_seccao(base)
                    if pref:
                        grupos.setdefault(pref, []).append((base, info))
                total_secoes_estimadas += len(grupos)
                zips_info.append((p, zf, grupos))
            except Exception as e:
                print(f"[TSE-ZIP-JOB] Falha ao ler zip {p}: {e}")

        job["total_secoes_estimadas"] = total_secoes_estimadas
        job["mensagem"] = f"Total estimado: {total_secoes_estimadas} seções. Iniciando decodificação..."
        _salvar_job_status(job_id, job)

        chunk_size = 50
        for zip_idx, (p, zf, grupos) in enumerate(zips_info):
            nome_zip = os.path.basename(p)
            prefixos = list(grupos.keys())

            for i in range(0, len(prefixos), chunk_size):
                fatia = prefixos[i : i + chunk_size]
                micro_lote_bytes = {}
                for pref in fatia:
                    for base_name, zinfo in grupos[pref]:
                        try:
                            micro_lote_bytes[base_name] = zf.read(zinfo)
                        except Exception:
                            pass
                if micro_lote_bytes:
                    res = processar_lote_arquivos_tse(micro_lote_bytes)
                    total_secoes_gravadas += res.get("secoes_processadas_neste_lote", 0)
                    micro_lote_bytes.clear()

                progresso = (
                    round((total_secoes_gravadas / max(1, total_secoes_estimadas)) * 100, 1)
                    if total_secoes_estimadas > 0
                    else 50.0
                )
                job["secoes_gravadas"] = total_secoes_gravadas
                job["progresso_pct"] = min(99.0, progresso)
                job["tempo_segundos"] = round(time.time() - t0, 1)
                job["mensagem"] = (
                    f"Decodificando {nome_zip}: {total_secoes_gravadas}/{total_secoes_estimadas} seções gravadas no PostgreSQL ({job['progresso_pct']}%)"
                )
                _salvar_job_status(job_id, job)

            try:
                zf.close()
            except Exception:
                pass
            # Remove o arquivo temporário imediatamente (Zero-Disk Raw)
            try:
                if os.path.exists(p):
                    os.remove(p)
            except Exception:
                pass

        # Conclusão e sincronização do catálogo em memória com selectinload em <0.2s
        job["mensagem"] = "Sincronizando catálogo e árvore de 5 níveis com PostgreSQL..."
        _salvar_job_status(job_id, job)
        sincronizar_catalogo_com_banco()

        duracao = round(time.time() - t0, 2)
        job["status"] = "CONCLUIDO"
        job["concluido"] = True
        job["progresso_pct"] = 100.0
        job["secoes_gravadas"] = total_secoes_gravadas
        job["tempo_segundos"] = duracao
        job["mensagem"] = f"Sucesso! {total_secoes_gravadas} seções processadas e gravadas no PostgreSQL em {duracao}s."
        _salvar_job_status(job_id, job)

    except Exception as exc:
        print(f"[TSE-ZIP-JOB] Erro fatal no job {job_id}: {exc}")
        job["status"] = "ERRO"
        job["concluido"] = True
        job["erro"] = str(exc)
        job["mensagem"] = f"Erro durante o processamento: {exc}"
        _salvar_job_status(job_id, job)
        for p in temp_paths:
            try:
                if os.path.exists(p):
                    os.remove(p)
            except Exception:
                pass


@app.post("/api/tse-reverso/upload-zip")
async def api_tse_reverso_upload_zip(
    request: Request,
    background_tasks: BackgroundTasks,
):
    """
    Recebe um ou mais arquivos .ZIP do TSE (ex: SC_1T.zip, SC_2T.zip, PR_2T.zip).
    Salva temporariamente em disco e despacha o processamento em background (BackgroundTasks),
    retornando imediatamente um job_id para o frontend acompanhar o progresso em tempo real
    sem risco de timeout reverso (180s do Traefik/Cloudflare).
    """
    form = await request.form(max_files=100, max_fields=100)
    files = form.getlist("files")
    if not files:
        raise HTTPException(status_code=400, detail="Nenhum arquivo .ZIP enviado.")

    job_id = str(uuid.uuid4())[:8]
    temp_dir = tempfile.gettempdir()
    temp_paths = []

    for f in files:
        filename = getattr(f, "filename", "") or ""
        if not filename.lower().endswith(".zip"):
            continue
        temp_path = os.path.join(temp_dir, f"tse_upload_{job_id}_{filename}")
        with open(temp_path, "wb") as out_fp:
            while chunk := await f.read(1024 * 1024 * 4):  # 4MB chunks
                out_fp.write(chunk)
        temp_paths.append(temp_path)

    if not temp_paths:
        raise HTTPException(status_code=400, detail="Nenhum arquivo .ZIP válido encontrado.")

    # Mantém apenas os últimos 30 jobs no histórico
    if len(_JOBS_IMPORTACAO_TSE) > 30:
        for k in list(_JOBS_IMPORTACAO_TSE.keys())[:-20]:
            _JOBS_IMPORTACAO_TSE.pop(k, None)

    _salvar_job_status(job_id, {
        "job_id": job_id,
        "status": "PROCESSANDO",
        "concluido": False,
        "total_zips": len(temp_paths),
        "total_secoes_estimadas": 0,
        "secoes_gravadas": 0,
        "progresso_pct": 2.0,
        "mensagem": f"Upload de {len(temp_paths)} arquivo(s) concluído. Iniciando varredura das urnas...",
        "erro": None,
        "tempo_inicio": time.time(),
        "tempo_segundos": 0.0,
    })

    background_tasks.add_task(_executar_job_importacao_zip, job_id, temp_paths)

    return {
        "ok": True,
        "job_id": job_id,
        "total_zips": len(temp_paths),
        "mensagem": f"Upload concluído. Processamento em segundo plano iniciado (Job {job_id}).",
    }


@app.get("/api/tse-reverso/job-status/{job_id}")
def api_tse_reverso_job_status(job_id: str):
    """Retorna o status e percentual de progresso de um job de importação em background."""
    job = _obter_job_status(job_id)
    if not job:
        return {"ok": False, "status": "NAO_ENCONTRADO", "mensagem": "Job não encontrado ou expirado."}
    return job


@app.post("/api/tse-reverso/sincronizar-banco")
def api_tse_reverso_sincronizar_banco():
    """
    Sincroniza o catálogo em memória com 100% das seções gravadas no PostgreSQL.
    Rápido (<0.2s) graças ao uso de selectinload com 4 queries SQL em lote.
    """
    res = sincronizar_catalogo_com_banco()
    return {
        "ok": res.get("ok", True),
        "total_secoes_sincronizadas": res.get("total", 0),
        "estados": res.get("estados", []),
        "mensagem": f"{res.get('total', 0)} seções sincronizadas com sucesso do PostgreSQL.",
    }



@app.get("/api/tse-reverso/consolidar")
def api_tse_reverso_consolidar(
    regiao: str = "TODAS",
    uf: str = "TODAS",
    municipio: str = "TODAS",
    zona: str = "TODAS",
    secao: str = "CONSOLIDADO",
    filtro_forense: str = "TODAS",
):
    """
    Retorna a hierarquia completa de 5 níveis (Região -> Estado -> Cidade -> Zona -> Seção/Urna) e:
    - A consolidação global de todas as urnas do nível/filtro (`secao=CONSOLIDADO`), OU
    - O dossiê forense individual da urna escolhida (`secao=<prefixo>`).
    Suporta `filtro_forense` (`TODAS`, `APENAS_DIVERGENTES`, `CAND:<num>`, `DIV_CAND:<num>`).
    """
    return consolidar_secoes_tse(
        regiao_filtro=regiao,
        uf_filtro=uf,
        municipio_filtro=municipio,
        zona_filtro=zona,
        secao_filtro=secao,
        filtro_forense=filtro_forense,
    )


@app.post("/api/tse-reverso/reauditar-divergentes")
def api_tse_reverso_reauditar_divergentes():
    """
    Reprocessa as urnas marcadas com divergência isolando cada container `VotosCargo`
    (`81 01 01` = Presidente vs 2º cargo/consulta popular), sem exigir novo upload.
    """
    return reauditar_urnas_divergentes_catalogo()


@app.delete("/api/tse-reverso/catalogo")
def api_tse_reverso_limpar_catalogo():
    """Limpa todas as seções/urnas carregadas no catálogo de Engenharia Reversa TSE."""
    return limpar_catalogo_tse()


@app.post("/api/tse-reverso/amostra-pr")
def api_tse_reverso_amostra_pr():
    """
    Carrega instantaneamente a Seção Oficial 0017 (Zona 0171 - Almirante Tamandaré/PR - 2º Turno 2026)
    incluída no servidor, indexa no catálogo estadual e retorna o dossiê.
    """
    sample_dir = os.path.join(BASE_DIR, "samples_tse_pr")
    paths = glob.glob(os.path.join(sample_dir, "o03221pr7407101710017-*"))
    if not paths:
        raise HTTPException(status_code=404, detail="Arquivos de amostra PR não encontrados no container.")

    arquivos_dict = {}
    for p in paths:
        with open(p, "rb") as fp:
            arquivos_dict[os.path.basename(p)] = fp.read()

    lote_res = processar_lote_arquivos_tse(arquivos_dict)
    return lote_res["ultimo_relatorio_individual"]


@app.get("/api/tse-reverso/status-banco")
def api_tse_reverso_status_banco():
    """
    Retorna o status físico de armazenamento e volumetria das tabelas do PostgreSQL:
    total de seções, estados, municípios, apurações e métricas de log cadastradas.
    """
    from .database import TseSecao, TseApuracaoBU, TseMetricasLog, TseVotoCandidato, DATABASE_URL
    from .tse_reverse_analyzer import TSE_ZERO_DISK_RAW, _carregar_catalogo_disco
    db = SessionLocal()
    try:
        total_secoes_db = db.query(TseSecao).count()
        total_ufs_db = db.query(TseSecao.uf).distinct().count()
        total_municipios = db.query(TseSecao.municipio_codigo).distinct().count()
        total_bu = db.query(TseApuracaoBU).count()
        total_metricas = db.query(TseMetricasLog).count()
        total_votos = db.query(TseVotoCandidato).count()

        catalogo = _carregar_catalogo_disco()
        total_catalogo = len(catalogo)
        ufs_catalogo = list(set(s.get("uf") for s in catalogo.values() if s.get("uf")))

        total_secoes = max(total_secoes_db, total_catalogo)
        total_ufs = max(total_ufs_db, len(ufs_catalogo))

        return {
            "banco": "PostgreSQL" if "postgres" in DATABASE_URL.lower() else "SQLite",
            "zero_disk_raw_ativo": TSE_ZERO_DISK_RAW,
            "total_secoes": total_secoes,
            "total_secoes_db": total_secoes_db,
            "total_secoes_catalogo": total_catalogo,
            "total_ufs": total_ufs,
            "total_ufs_db": total_ufs_db,
            "total_ufs_catalogo": len(ufs_catalogo),
            "ufs_catalogo": ufs_catalogo,
            "total_municipios": total_municipios,
            "total_apuracoes_bu": total_bu,
            "total_metricas_log": total_metricas,
            "total_registros_votos": total_votos,
        }
    finally:
        db.close()




