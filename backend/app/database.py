import os
import json
from datetime import datetime, timezone
from sqlalchemy import (
    create_engine, Column, Integer, SmallInteger, String, Boolean,
    DateTime, Text, text, ForeignKey, Index, UniqueConstraint
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship, Session

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./data/urna_eleitoral.db")

if DATABASE_URL.startswith("sqlite"):
    os.makedirs("./data", exist_ok=True)
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
else:
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class SeccaoConfig(Base):
    """Estado operacional da Urna e do Terminal do Mesário na Seção Eleitoral."""
    __tablename__ = "seccao_config"

    id = Column(Integer, primary_key=True, index=True)
    zona = Column(String(10), default=os.getenv("URNA_ZONA", "0001"))
    secao = Column(String(10), default=os.getenv("URNA_SECAO", "0105"))
    municipio = Column(String(100), default=os.getenv("URNA_MUNICIPIO", "BRASILIA - DF"))
    turno = Column(Integer, default=1)  # 1 = Primeiro Turno, 2 = Segundo Turno
    status = Column(String(30), default="NAO_INICIALIZADA")
    # Estados possíveis: NAO_INICIALIZADA -> EM_VOTACAO -> ENCERRADA
    terminal_eleitor_liberado = Column(Boolean, default=False)
    eleitor_habilitado_titulo = Column(String(20), nullable=True)
    eleitores_aptos = Column(Integer, default=450)
    eleitores_compareceram = Column(Integer, default=0)
    zeresima_timestamp = Column(DateTime, nullable=True)
    abertura_timestamp = Column(DateTime, nullable=True)
    encerramento_timestamp = Column(DateTime, nullable=True)
    ultimo_hash_log = Column(String(64), default="0" * 64)


class EleitorSeccao(Base):
    """Caderno de Votação do Terminal do Mesário (Título, CPF, Biometria e Controle de Presença por Turno)."""
    __tablename__ = "eleitores_seccao"

    id = Column(Integer, primary_key=True, index=True)
    titulo = Column(String(20), unique=True, index=True, nullable=False)
    cpf = Column(String(14), index=True, nullable=False)
    nome = Column(String(120), nullable=False)
    data_nascimento = Column(String(12), nullable=False)
    nome_mae = Column(String(120), nullable=True)
    biometria_cadastrada = Column(Boolean, default=True)
    hash_template_biometrico = Column(String(64), nullable=False)
    votou_turno_1 = Column(Boolean, default=False)
    votou_turno_2 = Column(Boolean, default=False)


class Partido(Base):
    """Partidos e Federações para validação de voto de legenda e associação de candidatos."""
    __tablename__ = "partidos"

    id = Column(Integer, primary_key=True, index=True)
    numero = Column(String(2), unique=True, index=True, nullable=False)
    sigla = Column(String(20), nullable=False)
    nome = Column(String(100), nullable=False)


class Candidato(Base):
    """Cadastro de Candidatos por Cargo e Turno."""
    __tablename__ = "candidatos"

    id = Column(Integer, primary_key=True, index=True)
    cargo = Column(String(40), index=True, nullable=False)
    numero = Column(String(5), index=True, nullable=False)
    nome_urna = Column(String(100), nullable=False)
    nome_completo = Column(String(150), nullable=True)
    sigla_partido = Column(String(20), nullable=False)
    numero_partido = Column(String(2), index=True, nullable=False)
    vice_ou_suplente1 = Column(String(100), nullable=True)
    suplente2 = Column(String(100), nullable=True)
    turno = Column(Integer, default=1)
    foto_svg = Column(Text, nullable=True)


class RegistroDigitalVoto(Base):
    """
    RDV (Registro Digital do Voto):
    Armazena cada voto individual sem vínculo com o eleitor ou timestamp sequencial direto,
    usando chave de embaralhamento (shuffle_key) para garantir o sigilo constitucional do voto.
    """
    __tablename__ = "rdv_votos"

    id = Column(Integer, primary_key=True, index=True)
    shuffle_key = Column(String(64), index=True, nullable=False)
    turno = Column(Integer, nullable=False)
    cargo = Column(String(40), index=True, nullable=False)
    tipo_voto = Column(String(20), nullable=False)  # NOMINAL, LEGENDA, BRANCO, NULO
    numero_digitado = Column(String(10), nullable=True)
    partido_legenda = Column(String(2), nullable=True)
    hash_integridade = Column(String(64), nullable=False)


class LogAuditoriaUrna(Base):
    """Log encadeado por SHA-256 (Merkle-like chain) para auditoria da seção."""
    __tablename__ = "log_auditoria"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    evento = Column(String(60), nullable=False)
    detalhes = Column(Text, nullable=False)
    hash_anterior = Column(String(64), nullable=False)
    hash_atual = Column(String(64), nullable=False)


# ==============================================================================
# MODELAGEM COMPACTA TSE (BRASIL INTEIRO — ZERO-DISK RAW)
# Otimizado para PostgreSQL: armazenamento ultraleve (~2.2 GB para o país todo)
# e tempos de resposta instantâneos (< 10ms) em árvores e comparativos 1T vs 2T.
# ==============================================================================

class TseSecao(Base):
    """
    Cadastro Geográfico Unificado das Seções Eleitorais do Brasil (~472.000 seções).
    Agrega o 1º e o 2º turno sob a mesma chave física.
    """
    __tablename__ = "tse_secoes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    chave_secao = Column(String(30), unique=True, index=True, nullable=False)  # Ex: "PR_74071_0171_0017"
    regiao = Column(String(15), index=True, nullable=False)  # SUL, SUDESTE, NORDESTE, NORTE, CENTRO-OESTE, EXTERIOR
    uf = Column(String(2), index=True, nullable=False)  # Ex: "PR"
    municipio_codigo = Column(String(5), index=True, nullable=False)  # Código TSE (ex: "74071")
    municipio_nome = Column(String(60), index=True, nullable=False)  # Ex: "CURITIBA"
    zona = Column(Integer, index=True, nullable=False)  # Ex: 171
    secao = Column(Integer, index=True, nullable=False)  # Ex: 17
    local_votacao = Column(String(100), nullable=True)
    modelo_urna = Column(String(10), nullable=True)  # Ex: "UE2020", "UE2015"
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relacionamentos
    apuracoes = relationship("TseApuracaoBU", back_populates="secao_rel", cascade="all, delete-orphan")
    votos_candidatos = relationship("TseVotoCandidato", back_populates="secao_rel", cascade="all, delete-orphan")
    metricas_log = relationship("TseMetricasLog", back_populates="secao_rel", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_tse_secoes_arvore", "regiao", "uf", "municipio_nome", "zona", "secao"),
        Index("idx_tse_secoes_geo", "uf", "municipio_codigo", "zona", "secao"),
    )


class TseApuracaoBU(Base):
    """
    Totais e apuração do Boletim de Urna (BU) por turno (~944.000 registros para o Brasil).
    """
    __tablename__ = "tse_apuracao_bu"

    id = Column(Integer, primary_key=True, autoincrement=True)
    secao_id = Column(Integer, ForeignKey("tse_secoes.id", ondelete="CASCADE"), index=True, nullable=False)
    turno = Column(SmallInteger, index=True, nullable=False)  # 1 ou 2
    pleito = Column(String(10), nullable=True)  # "03220" (1T) ou "03221" (2T)

    eleitores_aptos = Column(Integer, default=0)
    comparecimento = Column(Integer, default=0)
    faltosos = Column(Integer, default=0)
    votos_nominais = Column(Integer, default=0)
    votos_brancos = Column(Integer, default=0)
    votos_nulos = Column(Integer, default=0)
    votos_legenda = Column(Integer, default=0)

    # Hashes criptográficos e integridade oficial
    hash_bu_sha256 = Column(String(64), nullable=True)
    mac_urna = Column(String(64), nullable=True)
    divergencia_detectada = Column(Boolean, default=False)
    divergencia_descricao = Column(Text, nullable=True)

    secao_rel = relationship("TseSecao", back_populates="apuracoes")

    __table_args__ = (
        UniqueConstraint("secao_id", "turno", name="uq_tse_bu_secao_turno"),
        Index("idx_tse_bu_turno_hash", "turno", "hash_bu_sha256"),
    )


class TseVotoCandidato(Base):
    """
    Votação nominal por candidato e seção.
    Focado primariamente em Presidente (1ºT e 2ºT).
    """
    __tablename__ = "tse_votos_candidatos"

    id = Column(Integer, primary_key=True, autoincrement=True)
    secao_id = Column(Integer, ForeignKey("tse_secoes.id", ondelete="CASCADE"), index=True, nullable=False)
    turno = Column(SmallInteger, index=True, nullable=False)  # 1 ou 2
    cargo = Column(String(30), default="PRESIDENTE", index=True, nullable=False)
    numero_candidato = Column(Integer, index=True, nullable=False)  # Ex: 13, 22
    nome_candidato = Column(String(60), nullable=True)
    quantidade_votos = Column(Integer, default=0, nullable=False)

    secao_rel = relationship("TseSecao", back_populates="votos_candidatos")

    __table_args__ = (
        UniqueConstraint("secao_id", "turno", "cargo", "numero_candidato", name="uq_tse_voto_secao_cand"),
        Index("idx_tse_votos_cand_total", "cargo", "turno", "numero_candidato"),
    )


class TseMetricasLog(Base):
    """
    Métricas operacionais e forenses do arquivo de log da urna (.logjez).
    Armazena a contagem de teclas indevidas estritamente isoladas para Presidente.
    """
    __tablename__ = "tse_metricas_log"

    id = Column(Integer, primary_key=True, autoincrement=True)
    secao_id = Column(Integer, ForeignKey("tse_secoes.id", ondelete="CASCADE"), index=True, nullable=False)
    turno = Column(SmallInteger, index=True, nullable=False)  # 1 ou 2

    # Teclas indevidas (com a separação forense estrita)
    teclas_indevidas_pres = Column(Integer, default=0)  # Isoladas estritamente durante o voto para Presidente
    teclas_indevidas_total = Column(Integer, default=0)  # Total geral na urna (todos os cargos)

    # Tempos operacionais e vazão
    total_votos_computados = Column(Integer, default=0)
    tempo_medio_voto_segundos = Column(Integer, default=0)
    tempo_mediano_voto_segundos = Column(Integer, default=0)
    primeiro_voto_timestamp = Column(DateTime, nullable=True)
    ultimo_voto_timestamp = Column(DateTime, nullable=True)

    # Curva de vazão horária compacta (formato JSON: [h8, h9, ..., h17])
    vazao_horaria_json = Column(Text, nullable=True)

    secao_rel = relationship("TseSecao", back_populates="metricas_log")

    __table_args__ = (
        UniqueConstraint("secao_id", "turno", name="uq_tse_log_secao_turno"),
    )


class TseHistoricoUpload(Base):
    """
    Histórico e Auditoria de Ingestão de Arquivos e Pastas do TSE.
    Permite rastrear cada upload realizado (Pasta Aberta ou .ZIP),
    quantas urnas foram identificadas, novas gravadas no PostgreSQL,
    duplicadas ignoradas, erros e tempo de processamento.
    """
    __tablename__ = "tse_historico_upload"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String(64), unique=True, index=True, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    finalizado_em = Column(DateTime, nullable=True)
    tipo_envio = Column(String(30), default="PASTA_ABERTA")  # PASTA_ABERTA, ARQUIVO_ZIP, LOTE_AVULSO
    nome_origem = Column(String(255), default="Upload Avulso")
    uf = Column(String(20), default="DESCONHECIDO")  # "PR", "SC", "PR, SC", etc.
    total_arquivos_recebidos = Column(Integer, default=0)
    total_urnas_detectadas = Column(Integer, default=0)
    total_urnas_novas_gravadas = Column(Integer, default=0)
    total_urnas_duplicadas_ignoradas = Column(Integer, default=0)
    total_erros = Column(Integer, default=0)
    status = Column(String(30), default="EM_ANDAMENTO")  # EM_ANDAMENTO, CONCLUIDO, CONCLUIDO_COM_AVISOS, ERRO
    duracao_segundos = Column(Integer, default=0)
    mensagem_resumo = Column(Text, nullable=True)
    detalhes_json = Column(Text, nullable=True)

    __table_args__ = (
        Index("idx_tse_historico_data", "created_at"),
    )


# Mapeamento Oficial de Regiões do Brasil
ESTADOS_E_REGIOES_BR = {
    "AC": {"nome": "Acre", "regiao": "NORTE"},
    "AL": {"nome": "Alagoas", "regiao": "NORDESTE"},
    "AM": {"nome": "Amazonas", "regiao": "NORTE"},
    "AP": {"nome": "Amapá", "regiao": "NORTE"},
    "BA": {"nome": "Bahia", "regiao": "NORDESTE"},
    "CE": {"nome": "Ceará", "regiao": "NORDESTE"},
    "DF": {"nome": "Distrito Federal", "regiao": "CENTRO-OESTE"},
    "ES": {"nome": "Espírito Santo", "regiao": "SUDESTE"},
    "GO": {"nome": "Goiás", "regiao": "CENTRO-OESTE"},
    "MA": {"nome": "Maranhão", "regiao": "NORDESTE"},
    "MG": {"nome": "Minas Gerais", "regiao": "SUDESTE"},
    "MS": {"nome": "Mato Grosso do Sul", "regiao": "CENTRO-OESTE"},
    "MT": {"nome": "Mato Grosso", "regiao": "CENTRO-OESTE"},
    "PA": {"nome": "Pará", "regiao": "NORTE"},
    "PB": {"nome": "Paraíba", "regiao": "NORDESTE"},
    "PE": {"nome": "Pernambuco", "regiao": "NORDESTE"},
    "PI": {"nome": "Piauí", "regiao": "NORDESTE"},
    "PR": {"nome": "Paraná", "regiao": "SUL"},
    "RJ": {"nome": "Rio de Janeiro", "regiao": "SUDESTE"},
    "RN": {"nome": "Rio Grande do Norte", "regiao": "NORDESTE"},
    "RO": {"nome": "Rondônia", "regiao": "NORTE"},
    "RR": {"nome": "Roraima", "regiao": "NORTE"},
    "RS": {"nome": "Rio Grande do Sul", "regiao": "SUL"},
    "SC": {"nome": "Santa Catarina", "regiao": "SUL"},
    "SE": {"nome": "Sergipe", "regiao": "NORDESTE"},
    "SP": {"nome": "São Paulo", "regiao": "SUDESTE"},
    "TO": {"nome": "Tocantins", "regiao": "NORTE"},
    "ZZ": {"nome": "Exterior", "regiao": "EXTERIOR"},
}


def obter_regiao_uf(uf: str) -> str:
    sigla = (uf or "").upper().strip()
    return ESTADOS_E_REGIOES_BR.get(sigla, {}).get("regiao", "EXTERIOR" if sigla == "ZZ" else "OUTRO")


def salvar_resumo_tse_no_banco(db, resumo: dict, relatorio_completo: dict = None, auto_commit: bool = True) -> TseSecao:
    """
    Persiste de forma normalizada e atômica um resumo de urna no banco PostgreSQL.
    Permite agregação transparente de 1º e 2º turno na mesma seção física.
    """
    uf = (resumo.get("uf") or "PR").upper().strip()
    mun_cod = str(resumo.get("municipio_codigo") or "00000").strip()
    mun_nome = str(resumo.get("municipio_nome") or f"MUNICÍPIO {mun_cod}").upper().strip()
    
    try:
        zona_int = int(resumo.get("zona") or 0)
    except Exception:
        zona_int = 0
    try:
        secao_int = int(resumo.get("secao") or 0)
    except Exception:
        secao_int = 0

    chave_secao = f"{uf}_{mun_cod}_{zona_int:04d}_{secao_int:04d}"
    regiao = obter_regiao_uf(uf)

    # 1. Obter ou Criar a Seção Física Unificada
    secao_db = db.query(TseSecao).filter(TseSecao.chave_secao == chave_secao).first()
    if not secao_db:
        secao_db = TseSecao(
            chave_secao=chave_secao,
            regiao=regiao,
            uf=uf,
            municipio_codigo=mun_cod,
            municipio_nome=mun_nome,
            zona=zona_int,
            secao=secao_int,
            local_votacao=resumo.get("local_votacao") if resumo.get("local_votacao") != "-" else None,
            modelo_urna=resumo.get("modelo_ue") or "UE2020",
        )
        db.add(secao_db)
        db.flush()
    else:
        # Atualiza metadados se disponíveis
        if not secao_db.local_votacao and resumo.get("local_votacao") and resumo.get("local_votacao") != "-":
            secao_db.local_votacao = resumo.get("local_votacao")
        if resumo.get("modelo_ue") and secao_db.modelo_urna != resumo.get("modelo_ue"):
            secao_db.modelo_urna = resumo.get("modelo_ue")

    turno_pacote = int(resumo.get("turno_pacote") or 2)

    # 2. Upsert Apuração BU (Turno do Pacote)
    bu_db = db.query(TseApuracaoBU).filter(
        TseApuracaoBU.secao_id == secao_db.id,
        TseApuracaoBU.turno == turno_pacote
    ).first()
    if not bu_db:
        bu_db = TseApuracaoBU(
            secao_id=secao_db.id,
            turno=turno_pacote,
            pleito=resumo.get("prefixo", "")[:6] if resumo.get("prefixo") else None,
            eleitores_aptos=int(resumo.get("eleitores_aptos") or 0),
            comparecimento=int(resumo.get("comparecimento_bu") or resumo.get("comparecimento_efetivo") or 0),
            faltosos=int(resumo.get("faltosos") or 0),
            votos_brancos=int(resumo.get("brancos_bu") or resumo.get("brancos_rdv") or 0),
            votos_nulos=int(resumo.get("nulos_bu") or resumo.get("nulos_rdv") or 0),
            divergencia_detectada=resumo.get("nivel_risco") == "CRITICO",
            divergencia_descricao=resumo.get("veredito_geral"),
        )
        db.add(bu_db)
    else:
        bu_db.eleitores_aptos = int(resumo.get("eleitores_aptos") or bu_db.eleitores_aptos)
        bu_db.comparecimento = int(resumo.get("comparecimento_bu") or resumo.get("comparecimento_efetivo") or bu_db.comparecimento)
        bu_db.faltosos = int(resumo.get("faltosos") or bu_db.faltosos)
        bu_db.votos_brancos = int(resumo.get("brancos_bu") or resumo.get("brancos_rdv") or bu_db.votos_brancos)
        bu_db.votos_nulos = int(resumo.get("nulos_bu") or resumo.get("nulos_rdv") or bu_db.votos_nulos)

    # 3. Upsert Votos dos Candidatos a Presidente
    candidatos_list = resumo.get("candidatos", [])
    if candidatos_list:
        for cand in candidatos_list:
            try:
                num_cand = int(cand.get("numero") or 0)
            except Exception:
                continue
            if not num_cand:
                continue
            voto_db = db.query(TseVotoCandidato).filter(
                TseVotoCandidato.secao_id == secao_db.id,
                TseVotoCandidato.turno == turno_pacote,
                TseVotoCandidato.cargo == "PRESIDENTE",
                TseVotoCandidato.numero_candidato == num_cand
            ).first()
            if not voto_db:
                voto_db = TseVotoCandidato(
                    secao_id=secao_db.id,
                    turno=turno_pacote,
                    cargo="PRESIDENTE",
                    numero_candidato=num_cand,
                    nome_candidato=cand.get("nome"),
                    quantidade_votos=int(cand.get("votos") or 0),
                )
                db.add(voto_db)
            else:
                voto_db.quantidade_votos = int(cand.get("votos") or voto_db.quantidade_votos)
                if cand.get("nome"):
                    voto_db.nome_candidato = cand.get("nome")

    # 4. Upsert Métricas do Log (Turno Principal do Pacote)
    teclas_pres_t2 = int(resumo.get("total_teclas_indevidas_presidente_t2") or resumo.get("total_teclas_indevidas_presidente") or 0)
    teclas_totais_t2 = int(resumo.get("total_teclas_indevidas_t2") or resumo.get("total_teclas_indevidas") or 0)
    tempo_medio_t2 = int(round(float(resumo.get("tempo_medio_cabine_s") or resumo.get("tempo_medio_ciclo_s") or 0.0)))
    vazao_t2 = json.dumps(resumo.get("votos_por_hora", {})) if resumo.get("votos_por_hora") else None

    metricas_t2 = db.query(TseMetricasLog).filter(
        TseMetricasLog.secao_id == secao_db.id,
        TseMetricasLog.turno == turno_pacote
    ).first()
    if not metricas_t2:
        metricas_t2 = TseMetricasLog(
            secao_id=secao_db.id,
            turno=turno_pacote,
            teclas_indevidas_pres=teclas_pres_t2,
            teclas_indevidas_total=teclas_totais_t2,
            total_votos_computados=int(resumo.get("comparecimento_log") or 0),
            tempo_medio_voto_segundos=tempo_medio_t2,
            vazao_horaria_json=vazao_t2,
        )
        db.add(metricas_t2)
    else:
        metricas_t2.teclas_indevidas_pres = teclas_pres_t2
        metricas_t2.teclas_indevidas_total = teclas_totais_t2
        metricas_t2.tempo_medio_voto_segundos = tempo_medio_t2
        if vazao_t2:
            metricas_t2.vazao_horaria_json = vazao_t2

    # 5. Se o log acumula dados do 1º Turno (Mídia Interna), salva também as métricas do 1º Turno
    if resumo.get("tem_comparativo_1t_log"):
        teclas_pres_t1 = int(resumo.get("total_teclas_indevidas_presidente_t1") or 0)
        teclas_totais_t1 = int(resumo.get("total_teclas_indevidas_t1") or 0)
        tempo_medio_t1 = int(round(float(resumo.get("tempo_medio_cabine_t1_s") or resumo.get("tempo_medio_ciclo_t1_s") or 0.0)))
        vazao_t1 = json.dumps(resumo.get("votos_por_hora_t1", {})) if resumo.get("votos_por_hora_t1") else None

        metricas_t1 = db.query(TseMetricasLog).filter(
            TseMetricasLog.secao_id == secao_db.id,
            TseMetricasLog.turno == 1
        ).first()
        if not metricas_t1:
            metricas_t1 = TseMetricasLog(
                secao_id=secao_db.id,
                turno=1,
                teclas_indevidas_pres=teclas_pres_t1,
                teclas_indevidas_total=teclas_totais_t1,
                total_votos_computados=int(resumo.get("comparecimento_log_t1") or 0),
                tempo_medio_voto_segundos=tempo_medio_t1,
                vazao_horaria_json=vazao_t1,
            )
            db.add(metricas_t1)
        else:
            metricas_t1.teclas_indevidas_pres = teclas_pres_t1
            metricas_t1.teclas_indevidas_total = teclas_totais_t1
            metricas_t1.tempo_medio_voto_segundos = tempo_medio_t1
            if vazao_t1:
                metricas_t1.vazao_horaria_json = vazao_t1

    if auto_commit:
        db.commit()
    return secao_db


# ==============================================================================
# AUDITORIA E HISTÓRICO DE UPLOADS E INGESTÃO DO TSE
# ==============================================================================

def criar_historico_upload(
    db: Session,
    job_id: str,
    tipo_envio: str = "PASTA_ABERTA",
    nome_origem: str = "Pasta Selecionada",
    uf: str = "DESCONHECIDO",
    total_arquivos: int = 0,
    total_urnas: int = 0,
    total_duplicadas_ignoradas: int = 0,
) -> TseHistoricoUpload:
    """Registra o início de uma sessão de upload de arquivos/pastas no histórico."""
    registro = TseHistoricoUpload(
        job_id=job_id,
        tipo_envio=tipo_envio,
        nome_origem=nome_origem,
        uf=uf.upper().strip(),
        total_arquivos_recebidos=total_arquivos,
        total_urnas_detectadas=total_urnas,
        total_urnas_novas_gravadas=0,
        total_urnas_duplicadas_ignoradas=total_duplicadas_ignoradas,
        total_erros=0,
        status="EM_ANDAMENTO",
        mensagem_resumo=f"Iniciado upload ({tipo_envio}): {total_urnas} urnas detectadas.",
        detalhes_json=json.dumps({"municipios": {}, "erros": []}, ensure_ascii=False),
    )
    db.add(registro)
    db.commit()
    db.refresh(registro)
    return registro


def atualizar_historico_upload(
    db: Session,
    job_id: str,
    arquivos_add: int = 0,
    urnas_novas_add: int = 0,
    urnas_duplicadas_add: int = 0,
    erros_add: int = 0,
    uf: str = None,
    erro_detalhe: str = None,
    municipio_detalhe: dict = None,
):
    """Atualiza atomicamente as métricas e o progresso da sessão de upload."""
    registro = db.query(TseHistoricoUpload).filter(TseHistoricoUpload.job_id == job_id).first()
    if not registro:
        return None

    registro.total_arquivos_recebidos = (registro.total_arquivos_recebidos or 0) + arquivos_add
    registro.total_urnas_novas_gravadas = (registro.total_urnas_novas_gravadas or 0) + urnas_novas_add
    registro.total_urnas_duplicadas_ignoradas = (registro.total_urnas_duplicadas_ignoradas or 0) + urnas_duplicadas_add
    registro.total_erros = (registro.total_erros or 0) + erros_add

    if uf and uf != "DESCONHECIDO":
        ufs_atuais = set(x.strip() for x in (registro.uf or "").split(",") if x.strip() and x.strip() != "DESCONHECIDO")
        ufs_atuais.add(uf.upper().strip())
        registro.uf = ", ".join(sorted(ufs_atuais))

    try:
        detalhes = json.loads(registro.detalhes_json or "{}")
    except Exception:
        detalhes = {"municipios": {}, "erros": []}

    if erro_detalhe:
        detalhes.setdefault("erros", []).append(erro_detalhe)

    if municipio_detalhe:
        muns = detalhes.setdefault("municipios", {})
        mc = str(municipio_detalhe.get("codigo", "00000"))
        mn = str(municipio_detalhe.get("nome", f"MUNICÍPIO {mc}"))
        if mc not in muns:
            muns[mc] = {"nome": mn, "urnas": 0}
        muns[mc]["urnas"] += 1

    registro.detalhes_json = json.dumps(detalhes, ensure_ascii=False)
    db.commit()
    return registro


def finalizar_historico_upload(
    db: Session,
    job_id: str,
    status: str = "CONCLUIDO",
    mensagem: str = None,
    detalhes_adicionais: dict = None,
) -> TseHistoricoUpload | None:
    """Finaliza o registro de upload gravando o tempo de processamento e resumo."""
    registro = db.query(TseHistoricoUpload).filter(TseHistoricoUpload.job_id == job_id).first()
    if not registro:
        return None

    agora = datetime.now(timezone.utc)
    registro.finalizado_em = agora
    if registro.created_at:
        try:
            delta = (agora - registro.created_at.replace(tzinfo=timezone.utc)).total_seconds()
            registro.duracao_segundos = max(1, int(round(delta)))
        except Exception:
            registro.duracao_segundos = 0

    if registro.total_erros and registro.total_erros > 0:
        status = "CONCLUIDO_COM_AVISOS" if status == "CONCLUIDO" else status

    registro.status = status
    if mensagem:
        registro.mensagem_resumo = mensagem
    else:
        registro.mensagem_resumo = (
            f"Concluído em {registro.duracao_segundos}s: "
            f"{registro.total_urnas_novas_gravadas} urnas novas gravadas no PostgreSQL, "
            f"{registro.total_urnas_duplicadas_ignoradas} ignoradas (já salvas), "
            f"{registro.total_erros} erros."
        )

    if detalhes_adicionais:
        try:
            det = json.loads(registro.detalhes_json or "{}")
            det.update(detalhes_adicionais)
            registro.detalhes_json = json.dumps(det, ensure_ascii=False)
        except Exception:
            pass

    db.commit()
    db.refresh(registro)
    return registro


def listar_historico_uploads(db: Session, limit: int = 100) -> list[dict]:
    """Retorna a lista cronológica decrescente dos uploads de auditoria."""
    registros = (
        db.query(TseHistoricoUpload)
        .order_by(TseHistoricoUpload.created_at.desc())
        .limit(limit)
        .all()
    )
    resultado = []
    for r in registros:
        det = {}
        if r.detalhes_json:
            try:
                det = json.loads(r.detalhes_json)
            except Exception:
                pass
        resultado.append({
            "id": r.id,
            "job_id": r.job_id,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "finalizado_em": r.finalizado_em.isoformat() if r.finalizado_em else None,
            "tipo_envio": r.tipo_envio,
            "nome_origem": r.nome_origem,
            "uf": r.uf,
            "total_arquivos_recebidos": r.total_arquivos_recebidos or 0,
            "total_urnas_detectadas": r.total_urnas_detectadas or 0,
            "total_urnas_novas_gravadas": r.total_urnas_novas_gravadas or 0,
            "total_urnas_duplicadas_ignoradas": r.total_urnas_duplicadas_ignoradas or 0,
            "total_erros": r.total_erros or 0,
            "status": r.status,
            "duracao_segundos": r.duracao_segundos or 0,
            "mensagem_resumo": r.mensagem_resumo,
            "detalhes": det,
        })
    return resultado


def excluir_historico_upload(db: Session, upload_id: int) -> bool:
    """Exclui um registro individual do histórico."""
    reg = db.query(TseHistoricoUpload).filter(TseHistoricoUpload.id == upload_id).first()
    if reg:
        db.delete(reg)
        db.commit()
        return True
    return False


# ==============================================================================
# CONSULTAS DE NAVEGAÇÃO EM ÁRVORE E CONSOLIDAÇÃO FORENSE (SUB-10MS)
# ==============================================================================

def obter_arvore_regioes(db) -> list[dict]:
    """Retorna as regiões disponíveis com contagem de seções."""
    rows = (
        db.query(TseSecao.regiao, text("count(id) as total"))
        .group_by(TseSecao.regiao)
        .order_by(TseSecao.regiao)
        .all()
    )
    return [{"regiao": r[0], "total_secoes": r[1]} for r in rows]


def obter_arvore_ufs(db, regiao: str = None) -> list[dict]:
    """Retorna os Estados (UFs) cadastrados, opcionalmente filtrados por região."""
    q = db.query(TseSecao.uf, TseSecao.regiao, text("count(id) as total"))
    if regiao:
        q = q.filter(TseSecao.regiao == regiao.upper().strip())
    rows = q.group_by(TseSecao.uf, TseSecao.regiao).order_by(TseSecao.uf).all()
    return [
        {
            "uf": r[0],
            "nome": ESTADOS_E_REGIOES_BR.get(r[0], {}).get("nome", r[0]),
            "regiao": r[1],
            "total_secoes": r[2],
        }
        for r in rows
    ]


def obter_arvore_municipios(db, uf: str, busca: str = None) -> list[dict]:
    """Retorna os municípios de uma UF com contagem de seções e suporte a busca textual."""
    q = db.query(TseSecao.municipio_codigo, TseSecao.municipio_nome, text("count(id) as total")).filter(
        TseSecao.uf == uf.upper().strip()
    )
    if busca:
        termo = f"%{busca.strip()}%"
        q = q.filter((TseSecao.municipio_nome.ilike(termo)) | (TseSecao.municipio_codigo.like(termo)))
    rows = (
        q.group_by(TseSecao.municipio_codigo, TseSecao.municipio_nome)
        .order_by(TseSecao.municipio_nome)
        .all()
    )
    return [
        {"codigo": r[0], "nome": r[1], "total_secoes": r[2]}
        for r in rows
    ]


def obter_arvore_zonas(db, uf: str, municipio_codigo: str) -> list[dict]:
    """Retorna as zonas de um município com contagem de seções."""
    rows = (
        db.query(TseSecao.zona, text("count(id) as total"))
        .filter(
            TseSecao.uf == uf.upper().strip(),
            TseSecao.municipio_codigo == str(municipio_codigo).strip()
        )
        .group_by(TseSecao.zona)
        .order_by(TseSecao.zona)
        .all()
    )
    return [{"zona": f"{r[0]:04d}", "zona_num": r[0], "total_secoes": r[1]} for r in rows]


def obter_arvore_secoes(db, uf: str, municipio_codigo: str, zona: int) -> list[dict]:
    """Retorna as seções de uma zona específica."""
    rows = (
        db.query(TseSecao.id, TseSecao.secao, TseSecao.chave_secao, TseSecao.modelo_urna, TseSecao.local_votacao)
        .filter(
            TseSecao.uf == uf.upper().strip(),
            TseSecao.municipio_codigo == str(municipio_codigo).strip(),
            TseSecao.zona == int(zona)
        )
        .order_by(TseSecao.secao)
        .all()
    )
    return [
        {
            "id": r[0],
            "secao": f"{r[1]:04d}",
            "secao_num": r[1],
            "chave_secao": r[2],
            "modelo_urna": r[3] or "UE2020",
            "local_votacao": r[4] or "-",
        }
        for r in rows
    ]


def obter_totais_consolidados_tse(
    db,
    regiao: str = None,
    uf: str = None,
    municipio_codigo: str = None,
    zona: int = None,
    secao: int = None
) -> dict:
    """
    Consolida métricas e apuração em qualquer nível da árvore geográfica:
    Brasil > Região > Estado > Cidade > Zona > Seção.
    """
    # Base filter para seções
    filtro_secao = []
    if regiao:
        filtro_secao.append(TseSecao.regiao == regiao.upper().strip())
    if uf:
        filtro_secao.append(TseSecao.uf == uf.upper().strip())
    if municipio_codigo:
        filtro_secao.append(TseSecao.municipio_codigo == str(municipio_codigo).strip())
    if zona is not None:
        filtro_secao.append(TseSecao.zona == int(zona))
    if secao is not None:
        filtro_secao.append(TseSecao.secao == int(secao))

    # Total de urnas
    total_urnas = db.query(TseSecao.id).filter(*filtro_secao).count()

    # Totais de Apuração por Turno
    totais_bu = (
        db.query(
            TseApuracaoBU.turno,
            text("coalesce(sum(tse_apuracao_bu.eleitores_aptos), 0) as aptos"),
            text("coalesce(sum(tse_apuracao_bu.comparecimento), 0) as comp"),
            text("coalesce(sum(tse_apuracao_bu.faltosos), 0) as faltosos"),
            text("coalesce(sum(tse_apuracao_bu.votos_brancos), 0) as brancos"),
            text("coalesce(sum(tse_apuracao_bu.votos_nulos), 0) as nulos"),
        )
        .join(TseSecao, TseApuracaoBU.secao_id == TseSecao.id)
        .filter(*filtro_secao)
        .group_by(TseApuracaoBU.turno)
        .all()
    )

    bu_t1 = next((r for r in totais_bu if r[0] == 1), (1, 0, 0, 0, 0, 0))
    bu_t2 = next((r for r in totais_bu if r[0] == 2), (2, 0, 0, 0, 0, 0))

    # Votos dos Candidatos a Presidente por Turno
    votos_cand = (
        db.query(
            TseVotoCandidato.turno,
            TseVotoCandidato.numero_candidato,
            TseVotoCandidato.nome_candidato,
            text("coalesce(sum(tse_votos_candidatos.quantidade_votos), 0) as total_votos")
        )
        .join(TseSecao, TseVotoCandidato.secao_id == TseSecao.id)
        .filter(*filtro_secao, TseVotoCandidato.cargo == "PRESIDENTE")
        .group_by(TseVotoCandidato.turno, TseVotoCandidato.numero_candidato, TseVotoCandidato.nome_candidato)
        .order_by(text("total_votos desc"))
        .all()
    )

    candidatos_t1 = [
        {"numero": r[1], "nome": r[2] or f"Candidato {r[1]}", "votos": int(r[3])}
        for r in votos_cand if r[0] == 1
    ]
    candidatos_t2 = [
        {"numero": r[1], "nome": r[2] or f"Candidato {r[1]}", "votos": int(r[3])}
        for r in votos_cand if r[0] == 2
    ]

    # Métricas Operacionais de Log (Teclas Indevidas Isoladas para Presidente)
    metricas = (
        db.query(
            TseMetricasLog.turno,
            text("coalesce(sum(tse_metricas_log.teclas_indevidas_pres), 0) as teclas_pres"),
            text("coalesce(sum(tse_metricas_log.teclas_indevidas_total), 0) as teclas_total"),
            text("coalesce(avg(tse_metricas_log.tempo_medio_voto_segundos), 0) as tempo_medio"),
        )
        .join(TseSecao, TseMetricasLog.secao_id == TseSecao.id)
        .filter(*filtro_secao)
        .group_by(TseMetricasLog.turno)
        .all()
    )

    met_t1 = next((r for r in metricas if r[0] == 1), (1, 0, 0, 0.0))
    met_t2 = next((r for r in metricas if r[0] == 2), (2, 0, 0, 0.0))

    return {
        "total_urnas": total_urnas,
        "turno_1": {
            "aptos": int(bu_t1[1]),
            "comparecimento": int(bu_t1[2]),
            "faltosos": int(bu_t1[3]),
            "brancos": int(bu_t1[4]),
            "nulos": int(bu_t1[5]),
            "candidatos": candidatos_t1,
            "teclas_indevidas_presidente": int(met_t1[1]),
            "teclas_indevidas_total": int(met_t1[2]),
            "tempo_medio_voto_s": float(met_t1[3]),
        },
        "turno_2": {
            "aptos": int(bu_t2[1]),
            "comparecimento": int(bu_t2[2]),
            "faltosos": int(bu_t2[3]),
            "brancos": int(bu_t2[4]),
            "nulos": int(bu_t2[5]),
            "candidatos": candidatos_t2,
            "teclas_indevidas_presidente": int(met_t2[1]),
            "teclas_indevidas_total": int(met_t2[2]),
            "tempo_medio_voto_s": float(met_t2[3]),
        },
    }




def init_db():
    Base.metadata.create_all(bind=engine)
    # Migração automática suave para bancos PostgreSQL/SQLite já criados anteriormente
    with engine.begin() as conn:
        try:
            conn.execute(text("ALTER TABLE seccao_config ADD COLUMN terminal_eleitor_liberado BOOLEAN DEFAULT FALSE"))
        except Exception:
            pass
        try:
            conn.execute(text("ALTER TABLE seccao_config ADD COLUMN eleitor_habilitado_titulo VARCHAR(20)"))
        except Exception:
            pass

