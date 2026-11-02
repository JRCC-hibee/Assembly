import os
from datetime import datetime, timezone
from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Text, text
from sqlalchemy.orm import declarative_base, sessionmaker

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
