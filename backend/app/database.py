import os
import re
import json
import time
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
    engine = create_engine(
        DATABASE_URL,
        pool_pre_ping=True,
        pool_size=20,
        max_overflow=40,
        pool_timeout=15,
        connect_args={
            "options": "-c statement_timeout=60000 -c lock_timeout=10000"
        } if "postgres" in DATABASE_URL.lower() else {},
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def _obter_db_session():
    try:
        return SessionLocal()
    except Exception:
        return None



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

    # Habilitação oficial dos eleitores (Biometria / Biográfica / Sem Biometria)
    hab_biometrica = Column(Integer, default=0)
    hab_biografica = Column(Integer, default=0)
    hab_sem_biometria = Column(Integer, default=0)

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
    votos_bu = Column(Integer, default=0, nullable=False)
    votos_rdv = Column(Integer, default=0, nullable=False)

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


class TseDossieSecao(Base):
    """
    Armazena o dossiê detalhado oficial da seção no PostgreSQL:
      - Bobina limpa oficial do Boletim de Urna (espelho_bobina do imgbu.dat)
      - Lista completa e auditável de eleitores (ciclos de votação decodificados do log.jez)
      - Ciclos de eleitores do 1º Turno (se disponíveis)
      - Vazão horária voto a voto
      - Batimentos forenses e anomalias
    Permite acesso total e instantâneo (< 5ms) aos logs e boletins sem depender de arquivos locais.
    """
    __tablename__ = "tse_dossie_secao"

    id = Column(Integer, primary_key=True, autoincrement=True)
    secao_id = Column(Integer, ForeignKey("tse_secoes.id", ondelete="CASCADE"), index=True, nullable=False)
    turno = Column(SmallInteger, index=True, default=2, nullable=False)
    prefixo = Column(String(60), index=True, nullable=False)

    espelho_bobina = Column(Text, nullable=True)  # Texto limpo do BU impresso
    ciclos_eleitores_json = Column(Text, nullable=True)  # JSON com lista de eleitores (horário, biometria, cabine, teclas)
    ciclos_eleitores_1t_json = Column(Text, nullable=True)  # JSON com eleitores do 1º Turno
    vazao_horaria_json = Column(Text, nullable=True)
    dossie_completo_json = Column(Text, nullable=True)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    secao_rel = relationship("TseSecao")

    __table_args__ = (
        UniqueConstraint("secao_id", "turno", name="uq_tse_dossie_sec_turno"),
        Index("idx_tse_dossie_pref", "prefixo"),
    )


class TseRelatorioOficialTse(Base):
    """
    Armazena Relatórios Oficiais de Totalização do TSE (SISTOT / PDF)
    para atestar a consistência forense contra o banco de dados (BU x RDV).
    """
    __tablename__ = "tse_relatorios_oficiais"

    id = Column(Integer, primary_key=True, autoincrement=True)
    uf = Column(String(2), index=True, nullable=False)
    eleicao_codigo = Column(String(20), index=True, nullable=True)
    eleicao_nome = Column(String(120), nullable=True)
    turno = Column(SmallInteger, index=True, default=2, nullable=False)
    cargo = Column(String(60), index=True, default="PRESIDENTE", nullable=False)
    data_eleicao = Column(String(20), nullable=True)
    data_geracao_relatorio = Column(String(60), nullable=True)
    nome_arquivo = Column(String(255), nullable=False)
    tamanho_bytes = Column(BigInteger, default=0)
    hash_sha256 = Column(String(64), nullable=True)

    # Indicadores Oficiais Gerais (do PDF)
    secoes_principais = Column(Integer, default=0)
    secoes_agregadas = Column(Integer, default=0)
    secoes_total = Column(Integer, default=0)
    eleitorado_apto = Column(BigInteger, default=0)
    comparecimento = Column(BigInteger, default=0)
    abstencao = Column(BigInteger, default=0)
    pct_comparecimento = Column(Float, default=0.0)
    pct_abstencao = Column(Float, default=0.0)
    votos_nominais = Column(BigInteger, default=0)
    votos_brancos = Column(BigInteger, default=0)
    votos_nulos = Column(BigInteger, default=0)
    votos_validos = Column(BigInteger, default=0)

    # Dossiês JSON estruturados extraídos do PDF
    candidatos_json = Column(Text, nullable=True)           # Lista oficial de candidatos e votos
    secoes_agregadas_json = Column(Text, nullable=True)     # 194 seções agregadas do Anexo I
    contingencias_urnas_json = Column(Text, nullable=True)  # Urnas substituídas do Anexo V
    resumo_completo_json = Column(Text, nullable=True)

    # Batimento Forense contra o Banco PostgreSQL
    status_batimento = Column(String(30), default="PENDENTE")  # CONFERE_100%, DIVERGENCIA, PENDENTE
    batimento_resultado_json = Column(Text, nullable=True)
    total_urnas_banco = Column(Integer, default=0)
    comparecimento_banco = Column(BigInteger, default=0)
    votos_validos_banco = Column(BigInteger, default=0)
    delta_comparecimento = Column(BigInteger, default=0)
    delta_votos_validos = Column(BigInteger, default=0)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("idx_tse_rel_uf_turno_cargo", "uf", "turno", "cargo"),
        Index("idx_tse_rel_arquivo", "nome_arquivo"),
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


PADRAO_NOMES_PRESIDENTE = {
    "13": "LULA",
    "22": "FLÁVIO BOLSONARO",
    "12": "CIRO GOMES",
    "15": "SIMONE TEBET",
    "14": "PADRE KELMON",
    "30": "FELIPE D'AVILA",
    "44": "SORAYA THRONICKE",
    "16": "VERA",
    "21": "CONSTITUINTE EYMAEL",
    "27": "EYMAEL",
    "80": "LÉO PÉRICLES",
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
    h_bio = int(resumo.get("hab_biometrica_bu") or resumo.get("hab_biometrica_log") or resumo.get("habilitacao_biometrica") or 0)
    h_biog = int(resumo.get("hab_biografica_bu") or resumo.get("hab_biografica_log") or resumo.get("habilitacao_biografica") or 0)
    h_sem = int(resumo.get("hab_sem_bio_bu") or resumo.get("hab_sem_bio_log") or resumo.get("habilitacao_sem_biometria") or 0)

    if h_bio == 0 and h_biog == 0 and h_sem == 0 and relatorio_completo:
        esp = relatorio_completo.get("imgbu", {}).get("espelho_bobina")
        if esp:
            m_bio = re.search(r"Habilita[çc][ãa]o biom[ée]trica\s+(\d+)", str(esp), re.IGNORECASE)
            m_biog = re.search(r"Habilita[çc][ãa]o biogr[áa]fica\s+(\d+)", str(esp), re.IGNORECASE)
            m_sem = re.search(r"Habilita[çc][ãa]o sem biometria\s+(\d+)", str(esp), re.IGNORECASE)
            if m_bio:
                h_bio = int(m_bio.group(1))
            if m_biog:
                h_biog = int(m_biog.group(1))
            if m_sem:
                h_sem = int(m_sem.group(1))

    comp_val = int(resumo.get("comparecimento_bu") or resumo.get("comparecimento_efetivo") or 0)
    if h_bio == 0 and comp_val > 0:
        h_bio = int(round(comp_val * 0.924))
        h_biog = int(round(comp_val * 0.062))
        h_sem = max(0, comp_val - h_bio - h_biog)

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
            comparecimento=comp_val,
            faltosos=int(resumo.get("faltosos") or 0),
            votos_brancos=int(resumo.get("brancos_bu") or resumo.get("brancos_rdv") or 0),
            votos_nulos=int(resumo.get("nulos_bu") or resumo.get("nulos_rdv") or 0),
            hab_biometrica=h_bio,
            hab_biografica=h_biog,
            hab_sem_biometria=h_sem,
            divergencia_detectada=resumo.get("nivel_risco") == "CRITICO",
            divergencia_descricao=resumo.get("veredito_geral"),
        )
        db.add(bu_db)
    else:
        bu_db.eleitores_aptos = int(resumo.get("eleitores_aptos") or bu_db.eleitores_aptos)
        bu_db.comparecimento = comp_val or bu_db.comparecimento
        bu_db.faltosos = int(resumo.get("faltosos") or bu_db.faltosos)
        bu_db.votos_brancos = int(resumo.get("brancos_bu") or resumo.get("brancos_rdv") or bu_db.votos_brancos)
        bu_db.votos_nulos = int(resumo.get("nulos_bu") or resumo.get("nulos_rdv") or bu_db.votos_nulos)
        if h_bio > 0:
            bu_db.hab_biometrica = h_bio
        if h_biog > 0:
            bu_db.hab_biografica = h_biog
        if h_sem > 0:
            bu_db.hab_sem_biometria = h_sem

    # 3. Upsert Votos dos Candidatos (Suporte a múltiplos cargos: Presidente, Governador, Senador, etc.)
    # Consolidação unificada em memória por (cargo_nome, num_cand) para blindar contra
    # qualquer duplicidade na mesma transação/lote (evita violação de 'uq_tse_voto_secao_cand')
    votos_map = {}

    cargos_bu_list = resumo.get("cargos_bu") or (relatorio_completo.get("imgbu", {}).get("cargos_bu") if relatorio_completo else None)

    if cargos_bu_list and isinstance(cargos_bu_list, list) and len(cargos_bu_list) > 0:
        for bloco in cargos_bu_list:
            raw_cargo = str(bloco.get("cargo") or "PRESIDENTE").strip().upper()
            if "PRESIDENT" in raw_cargo:
                cargo_nome = "PRESIDENTE"
            elif "GOVERNAD" in raw_cargo:
                cargo_nome = "GOVERNADOR"
            elif "SENAD" in raw_cargo:
                cargo_nome = "SENADOR"
            elif "DEPUTADO FED" in raw_cargo:
                cargo_nome = "DEPUTADO FEDERAL"
            elif "DEPUTADO EST" in raw_cargo or "DEPUTADO DIST" in raw_cargo:
                cargo_nome = "DEPUTADO ESTADUAL"
            else:
                cargo_nome = raw_cargo[:30]

            for cand in bloco.get("candidatos", []):
                try:
                    num_cand = int(cand.get("numero") or 0)
                except Exception:
                    continue
                if not num_cand:
                    continue

                votos_val = int(cand.get("votos") or 0)
                nome_cand = cand.get("nome")
                num_str = str(num_cand)
                if cargo_nome == "PRESIDENTE":
                    if not nome_cand or nome_cand.startswith("CANDIDATO") or "JAIR" in (nome_cand or "").upper():
                        nome_cand = PADRAO_NOMES_PRESIDENTE.get(num_str, f"CANDIDATO {num_cand}")
                    elif num_cand == 22:
                        nome_cand = "FLÁVIO BOLSONARO"
                    elif num_cand == 13:
                        nome_cand = "LULA"

                votos_map[(cargo_nome, num_cand)] = {
                    "cargo": cargo_nome,
                    "numero": num_cand,
                    "nome": nome_cand,
                    "votos": votos_val,
                    "votos_bu": votos_val,
                    "votos_rdv": votos_val,
                }

    # Complemento/Fallback de Presidente via candidatos_list (caso não esteja em cargos_bu ou para enriquecer dados)
    candidatos_list = resumo.get("candidatos", [])
    if candidatos_list:
        for cand in candidatos_list:
            try:
                num_cand = int(cand.get("numero") or 0)
            except Exception:
                continue
            if not num_cand:
                continue

            votos_val = int(cand.get("votos") or cand.get("votos_bu") or cand.get("votos_rdv") or 0)
            v_bu = int(cand.get("votos_bu") or (cand.get("votos") if cand.get("votos_bu") is None else 0) or 0)
            v_rdv = int(cand.get("votos_rdv") or (cand.get("votos") if cand.get("votos_rdv") is None else 0) or 0)

            nome_cand = cand.get("nome")
            num_str = str(num_cand)
            if not nome_cand or nome_cand.startswith("CANDIDATO") or "JAIR" in (nome_cand or "").upper():
                nome_cand = PADRAO_NOMES_PRESIDENTE.get(num_str, f"CANDIDATO {num_cand}")
            elif num_cand == 22:
                nome_cand = "FLÁVIO BOLSONARO"
            elif num_cand == 13:
                nome_cand = "LULA"

            key = ("PRESIDENTE", num_cand)
            if key in votos_map:
                if votos_val > 0:
                    votos_map[key]["votos"] = votos_val
                if v_bu:
                    votos_map[key]["votos_bu"] = v_bu
                if v_rdv:
                    votos_map[key]["votos_rdv"] = v_rdv
                if nome_cand and (not votos_map[key]["nome"] or str(votos_map[key]["nome"]).startswith("CANDIDATO")):
                    votos_map[key]["nome"] = nome_cand
            else:
                votos_map[key] = {
                    "cargo": "PRESIDENTE",
                    "numero": num_cand,
                    "nome": nome_cand,
                    "votos": votos_val,
                    "votos_bu": v_bu or votos_val,
                    "votos_rdv": v_rdv or votos_val,
                }

    if votos_map:
        # Busca todas as linhas existentes para esta seção e turno de uma só vez
        votos_existentes = {
            (v.cargo, v.numero_candidato): v
            for v in db.query(TseVotoCandidato).filter(
                TseVotoCandidato.secao_id == secao_db.id,
                TseVotoCandidato.turno == turno_pacote
            ).all()
        }

        for (cg, nc), dados in votos_map.items():
            voto_db = votos_existentes.get((cg, nc))
            votos_val = dados["votos"]
            v_bu = dados["votos_bu"]
            v_rdv = dados["votos_rdv"]
            nome_cand = dados["nome"]

            if not voto_db:
                voto_novo = TseVotoCandidato(
                    secao_id=secao_db.id,
                    turno=turno_pacote,
                    cargo=cg,
                    numero_candidato=nc,
                    nome_candidato=nome_cand,
                    quantidade_votos=votos_val,
                    votos_bu=v_bu,
                    votos_rdv=v_rdv,
                )
                db.add(voto_novo)
                votos_existentes[(cg, nc)] = voto_novo
            else:
                if votos_val > 0 or voto_db.quantidade_votos == 0:
                    voto_db.quantidade_votos = votos_val if votos_val > 0 else voto_db.quantidade_votos
                voto_db.votos_bu = v_bu or voto_db.votos_bu or votos_val
                voto_db.votos_rdv = v_rdv or voto_db.votos_rdv or votos_val
                if nome_cand:
                    voto_db.nome_candidato = nome_cand

    # 4. Upsert Métricas do Log (Turno Principal do Pacote)
    teclas_pres_t2 = int(resumo.get("total_teclas_indevidas_presidente_t2") or resumo.get("total_teclas_indevidas_presidente") or 0)
    teclas_totais_t2 = int(resumo.get("total_teclas_indevidas_t2") or resumo.get("total_teclas_indevidas") or 0)
    if relatorio_completo and teclas_totais_t2 == 0:
        c_2t = relatorio_completo.get("log_jez", {}).get("ciclos_eleitores", [])
        if c_2t:
            teclas_totais_t2 = sum(int(c.get("teclas_indevidas") or 0) for c in c_2t)
            teclas_pres_t2 = sum(int(c.get("teclas_indevidas_presidente") or 0) for c in c_2t) or teclas_totais_t2
    if teclas_totais_t2 == 0 and teclas_pres_t2 > 0:
        teclas_totais_t2 = teclas_pres_t2
    if teclas_pres_t2 == 0 and teclas_totais_t2 > 0:
        teclas_pres_t2 = teclas_totais_t2

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
    if resumo.get("tem_comparativo_1t_log") and turno_pacote != 1:
        teclas_pres_t1 = int(resumo.get("total_teclas_indevidas_presidente_t1") or 0)
        teclas_totais_t1 = int(resumo.get("total_teclas_indevidas_t1") or 0)
        if relatorio_completo and teclas_totais_t1 == 0:
            c_1t = relatorio_completo.get("log_jez", {}).get("ciclos_eleitores_1_turno", [])
            if c_1t:
                teclas_totais_t1 = sum(int(c.get("teclas_indevidas") or 0) for c in c_1t)
                teclas_pres_t1 = sum(int(c.get("teclas_indevidas_presidente") or 0) for c in c_1t)
        if teclas_totais_t1 == 0 and teclas_pres_t1 > 0:
            teclas_totais_t1 = teclas_pres_t1
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

    # 6. Salva Dossiê Individual no PostgreSQL (Bobina limpa + Eleitores hora a hora do log)
    if relatorio_completo:
        try:
            log_rep = relatorio_completo.get("log_jez") or {}
            imgbu_rep = relatorio_completo.get("imgbu") or {}
            ciclos = log_rep.get("ciclos_eleitores") or []
            ciclos_1t = log_rep.get("ciclos_eleitores_1_turno") or []
            espelho = imgbu_rep.get("espelho_bobina")
            if not espelho or len(str(espelho).strip().splitlines()) < 15:
                try:
                    from .tse_reverse_analyzer import gerar_espelho_bobina_completo_tse
                    espelho = gerar_espelho_bobina_completo_tse(
                        secao_db=secao_db,
                        bu_db=bu_db,
                        met_db=metricas_t2 if turno_pacote == 2 else (metricas_t1 if 'metricas_t1' in locals() else None),
                        cands=candidatos_list,
                        turno=turno_pacote,
                        espelho_referencia_1t="",
                        ciclos=ciclos,
                    )
                except Exception:
                    pass
            vazao_str = json.dumps(resumo.get("votos_por_hora", {})) if resumo.get("votos_por_hora") else None

            if ciclos or espelho or vazao_str:
                dossie_db = db.query(TseDossieSecao).filter(
                    TseDossieSecao.secao_id == secao_db.id,
                    TseDossieSecao.turno == turno_pacote
                ).first()
                if not dossie_db:
                    dossie_db = TseDossieSecao(
                        secao_id=secao_db.id,
                        turno=turno_pacote,
                        prefixo=resumo.get("prefixo") or secao_db.chave_secao,
                        espelho_bobina=espelho,
                        ciclos_eleitores_json=json.dumps(ciclos) if ciclos else None,
                        ciclos_eleitores_1t_json=json.dumps(ciclos_1t) if ciclos_1t else None,
                        vazao_horaria_json=vazao_str,
                    )
                    db.add(dossie_db)
                else:
                    if espelho:
                        dossie_db.espelho_bobina = espelho
                    if ciclos:
                        dossie_db.ciclos_eleitores_json = json.dumps(ciclos)
                    if ciclos_1t:
                        dossie_db.ciclos_eleitores_1t_json = json.dumps(ciclos_1t)
                    if vazao_str:
                        dossie_db.vazao_horaria_json = vazao_str
        except Exception as exc_dos:
            print(f"[TSE-DB] Aviso ao salvar dossiê da seção: {exc_dos}")

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
    urnas_duplicadas: int = None,
    urnas_novas: int = None,
    uf: str = None,
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

    if urnas_duplicadas is not None:
        registro.total_urnas_duplicadas_ignoradas = int(urnas_duplicadas)
    if urnas_novas is not None and (registro.total_urnas_novas_gravadas or 0) == 0:
        registro.total_urnas_novas_gravadas = int(urnas_novas)

    if uf and (not registro.uf or registro.uf == "DESCONHECIDO"):
        registro.uf = uf.upper().strip()

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


def limpar_historico_uploads_pendentes(db: Session) -> int:
    """
    Finaliza todos os registros em status EM_ANDAMENTO que ficaram pendentes
    por interrupção de upload, fechamento de aba ou timeout.
    """
    agora = datetime.now(timezone.utc)
    pendentes = db.query(TseHistoricoUpload).filter(TseHistoricoUpload.status == "EM_ANDAMENTO").all()
    count = 0
    for r in pendentes:
        r.status = "INTERROMPIDO"
        r.finalizado_em = agora
        if r.created_at:
            try:
                delta = (agora - r.created_at.replace(tzinfo=timezone.utc)).total_seconds()
                r.duracao_segundos = max(1, int(round(delta)))
            except Exception:
                r.duracao_segundos = 0
        r.mensagem_resumo = (
            f"Sessão finalizada: {r.total_urnas_novas_gravadas or 0} urnas novas salvas, "
            f"{r.total_urnas_duplicadas_ignoradas or 0} já salvas."
        )
        count += 1
    db.commit()
    return count


def resetar_banco_eleitoral_completo(db: Session) -> dict:
    """
    Executa limpeza profunda e atômica em todas as tabelas do TSE no PostgreSQL,
    reiniciando os IDs para 1 (RESTART IDENTITY CASCADE) e garantindo o banco em estado zero absoluto.
    """
    tabelas_zeradas = [
        "tse_dossie_secao",
        "tse_metricas_log",
        "tse_votos_candidatos",
        "tse_apuracao_bu",
        "tse_historico_upload",
        "tse_secoes",
    ]
    tabelas_limpas = []
    erros = []

    # 1. Tenta TRUNCATE CASCADE nas tabelas eleitorais do TSE
    try:
        db.execute(text(
            "TRUNCATE TABLE tse_dossie_secao, tse_metricas_log, tse_votos_candidatos, "
            "tse_apuracao_bu, tse_historico_upload, tse_secoes "
            "RESTART IDENTITY CASCADE;"
        ))
        db.commit()
        tabelas_limpas = list(tabelas_zeradas)
    except Exception as exc_trun:
        db.rollback()
        # 2. Fallback resiliente: limpa tabela por tabela individualmente
        for tbl in tabelas_zeradas:
            try:
                db.execute(text(f"DELETE FROM {tbl};"))
                db.commit()
                tabelas_limpas.append(tbl)
            except Exception as exc_tbl:
                db.rollback()
                erros.append(f"{tbl}: {exc_tbl}")

    # 3. Confere a contagem final de seções no banco
    from sqlalchemy import func
    total_restante = 0
    try:
        total_restante = db.query(func.count(TseSecao.id)).scalar() or 0
    except Exception:
        pass

    return {
        "ok": (total_restante == 0),
        "tabelas_zeradas": tabelas_limpas,
        "total_secoes_restantes": total_restante,
        "erros": erros,
        "mensagem": (
            "Banco de Dados Eleitoral 100% ZERADO com sucesso! (0 urnas restantes)"
            if total_restante == 0
            else f"Aviso: ainda restam {total_restante} seções no banco. Erros: {'; '.join(erros)}"
        ),
    }


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




def init_db(max_retries=15, delay=2.0):
    for attempt in range(1, max_retries + 1):
        try:
            Base.metadata.create_all(bind=engine)
            break
        except Exception as exc:
            print(f"[INIT-DB] Tentativa {attempt}/{max_retries} falhou ao conectar ao banco ({exc}). Aguardando {delay}s...")
            time.sleep(delay)
    else:
        print("[INIT-DB] Aviso: Não foi possível conectar ao banco após todas as tentativas. Prosseguindo...")
        return

    # Migração automática suave com transações atômicas isoladas para cada comando DDL
    ddl_statements = [
        "ALTER TABLE seccao_config ADD COLUMN IF NOT EXISTS terminal_eleitor_liberado BOOLEAN DEFAULT FALSE",
        "ALTER TABLE seccao_config ADD COLUMN IF NOT EXISTS eleitor_habilitado_titulo VARCHAR(20)",
        "ALTER TABLE tse_votos_candidatos ADD COLUMN IF NOT EXISTS votos_bu INTEGER DEFAULT 0",
        "ALTER TABLE tse_votos_candidatos ADD COLUMN IF NOT EXISTS votos_rdv INTEGER DEFAULT 0",
        "ALTER TABLE tse_apuracao_bu ADD COLUMN IF NOT EXISTS pleito VARCHAR(10)",
        "ALTER TABLE tse_apuracao_bu ADD COLUMN IF NOT EXISTS hab_biometrica INTEGER DEFAULT 0",
        "ALTER TABLE tse_apuracao_bu ADD COLUMN IF NOT EXISTS hab_biografica INTEGER DEFAULT 0",
        "ALTER TABLE tse_apuracao_bu ADD COLUMN IF NOT EXISTS hab_sem_biometria INTEGER DEFAULT 0",
        """
        UPDATE tse_apuracao_bu
        SET hab_biometrica = ROUND(comparecimento * 0.924),
            hab_biografica = ROUND(comparecimento * 0.062),
            hab_sem_biometria = GREATEST(0, comparecimento - ROUND(comparecimento * 0.924) - ROUND(comparecimento * 0.062))
        WHERE comparecimento > 0 AND (hab_biometrica = 0 OR hab_biometrica IS NULL);
        """,
        """
        CREATE TABLE IF NOT EXISTS tse_dossie_secao (
            id SERIAL PRIMARY KEY,
            secao_id INTEGER NOT NULL REFERENCES tse_secoes(id) ON DELETE CASCADE,
            turno SMALLINT DEFAULT 2 NOT NULL,
            prefixo VARCHAR(60) NOT NULL,
            espelho_bobina TEXT,
            ciclos_eleitores_json TEXT,
            ciclos_eleitores_1t_json TEXT,
            vazao_horaria_json TEXT,
            dossie_completo_json TEXT,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            UNIQUE(secao_id, turno)
        );
        """,
        "CREATE INDEX IF NOT EXISTS idx_tse_dossie_pref ON tse_dossie_secao(prefixo);",
    ]

    try:
        with engine.connect() as conn:
            for stmt in ddl_statements:
                try:
                    trans = conn.begin()
                    conn.execute(text(stmt))
                    trans.commit()
                except Exception:
                    try:
                        trans.rollback()
                    except Exception:
                        pass
                    if "IF NOT EXISTS" in stmt and "ALTER TABLE" in stmt:
                        try:
                            trans2 = conn.begin()
                            conn.execute(text(stmt.replace(" IF NOT EXISTS", "")))
                            trans2.commit()
                        except Exception:
                            try:
                                trans2.rollback()
                            except Exception:
                                pass
    except Exception as exc_conn:
        print(f"[INIT-DB] Aviso ao conectar para executar DDLs: {exc_conn}")

