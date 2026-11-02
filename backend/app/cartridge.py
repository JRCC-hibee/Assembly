import os
import json
import zipfile
import hashlib
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from sqlalchemy.orm import Session
from .database import SeccaoConfig, RegistroDigitalVoto, LogAuditoriaUrna
from .thermal_printer import apurar_boletim_de_urna

CARTRIDGE_DIR = os.getenv("CARTRIDGE_DIR", "./cartuchos")


def _get_or_derive_signing_key() -> ed25519.Ed25519PrivateKey:
    secret_seed = os.getenv("URNA_SECRET_KEY", "tse-simulador-chave-assinatura-2026")
    raw_32 = hashlib.sha256(secret_seed.encode("utf-8")).digest()
    return ed25519.Ed25519PrivateKey.from_private_bytes(raw_32)


def gerar_cartucho_midia_resultado(db: Session, config: SeccaoConfig) -> dict:
    """
    Gera a Mídia de Resultado (Cartucho Flash da Urna Eletrônica) contendo:
    1. rdv.json (Registro Digital do Voto embaralhado por shuffle_key - sigilo garantido)
    2. bu.json e bu.txt (Boletim de Urna eletrônico e impresso)
    3. logurna.json (Cadeia de logs auditáveis com hashes encadeados)
    4. assinatura.sig (Manifesto de hashes SHA-256 + Assinatura Digital Ed25519)
    Compacta tudo em um arquivo `.cartucho.zip` pronto para cópia em Cartucho/Pendrive ou transmissão.
    """
    os.makedirs(CARTRIDGE_DIR, exist_ok=True)

    bu_data = apurar_boletim_de_urna(db, config)

    # 1. RDV ordenado pela chave aleatória CSPRNG `shuffle_key` (desvincula ordem cronológica)
    votos_embaralhados = (
        db.query(RegistroDigitalVoto)
        .filter(RegistroDigitalVoto.turno == config.turno)
        .order_by(RegistroDigitalVoto.shuffle_key.asc())
        .all()
    )
    rdv_payload = {
        "cabecalho": {
            "formato": "RDV-TSE-SIM-v1",
            "zona": config.zona,
            "secao": config.secao,
            "municipio": config.municipio,
            "turno": config.turno,
            "total_registros_voto": len(votos_embaralhados),
            "nota_sigilo": "Votos ordenados por chave criptografica CSPRNG sem timestamp ou identificacao do eleitor.",
        },
        "votos": [
            {
                "shuffle_key": v.shuffle_key,
                "cargo": v.cargo,
                "tipo_voto": v.tipo_voto,
                "numero_digitado": v.numero_digitado,
                "partido_legenda": v.partido_legenda,
                "hash_integridade": v.hash_integridade,
            }
            for v in votos_embaralhados
        ],
    }

    # 2. Cadeia de Logs da Urna
    logs = db.query(LogAuditoriaUrna).order_by(LogAuditoriaUrna.id.asc()).all()
    log_payload = [
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

    rdv_bytes = json.dumps(rdv_payload, indent=2, ensure_ascii=False).encode("utf-8")
    bu_json_bytes = json.dumps(bu_data, indent=2, ensure_ascii=False).encode("utf-8")
    bu_txt_bytes = bu_data["cupom_termico"].encode("utf-8")
    log_bytes = json.dumps(log_payload, indent=2, ensure_ascii=False).encode("utf-8")

    # 3. Assinatura Digital Ed25519 sobre os hashes de todos os artefatos do cartucho
    priv_key = _get_or_derive_signing_key()
    pub_key = priv_key.public_key()
    pub_hex = pub_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()

    manifest = {
        "zona": config.zona,
        "secao": config.secao,
        "turno": config.turno,
        "gerado_em_utc": datetime.now(timezone.utc).isoformat(),
        "arquivos_sha256": {
            "rdv.json": hashlib.sha256(rdv_bytes).hexdigest(),
            "bu.json": hashlib.sha256(bu_json_bytes).hexdigest(),
            "bu.txt": hashlib.sha256(bu_txt_bytes).hexdigest(),
            "logurna.json": hashlib.sha256(log_bytes).hexdigest(),
        },
        "chave_publica_ed25519": pub_hex,
    }
    manifest_canonical = json.dumps(manifest, sort_keys=True).encode("utf-8")
    signature_hex = priv_key.sign(manifest_canonical).hex()
    manifest["assinatura_ed25519"] = signature_hex
    sig_bytes = json.dumps(manifest, indent=2, ensure_ascii=False).encode("utf-8")

    filename = f"cartucho_Z{config.zona}_S{config.secao}_T{config.turno}.cartucho.zip"
    filepath = os.path.join(CARTRIDGE_DIR, filename)

    with zipfile.ZipFile(filepath, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("rdv.json", rdv_bytes)
        zf.writestr("bu.json", bu_json_bytes)
        zf.writestr("bu.txt", bu_txt_bytes)
        zf.writestr("logurna.json", log_bytes)
        zf.writestr("assinatura.sig.json", sig_bytes)

    return {
        "arquivo": filename,
        "caminho": filepath,
        "manifesto": manifest,
    }
