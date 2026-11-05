"""
Módulo de Diagnóstico e Extração Resiliente de Arquivos Eleitorais TSE.

Suporta:
- Arquivos .ZIP íntegros (via standard zipfile)
- Arquivos .ZIP com bytes extras ao final (trailing padding de SFTP/rede)
- Arquivos .ZIP truncados/incompletos (upload ou download parcial interrompido)
- Arquivos .7Z (via 7z CLI ou py7zr)
- Arquivos .TAR / .TAR.GZ / .TGZ / .TAR.BZ2 / .TAR.XZ (via tarfile padrão)
- Detecção preventiva de arquivos inválidos (HTML de erro, 404, arquivos vazios)
"""

import io
import os
import re
import shutil
import struct
import subprocess
import tarfile
import tempfile
import time
import zipfile
import zlib
from typing import Any, Callable, Dict, Generator, List, Optional, Set, Tuple

EXTENSOES_TSE_VALIDAS = {
    ".bu",
    ".rdv",
    ".logjez",
    ".vscmr",
    ".vscv",
    ".imgbu",
    ".dat",
    ".jez",
    ".bin",
    ".asn1",
}

EXTENSOES_COMPACTADAS_VALIDAS = (
    ".zip",
    ".7z",
    ".tar",
    ".tar.gz",
    ".tgz",
    ".tar.bz2",
    ".tar.xz",
    ".rar",
)


def diagnosticar_arquivo_compactado(caminho_arquivo: str) -> dict:
    """
    Inspeciona os bytes iniciais e finais do arquivo no disco para determinar
    formato real, integridade estrutural e causas de eventuais erros de descompactação.
    """
    if not os.path.exists(caminho_arquivo):
        return {
            "valido": False,
            "formato": "INEXISTENTE",
            "status": "ERRO",
            "tamanho_mb": 0.0,
            "mensagem_diagnostico": f"Arquivo não encontrado: {caminho_arquivo}",
            "acao_recomendada": "Verifique o caminho do arquivo na VPS.",
            "tem_7z_sistema": bool(shutil.which("7z") or shutil.which("7za")),
            "tem_unzip_sistema": bool(shutil.which("unzip")),
        }

    try:
        tamanho_bytes = os.path.getsize(caminho_arquivo)
    except Exception as e:
        return {
            "valido": False,
            "formato": "ERRO_ACESSO",
            "status": "ERRO",
            "tamanho_mb": 0.0,
            "mensagem_diagnostico": f"Erro ao acessar arquivo: {e}",
            "acao_recomendada": "Verifique as permissões de leitura do arquivo.",
            "tem_7z_sistema": bool(shutil.which("7z") or shutil.which("7za")),
            "tem_unzip_sistema": bool(shutil.which("unzip")),
        }

    tamanho_mb = round(tamanho_bytes / (1024 * 1024), 2)
    tem_7z = bool(shutil.which("7z") or shutil.which("7za"))
    tem_unzip = bool(shutil.which("unzip"))

    if tamanho_bytes == 0:
        return {
            "valido": False,
            "formato": "VAZIO",
            "status": "ERRO",
            "tamanho_mb": 0.0,
            "mensagem_diagnostico": "Arquivo possui 0 bytes (completamente vazio).",
            "acao_recomendada": "O arquivo não foi transferido. Reenvie o arquivo pelo Termius SFTP.",
            "tem_7z_sistema": tem_7z,
            "tem_unzip_sistema": tem_unzip,
        }

    try:
        with open(caminho_arquivo, "rb") as f:
            header = f.read(512)
    except Exception as e:
        return {
            "valido": False,
            "formato": "ERRO_LEITURA",
            "status": "ERRO",
            "tamanho_mb": tamanho_mb,
            "mensagem_diagnostico": f"Não foi possível ler o cabeçalho do arquivo: {e}",
            "acao_recomendada": "Verifique as permissões do arquivo.",
            "tem_7z_sistema": tem_7z,
            "tem_unzip_sistema": tem_unzip,
        }

    # 1. Detecção de HTML / Texto (Ex: Página de erro 403/404 baixada como se fosse zip)
    header_low = header[:120].lower()
    if (
        b"<!doctype" in header_low
        or b"<html" in header_low
        or b"<head" in header_low
        or header.startswith(b"{\n")
        or header.startswith(b"{\"error\"")
        or b"404 not found" in header_low
        or b"accessdenied" in header_low
    ):
        return {
            "valido": False,
            "formato": "TEXTO_HTML",
            "status": "ERRO",
            "tamanho_mb": tamanho_mb,
            "mensagem_diagnostico": "O arquivo contém texto/página HTML de erro em vez de dados compactados.",
            "acao_recomendada": "O download oficial do TSE falhou e salvou uma página web. Baixe novamente o arquivo oficial.",
            "tem_7z_sistema": tem_7z,
            "tem_unzip_sistema": tem_unzip,
        }

    # 2. Formato 7-Zip (.7z)
    if header.startswith(b"7z\xbc\xaf\x27\x1c"):
        return {
            "valido": True,
            "formato": "7Z",
            "status": "OK" if tem_7z else "AVISO_NECESSITA_7Z",
            "tamanho_mb": tamanho_mb,
            "mensagem_diagnostico": "Arquivo compactado no formato oficial 7-Zip (.7z).",
            "acao_recomendada": "Extração nativa via 7z disponível." if tem_7z else "Instale 7z com 'apt-get install -y p7zip-full' ou descompacte antes de enviar.",
            "tem_7z_sistema": tem_7z,
            "tem_unzip_sistema": tem_unzip,
        }

    # 3. Formato TAR / GZIP / BZIP2 / XZ
    if header.startswith(b"\x1f\x8b"):
        return {
            "valido": True,
            "formato": "GZIP",
            "status": "OK",
            "tamanho_mb": tamanho_mb,
            "mensagem_diagnostico": "Arquivo compactado GZIP / TAR.GZ.",
            "acao_recomendada": "Processamento direto compatível com tarfile.",
            "tem_7z_sistema": tem_7z,
            "tem_unzip_sistema": tem_unzip,
        }

    if header.startswith(b"BZh"):
        return {
            "valido": True,
            "formato": "BZIP2",
            "status": "OK",
            "tamanho_mb": tamanho_mb,
            "mensagem_diagnostico": "Arquivo compactado BZIP2.",
            "acao_recomendada": "Processamento direto compatível com tarfile.",
            "tem_7z_sistema": tem_7z,
            "tem_unzip_sistema": tem_unzip,
        }

    if len(header) >= 262 and header[257:262] == b"ustar":
        return {
            "valido": True,
            "formato": "TAR",
            "status": "OK",
            "tamanho_mb": tamanho_mb,
            "mensagem_diagnostico": "Arquivo de arquivo TAR padrão.",
            "acao_recomendada": "Processamento direto compatível com tarfile.",
            "tem_7z_sistema": tem_7z,
            "tem_unzip_sistema": tem_unzip,
        }

    # 4. Formato RAR
    if header.startswith(b"Rar!\x1a\x07"):
        return {
            "valido": False,
            "formato": "RAR",
            "status": "AVISO_RAR",
            "tamanho_mb": tamanho_mb,
            "mensagem_diagnostico": "Arquivo no formato proprietário RAR.",
            "acao_recomendada": "Descompacte o arquivo na VPS com 'unrar x' ou use arquivos .zip/.7z.",
            "tem_7z_sistema": tem_7z,
            "tem_unzip_sistema": tem_unzip,
        }

    # 5. Formato ZIP
    eh_zip_header = (
        header.startswith(b"PK\x03\x04")
        or header.startswith(b"PK\x05\x06")
        or header.startswith(b"PK\x07\x08")
    )

    if eh_zip_header:
        # Testa se a biblioteca padrão do Python consegue abrir diretamente
        is_std_zip = False
        try:
            is_std_zip = zipfile.is_zipfile(caminho_arquivo)
        except Exception:
            is_std_zip = False

        if is_std_zip:
            return {
                "valido": True,
                "formato": "ZIP",
                "status": "OK",
                "tamanho_mb": tamanho_mb,
                "mensagem_diagnostico": f"Arquivo ZIP válido e íntegro ({tamanho_mb} MB). Diretório central confirmado.",
                "acao_recomendada": "Pronto para processamento direto de alta velocidade.",
                "tem_7z_sistema": tem_7z,
                "tem_unzip_sistema": tem_unzip,
            }

        # Não abriu diretamente: vamos inspecionar o final do arquivo
        try:
            with open(caminho_arquivo, "rb") as f:
                tail_len = min(tamanho_bytes, 2 * 1024 * 1024)
                f.seek(tamanho_bytes - tail_len)
                tail = f.read(tail_len)
        except Exception:
            tail = b""

        pos_eocd = tail.rfind(b"PK\x05\x06")
        pos_zip64 = tail.rfind(b"PK\x06\x06")

        if pos_eocd != -1 or pos_zip64 != -1:
            # Diretório central existe, mas há trailing bytes ou comentário grande
            dist_eof = tail_len - (pos_eocd if pos_eocd != -1 else pos_zip64)
            return {
                "valido": True,
                "formato": "ZIP",
                "status": "TRAILING_BYTES",
                "tamanho_mb": tamanho_mb,
                "mensagem_diagnostico": f"Arquivo ZIP íntegro com {dist_eof} bytes adicionais após o diretório central.",
                "acao_recomendada": "O extrator resiliente compensará os bytes automaticamente durante a ingestão.",
                "tem_7z_sistema": tem_7z,
                "tem_unzip_sistema": tem_unzip,
            }

        # Diretório central NÃO encontrado no final do arquivo: o arquivo está truncado/incompleto!
        return {
            "valido": False,
            "formato": "ZIP_TRUNCADO",
            "status": "TRUNCADO",
            "tamanho_mb": tamanho_mb,
            "mensagem_diagnostico": (
                f"Arquivo ZIP incompleto/truncado ({tamanho_mb} MB). "
                f"O cabeçalho inicial (PK\\x03\\x04) é válido, mas os bytes finais foram cortados "
                f"(upload via Termius SFTP ou download do TSE foi interrompido antes de 100%)."
            ),
            "acao_recomendada": (
                "Para recuperar urnas já presentes neste arquivo, o extrator resiliente lerá seções até o ponto de corte. "
                "Para carga total de 100%, reenvie o arquivo via SFTP garantindo a conclusão completa, "
                "ou descompacte com '7z x' ou 'unzip' diretamente no terminal da VPS."
            ),
            "tem_7z_sistema": tem_7z,
            "tem_unzip_sistema": tem_unzip,
        }

    # Formato não reconhecido
    return {
        "valido": False,
        "formato": "DESCONHECIDO",
        "status": "ERRO",
        "tamanho_mb": tamanho_mb,
        "mensagem_diagnostico": f"Formato não reconhecido (bytes iniciais: {header[:8].hex()}).",
        "acao_recomendada": "Certifique-se de enviar arquivos .zip, .7z ou .tar oficiais do TSE.",
        "tem_7z_sistema": tem_7z,
        "tem_unzip_sistema": tem_unzip,
    }


def iterar_entradas_zip_streaming(caminho_arquivo: str) -> Generator[Tuple[str, bytes], None, None]:
    """
    Lê um arquivo ZIP sequencialmente a partir do byte 0, analisando cabeçalhos locais (PK\\x03\\x04).
    Funciona mesmo quando o arquivo está TRUNCADO e não possui o diretório central ao final.
    """
    with open(caminho_arquivo, "rb") as fp:
        while True:
            sig = fp.read(4)
            if sig != b"PK\x03\x04":
                # Se encontrou diretório central ou fim do arquivo, encerra
                break
            hdr = fp.read(26)
            if len(hdr) < 26:
                break

            (
                version,
                flags,
                method,
                mtime,
                mdate,
                crc,
                comp_size,
                uncomp_size,
                name_len,
                extra_len,
            ) = struct.unpack("<HHHHHIIIHH", hdr)

            name_bytes = fp.read(name_len)
            name = name_bytes.decode("utf-8", errors="replace")
            extra = fp.read(extra_len)

            # Suporte a campos extras ZIP64 (0x0001)
            if extra_len > 0:
                i = 0
                while i + 4 <= len(extra):
                    eid, esz = struct.unpack("<HH", extra[i : i + 4])
                    edata = extra[i + 4 : i + 4 + esz]
                    if eid == 0x0001:  # ZIP64
                        off = 0
                        if uncomp_size == 0xFFFFFFFF and off + 8 <= len(edata):
                            uncomp_size = struct.unpack("<Q", edata[off : off + 8])[0]
                            off += 8
                        if comp_size == 0xFFFFFFFF and off + 8 <= len(edata):
                            comp_size = struct.unpack("<Q", edata[off : off + 8])[0]
                            off += 8
                    i += 4 + esz

            has_dd = bool(flags & 0x08)
            payload = b""

            if method == 0:  # Stored (sem compressão)
                if not has_dd or comp_size > 0:
                    payload = fp.read(comp_size)
                else:
                    break
            elif method == 8:  # Deflate
                if comp_size > 0:
                    comp_data = fp.read(comp_size)
                    try:
                        payload = zlib.decompress(comp_data, -15)
                    except Exception:
                        payload = b""
                else:
                    # Descompressão contínua com zlib.decompressobj
                    d = zlib.decompressobj(-15)
                    chunks = []
                    try:
                        while not d.eof:
                            chunk = fp.read(65536)
                            if not chunk:
                                break
                            dec = d.decompress(chunk)
                            if dec:
                                chunks.append(dec)
                        payload = b"".join(chunks)
                        if d.unused_data:
                            fp.seek(-len(d.unused_data), os.SEEK_CUR)
                    except Exception:
                        payload = b"".join(chunks)
            else:
                # Método não suportado (ex: Deflate64, BZIP2 interno)
                if comp_size > 0:
                    fp.seek(comp_size, os.SEEK_CUR)
                continue

            if has_dd:
                dd_sig = fp.read(4)
                if dd_sig == b"PK\x07\x08":
                    fp.seek(12, os.SEEK_CUR)
                else:
                    # Pode não ter assinatura PK\x07\x08 e ter apenas 12 bytes
                    fp.seek(8, os.SEEK_CUR)

            if payload or comp_size == 0:
                yield name, payload


def descompactar_com_7z_ou_unzip(caminho_arquivo: str, dir_destino: str) -> bool:
    """
    Executa a ferramenta nativa 7z ou unzip se instalada no sistema operacional.
    O 7z é capaz de recuperar automaticamente dados parciais mesmo com aviso de fim inesperado.
    """
    cmd_7z = shutil.which("7z") or shutil.which("7za")
    if cmd_7z:
        try:
            res = subprocess.run(
                [cmd_7z, "x", "-y", f"-o{dir_destino}", caminho_arquivo],
                capture_output=True,
                text=True,
                timeout=1800,  # 30 minutos máximo para arquivos gigantes
            )
            # 7z retorna 0 para sucesso, 1 para avisos (ex: arquivos truncados com dados recuperados)
            if res.returncode in (0, 1):
                return True
            # Mesmo com código 2 (erro fatal/truncamento), verifica se extraiu arquivos
            if os.path.exists(dir_destino) and len(os.listdir(dir_destino)) > 0:
                return True
        except Exception as e:
            print(f"[7Z-EXTRACT] Erro ao invocar 7z: {e}")

    cmd_unzip = shutil.which("unzip")
    if cmd_unzip:
        try:
            res = subprocess.run(
                [cmd_unzip, "-q", "-o", caminho_arquivo, "-d", dir_destino],
                capture_output=True,
                text=True,
                timeout=1800,
            )
            if res.returncode in (0, 1):
                return True
            if os.path.exists(dir_destino) and len(os.listdir(dir_destino)) > 0:
                return True
        except Exception as e:
            print(f"[UNZIP-EXTRACT] Erro ao invocar unzip: {e}")

    return False


def extrair_arquivo_tse_resiliente(caminho_arquivo: str, dir_destino: str) -> dict:
    """
    Extrai um arquivo compactado (ZIP íntegro, ZIP truncado, 7Z, TAR, etc.) para dir_destino
    utilizando cascata de técnicas automáticas de recuperação.

    Retorna relatório com:
    - sucesso: bool
    - total_arquivos: int
    - metodo_usado: str ("ZIPFILE_PADRAO", "7Z_SISTEMA", "UNZIP_SISTEMA", "STREAMING_RESILIENTE", "TARFILE")
    - diagnostico: dict
    """
    diag = diagnosticar_arquivo_compactado(caminho_arquivo)
    os.makedirs(dir_destino, exist_ok=True)
    metodo_usado = "NENHUM"

    # Tentativa 1: Standard zipfile (se for ZIP e íntegro)
    if diag["formato"] == "ZIP" and diag["status"] in ("OK", "TRAILING_BYTES"):
        try:
            with zipfile.ZipFile(caminho_arquivo, "r") as zf:
                for name in zf.namelist():
                    if name.startswith("__MACOSX") or name.endswith("/"):
                        continue
                    base = os.path.basename(name)
                    if not any(base.lower().endswith(ext) for ext in EXTENSOES_TSE_VALIDAS) and not base.lower().endswith(".zip"):
                        continue
                    dest = os.path.join(dir_destino, base)
                    with open(dest, "wb") as f_out:
                        f_out.write(zf.read(name))
            metodo_usado = "ZIPFILE_PADRAO"
        except Exception as e_zip:
            print(f"[EXTRACT-RESILIENTE] zipfile padrão falhou ({e_zip}), tentando fallbacks...")

    # Tentativa 2: Se não extraiu e o sistema tem 7z ou unzip
    if metodo_usado == "NENHUM" and (diag.get("tem_7z_sistema") or diag.get("tem_unzip_sistema")):
        ok_sys = descompactar_com_7z_ou_unzip(caminho_arquivo, dir_destino)
        if ok_sys and len(os.listdir(dir_destino)) > 0:
            metodo_usado = "7Z_SISTEMA" if diag.get("tem_7z_sistema") else "UNZIP_SISTEMA"

    # Tentativa 3: Se ainda não extraiu e o cabeçalho é ZIP (inclusive ZIP_TRUNCADO)
    if metodo_usado == "NENHUM" and (diag["formato"] in ("ZIP", "ZIP_TRUNCADO")):
        try:
            count = 0
            for name, payload in iterar_entradas_zip_streaming(caminho_arquivo):
                base = os.path.basename(name)
                if any(base.lower().endswith(ext) for ext in EXTENSOES_TSE_VALIDAS) or base.lower().endswith(".zip"):
                    dest = os.path.join(dir_destino, base)
                    with open(dest, "wb") as f_out:
                        f_out.write(payload)
                    count += 1
            if count > 0:
                metodo_usado = "STREAMING_RESILIENTE"
        except Exception as e_stream:
            print(f"[EXTRACT-RESILIENTE] Streaming falhou: {e_stream}")

    # Tentativa 4: Se o formato for TAR / GZIP / BZIP2
    if metodo_usado == "NENHUM" and diag["formato"] in ("TAR", "GZIP", "BZIP2"):
        try:
            with tarfile.open(caminho_arquivo, "r:*") as tf:
                for m in tf.getmembers():
                    if m.isfile():
                        base = os.path.basename(m.name)
                        if any(base.lower().endswith(ext) for ext in EXTENSOES_TSE_VALIDAS) or base.lower().endswith(".zip"):
                            src = tf.extractfile(m)
                            if src:
                                with open(os.path.join(dir_destino, base), "wb") as dst:
                                    shutil.copyfileobj(src, dst)
            if len(os.listdir(dir_destino)) > 0:
                metodo_usado = "TARFILE"
        except Exception as e_tar:
            print(f"[EXTRACT-RESILIENTE] tarfile falhou: {e_tar}")

    # Expande inner zips se houver algum .zip dentro do diretório extraído
    try:
        for f in list(os.listdir(dir_destino)):
            if f.lower().endswith(".zip"):
                iz_path = os.path.join(dir_destino, f)
                try:
                    with zipfile.ZipFile(iz_path, "r") as iz_zf:
                        for iname in iz_zf.namelist():
                            ibase = os.path.basename(iname)
                            if any(ibase.lower().endswith(ext) for ext in EXTENSOES_TSE_VALIDAS):
                                with open(os.path.join(dir_destino, ibase), "wb") as f_out:
                                    f_out.write(iz_zf.read(iname))
                    os.unlink(iz_path)
                except Exception:
                    pass
    except Exception:
        pass

    arquivos_extraidos = [f for f in os.listdir(dir_destino) if any(f.lower().endswith(ext) for ext in EXTENSOES_TSE_VALIDAS)]
    sucesso = len(arquivos_extraidos) > 0

    return {
        "sucesso": sucesso,
        "total_arquivos": len(arquivos_extraidos),
        "metodo_usado": metodo_usado,
        "diagnostico": diag,
        "arquivos": arquivos_extraidos,
    }
