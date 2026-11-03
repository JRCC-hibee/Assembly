"""
importer_brasil.py
Utilitário de Linha de Comando (CLI) para Ingestão em Lote do Brasil Inteiro (TSE).
Estratégia Zero-Disk Raw: lê arquivos compactados (.zip / .jez) em streaming na memória,
extrai os dados de apuração e métricas operacionais para o PostgreSQL e descarta os brutos,
mantendo o consumo de disco da VPS mínimo (< 3 GB para o Brasil todo).

Uso:
  python -m backend.app.importer_brasil --zip /caminho/para/PR_2T.zip
  python -m backend.app.importer_brasil --dir /caminho/para/pasta_com_zips/
  python -m backend.app.importer_brasil --vacuum
"""

import os
import sys
import time
import zipfile
import argparse
from glob import glob

from .database import init_db, SessionLocal, engine, text
from .tse_reverse_analyzer import processar_lote_arquivos_tse


def importar_zip(caminho_zip: str, chunk_size: int = 150):
    if not os.path.exists(caminho_zip):
        print(f"❌ Arquivo não encontrado: {caminho_zip}")
        return

    print(f"\n📦 Iniciando ingestão Stream & Discard: {caminho_zip}")
    t0 = time.time()
    init_db()

    with zipfile.ZipFile(caminho_zip, "r") as zf:
        infolist = [
            info for info in zf.infolist()
            if not info.is_dir() and any(info.filename.lower().endswith(ext) for ext in (".jez", ".dat", ".vsc"))
        ]
        total_arquivos = len(infolist)
        print(f"   Total de arquivos eleitorais identificados no ZIP: {total_arquivos:,}")

        lote_atual = {}
        arquivos_lidos = 0
        secoes_total_processadas = 0

        for info in infolist:
            nome = os.path.basename(info.filename)
            try:
                lote_atual[nome] = zf.read(info)
                arquivos_lidos += 1
            except Exception as e:
                print(f"   ⚠️ Erro ao ler {nome}: {e}")
                continue

            if len(lote_atual) >= chunk_size:
                res = processar_lote_arquivos_tse(lote_atual)
                secoes_total_processadas += res.get("secoes_processadas_neste_lote", 0)
                pct = (arquivos_lidos / total_arquivos) * 100
                print(f"   [{pct:5.1f}%] {arquivos_lidos:,}/{total_arquivos:,} arqs | {secoes_total_processadas:,} seções gravadas no DB...")
                lote_atual.clear()

        if lote_atual:
            res = processar_lote_arquivos_tse(lote_atual)
            secoes_total_processadas += res.get("secoes_processadas_neste_lote", 0)
            lote_atual.clear()

    duracao = time.time() - t0
    print(f"\n✅ Concluída importação de {caminho_zip}!")
    print(f"   Arquivos processados: {arquivos_lidos:,}")
    print(f"   Seções gravadas: {secoes_total_processadas:,}")
    print(f"   Tempo total: {duracao:.1f}s ({arquivos_lidos / max(1, duracao):.1f} arqs/s)")


def executar_vacuum_optimize():
    print("\n🧹 Executando otimização física no PostgreSQL (VACUUM ANALYZE)...")
    t0 = time.time()
    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        try:
            conn.execute(text("VACUUM ANALYZE tse_secoes;"))
            conn.execute(text("VACUUM ANALYZE tse_apuracao_bu;"))
            conn.execute(text("VACUUM ANALYZE tse_votos_candidatos;"))
            conn.execute(text("VACUUM ANALYZE tse_metricas_log;"))
            print(f"✅ Otimização concluída em {time.time() - t0:.2f}s! Páginas compactadas a 100%.")
        except Exception as e:
            print(f"⚠️ Aviso ao executar VACUUM: {e}")


def main():
    parser = argparse.ArgumentParser(description="Ingestor Zero-Disk Raw para Dados Eleitorais do Brasil")
    parser.add_argument("--zip", help="Caminho para arquivo .zip do estado (ex: PR.zip)")
    parser.add_argument("--dir", help="Caminho para diretório com múltiplos arquivos .zip ou .jez")
    parser.add_argument("--chunk", type=int, default=150, help="Tamanho do micro-lote de processamento em memória")
    parser.add_argument("--vacuum", action="store_true", help="Executa VACUUM ANALYZE nas tabelas do PostgreSQL")

    args = parser.parse_args()

    if args.zip:
        importar_zip(args.zip, chunk_size=args.chunk)
    elif args.dir:
        zips = sorted(glob(os.path.join(args.dir, "*.zip")))
        if not zips:
            print(f"Nenhum arquivo .zip encontrado em {args.dir}")
        for z in zips:
            importar_zip(z, chunk_size=args.chunk)
    elif args.vacuum:
        executar_vacuum_optimize()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
