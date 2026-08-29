"""
tools/fetch_corpus.py — Script de adquisición reproducible para CorpusReal (T-13).

Permite a revisores descargar el corpus usando su propia API key de VirusTotal.
El repositorio solo contiene manifest.csv con hashes y metadatos (sin binarios).

Uso:
    python tools/fetch_corpus.py --manifest data/eval_real/manifest.csv \
        --out data/eval_real/ --vt-api-key <TU_API_KEY>

    python tools/fetch_corpus.py --help
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import sys
import time
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch_from_vt(sha256: str, out_dir: Path, api_key: str, dry_run: bool = False) -> bool:
    """
    Descarga un binario de VirusTotal usando el hash SHA-256.
    Requiere VT Intelligence plan (descarga de archivos).
    """
    try:
        import requests
    except ImportError:
        print("[ERROR] 'requests' no instalado. pip install requests", file=sys.stderr)
        sys.exit(1)

    out_path = out_dir / f"{sha256}.exe"
    if out_path.exists():
        local_sha = sha256_file(out_path)
        if local_sha.lower() == sha256.lower():
            print(f"  [SKIP] {sha256[:16]}... ya descargado y verificado")
            return True
        else:
            print(f"  [WARN] {sha256[:16]}... existe pero hash no coincide, re-descargando")

    if dry_run:
        print(f"  [DRY-RUN] Descargaría: {sha256}")
        return True

    url = f"https://www.virustotal.com/api/v3/files/{sha256}/download"
    headers = {"x-apikey": api_key}

    try:
        resp = requests.get(url, headers=headers, stream=True, timeout=60)
        if resp.status_code == 200:
            out_dir.mkdir(parents=True, exist_ok=True)
            with open(out_path, "wb") as f:
                for chunk in resp.iter_content(chunk_size=65536):
                    f.write(chunk)
            # Verificar integridad
            local_sha = sha256_file(out_path)
            if local_sha.lower() != sha256.lower():
                out_path.unlink(missing_ok=True)
                print(f"  [ERROR] {sha256[:16]}... hash mismatch tras descarga")
                return False
            print(f"  [OK] {sha256[:16]}... descargado y verificado")
            return True
        elif resp.status_code == 403:
            print(f"  [ERROR] {sha256[:16]}... 403 Forbidden — requiere VT Intelligence plan")
            return False
        elif resp.status_code == 404:
            print(f"  [WARN] {sha256[:16]}... 404 Not Found en VT")
            return False
        else:
            print(f"  [ERROR] {sha256[:16]}... HTTP {resp.status_code}")
            return False
    except Exception as exc:
        print(f"  [ERROR] {sha256[:16]}... excepción: {exc}")
        return False


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Descarga el CorpusReal (T-13) desde VirusTotal usando manifest.csv.\n\n"
            "Proceso de adquisición reproducible documentado en:\n"
            "  docs/academico/07_metricas_y_resultados.md — Sección Métricas de campo (T-13)\n\n"
            "Fuentes de adquisición:\n"
            "  - Malware: VirusTotal API (positives ≥5, type=peexe, size<10MB)\n"
            "    Colección: 2024-2026 para evitar overlap con SOREL-20M (2020)\n"
            "  - Benignos: C:\\Windows\\System32, Sysinternals, fresh installs (VT positives=0)\n\n"
            "Filtros aplicados al generar manifest.csv:\n"
            "  positives ≥5 → malware (label=1)\n"
            "  positives == 0 → benigno (label=0)\n"
            "  type == peexe, size < 10MB (evitar sesgo PE_FASTLOAD)\n"
            "  first_seen >= 2024 (evitar overlap SOREL-20M)"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=_PROJECT_ROOT / "data" / "eval_real" / "manifest.csv",
        help="Ruta al manifest.csv con columnas sha256,label,source,vt_report.",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=_PROJECT_ROOT / "data" / "eval_real",
        help="Directorio de salida para los binarios descargados.",
    )
    parser.add_argument(
        "--vt-api-key",
        default="",
        help="API key de VirusTotal (requiere plan Intelligence para descarga).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Mostrar qué se descargaría sin descargar.",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=15.0,
        help="Delay en segundos entre solicitudes VT (default 15s para plan público).",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=0,
        help="Límite de muestras a descargar (0=todas).",
    )
    args = parser.parse_args()

    if not args.manifest.exists():
        print(f"[ERROR] Manifest no encontrado: {args.manifest}", file=sys.stderr)
        print(
            "\nPara crear un manifest desde cero con la VT API:\n"
            "  1. Descargar hashes de malware: vt search 'positives:5+ type:peexe size:0-10MB'\n"
            "  2. Descargar hashes de benignos de System32 (positives:0)\n"
            "  3. Generar manifest.csv con columnas: sha256,label,source,vt_report,file_size,overlay_ratio\n"
            "  4. Ejecutar: python tools/fetch_corpus.py --manifest data/eval_real/manifest.csv\n",
            file=sys.stderr,
        )
        sys.exit(1)

    if not args.vt_api_key and not args.dry_run:
        print("[ERROR] Se requiere --vt-api-key para descargar.", file=sys.stderr)
        print("        Modo dry-run disponible con --dry-run", file=sys.stderr)
        sys.exit(1)

    rows = []
    with open(args.manifest, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    print(f"[fetch_corpus] Manifest: {args.manifest}  ({len(rows)} entradas)")
    print(f"               Output:   {args.out}")
    print(f"               Dry-run:  {args.dry_run}")

    if args.limit > 0:
        rows = rows[: args.limit]

    ok = failed = skipped = 0
    for i, row in enumerate(rows):
        sha = row.get("sha256", "").strip()
        label = row.get("label", "?").strip()
        if not sha:
            skipped += 1
            continue

        print(f"[{i+1}/{len(rows)}] label={label} sha256={sha[:24]}...")
        success = fetch_from_vt(sha, args.out, args.vt_api_key, dry_run=args.dry_run)
        if success:
            ok += 1
        else:
            failed += 1

        if not args.dry_run and i < len(rows) - 1:
            time.sleep(args.delay)

    print(f"\n[fetch_corpus] Completado: {ok} OK  {failed} fallidos  {skipped} sin sha256")
    if failed > 0:
        print(f"               {failed} archivos no descargados — verificar plan VT Intelligence.")


if __name__ == "__main__":
    main()
