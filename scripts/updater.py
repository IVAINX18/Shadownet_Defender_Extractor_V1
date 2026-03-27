from __future__ import annotations

import argparse
import shutil
import tempfile
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import urlopen

from security.artifact_verifier import load_manifest, sha256_file


def _fetch_text(source: str) -> str:
    parsed = urlparse(source)
    if parsed.scheme in ("http", "https"):
        with urlopen(source, timeout=30) as resp:
            return resp.read().decode("utf-8")
    return Path(source).read_text(encoding="utf-8")


def _download_bytes(url: str) -> bytes:
    with urlopen(url, timeout=60) as resp:
        return resp.read()


def _backup_dir(path: Path) -> Path:
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    backup = path.parent / "backups" / timestamp
    backup.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(path, backup)
    return backup


def apply_update(
    manifest_source: str,
    *,
    project_root: Path,
    local_package_dir: Path | None = None,
) -> None:
    manifest_text = _fetch_text(manifest_source)
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_dir_path = Path(tmp_dir)
        manifest_path = tmp_dir_path / "manifest.json"
        manifest_path.write_text(manifest_text, encoding="utf-8")
        manifest = load_manifest(manifest_path)

        staging_root = tmp_dir_path / "staging"
        staging_root.mkdir(parents=True, exist_ok=True)

        for artifact in manifest.get("artifacts", []):
            rel_path = artifact["path"]
            target = staging_root / rel_path
            target.parent.mkdir(parents=True, exist_ok=True)

            download_url = artifact.get("download_url")
            if download_url:
                target.write_bytes(_download_bytes(download_url))
            elif local_package_dir:
                source = local_package_dir / rel_path
                if not source.exists():
                    raise FileNotFoundError(f"Artifact not found in package dir: {source}")
                shutil.copy2(source, target)
            else:
                raise ValueError(
                    f"Artifact '{rel_path}' has no download_url and no local_package_dir was provided"
                )

            actual_hash = sha256_file(target)
            if actual_hash.lower() != artifact["sha256"].lower():
                raise RuntimeError(
                    f"Integrity check failed for {rel_path}: expected {artifact['sha256']} got {actual_hash}"
                )

        models_dir = project_root / "models"
        backup = _backup_dir(models_dir)

        try:
            for artifact in manifest.get("artifacts", []):
                rel_path = artifact["path"]
                staged_file = staging_root / rel_path
                final_file = project_root / rel_path
                final_file.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(staged_file, final_file)
        except Exception as exc:
            if models_dir.exists():
                shutil.rmtree(models_dir)
            shutil.copytree(backup, models_dir)
            raise RuntimeError(f"Update failed, rollback restored from {backup}: {exc}") from exc


def main() -> None:
    parser = argparse.ArgumentParser(description="ShadowNet model updater")
    parser.add_argument("--manifest-source", required=True, help="URL or local path to manifest")
    parser.add_argument(
        "--local-package-dir",
        default=None,
        help="Local folder containing artifact files matching manifest paths",
    )
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parent
    package_dir = Path(args.local_package_dir).resolve() if args.local_package_dir else None

    apply_update(args.manifest_source, project_root=project_root, local_package_dir=package_dir)
    print("Model update completed successfully.")


if __name__ == "__main__":
    main()
