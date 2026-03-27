from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple


@dataclass(frozen=True)
class ArtifactSpec:
    path: str
    sha256: str
    size_bytes: int | None = None


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def load_manifest(manifest_path: Path) -> Dict:
    with manifest_path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def write_manifest(manifest: Dict, manifest_path: Path) -> None:
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    with manifest_path.open("w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, ensure_ascii=True)
        fh.write("\n")


def create_manifest_from_artifacts(
    base_dir: Path,
    artifact_paths: List[str],
    *,
    version: str,
    threshold: float = 0.5,
    model_format: str = "onnx",
) -> Dict:
    created_at = datetime.now(timezone.utc).isoformat()
    artifacts = []

    for rel_path in artifact_paths:
        file_path = base_dir / rel_path
        if not file_path.exists():
            raise FileNotFoundError(f"Missing artifact: {file_path}")

        artifacts.append(
            {
                "path": rel_path,
                "sha256": sha256_file(file_path),
                "size_bytes": file_path.stat().st_size,
            }
        )

    return {
        "schema_version": "1.0",
        "model": {
            "name": "ShadowNet Defender",
            "version": version,
            "format": model_format,
            "threshold": threshold,
            "feature_dim": 2381,
            "created_at_utc": created_at,
        },
        "artifacts": artifacts,
    }


def _manifest_specs(manifest: Dict) -> List[ArtifactSpec]:
    specs: List[ArtifactSpec] = []
    for entry in manifest.get("artifacts", []):
        specs.append(
            ArtifactSpec(
                path=entry["path"],
                sha256=entry["sha256"],
                size_bytes=entry.get("size_bytes"),
            )
        )
    return specs


def verify_artifacts(
    base_dir: Path,
    manifest_path: Path,
    *,
    check_size: bool = True,
) -> Tuple[bool, List[str]]:
    manifest = load_manifest(manifest_path)
    specs = _manifest_specs(manifest)

    errors: List[str] = []
    for spec in specs:
        target = base_dir / spec.path
        if not target.exists():
            errors.append(f"missing: {spec.path}")
            continue

        actual_hash = sha256_file(target)
        if actual_hash.lower() != spec.sha256.lower():
            errors.append(
                f"hash mismatch: {spec.path} expected={spec.sha256} actual={actual_hash}"
            )

        if check_size and spec.size_bytes is not None:
            actual_size = target.stat().st_size
            if actual_size != spec.size_bytes:
                errors.append(
                    f"size mismatch: {spec.path} expected={spec.size_bytes} actual={actual_size}"
                )

    return (len(errors) == 0, errors)
