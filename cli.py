from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from core.engine import ShadowNetEngine
from llm_agent_bridge import LLMAgentBridge
from security.artifact_verifier import (
    create_manifest_from_artifacts,
    verify_artifacts,
    write_manifest,
)
from telemetry_client import TelemetryClient
from updater import apply_update


def _cmd_scan(args: argparse.Namespace) -> int:
    engine = ShadowNetEngine()
    result = engine.scan_file(args.file)
    print(json.dumps(result, indent=2, ensure_ascii=True))
    return 0 if result.get("error") is None else 1


def _cmd_verify_model(args: argparse.Namespace) -> int:
    ok, errors = verify_artifacts(Path("."), Path(args.manifest), check_size=not args.skip_size)
    if ok:
        print("Model artifacts verification: OK")
        return 0

    print("Model artifacts verification: FAILED")
    for err in errors:
        print(f"- {err}")
    return 1


def _cmd_init_manifest(args: argparse.Namespace) -> int:
    artifact_paths = [
        "models/best_model.onnx",
        "models/best_model.onnx.data",
        "models/scaler.pkl",
    ]
    manifest = create_manifest_from_artifacts(
        Path("."),
        artifact_paths,
        version=args.version,
        threshold=args.threshold,
    )
    write_manifest(manifest, Path(args.output))
    print(f"Manifest written to: {args.output}")
    return 0


def _cmd_update_model(args: argparse.Namespace) -> int:
    local_dir = Path(args.local_package_dir).resolve() if args.local_package_dir else None
    apply_update(
        args.manifest_source,
        project_root=Path(__file__).resolve().parent,
        local_package_dir=local_dir,
    )
    print("Model update completed successfully.")
    return 0


def _cmd_llm_explain(args: argparse.Namespace) -> int:
    telemetry = TelemetryClient()
    bridge = LLMAgentBridge()

    if not args.scan_json and not args.file:
        raise ValueError("Provide --file or --scan-json.")

    if args.scan_json:
        scan_result = json.loads(Path(args.scan_json).read_text(encoding="utf-8"))
    else:
        engine = ShadowNetEngine()
        scan_result = engine.scan_file(args.file)

    start = time.time()
    try:
        out = bridge.explain_scan(
            scan_result,
            provider=args.provider,
            model=args.model,
        )
        latency_ms = (time.time() - start) * 1000
        telemetry.record_llm_interaction(
            provider=out["provider"],
            model=out["model"],
            ok=True,
            latency_ms=latency_ms,
        )
    except Exception as exc:
        latency_ms = (time.time() - start) * 1000
        telemetry.record_llm_interaction(
            provider=args.provider or "ollama",
            model=args.model or "default",
            ok=False,
            latency_ms=latency_ms,
            error=str(exc),
        )
        print(
            json.dumps(
                {
                    "scan_result": scan_result,
                    "llm": {
                        "provider": args.provider or "ollama",
                        "model": args.model or "default",
                        "error": str(exc),
                    },
                },
                indent=2,
                ensure_ascii=True,
            )
        )
        return 1

    print(json.dumps({"scan_result": scan_result, "llm": out}, indent=2, ensure_ascii=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="ShadowNet Defender CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan a PE file")
    scan_parser.add_argument("file", help="Path to file to scan")
    scan_parser.set_defaults(func=_cmd_scan)

    verify_parser = subparsers.add_parser("verify-model", help="Verify artifact hashes and sizes")
    verify_parser.add_argument("--manifest", default="model_manifest.json")
    verify_parser.add_argument("--skip-size", action="store_true")
    verify_parser.set_defaults(func=_cmd_verify_model)

    init_manifest_parser = subparsers.add_parser("init-manifest", help="Generate manifest from current artifacts")
    init_manifest_parser.add_argument("--version", default="v1.0.0")
    init_manifest_parser.add_argument("--threshold", type=float, default=0.5)
    init_manifest_parser.add_argument("--output", default="model_manifest.json")
    init_manifest_parser.set_defaults(func=_cmd_init_manifest)

    update_parser = subparsers.add_parser("update-model", help="Update model artifacts from manifest")
    update_parser.add_argument("--manifest-source", required=True, help="Manifest URL or local path")
    update_parser.add_argument(
        "--local-package-dir",
        default=None,
        help="Folder with files matching manifest artifact paths",
    )
    update_parser.set_defaults(func=_cmd_update_model)

    llm_parser = subparsers.add_parser("llm-explain", help="Generate LLM incident explanation from scan result")
    llm_parser.add_argument("--file", help="File to scan before asking LLM")
    llm_parser.add_argument("--scan-json", help="Path to precomputed scan result JSON")
    llm_parser.add_argument("--provider", default="ollama", help="ollama | google_opal | opal")
    llm_parser.add_argument("--model", default=None, help="Override provider model")
    llm_parser.set_defaults(func=_cmd_llm_explain)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
