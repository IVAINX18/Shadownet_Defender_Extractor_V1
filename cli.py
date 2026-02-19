from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from rich.console import Console
from rich.json import JSON
from rich.panel import Panel
from rich.table import Table

from core.engine import ShadowNetEngine
from core.integrations.n8n_client import N8NClient
from llm_agent_bridge import LLMAgentBridge
from security.artifact_verifier import (
    create_manifest_from_artifacts,
    verify_artifacts,
    write_manifest,
)
from telemetry_client import TelemetryClient
from updater import apply_update

console = Console()


def _run_llm_explanation(
    scan_result: dict,
    *,
    provider: str | None,
    model: str | None,
    telemetry: TelemetryClient,
) -> tuple[int, dict]:
    """
    Ejecuta explicación LLM y registra telemetría.
    Retorna (exit_code, payload_json).
    """
    bridge = LLMAgentBridge()
    start = time.time()
    try:
        out = bridge.explain_scan(
            scan_result,
            provider=provider,
            model=model,
        )
        latency_ms = (time.time() - start) * 1000
        telemetry.record_llm_interaction(
            provider=out["provider"],
            model=out["model"],
            ok=True,
            latency_ms=latency_ms,
        )
        return 0, {"scan_result": scan_result, "llm": out}
    except Exception as exc:
        latency_ms = (time.time() - start) * 1000
        telemetry.record_llm_interaction(
            provider=provider or "ollama",
            model=model or "mistral",
            ok=False,
            latency_ms=latency_ms,
            error=str(exc),
        )
        return 1, {
            "scan_result": scan_result,
            "llm": {
                "provider": provider or "ollama",
                "model": model or "mistral",
                "error": str(exc),
            },
        }


def _format_llm_response(payload: dict) -> None:
    """
    Formatea y muestra la respuesta del LLM de manera legible y colorida.
    """
    llm_block = payload.get("llm", {})
    response_text = llm_block.get("response_text", "")
    
    # Intentar parsear el response_text como JSON
    try:
        parsed = json.loads(response_text)
        llm_block["parsed_response"] = parsed
    except (json.JSONDecodeError, TypeError):
        pass  # Si no es JSON válido, leave as-is
    
    # Mostrar panel con información del LLM
    provider = llm_block.get("provider", "unknown")
    model = llm_block.get("model", "unknown")
    
    # Crear tabla con metadatos
    meta_table = Table(title="📡 Información del LLM", show_header=False, box=None)
    meta_table.add_column("key", style="cyan bold")
    meta_table.add_column("value", style="green")
    meta_table.add_row("Provider", provider)
    meta_table.add_row("Model", model)
    meta_table.add_row("Prompt Version", llm_block.get("prompt_version", "N/A"))
    
    console.print(meta_table)
    console.print()
    
    # Si tenemos respuesta parseada, mostrarla en panel bonito
    if "parsed_response" in llm_block:
        parsed = llm_block["parsed_response"]
        
        # Resumen Ejecutivo
        if "resumen_ejecutivo" in parsed:
            console.print(Panel(
                parsed["resumen_ejecutivo"],
                title="📋 Resumen Ejecutivo",
                border_style="green",
                expand=False,
            ))
            console.print()
        
        # Explicación Técnica
        if "explicacion_tecnica" in parsed:
            console.print(Panel(
                parsed["explicacion_tecnica"],
                title="🔍 Explicación Técnica",
                border_style="blue",
                expand=False,
            ))
            console.print()
        
        # Justificación Matemática
        if "justificacion_matematica" in parsed:
            console.print(Panel(
                parsed["justificacion_matematica"],
                title="📐 Justificación Matemática",
                border_style="yellow",
                expand=False,
            ))
            console.print()
        
        # Indicadores Clave
        if "indicadores_clave" in parsed:
            indicadores = parsed["indicadores_clave"]
            if indicadores:
                indicadores_text = "\n".join(f"• {ind}" for ind in indicadores)
                console.print(Panel(
                    indicadores_text,
                    title="🔑 Indicadores Clave",
                    border_style="red",
                    expand=False,
                ))
                console.print()
        
        # Recomendaciones
        if "recomendaciones" in parsed:
            recomendaciones = parsed["recomendaciones"]
            if recomendaciones:
                recs_text = "\n".join(f"• {rec}" for rec in recomendaciones)
                console.print(Panel(
                    recs_text,
                    title="💡 Recomendaciones",
                    border_style="magenta",
                    expand=False,
                ))
                console.print()
    else:
        # Si no se pudo parsear, mostrar raw
        console.print(Panel(
            response_text,
            title="📝 Respuesta LLM (Raw)",
            border_style="white",
            expand=False,
        ))


def _cmd_scan(args: argparse.Namespace) -> int:
    engine = ShadowNetEngine()
    n8n_client = N8NClient()
    result = engine.scan_file(args.file)

    if not args.explain:
        # Non-blocking automation dispatch for operational workflows.
        detection_payload = n8n_client.build_detection_payload(result)
        n8n_client.send_detection_to_n8n(detection_payload)
        # Mostrar resultado con rich
        scan_table = Table(title="🔬 Resultado del Escaneo", show_header=False)
        scan_table.add_column("key", style="cyan bold")
        scan_table.add_column("value", style="green")
        scan_table.add_row("File", result.get("file", "N/A"))
        scan_table.add_row("Label", result.get("label", "N/A"))
        scan_table.add_row("Score", str(result.get("score", "N/A")))
        scan_table.add_row("Confidence", result.get("confidence", "N/A"))
        scan_table.add_row("Status", result.get("status", "N/A"))
        if result.get("scan_time_ms"):
            scan_table.add_row("Scan Time (ms)", f"{result.get('scan_time_ms'):.2f}")
        
        console.print(scan_table)
        return 0 if result.get("error") is None else 1

    telemetry = TelemetryClient()
    code, payload = _run_llm_explanation(
        result,
        provider=args.provider,
        model=args.model,
        telemetry=telemetry,
    )
    llm_block = payload.get("llm", {})
    n8n_llm_payload = n8n_client.build_detection_payload(
        result,
        llm_explanation=llm_block.get("response_text"),
    )
    n8n_client.send_detection_to_n8n(n8n_llm_payload)
    # Mostrar resultado formateado
    scan_result = payload.get("scan_result", {})
    
    # Mostrar información del escaneo
    scan_table = Table(title="🔬 Resultado del Escaneo", show_header=False)
    scan_table.add_column("key", style="cyan bold")
    scan_table.add_column("value", style="green")
    scan_table.add_row("File", scan_result.get("file", "N/A"))
    scan_table.add_row("Label", scan_result.get("label", "N/A"))
    scan_table.add_row("Score", str(scan_result.get("score", "N/A")))
    scan_table.add_row("Confidence", scan_result.get("confidence", "N/A"))
    scan_table.add_row("Status", scan_result.get("status", "N/A"))
    
    console.print(scan_table)
    console.print()
    
    # Si hay explicación LLM, mostrarla formateada
    if "llm" in payload and payload["llm"].get("response_text"):
        _format_llm_response(payload)
    else:
        # Mostrar JSON completo
        console.print(Panel(
            JSON.from_data(payload),
            title="📄 Respuesta Completa (JSON)",
            border_style="white",
        ))
    
    if scan_result.get("error") is not None:
        return 1
    return code


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

    if not args.scan_json and not args.file:
        raise ValueError("Provide --file or --scan-json.")

    if args.scan_json:
        scan_result = json.loads(Path(args.scan_json).read_text(encoding="utf-8"))
    else:
        engine = ShadowNetEngine()
        scan_result = engine.scan_file(args.file)

    code, payload = _run_llm_explanation(
        scan_result,
        provider=args.provider,
        model=args.model,
        telemetry=telemetry,
    )
    # Mostrar resultado formateado
    scan_result = payload.get("scan_result", {})
    
    # Mostrar información del escaneo
    scan_table = Table(title="🔬 Resultado del Escaneo", show_header=False)
    scan_table.add_column("key", style="cyan bold")
    scan_table.add_column("value", style="green")
    
    if args.scan_json:
        scan_table.add_row("Source", args.scan_json)
    else:
        scan_table.add_row("File", scan_result.get("file", "N/A"))
    scan_table.add_row("Label", scan_result.get("label", "N/A"))
    scan_table.add_row("Score", str(scan_result.get("score", "N/A")))
    scan_table.add_row("Confidence", scan_result.get("confidence", "N/A"))
    scan_table.add_row("Status", scan_result.get("status", "N/A"))
    
    console.print(scan_table)
    console.print()
    
    # Mostrar explicación LLM formateada
    if "llm" in payload and payload["llm"].get("response_text"):
        _format_llm_response(payload)
    else:
        console.print(Panel(
            JSON.from_data(payload),
            title="📄 Respuesta Completa (JSON)",
            border_style="white",
        ))
    
    return code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="ShadowNet Defender CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan a PE file")
    scan_parser.add_argument("file", help="Path to file to scan")
    scan_parser.add_argument("--explain", action="store_true", help="Generate LLM explanation with Ollama")
    scan_parser.add_argument(
        "--provider",
        default="ollama",
        help="LLM provider (actual): ollama",
    )
    scan_parser.add_argument("--model", default=None, help="LLM model name for Ollama (default: from OLLAMA_MODEL env)")
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
    llm_parser.add_argument(
        "--provider",
        default="ollama",
        help="LLM provider (actual): ollama",
    )
    llm_parser.add_argument("--model", default=None, help="Override model (default: from OLLAMA_MODEL env)")
    llm_parser.set_defaults(func=_cmd_llm_explain)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
