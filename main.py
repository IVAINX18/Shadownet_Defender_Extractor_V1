from core.scanner import scan_file
from rich import print

result = scan_file("samples/procexp.exe")

print("[bold cyan]ShadowNet Defender Scan Result[/bold cyan]")
print(result)
