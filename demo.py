import subprocess
import sys
from pathlib import Path

def run_demo():
    print("🚀 Starting IOC Enricher Demo")
    
    # Create demo directory
    demo_dir = Path("demo")
    demo_dir.mkdir(exist_ok=True)
    
    # The command list is now using sys.executable
    # and the invalid flag has been removed.
    print("\n🔍 Enriching sample IOCs (JSON output)")
    subprocess.run([
        sys.executable, "main.py", "enrich",
        "examples/input_iocs.json",
        "--output-format", "json",
        "--output-file", "demo/output.json"
    ])
    
    print("\n📊 Enriching sample IOCs (CSV output)")
    subprocess.run([
        sys.executable, "main.py", "enrich", 
        "examples/input_iocs.csv",
        "--output-format", "csv",
        "--output-file", "demo/output.csv"
    ])
    
    print("\n📝 Generating Markdown report")
    subprocess.run([
        sys.executable, "main.py", "enrich",
        "examples/input_iocs.json",
        "--output-format", "markdown",
        "--output-file", "demo/report.md"
    ])
    
    print("\n🎉 Demo complete! Output files saved in demo/ directory")

if __name__ == "__main__":
    run_demo()