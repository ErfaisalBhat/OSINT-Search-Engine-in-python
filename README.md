OSINT Search Engine in Python is a lightweight toolkit for performing open-source intelligence (OSINT) searches across public sources. The project aims to provide a simple, extensible foundation for collecting publicly-available information about people, organizations, and domains, while prioritizing responsible, ethical usage.

NOTE: This repository is a toolkit for lawful, ethical OSINT research and red-team/reconnaisance in environments where you have permission. Do not use it to invade privacy, harass, or break laws or terms of service.
Quick start
1. Clone the repo
```bash
git clone https://github.com/ErfaisalBhat/OSINT-Search-Engine-in-python.git
cd OSINT-Search-Engine-in-python
```

2. Create and activate a virtual environment
```bash
python -m venv .venv
# Linux / macOS
source .venv/bin/activate
# Windows (PowerShell)
.venv\Scripts\Activate.ps1
```

3. Install dependencies
```bash
pip install -r requirements.txt
```

4. Run the tool (example)
Replace `osint_search.py` with your actual entrypoint script if different.
```bash
# Basic query
python osint_search.py --query "John Doe" --output results.json

# Query with specific sources and CSV output
python osint_search.py --query "example.com" --sources google,bing,whois --format csv --output example_results.csv
```

Usage (CLI)
The CLI supports these common options (update to match your implementation):
```
--query     / -q    : Search query (required)
--sources   / -s    : Comma-separated source list (default: all)
--format    / -f    : Output format: json | csv (default: json)
--output    / -o    : Output file path (default: results.json)
--limit     / -l    : Max number of results per-source
--verbose   / -v    : Verbose logging
--config    / -c    : Path to YAML/JSON config
```
If your repo exposes a Python package entrypoint, run it as:
```bash
python -m your_package_name --query "..."
```

Configuration
- requirements.txt — list your Python dependencies.
- .env or environment variables — store API keys (if any) as environment variables rather than hardcoding them.
Example environment variables:
```
GOOGLE_API_KEY=xxx
BING_API_KEY=xxx
WHOIS_API_KEY=xxx
```
If using third-party APIs that require credentials, document required keys and how to obtain them.
