IOC Enrichment & Correlation Tool
🔎 Background & Motivation
This is a comprehensive tool designed to streamline the process of enriching Indicators of Compromise (IOCs) from various sources. It automates the correlation of security data, providing a unified view for threat intelligence analysis. The project offers multiple interfaces, including a command-line tool, a real-time web dashboard, an automated directory watcher, and a high-performance REST API.

✨ Features
Command-Line Interface (CLI): Process IOCs directly from your terminal.

Web Dashboard (Flask): A clean, user-friendly UI for file uploads with real-time streaming output.

Directory Watcher: Automatically process files placed in a designated folder.

REST API (FastAPI): A high-performance API endpoint for programmatically enriching IOCs.

Flexible Output: Generate enriched data in JSON, CSV, Markdown, or Splunk-compatible formats.

💻 Installation & Usage
1. Setup
First, clone the repository and navigate into the project directory.

Bash

git clone [YOUR_REPO_URL]
cd ioc-enricher
2. Virtual Environment
Create and activate a Python virtual environment to manage dependencies.

Bash

# On Windows PowerShell
python -m venv venv
.\venv\Scripts\Activate.ps1
3. Install Dependencies
Install all required packages using the requirements.txt file.

Bash

pip install -r requirements.txt
🔑 API Key Setup
This tool uses environment variables to manage API keys for enrichment services. Create a file named .env in your project's root directory and add your keys inside.

Ini, TOML

# .env file
VT_API_KEY="your_virustotal_api_key_here"
SHODAN_API_KEY="your_shodan_api_key_here"
# Add other keys as needed
🚀 Example Commands
CLI Tool
Run the tool from your terminal to enrich a file and save the output.

Bash

python main.py enrich examples/input_iocs.json --output-format json --output-file output/enriched_data.json
Web Dashboard
Start the Flask web server and access the dashboard in your browser.

Bash

python app.py
Then, open your browser and navigate to http://127.0.0.1:5000.

Directory Watcher
Run the watcher script to automatically process files dropped into the watch/ directory.

Bash

python watcher.py
REST API
Start the FastAPI server and access the interactive documentation.

Bash

uvicorn api:app --reload
Then, go to http://127.0.0.1:8000/docs to test the API endpoint.

📂 Sample Inputs/Outputs
This project includes an examples/ directory containing a sample input_iocs.json file. The output of the enrichment process is stored in the output/ directory.

Sample Input File

Sample Output File (Placeholder)

🎬 Demo Video
https://youtu.be/z63Pb1SQjEI
