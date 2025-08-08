from flask import Flask, render_template, request, Response
import subprocess
import os
import sys
import json

app = Flask(__name__)

# Route to serve the main HTML page
@app.route('/')
def index():
    return render_template('index.html')

# New route for real-time streaming
@app.route('/stream-enrichment', methods=['POST'])
def stream_enrichment():
    if 'file' not in request.files:
        return Response("No file part", status=400)

    file = request.files['file']
    if file.filename == '':
        return Response("No selected file", status=400)

    # Save the uploaded file temporarily
    file_path = os.path.join("uploads", file.filename)
    os.makedirs("uploads", exist_ok=True)
    file.save(file_path)

    # Get the path to the python executable from the virtual environment
    venv_python = os.path.join(sys.prefix, 'Scripts', 'python.exe')
    
    # Prepare the command to run your CLI tool
    # Note: We're not specifying an output file, so the output goes to stdout
    command = [
        venv_python, "main.py", "enrich", file_path,
        "--output-format", "json"
    ]

    # Create a generator function to stream the output
    def generate_output():
        try:
            # Use subprocess.Popen for real-time output
            proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8')
            
            # Read and yield each line from the process's stdout
            for line in proc.stdout:
                yield line
            
            # Wait for the process to finish and check the return code
            proc.wait()
            if proc.returncode != 0:
                yield f"\n❌ Error: The process exited with code {proc.returncode}"
            
        except FileNotFoundError:
            yield f"\n❌ Error: The command '{venv_python}' was not found. Check your virtual environment path."
        except Exception as e:
            yield f"\n❌ An unexpected error occurred: {e}"
        finally:
            # Clean up the temporary file
            os.remove(file_path)

    # Return a streaming response with the generator
    return Response(generate_output(), mimetype='text/plain')

if __name__ == '__main__':
    app.run(debug=True)