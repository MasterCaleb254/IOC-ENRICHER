from fastapi import FastAPI, UploadFile, File, HTTPException, status
import subprocess
import os
import sys
import json
from pathlib import Path

app = FastAPI(
    title="IOC Enricher API",
    description="A simple API to enrich IOCs from a file.",
    version="1.0.0"
)

# Get the path to the python executable from the virtual environment
# This ensures the subprocess runs with the correct interpreter
venv_python = os.path.join(sys.prefix, 'Scripts', 'python.exe')

@app.post("/enrich", status_code=status.HTTP_200_OK)
async def enrich_iocs(file: UploadFile = File(...)):
    """
    Enriches IOCs from an uploaded file and returns the result as JSON.
    """
    # Create temporary directories if they don't exist
    uploads_dir = Path("uploads")
    outputs_dir = Path("outputs")
    uploads_dir.mkdir(exist_ok=True)
    outputs_dir.mkdir(exist_ok=True)

    # Save the uploaded file temporarily
    temp_file_path = uploads_dir / file.filename
    try:
        with open(temp_file_path, "wb") as buffer:
            buffer.write(await file.read())
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error saving uploaded file: {str(e)}"
        )

    # Define the output file for the enriched data
    output_filename = f"enriched_{Path(file.filename).stem}.json"
    output_file_path = outputs_dir / output_filename
    
    # Prepare the command to run your CLI tool
    command = [
        venv_python, "main.py", "enrich", str(temp_file_path),
        "--output-format", "json",
        "--output-file", str(output_file_path)
    ]

    try:
        # Run the command and capture its output
        subprocess.run(command, check=True, capture_output=True, text=True, encoding='utf-8')

        # Read the enriched data from the output file
        with open(output_file_path, 'r', encoding='utf-8') as f:
            enriched_data = json.load(f)

        return enriched_data

    except subprocess.CalledProcessError as e:
        # If the subprocess fails, return the error message
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"CLI tool error: {e.stderr}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An unexpected error occurred: {str(e)}"
        )
    finally:
        # Clean up temporary files
        if temp_file_path.exists():
            os.remove(temp_file_path)
        if output_file_path.exists():
            # Optionally, you might want to keep the output file, but for an API, cleanup is often preferred.
            os.remove(output_file_path)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)