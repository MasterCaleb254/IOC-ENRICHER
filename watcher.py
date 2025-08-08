import time
import os
import sys
import subprocess
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# The directory to watch for new files
WATCH_DIRECTORY = "watch"

# Get the path to the python executable from the virtual environment
venv_python = os.path.join(sys.prefix, 'Scripts', 'python.exe')

class MyHandler(FileSystemEventHandler):
    def on_created(self, event):
        """Called when a file or directory is created."""
        if not event.is_directory:
            file_path = event.src_path
            print(f"\n✨ New file detected: {file_path}")
            
            # Run the CLI tool with the new file
            command = [
                venv_python, "main.py", "enrich", file_path,
                "--output-format", "json",
                "--output-file", f"output/auto_enriched_{os.path.basename(file_path)}.json"
            ]
            
            try:
                print(f"🚀 Processing {os.path.basename(file_path)}...")
                subprocess.run(command, check=True)
                print(f"✅ Processing complete for {os.path.basename(file_path)}")
            except subprocess.CalledProcessError as e:
                print(f"❌ Error processing file: {e}")
            except FileNotFoundError:
                print(f"❌ Error: Python interpreter not found at {venv_python}")

if __name__ == "__main__":
    # Ensure the watch directory exists
    if not os.path.exists(WATCH_DIRECTORY):
        os.makedirs(WATCH_DIRECTORY)
        print(f"Created watch directory: {WATCH_DIRECTORY}")
    
    # Ensure the output directory exists
    if not os.path.exists("output"):
        os.makedirs("output")
        print("Created output directory: output")

    event_handler = MyHandler()
    observer = Observer()
    observer.schedule(event_handler, WATCH_DIRECTORY, recursive=False)
    
    print(f"👀 Watching directory '{WATCH_DIRECTORY}' for new files...")
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()