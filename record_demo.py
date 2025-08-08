import pyautogui
import cv2
import numpy as np
from datetime import datetime
import subprocess
import time
from multiprocessing import Process
import sys
import webbrowser
import os

# Define the duration for the screen recording (e.g., 90 seconds)
RECORDING_DURATION = 90

def record_screen(output_file, duration):
    screen_size = pyautogui.size()
    fourcc = cv2.VideoWriter_fourcc(*"mp4v")
    out = cv2.VideoWriter(output_file, fourcc, 20.0, screen_size)
    
    try:
        start_time = datetime.now()
        while (datetime.now() - start_time).seconds < duration:
            img = pyautogui.screenshot()
            frame = np.array(img)
            frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            out.write(frame)
    except Exception as e:
        print(f"An error occurred during screen recording: {e}")
    finally:
        out.release()

def run_flask_app():
    """Starts the Flask app and keeps it running."""
    # This command uses uvicorn to run the Flask app
    # The --host 0.0.0.0 makes it accessible to the browser
    subprocess.run([sys.executable, "-m", "flask", "run", "--host", "0.0.0.0"])

def run_and_record_dashboard_demo():
    print("🎥 Starting web dashboard recording...")
    
    # 1. Start the Flask app in a separate process
    flask_app_process = subprocess.Popen([sys.executable, "-m", "flask", "run", "--host", "0.0.0.0"],
                                         cwd=os.getcwd(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("🚀 Flask app started in the background...")
    
    # Give the server a few seconds to start up
    time.sleep(5)
    
    # 2. Start the screen recording
    recorder = Process(target=record_screen, args=("dashboard_demo.mp4", RECORDING_DURATION))
    recorder.start()
    
    # 3. Open the web browser
    demo_url = "http://127.0.0.1:5000/"
    webbrowser.open(demo_url)
    print(f"🌐 Opening browser to {demo_url}. Please perform the demo actions now.")
    
    # 4. Wait for the recording to finish
    recorder.join() 
    
    # 5. Terminate the Flask app process gracefully
    flask_app_process.terminate()
    print("✅ Demo recording saved as dashboard_demo.mp4")

if __name__ == "__main__":
    # Note: To run this script, ensure you have flask and your app.py file set up correctly.
    # The FLASK_APP environment variable might need to be set if not named app.py.
    # For now, this script assumes your app is named app.py and runs with 'flask run'
    run_and_record_dashboard_demo()