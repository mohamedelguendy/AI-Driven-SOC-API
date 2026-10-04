"""Starts the API and opens the docs page in your browser automatically.
 
Run this instead of the uvicorn command:
    python run.py
"""
import threading
import time
import webbrowser
 
import uvicorn
 
 
def _open_browser():
    time.sleep(1.5)  # give the server a moment to come up first
    webbrowser.open("http://127.0.0.1:8000/docs")
 
 
if __name__ == "__main__":
    threading.Thread(target=_open_browser, daemon=True).start()
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
 