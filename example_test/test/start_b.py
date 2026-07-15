import os
import sys
import subprocess

os.environ["LOCAL_HOST"] = "192.168.66.244"
os.environ["LOCAL_PORT"] = "8001"
os.environ["REMOTE_HOST"] = "192.168.66.243"
os.environ["REMOTE_PORT"] = "8000"
os.environ["DISPLAY_NAME"] = "Bob"

subprocess.run([sys.executable, "client.py"])
