import subprocess
import time
import os
import sys
import threading

# Use full path for python and script
PYTHON_EXE = sys.executable
SCRIPT_DIR = os.path.join(os.getcwd(), "baselines", "shelLM")
SCRIPT_PATH = "LinuxSSHbot.py"

print(f"Running {SCRIPT_PATH} in {SCRIPT_DIR}")

def reader(stream, name):
    try:
        while True:
            char = stream.read(1)
            if not char:
                break
            sys.stdout.write(char)
            sys.stdout.flush()
    except Exception as e:
        print(f"Reader error: {e}")

proc = subprocess.Popen(
    [PYTHON_EXE, "-u", SCRIPT_PATH],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    cwd=SCRIPT_DIR,
    text=True,
    bufsize=0 # Unbuffered
)

# Start readers
t_out = threading.Thread(target=reader, args=(proc.stdout, "OUT"))
t_out.daemon = True
t_out.start()

t_err = threading.Thread(target=reader, args=(proc.stderr, "ERR"))
t_err.daemon = True
t_err.start()

print("Process started. Waiting 20s for prompt...")
time.sleep(20)

print("\n--- Sending command 'id' ---\n")
try:
    proc.stdin.write("id\n")
    proc.stdin.flush()
except Exception as e:
    print(f"Write failed: {e}")

print("\n--- Waiting 20s for response ---\n")
time.sleep(20)
print("\n--- Terminating ---\n")
proc.terminate()
