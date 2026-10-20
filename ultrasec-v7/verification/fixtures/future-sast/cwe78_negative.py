import subprocess

def invoke():
    subprocess.run(["/bin/true"], check=True)
