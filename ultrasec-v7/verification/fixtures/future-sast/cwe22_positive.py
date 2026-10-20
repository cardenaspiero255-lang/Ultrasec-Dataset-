import os

def serve(base, name):
    return open(os.path.join(base, name), "rb")
