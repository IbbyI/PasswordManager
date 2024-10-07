import os
import subprocess
from cryptography.fernet import Fernet

def save_key():
    if 'FERNET_KEY' not in os.environ:
        print("Generating Key...")
        key = Fernet.generate_key().decode()
        subprocess.run(['setx', 'FERNET_KEY', key])
        print(f"Enviroment Variable FERNET_KEY SET WITH: {key}")
        print("Saved Fernet Key to User Environment Variables.")
    else:
        print("Fernet Key already Exists.")
save_key()

