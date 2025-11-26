import os, json, hashlib, datetime
from cryptography.fernet import Fernet

METADATA_FILE = "metadata.json"

# ---------------------- Helper Functions ---------------------- #
def generate_key(key_file="secret.key"):
    """Generate and save AES key (Fernet 256-bit)"""
    key = Fernet.generate_key()
    with open(key_file, "wb") as f:
        f.write(key)
    print(f"[+] Key saved to {key_file}")
    return key

def load_key(key_file="secret.key"):
    """Load existing key"""
    with open(key_file, "rb") as f:
        return f.read()

def file_hash(path):
    """Compute SHA256 hash"""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

def update_metadata(entry):
    """Append metadata entry to metadata.json"""
    data = []
    if os.path.exists(METADATA_FILE):
        with open(METADATA_FILE, "r") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                data = []
    data.append(entry)
    with open(METADATA_FILE, "w") as f:
        json.dump(data, f, indent=2)

# ---------------------- Core Functions ---------------------- #
def encrypt_file(input_path, key_file="secret.key"):
    key = load_key(key_file)
    fernet = Fernet(key)

    with open(input_path, "rb") as f:
        plaintext = f.read()

    encrypted = fernet.encrypt(plaintext)
    enc_path = input_path + ".enc"
    with open(enc_path, "wb") as f:
        f.write(encrypted)

    hash_val = file_hash(enc_path)
    entry = {
        "original_file": os.path.basename(input_path),
        "encrypted_file": os.path.basename(enc_path),
        "timestamp": datetime.datetime.utcnow().isoformat(),
        "hash": hash_val
    }
    update_metadata(entry)
    print(f"[+] Encrypted file saved as {enc_path}")
    print(f"[+] SHA256: {hash_val}")

def decrypt_file(enc_path, key_file="secret.key"):
    key = load_key(key_file)
    fernet = Fernet(key)

    with open(enc_path, "rb") as f:
        ciphertext = f.read()

    try:
        plaintext = fernet.decrypt(ciphertext)
    except Exception:
        print("[!] Error: invalid key or file corrupted.")
        return

    dec_path = enc_path.replace(".enc", ".dec")
    with open(dec_path, "wb") as f:
        f.write(plaintext)
    print(f"[+] Decrypted file saved as {dec_path}")

def verify_file(enc_path):
    """Verify integrity by comparing stored hash"""
    current_hash = file_hash(enc_path)
    if not os.path.exists(METADATA_FILE):
        print("[!] No metadata file found.")
        return
    with open(METADATA_FILE, "r") as f:
        data = json.load(f)
    for entry in data:
        if entry["encrypted_file"] == os.path.basename(enc_path):
            if entry["hash"] == current_hash:
                print("[✓] Integrity verified.")
            else:
                print("[✗] File has been modified or tampered!")
            return
    print("[!] File not found in metadata.")

# ---------------------- CLI Interface ---------------------- #
def main():
    import sys
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python secure_store.py genkey")
        print("  python secure_store.py encrypt <file>")
        print("  python secure_store.py decrypt <file.enc>")
        print("  python secure_store.py verify <file.enc>")
        return

    cmd = sys.argv[1].lower()
    if cmd == "genkey":
        generate_key()
    elif cmd == "encrypt" and len(sys.argv) == 3:
        encrypt_file(sys.argv[2])
    elif cmd == "decrypt" and len(sys.argv) == 3:
        decrypt_file(sys.argv[2])
    elif cmd == "verify" and len(sys.argv) == 3:
        verify_file(sys.argv[2])
    else:
        print("[!] Invalid command or arguments.")

if __name__ == "__main__":
    main()
