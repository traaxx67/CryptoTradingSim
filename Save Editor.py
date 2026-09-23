#!/usr/bin/env python3
"""
Crypto Trading Simulator save editor.

Reproduces CryptoTradingSimulator.Singleplayer.SaveSystem.Serialization.SaveEncryptionHelper
so you can decrypt, edit, and re-encrypt your own local save file.

Requires: pip install cryptography
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import shutil
from datetime import datetime

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

# --- Matches SaveEncryptionHelper exactly ---
KEY_MATERIAL = b"CTSO_SaveKey_v2"
HARDCODED_SEED = bytes([75, 114, 121, 112, 116, 111, 84, 114, 97, 100, 101, 83, 105, 109, 50, 53])  # "KryptoTradeSim25"
PBKDF2_ITERATIONS = 10000

# Save directory - uses current user's AppData\LocalLow folder
SAVE_DIR = os.path.join(os.path.expanduser("~"), "AppData", "LocalLow", "SumerWorks", "Crypto Trading Simulator")

# Create a subfolder in the script's directory for decrypted files and backups
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(SCRIPT_DIR, "SaveEditorData")
os.makedirs(DATA_DIR, exist_ok=True)


def derive_keys(salt):
    """Returns (aes_key, hmac_key), each 32 bytes, matching Rfc2898DeriveBytes.GetBytes(32) x2."""
    password = KEY_MATERIAL + HARDCODED_SEED
    derived = hashlib.pbkdf2_hmac("sha256", password, salt, PBKDF2_ITERATIONS, dklen=64)
    return derived[:32], derived[32:64]


def decrypt(blob):
    if len(blob) < 80:
        raise ValueError("Data too short to be a valid save (need salt+iv+hmac+ciphertext)")
    salt, iv, stored_hmac, ciphertext = blob[:16], blob[16:32], blob[32:64], blob[64:]
    aes_key, hmac_key = derive_keys(salt)
    calc_hmac = hmac.new(hmac_key, salt + iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(calc_hmac, stored_hmac):
        raise ValueError("HMAC check failed — wrong key derivation, or the save is corrupted/tampered")
    decryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return (unpadder.update(padded) + unpadder.finalize()).decode("utf-8")


def encrypt(plain_json):
    plain_bytes = plain_json.encode("utf-8")
    salt, iv = secrets.token_bytes(16), secrets.token_bytes(16)
    aes_key, hmac_key = derive_keys(salt)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plain_bytes) + padder.finalize()
    encryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    calc_hmac = hmac.new(hmac_key, salt + iv + ciphertext, hashlib.sha256).digest()
    return salt + iv + calc_hmac + ciphertext


def load_encrypted_file(path):
    with open(path, "r", encoding="utf-8") as f:
        content = f.read().strip()
    raw = base64.b64decode(content)
    plain = decrypt(raw)
    return json.loads(plain)


def write_encrypted_file(path, data):
    plain_json = json.dumps(data)
    encrypted_bytes = encrypt(plain_json)
    with open(path, "w", encoding="utf-8") as f:
        f.write(base64.b64encode(encrypted_bytes).decode("ascii"))


def find_wallet(data, wallet_field):
    return (data.get("walletSystem") or {}).get(wallet_field)


def list_save_files():
    """List all save files in the game's save directory."""
    try:
        files = [f for f in os.listdir(SAVE_DIR) if os.path.isfile(os.path.join(SAVE_DIR, f)) and f.endswith('.json')]
        # Filter out backup files and decrypted JSON files we might have created (though they shouldn't be .json in the save dir)
        files = [f for f in files if not f.endswith('.bak') and not f.endswith('.decrypted.json')]
        return sorted(files)
    except FileNotFoundError:
        print(f"Save directory not found: {SAVE_DIR}")
        return []


def list_decrypted_files():
    """List all decrypted JSON files in our data directory."""
    try:
        files = [f for f in os.listdir(DATA_DIR) if os.path.isfile(os.path.join(DATA_DIR, f)) and f.endswith('.json')]
        # We might have backed up files with .bak, but we are only interested in decrypted JSONs
        # We'll assume decrypted JSONs are the ones we created (they might have _decrypted in the name)
        return sorted(files)
    except FileNotFoundError:
        return []


def backup_encrypted_file(original_path):
    """Backup the encrypted file to our data directory with a timestamp."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.basename(original_path)
    backup_name = f"{filename}_{timestamp}.bak"
    backup_path = os.path.join(DATA_DIR, backup_name)
    shutil.copy2(original_path, backup_path)
    return backup_path


def save_decrypted_file(decrypted_data, original_filename):
    """Save decrypted JSON data to our data directory."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = os.path.splitext(original_filename)[0]
    decrypted_name = f"{base_name}_decrypted_{timestamp}.json"
    decrypted_path = os.path.join(DATA_DIR, decrypted_name)
    with open(decrypted_path, "w", encoding="utf-8") as f:
        json.dump(decrypted_data, f, indent=2)
    return decrypted_path


def main():
    print("=== Crypto Trading Simulator Save Editor ===")
    print(f"Save directory: {SAVE_DIR}")
    print(f"Editor data directory: {DATA_DIR}\n")

    # List save files
    save_files = list_save_files()
    if not save_files:
        print("No save files found in the save directory.")
        return

    print("Available save files:")
    for i, filename in enumerate(save_files, 1):
        print(f"  [{i}] {filename}")

    try:
        choice = int(input("\nSelect a save file by number: ").strip())
        if choice < 1 or choice > len(save_files):
            print("Invalid selection.")
            return
    except ValueError:
        print("Please enter a valid number.")
        return

    selected_file = save_files[choice - 1]
    save_path = os.path.join(SAVE_DIR, selected_file)

    print(f"\nSelected: {selected_file}")

    # Menu
    print("\nWhat would you like to do?")
    print("  [1] Just decrypt (to editor data directory)")
    print("  [2] Decrypt and edit money")
    print("  [3] Encrypt another save file (from decrypted files)")

    try:
        action = int(input("\nChoose an option: ").strip())
    except ValueError:
        print("Invalid option.")
        return

    if action == 1:
        # Just decrypt
        try:
            data = load_encrypted_file(save_path)
            print("\nDecrypted successfully.")
            decrypted_path = save_decrypted_file(data, selected_file)
            print(f"Decrypted save saved to: {decrypted_path}")
        except Exception as e:
            print(f"Error during decryption: {e}")

    elif action == 2:
        # Decrypt and edit money
        try:
            data = load_encrypted_file(save_path)
            print("\nDecrypted successfully.")

            # Backup the original encrypted file
            backup_path = backup_encrypted_file(save_path)
            print(f"Backed up original encrypted file to: {backup_path}")

            # Write a readable copy for inspection (optional, but kept for user)
            dump_path = save_decrypted_file(data, selected_file)  # This will create a decrypted copy with timestamp
            print(f"Wrote readable copy for inspection: {dump_path}")

            proceed = input("\nEdit a wallet balance now? (y/n): ").strip().lower()
            if proceed != "y":
                print("Done — nothing written back. Re-run and choose 'y' when ready to edit.")
                return

            wallet_choice = input("Which wallet? (main/margin/bot) [main]: ").strip().lower() or "main"
            wallet_field = {"main": "mainWallet", "margin": "marginWallet", "bot": "botWallet"}.get(
                wallet_choice, "mainWallet"
            )

            wallet = find_wallet(data, wallet_field)
            if wallet is None:
                print(f"Couldn't find walletSystem.{wallet_field} — check {dump_path} for the real structure.")
                return

            balances = wallet.get("balances")
            if balances is None:
                print(f"Couldn't find 'balances' under {wallet_field} — check {dump_path}.")
                return

            print(f"Current balances in {wallet_field}: {balances}")
            currency = input("Currency symbol to edit [USDT]: ").strip().upper() or "USDT"
            new_value = float(input(f"New {currency} balance: ").strip())

            old_value = balances.get(currency)
            balances[currency] = new_value
            print(f"{wallet_field}.balances['{currency}']: {old_value} -> {new_value}")

            write_encrypted_file(save_path, data)
            print("Re-encrypted and saved. Launch the game (correct save slot) to verify.")

        except Exception as e:
            print(f"Error: {e}")

    elif action == 3:
        # Encrypt another save file
        decrypted_files = list_decrypted_files()
        if not decrypted_files:
            print("No decrypted files found in the editor data directory.")
            print("First decrypt a save file using option 1 or 2.")
            return

        print("\nAvailable decrypted files:")
        for i, filename in enumerate(decrypted_files, 1):
            print(f"  [{i}] {filename}")

        try:
            dec_choice = int(input("\nSelect a decrypted file by number: ").strip())
            if dec_choice < 1 or dec_choice > len(decrypted_files):
                print("Invalid selection.")
                return
        except ValueError:
            print("Please enter a valid number.")
            return

        selected_decrypted = decrypted_files[dec_choice - 1]
        decrypted_path = os.path.join(DATA_DIR, selected_decrypted)

        try:
            with open(decrypted_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            print(f"\nLoaded decrypted data from: {selected_decrypted}")

            # Ask for the filename to save in the save directory
            default_name = os.path.splitext(selected_decrypted)[0]
            # Remove any _decrypted_* suffix
            if '_decrypted_' in default_name:
                default_name = default_name.split('_decrypted_')[0]
            save_name = input(f"Enter filename to save in save directory (without extension) [{default_name}]: ").strip()
            if not save_name:
                save_name = default_name
            # Ensure it has .json extension? The original save files are .json but contain base64.
            # We'll save as <save_name>.json in the save directory.
            save_filename = f"{save_name}.json"
            save_path = os.path.join(SAVE_DIR, save_filename)

            # Check if file already exists
            if os.path.exists(save_path):
                overwrite = input(f"File {save_filename} already exists. Overwrite? (y/n): ").strip().lower()
                if overwrite != 'y':
                    print("Cancelled.")
                    return

            # Encrypt and write
            write_encrypted_file(save_path, data)
            print(f"Encrypted save written to: {save_path}")
            print("You can now use this save in the game.")

        except Exception as e:
            print(f"Error during encryption: {e}")

    else:
        print("Invalid option.")


if __name__ == "__main__":
    main()
