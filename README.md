# Crypto Trading Simulator Save Editor

A tool to decrypt, edit, and re-encrypt save files for the Crypto Trading Simulator game.

## Features

- Decrypt save files to inspect and modify them
- Backup original encrypted files before modification
- Edit wallet balances (main, margin, bot)
- Re-encrypt modified saves and place them back in the game's save directory
- Create encrypted saves from decrypted JSON files
- All decrypted files and backups are stored in a local `SaveEditorData` directory

## Requirements

- Python 3.x
- `cryptography` package (`pip install cryptography`)

## Usage

1. Run the script: `python "Save Editor.py"`
2. The script will list available save files from the game's save directory.
3. Select a save file by number.
4. Choose an action:
   - **Option 1: Just decrypt** - Decrypts the save and stores the decrypted JSON in `SaveEditorData`
   - **Option 2: Decrypt and edit money** - Decrypts, lets you edit wallet balances, backs up the original, and writes the encrypted save back
   - **Option 3: Encrypt another save file** - Takes a decrypted JSON from `SaveEditorData` and encrypts it to the game's save directory

## How It Works

The save encryption uses AES-256-CBC with HMAC-SHA256 for integrity, matching the game's internal `SaveEncryptionHelper` class.

Keys are derived from:
- Key material: `CTSO_SaveKey_v2`
- Hardcoded seed: `KryptoTradeSim25` (as bytes)
- PBKDF2 with 10,000 iterations using a random salt stored in the save file

## File Locations

- Game save directory: Automatically detected as `%USERPROFILE%\AppData\LocalLow\SumerWorks\Crypto Trading Simulator`
- Editor data directory: `SaveEditorData` (created in the same directory as this script)

## License

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

## Disclaimer

This tool is for educational purposes only. Modify your own save files at your own risk. The author is not responsible for any damage or loss of game progress.

### Note
This is a POC feel free to use this as a base and let me know what you guys come up with!
