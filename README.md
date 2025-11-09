🧩 Bitcoin Address → HASH160 Converter (addr_to_h160_safe_v2.py)

This Python script decodes Bitcoin addresses (legacy, P2SH, and Bech32 types) and extracts their underlying HASH160 or witness program in hexadecimal format.
It supports mainnet and testnet, validates checksums, and safely handles invalid or malformed addresses.

⚙️ What It Does

Reads an input file (list of Bitcoin addresses, one per line).

Automatically detects address type:

Legacy P2PKH (1...)

P2SH (3...)

Bech32 SegWit (bc1... / tb1...)

Taproot (bc1p... or any witness v1 address)

Decodes the address:

For legacy / P2SH → uses Base58Check decoding.

For Bech32 → uses BIP173 checksum and witness program decoding.

Extracts and writes results to a tab-separated file:

ADDRESS<TAB>TYPE<TAB>HEX


where HEX = hash160 (for P2PKH/P2SH/P2WPKH) or the raw witness program.

🧾 Example Input (addresses.txt)
1BoatSLRHtKNngkdXEeobR76b53LETtpyT
3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy
bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080
bc1p5cyxnuxmeuwuvkwfem96l7wczxj0ds4n0z7a0u
tb1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh

📄 Example Output (decoded.txt)
1BoatSLRHtKNngkdXEeobR76b53LETtpyT	P2PKH(legacy)	62e907b15cbf27d5425399ebf6f0fb50ebb88f18
3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy	P2SH	74f209f6ea907e2ea48f74fae05782ae8a665257
bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080	P2WPKH(v0)	751e76e8199196d454941c45d1b3a323f1433bd6
bc1p5cyxnuxmeuwuvkwfem96l7wczxj0ds4n0z7a0u	TAPROOT(v1) len32	5120a82bafff2b7f7a1d1b20e9df6e55a5b4e6e843bfca54d3b26a8f4a6e0d75
tb1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh	TESTNET-P2WPKH(v0)	2098ac2a159cb6c4b75667f61a8ee332dfd2e42b


Invalid or corrupted addresses are logged with ERROR:

1FakeAddrXYZ	ERROR	Bad checksum

🧰 Features

✅ Supports:

Legacy Base58Check (P2PKH / P2SH)

SegWit (Bech32) – P2WPKH, P2WSH

Taproot (v1)

Both mainnet (bc1..., 1..., 3...) and testnet (tb1..., m..., n..., 2...)

✅ Includes:

Full Base58 and Bech32 decoding

Checksum verification (double SHA-256)

Error-safe handling (no crash on bad input)

📦 Requirements

Only standard Python libraries — no external dependencies.

Modules used:

sys
hashlib
binascii
typing

▶️ How to Run

Prepare an input text file (one Bitcoin address per line).
Example: addresses.txt

Run the script:

python3 addr_to_h160_safe_v2.py addresses.txt decoded.txt


The results will be written to decoded.txt.

You’ll see a short summary:

Done. ok=1250, bad=3

🧩 Output Columns Explained
Column	Meaning
ADDRESS	Original Bitcoin address
TYPE	Decoded address type
HEX	Hash160 (20 bytes) or witness program (in hex)
🧠 Use Cases

Blockchain analytics and address-type classification

Preparing address datasets for hash160-level analysis

Conversion of large address lists to their internal binary representation

Taproot / SegWit research and decoding tools

⚙️ Example Workflow
# Make executable (optional)
chmod +x addr_to_h160_safe_v2.py

# Run on address list
python3 addr_to_h160_safe_v2.py btc_addresses.txt decoded_hashes.txt


Result:

Done. ok=978, bad=2


And the output file will contain decoded info ready for analysis or database import.

🧩 Output Types Summary
Type	Description
P2PKH(legacy)	Legacy Pay-to-PubKey-Hash (Base58, starts with 1)
P2SH	Script hash (Base58, starts with 3)
P2WPKH(v0)	SegWit Pay-to-Witness-PubKey-Hash (bc1...)
P2WSH(v0)	SegWit Pay-to-Witness-Script-Hash
TAPROOT(v1)	Taproot address (BIP341, v1 witness)
TESTNET-*	Testnet variants
ERROR	Invalid or unrecognized address

BTC donation address: bc1q4nyq7kr4nwq6zw35pg0zl0k9jmdmtmadlfvqhr
