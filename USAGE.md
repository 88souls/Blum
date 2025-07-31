# xblum++ 2009 Mode - Usage Guide

## Overview
This script generates Bitcoin private keys directly (as in 2009 Bitcoin wallets) and searches for specific addresses in a Bloom filter.

## Prerequisites
- Bloom filter file: `target_addresses.blf`
- Compiled executable: `xblum_2009`

## Basic Usage

### Command Format
```bash
./xblum_2009 --2009 -b target_addresses.blf -o results_2009.txt -t 4
```

### Parameters
- `--2009`: Enables 2009 mode (direct private key generation)
- `-b target_addresses.blf`: Specifies the Bloom filter file containing target addresses
- `-o results_2009.txt`: Output file for found results
- `-t 4`: Number of threads (4 in this example)

### What it does
1. Generates random private keys directly (like 2009 Bitcoin wallets)
2. Converts private keys to public keys and addresses
3. Checks if generated addresses exist in the Bloom filter
4. Saves any matches to the output file

### Output
The script will create `results_2009.txt` containing any found matches in the format:
```
Private Key: [hex]
Address: [address]
```

### Stopping the script
Press `Ctrl+C` to stop the search process.

## Compilation
If you need to recompile:
```bash
make -f Makefile_2009
```

## Notes
- The script runs continuously until stopped
- It uses multi-threading for faster processing
- This is for educational/research purposes only 