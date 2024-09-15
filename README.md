# AES-OCB and AES-GCM Encryption

## Overview
This repository contains Python implementations of the AES-OCB and AES-GCM authenticated encryption algorithms. These algorithms provide secure encryption of data along with integrity and authenticity checks. The implementations are provided in two separate files: `aes-ocb.py` and `aes-gcm.py`.

## AES-OCB
### Description
The `aes-ocb.py` program implements the AES-OCB authenticated encryption algorithm.

### Features
1. Encrypt and decrypt plaintext messages using AES-OCB.
2. Encrypt and decrypt a default English sentence.
3. Measure the performance of the custom implementation against the standard implementation (70000 iterations each).
4. Exit the program.

### Installation
You can install the necessary libraries using pip:
```bash
pip install pycryptodome
```

## AES-GCM
### Description
The `aes-gcm.py` program implements the AES-GCM authenticated encryption algorithm.

### Features
1. Encrypt and decrypt plaintext messages using AES-GCM.
2. Encrypt and decrypt a default English sentence.
3. Measure the performance of the custom implementation against the standard implementation (70000 iterations each).
4. Exit the program.

### Installation
You can install the necessary libraries using pip:
```bash
pip install pycryptodome
```

## Usage
You can run the programs using the following commands:
```bash
python3 aes-ocb.py
```
Or
```bash
python3 aes-gcm.py
```