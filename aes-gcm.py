"""
File: aes-gcm.py
Author: LANGLOIS   Yvan     ER1696
        VILLEPREUX Thibault ER1697
Date: April 2024

Description:
This program implements the AES-GCM authenticated encryption algorithm. The program provides the following functionalities:
1. Encrypt and decrypt your plaintext message using AES-GCM
2. Encrypt and decrypt a default English sentence
3. Measure the performance of the custom implementation against the standard implementation (70000 iterations each).
4. Exit the program.
"""

# Import the necessary libraries, installation : pip install pycryptodome
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import time

def xor_bytes(a, b):
    """
    XOR two byte strings.

    Args:
        a: The first byte string.
        b: The second byte string.
    Return:
        The XOR of the two byte strings.
    """
    return bytes(x ^ y for x, y in zip(a, b))

def GHASH(H, A, C):
    """
    Computes the GHASH function for authenticated encryption.

    Args:
        H (int): The hash key.
        A (bytes): The additional data.
        C (bytes): The ciphertext.

    Returns:
        bytes: The GHASH value.
    """
    # Step 0: Initialize Xi to 0
    Xi = 0

    # Calculate the number of blocks in A and C
    m = len(A) // 16 + (1 if len(A) % 16 != 0 else 0)
    n = len(C) // 16 + (1 if len(C) % 16 != 0 else 0)

    # Calculate the remainder of the bit length for A and C
    u = len(A) % 16
    v = len(C) % 16

    # Step 1: Process Additional Data (A) (for i=1 to m-1)
    for i in range(m):
        # Convert the block Ai into an integer
        Ai_bytes = A[i * 16:(i + 1) * 16] + b'\x00' * (16 - len(A[i * 16:(i + 1) * 16]))
        Ai = int.from_bytes(Ai_bytes, byteorder='big')

        # Calculate Xi for each block Ai 
        # Xi = (Xi-1 ⊕ Ai)*H
        Xi ^= Ai
        Xi = (Xi * H) % (2**128)

    # Step 2: Process Additional Data (A*) if needed (for i=m)
    # Xi = (Xm-1 ⊕ (A*||0**(128-v))) * H
    if u != 0:
        # Calculate A* with padding zeros to 128 bits
        Am_bytes = A[-u:] + b'\x00' * (16 - u)
        Am = int.from_bytes(Am_bytes, byteorder='big')

        # Calculate Xi for the last block A*
        Xi ^= Am
        Xi = (Xi * pow(H, 2 ** (128 - u), 2**128)) % (2**128)

    # Step 3: Process Ciphertext (C) (for i=m+1 to m+n-1)
    # Xi = (Xi ⊕ Ci)*H
    for i in range(n):
        # Convert the block Ci into an integer
        Ci_bytes = C[i * 16:(i + 1) * 16] + b'\x00' * (16 - len(C[i * 16:(i + 1) * 16]))
        Ci = int.from_bytes(Ci_bytes, byteorder='big')

        # Calculate Xi for each block Ci
        Xi ^= Ci
        Xi = (Xi * H) % (2**128)

    # Step 4: Process Ciphertext (C*) if needed (for i=m+n)
    # Xi = (Xm+n-1 ⊕ (C*||0**(128-u))) * H
    if v != 0:
        # Calculate C* with padding zeros to 128 bits
        Cn_bytes = C[-v:] + b'\x00' * (16 - v)
        Cn = int.from_bytes(Cn_bytes, byteorder='big')

        # Calculate Xi for the last block C*
        Xi ^= Cn
        Xi = (Xi * pow(H, 2 ** (128 - v), 2**128)) % (2**128)

    # Step 5: Calculate X using len(A) and len(C) (for i=m+n+1)
    # Xi = Xm+n ⊕ (len(A)||len(C)) * H
    X = (Xi ^ (len(A) | len(C))) * H % (2**128)

    return X.to_bytes(16, byteorder='big')

def MSB(x):
    """
    Extracts the most significant 128 bits (16 bytes) from an integer and returns it as bytes.

    Args:
        x (int): The input integer.

    Returns:
        bytes: The most significant 128 bits of the input integer.
    """
    return x.to_bytes(16, byteorder='big')[:16]

def encrypt(K, IV, P, A):
    """
    Encrypts a plaintext message P using AES-GCM authenticated encryption.

    Args:
        K (bytes): The encryption key.
        IV (bytes): The initialization vector.
        P (bytes): The plaintext message.
        A (bytes): The additional data.

    Returns:
        bytes: The ciphertext.
        bytes: The authentication tag.
    """

    # Create a new AES cipher object with the key K in ECB mode
    cipher = AES.new(K, AES.MODE_ECB)

    # Step 0: Compute the hash subkey H
    H = int.from_bytes(cipher.encrypt(bytes(16)), byteorder='big')

    # Step 1: Initialize the counter Y0 to the IV
    if len(IV) == 96:
        Y0 = int.from_bytes(IV, byteorder='big')  # If the length of IV is 96, then Y0 = IV || 0^31 1
    else:
        Y0 = int.from_bytes(GHASH(H, {}, IV), byteorder='big')  # Otherwise, Y0 = GHASH(H, {}, IV)

    # Step 2: Process the plaintext message P for i = 1 to n-1
    # Ci = Pi ⊕ E(K, Yi)
    C = b''
    num_blocks = len(P) // 16
    for i in range(num_blocks):
        # Increment the counter for each block
        Y0 += 1

        # Encrypt the counter
        counter_bytes = Y0.to_bytes(16, byteorder='big')
        encrypted_counter = cipher.encrypt(counter_bytes)

        # XOR the plaintext block with the encrypted counter to get the ciphertext block
        plaintext_block = P[i * 16:(i + 1) * 16]
        ciphertext_block = xor_bytes(plaintext_block, encrypted_counter)

        # Append the ciphertext 
        C += ciphertext_block

    # Step 3: Handle the last block if its size is less than 16 bytes
    # Cn* = Pn* ⊕ E(K, Yn)
    if len(P) % 16 != 0:
        # Increment the counter for the last block
        Y0 += 1
        # Encrypt the counter
        counter_bytes = Y0.to_bytes(16, byteorder='big')
        encrypted_counter = cipher.encrypt(counter_bytes)
        # Get the plaintext block
        plaintext_block = P[num_blocks * 16:]
        # XOR the plaintext block with the encrypted counter to get the ciphertext block
        ciphertext_block = xor_bytes(plaintext_block, encrypted_counter)
        # Append the ciphertext 
        C += ciphertext_block

    # Step 4: Compute the Authentication Tag T
    T = MSB(int.from_bytes(GHASH(H, A, C), byteorder='big') ^ int.from_bytes(cipher.encrypt(IV), byteorder='big')) # T = MSB(GHASH(H, A, C) ⊕ E(K, Y0))

    return C, T

def decrypt(K, IV, C, A, T):
    """
    Decrypts a ciphertext message C using AES-GCM authenticated encryption.

    Args:
        K (bytes): The decryption key.
        IV (bytes): The initialization vector.
        C (bytes): The ciphertext message.
        A (bytes): The additional data.
        T (bytes): The authentication tag.

    Returns:
        bytes: The decrypted plaintext message.
    """
    # Create a new AES cipher object with the key K in ECB mode
    cipher = AES.new(K, AES.MODE_ECB)

    # Step 0: Compute the hash subkey H
    H = int.from_bytes(cipher.encrypt(bytes(16)), byteorder='big')

    # Step 1: Initialize the counter Y0 to the IV
    if len(IV) == 96:
        Y0 = int.from_bytes(IV, byteorder='big')  # If the length of IV is 96, then Y0 = IV || 0^31 1
    else:
        Y0 = int.from_bytes(GHASH(H, {}, IV), byteorder='big')  # Otherwise, Y0 = GHASH(H, {}, IV)

    # Step 2: Process the ciphertext message C for i = 1 to n
    # Pi = C ⊕ E(K, Yi)
    P = b''
    num_blocks = len(C) // 16
    for i in range(num_blocks):
        Y0 += 1

        # Encrypt the counter
        counter_bytes = Y0.to_bytes(16, byteorder='big')
        encrypted_counter = cipher.encrypt(counter_bytes)
        ciphertext_block = C[i * 16:(i + 1) * 16]
        plaintext_block = xor_bytes(ciphertext_block, encrypted_counter)

        # Append the plaintext
        P += plaintext_block

    # Step 3: Handle the last block if its size is less than 16 bytes
    # Pn* = Cn* ⊕ E(K, Yi)
    if len(C) % 16 != 0:
        Y0 += 1
        counter_bytes = Y0.to_bytes(16, byteorder='big')
        encrypted_counter = cipher.encrypt(counter_bytes)
        ciphertext_block = C[num_blocks * 16:]
        plaintext_block = xor_bytes(ciphertext_block, encrypted_counter)
        P += plaintext_block

    # Step 4: Compute the Authentication Tag T' and compare it with T
    T_prime = MSB(int.from_bytes(GHASH(H, A, C), byteorder='big') ^ int.from_bytes(cipher.encrypt(IV), byteorder='big')) # T' = MSB(GHASH(H, A, C) ⊕ E(K, Y0))

    if T_prime != T:
        raise ValueError("Authentication failed")

    return P

def process_encryption(sentence, A=b''):
    K = get_random_bytes(16)
    IV = get_random_bytes(16)
    

    print("\nEncrypting...")
    ciphertext, tag = encrypt(K, IV, sentence, A)
    print("Ciphertext:", ciphertext.hex())
    print("Tag:", tag.hex())

    print("\nDecrypting...")
    decrypted_sentence = decrypt(K, IV, ciphertext, A, tag)
    print("Decrypted sentence:", decrypted_sentence.decode())

def main():
    default_sentence = b'This is a very important and confidential message. It contains sensitive information that must be kept secure and confidential at all times.'
    A = b'AdditionalData'
    while True:
        print("\nMENU:")
        print("1. Enter a custom sentence")
        print("2. Use the default English sentence")
        print("3. Measure performance (70000 iterations each)")
        print("4. Quit")
        choice = input("Enter your choice (1, 2, 3, or 4): ")

        if choice == '1':
            sentence = input("Enter your sentence: ").encode()
            process_encryption(sentence, A)

        elif choice == '2':
            process_encryption(default_sentence, A)

        elif choice == '3':

            K = get_random_bytes(16)
            IV = get_random_bytes(16)
            start_time_custom = time.time()
            for _ in range(70000):
                ciphertext, tag = encrypt(K, IV, default_sentence, A)
                decrypt(K, IV, ciphertext, A, tag)
            total_time_custom = time.time() - start_time_custom

            start_time_standard = time.time()
            for _ in range(70000):
                cipher = AES.new(K, AES.MODE_GCM, nonce=IV)
                cipher.update(A)
                ciphertext, tag = cipher.encrypt_and_digest(default_sentence)
                cipher = AES.new(K, AES.MODE_GCM, nonce=IV)
                cipher.update(A)
                cipher.decrypt_and_verify(ciphertext, tag)
            total_time_standard = time.time() - start_time_standard

            print("Total Time for 70000 iterations (Custom):", total_time_custom, "seconds")
            print("Total Time for 70000 iterations (Standard):", total_time_standard, "seconds")

            if total_time_standard == 0:
                print("The standard implementation is faster or equally fast as our implementation.")
            else:
                speedup = total_time_custom / total_time_standard
                print("The standard implementation is", speedup, "times faster than our implementation :'(")

        elif choice == '4':
            print("Goodbye!")
            break

        else:
            print("Invalid choice")

if __name__ == "__main__":
    main()
