"""
File: aes-gcm.py
Author: LANGLOIS   Yvan     ER1696
        VILLEPREUX Thibault ER1697
Date: April 2024

Description:
This program implements the AES-OCB authenticated encryption algorithm. The program provides the following functionalities:
1. Encrypt and decrypt your plaintext message using AES-OCB
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

def ocb_encrypt(K, nonce, P, A):
    """
    Encrypts plaintext using the OCB mode of operation.

    Parameters:
    - K (bytes): The encryption key.
    - nonce (bytes): The nonce used for encryption.
    - P (bytes): The plaintext to be encrypted.
    - A (list of bytes): The associated data.

    Returns:
    - C (bytes): The ciphertext.
    - T (bytes): The authentication tag.
    """
    # Step 0: Initialize variables
    aes_cipher = AES.new(K, AES.MODE_ECB)
    O = aes_cipher.encrypt(nonce)
    S = b'\x00' * 16

    # Step 1: Encrypt the plaintext
    # Pad the plaintext if necessary
    if len(P) % 16 != 0:
        P += b'\x00' * (16 - len(P) % 16)

    # Encrypt the plaintext
    # C = E(K, P ⊕ O) ⊕ O
    C_blocks = []
    for i in range(0, len(P), 16):
        block = P[i:i+16]
        S = xor_bytes(S, block)
        C_block = aes_cipher.encrypt(xor_bytes(block, O))
        C_blocks.append(C_block)
        O = aes_cipher.encrypt(O)

    # Step 2: Generate the tag with the associated data
    # T = E(K, S ⊕ O*) ⊕ E(K, A1 ⊕ O1) ⊕ E(K, A2 ⊕ O2) ⊕ …
    T = xor_bytes(aes_cipher.encrypt(S), O)
    for ad in A: # Process the associated data
        if len(ad) < 16:
            ad += b'\x00' * (16 - len(ad))  # Pad the associated data if it's less than 16 bytes
        T = xor_bytes(T, aes_cipher.encrypt(ad))

    return b''.join(C_blocks), T

def ocb_decrypt(K, nonce, C, A, T):
    """
    Decrypts ciphertext encrypted using the OCB mode of operation.

    Parameters:
    - K (bytes): The decryption key.
    - nonce (bytes): The nonce used for encryption.
    - C (bytes): The ciphertext to be decrypted.
    - A (list of bytes): The associated data.
    - T (bytes): The authentication tag.

    Returns:
    - P (bytes): The decrypted plaintext.
    """
    # Step 0: Initialize variables
    aes_cipher = AES.new(K, AES.MODE_ECB)
    O = aes_cipher.encrypt(nonce)
    S = b'\x00' * 16

    # Step 1: Decrypt the ciphertext
    # P = D(K, C ⊕ O) ⊕ O
    P_blocks = []
    for i in range(0, len(C), 16):
        block = C[i:i+16]
        P_block = xor_bytes(aes_cipher.decrypt(block), O)
        P_blocks.append(P_block) 
        S = xor_bytes(S, P_block) # S = S ⊕ P
        O = aes_cipher.encrypt(O) # O = E(K, O)

    # Step 2: Verify the tag
    # T' = E(K, S) ⊕ O ⊕ E(K, A1) ⊕ E(K, A2) ⊕ …
    calculated_T = xor_bytes(aes_cipher.encrypt(S), O) # T' = E(K, S) ⊕ O
    for ad in A:
        if len(ad) < 16:
            ad += b'\x00' * (16 - len(ad))
        calculated_T = xor_bytes(calculated_T, aes_cipher.encrypt(ad)) # T' = T' ⊕ E(K, A)

    if calculated_T != T:
        print("Tag verification failed")
    return b''.join(P_blocks)

def process_encryption(sentence, A=b''):
    K = get_random_bytes(16)
    nonce = get_random_bytes(16)

    print("\nEncrypting...")
    ciphertext, tag = ocb_encrypt(K, nonce, sentence, [A])
    print("Ciphertext:", ciphertext.hex())
    print("Tag:", tag.hex())

    print("\nDecrypting...")
    decrypted_sentence = ocb_decrypt(K, nonce, ciphertext, [A], tag)
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
            nonce = get_random_bytes(16)
            nonce_prime = nonce[:15]

            start_time_custom = time.time()
            for _ in range(70000):
                ciphertext, tag = ocb_encrypt(K, nonce, default_sentence, [A]) 
                decrypted_sentence = ocb_decrypt(K, nonce, ciphertext, [A], tag)
            total_time_custom = time.time() - start_time_custom

            start_time_standard = time.time()
            for _ in range(70000):
                cipher = AES.new(K, AES.MODE_OCB, nonce=nonce_prime)
                cipher.update(A)
                ciphertext, tag = cipher.encrypt_and_digest(default_sentence)
                cipher = AES.new(K, AES.MODE_OCB, nonce=nonce_prime)
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
