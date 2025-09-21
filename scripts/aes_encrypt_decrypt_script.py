# type: ignore
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad 
from Crypto.Random import get_random_bytes
import os

def encrypt_message(data, key):
    """Encrypts data using AES with the given key."""
    data_bytes = str(data).encode('utf-8')
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext_bytes = cipher.encrypt(pad(data_bytes, AES.block_size))
    return cipher.iv + ciphertext_bytes

def decrypt_message(encrypted_data, key):
    """Decrypts data using AES with the given key."""
    # Extract the IV from the first 16 bytes
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_bytes = unpad(cipher.decrypt(ciphertext), AES.block_size)

    # Decode from bytes to string
    return decrypted_bytes.decode('utf-8')

def main():
    """Main function to demonstrate the hybrid encryption process."""
    # Alice chooses a random number 's'.
    s = 123
    
    print(f"")
    print(f"Chosen AES Key (s): {s}")
    print(f"")

    # create a valid AES key 32 bytes long
    aes_key = s.to_bytes(32, byteorder='big')

    M = 82
    print(f"Original message (M): {M}")

    # Alice encrypts M=82 using the shared secret 's' as the AES key.
    encrypted_grade = encrypt_message(M, aes_key)
    print(f"AES Ciphertext (hex): {encrypted_grade.hex()}")

    # Bob receives the ciphertext and decrypts it using the same shared secret 's'.
    decrypted_grade_str = decrypt_message(encrypted_grade, aes_key)
    M_prime = int(decrypted_grade_str)
    print(f"") 
    print(f"Decrypted Grade (M'): {M_prime}")
    print(f"")

    # verify the original message and the decrypted message are the same.
    # if M == M_prime:
    #     print("\nCorrectness confirmed: M = M'")
    # else:
    #     print("\nError: M != M'")

if __name__ == "__main__":
    main()
