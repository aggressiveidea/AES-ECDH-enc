
from crypto_core import SBoxGenerator, CustomAES
import os

def test_aes_consistency():
    poly = 0x11D
    sbox_gen = SBoxGenerator(poly)
    aes = CustomAES(sbox_gen)
    
    key = os.urandom(16)
    message = b"This is a test message 16B"
    # Ensure it's multiple of 16 for simplicity in block test
    if len(message) < 32:
        message = message.ljust(32, b'\0')
    
    print(f"Testing with Poly: {hex(poly)}")
    print(f"Key: {key.hex()}")
    
    ciphertext = bytearray()
    for i in range(0, len(message), 16):
        block = message[i:i+16]
        enc = aes.encrypt_block(block, key)
        ciphertext.extend(enc)
    
    print(f"Ciphertext: {ciphertext.hex()}")
    
    decrypted = bytearray()
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        dec = aes.decrypt_block(block, key)
        decrypted.extend(dec)
    
    print(f"Decrypted:  {decrypted.hex()}")
    print(f"Original:   {message.hex()}")
    
    if decrypted == message:
        print("SUCCESS: Encryption/Decryption are consistent.")
    else:
        print("FAILURE: Decrypted message does not match original.")

if __name__ == "__main__":
    test_aes_consistency()
