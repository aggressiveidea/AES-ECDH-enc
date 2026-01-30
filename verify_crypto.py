from crypto_core import GF256, SBoxGenerator, ECC, CustomAES
import os

def test_aes():
    print("Running AES Verification...")
    sbox_gen = SBoxGenerator(0x11D)
    aes = CustomAES(sbox_gen)
    
    key = os.urandom(16)
    block = os.urandom(16)
    
    print(f"Key: {key.hex()}")
    print(f"Original Block: {block.hex()}")
    
    encrypted = aes.encrypt_block(block, key)
    print(f"Encrypted Block: {encrypted.hex()}")
    
    decrypted = aes.decrypt_block(encrypted, key)
    print(f"Decrypted Block: {decrypted.hex()}")
    
    if block == decrypted:
        print("✅ AES Verification SUCCESS!")
    else:
        print("❌ AES Verification FAILED!")

def test_ecc():
    print("\nRunning ECC Verification...")
    ecc = ECC(a=3, b=5, p=17)
    G = (1, 3)
    
    # Check if G is on curve
    if ecc.is_on_curve(G):
        print("✅ Base Point G is on curve.")
    
    # Check associativity/commutativity: 5 * (7 * G) == 7 * (5 * G)
    P1 = ecc.multiply(5, ecc.multiply(7, G))
    P2 = ecc.multiply(7, ecc.multiply(5, G))
    
    if P1 == P2:
        print(f"✅ ECC Scalar Mult Commutative: {P1} == {P2}")
    else:
        print("❌ ECC Scalar Mult Failed!")

if __name__ == "__main__":
    test_aes()
    test_ecc()
