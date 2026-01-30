from crypto_core import GF256, SBoxGenerator, ECC, CustomAES
import os

def diag():
    sbox_gen = SBoxGenerator(0x11D)
    aes = CustomAES(sbox_gen)
    gf = sbox_gen.gf
    
    print("--- Diagnostic Start ---")
    
    # 1. Test GF Inverse
    test_val = 0x57
    inv = gf.inverse(test_val)
    prod = gf.multiply(test_val, inv)
    print(f"GF Inverse: 0x{test_val:02X} * 0x{inv:02X} = 0x{prod:02X} (Expected 0x01)")
    
    # 2. Test SBox
    val = 0x42
    sb = sbox_gen.sbox[val]
    isb = sbox_gen.inv_sbox[sb]
    print(f"SBox: 0x{val:02X} -> 0x{sb:02X} -> 0x{isb:02X} (Expected 0x42)")
    
    # 3. Test ShiftRows
    state = list(range(16))
    shifted = aes._shift_rows(state)
    inv_shifted = aes._inv_shift_rows(shifted)
    print(f"ShiftRows: Match={state == inv_shifted}")
    
    # 4. Test MixColumns
    state = [0xdb, 0x13, 0x53, 0x45] + [0]*12 # One column
    mixed = aes._mix_columns(list(state))
    inv_mixed = aes._inv_mix_columns(list(mixed))
    print(f"MixColumns: Match={state[:4] == inv_mixed[:4]}")
    if state[:4] != inv_mixed[:4]:
        print(f"  Expected: {[hex(x) for x in state[:4]]}")
        print(f"  Got:      {[hex(x) for x in inv_mixed[:4]]}")

    # 5. Full Block Test
    key = b'\x00' * 16
    block = b'\x01' * 16
    enc = aes.encrypt_block(block, key)
    dec = aes.decrypt_block(enc, key)
    print(f"Full Block: Match={list(block) == list(dec)}")

if __name__ == "__main__":
    diag()
