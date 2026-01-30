import numpy as np

class GF256:
    """Arithmetic in GF(2^8) with a custom irreducible polynomial."""
    def __init__(self, poly=0x11D):
        self.poly = poly

    def multiply(self, a, b):
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi_bit = a & 0x80
            a <<= 1
            if hi_bit:
                a ^= self.poly
            a &= 0xFF
            b >>= 1
        return p

    def inverse(self, n):
        if n == 0:
            return 0
       
        res = 1
        curr = n
        for i in range(8):
            if i > 0:
                curr = self.multiply(curr, curr)
                res = self.multiply(res, curr)
       
        res = 1
        curr = n
        for i in range(1, 8): # i=1 to 7
            curr = self.multiply(curr, curr) # n^2, n^4, ... n^128
            res = self.multiply(res, curr)
        return res

    def _ext_gcd_inv(self, a):
       
        if a == 0: return 0
        r0, r1 = self.poly | 0x100, a
        s0, s1 = 0, 1
        while r1 != 0:
            # Polynomial division
            shift = r0.bit_length() - r1.bit_length()
            if shift < 0:
                r0, r1 = r1, r0
                s0, s1 = s1, s0
                continue
            
            # Subtraction in GF(2) is XOR
            r0 ^= (r1 << shift)
            s0 ^= (s1 << shift)
            
            if r0.bit_length() < r1.bit_length():
                r0, r1 = r1, r0
                s0, s1 = s1, s0
        return s0 & 0xFF

class SBoxGenerator:
    def __init__(self, poly=0x11D):
        self.gf = GF256(poly)
        self.sbox = self._generate_sbox()
        self.inv_sbox = self._generate_inv_sbox()

    def _generate_sbox(self):
        sbox = [0] * 256
        for i in range(256):
            inv = self.gf.inverse(i)
            # s = inv ^ (inv <<< 1) ^ (inv <<< 2) ^ (inv <<< 3) ^ (inv <<< 4) ^ 0x63
            x = inv
            res = 0x63
            for _ in range(5):
                res ^= x
                x = ((x << 1) | (x >> 7)) & 0xFF
            sbox[i] = res
        return sbox

    def _generate_inv_sbox(self):
        inv = [0] * 256
        for i, val in enumerate(self.sbox):
            inv[val] = i
        return inv

class ECC:
 
    def __init__(self, a, b, p):
        self.a = a
        self.b = b
        self.p = p

    def is_on_curve(self, P):
        if P is None: return True
        x, y = P
        return (y**2 - (x**3 + self.a*x + self.b)) % self.p == 0

    def add(self, P, Q):
        if P is None: return Q
        if Q is None: return P
        x1, y1 = P
        x2, y2 = Q
        
        if x1 == x2 and (y1 + y2) % self.p == 0:
            return None
            
        if x1 == x2 and y1 == y2:
            m = (3 * x1**2 + self.a) * pow(2 * y1, -1, self.p)
        else:
            m = (y2 - y1) * pow(x2 - x1, -1, self.p)
            
        x3 = (m**2 - x1 - x2) % self.p
        y3 = (m * (x1 - x3) - y1) % self.p
        return (x3, y3)

    def multiply(self, k, P):
        res = None
        base = P
        while k > 0:
            if k & 1:
                res = self.add(res, base)
            base = self.add(base, base)
            k >>= 1
        return res

class CustomAES:
  
    def __init__(self, sbox_gen):
        self.sbox = sbox_gen.sbox
        self.inv_sbox = sbox_gen.inv_sbox
        self.gf = sbox_gen.gf
        
    def _sub_bytes(self, state):
        for i in range(16):
            state[i] = self.sbox[state[i]]
        return state

    def _inv_sub_bytes(self, state):
        for i in range(16):
            state[i] = self.inv_sbox[state[i]]
        return state

    def _shift_rows(self, state):
      
        res = [0] * 16
        # Row 0: no shift
        res[0], res[4], res[8], res[12] = state[0], state[4], state[8], state[12]
        # Row 1: left shift 1
        res[1], res[5], res[9], res[13] = state[5], state[9], state[13], state[1]
        # Row 2: left shift 2
        res[2], res[6], res[10], res[14] = state[10], state[14], state[2], state[6]
        # Row 3: left shift 3
        res[3], res[7], res[11], res[15] = state[15], state[3], state[7], state[11]
        return res

    def _inv_shift_rows(self, state):
        res = [0] * 16
        # Row 0
        res[0], res[4], res[8], res[12] = state[0], state[4], state[8], state[12]
        # Row 1: right shift 1
        res[1], res[5], res[9], res[13] = state[13], state[1], state[5], state[9]
        # Row 2: right shift 2
        res[2], res[6], res[10], res[14] = state[10], state[14], state[2], state[6]
        # Row 3: right shift 3
        res[3], res[7], res[11], res[15] = state[7], state[11], state[15], state[3]
        return res

    def _mix_columns(self, state):
        for i in range(0, 16, 4):
            c0, c1, c2, c3 = state[i:i+4]
            state[i]   = self.gf.multiply(0x02, c0) ^ self.gf.multiply(0x03, c1) ^ c2 ^ c3
            state[i+1] = c0 ^ self.gf.multiply(0x02, c1) ^ self.gf.multiply(0x03, c2) ^ c3
            state[i+2] = c0 ^ c1 ^ self.gf.multiply(0x02, c2) ^ self.gf.multiply(0x03, c3)
            state[i+3] = self.gf.multiply(0x03, c0) ^ c1 ^ c2 ^ self.gf.multiply(0x02, c3)
        return state

    def _inv_mix_columns(self, state):
        for i in range(0, 16, 4):
            c0, c1, c2, c3 = state[i:i+4]
            state[i]   = self.gf.multiply(0x0e, c0) ^ self.gf.multiply(0x0b, c1) ^ self.gf.multiply(0x0d, c2) ^ self.gf.multiply(0x09, c3)
            state[i+1] = self.gf.multiply(0x09, c0) ^ self.gf.multiply(0x0e, c1) ^ self.gf.multiply(0x0b, c2) ^ self.gf.multiply(0x0d, c3)
            state[i+2] = self.gf.multiply(0x0d, c0) ^ self.gf.multiply(0x09, c1) ^ self.gf.multiply(0x0e, c2) ^ self.gf.multiply(0x0b, c3)
            state[i+3] = self.gf.multiply(0x0b, c0) ^ self.gf.multiply(0x0d, c1) ^ self.gf.multiply(0x09, c2) ^ self.gf.multiply(0x0e, c3)
        return state

    def _add_round_key(self, state, round_key):
        for i in range(16):
            state[i] ^= round_key[i]
        return state

    def key_expansion(self, key):
       
        round_keys = [list(key)]
        rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]
        
        for i in range(1, 11):
            prev_key = round_keys[-1]
            last_word = prev_key[12:16]
            # RotWord
            last_word = last_word[1:] + last_word[:1]
            # SubWord
            last_word = [self.sbox[b] for b in last_word]
            # XOR Rcon
            last_word[0] ^= rcon[i-1]
            
            new_key = [0] * 16
            for j in range(4):
                new_key[j] = prev_key[j] ^ last_word[j]
            for j in range(4, 16):
                new_key[j] = prev_key[j] ^ new_key[j-4]
            round_keys.append(new_key)
        return round_keys

    def encrypt_block(self, block, key_bytes):
        round_keys = self.key_expansion(key_bytes)
        state = self._add_round_key(list(block), round_keys[0])
        
        for i in range(1, 10):
            state = self._sub_bytes(state)
            state = self._shift_rows(state)
            state = self._mix_columns(state)
            state = self._add_round_key(state, round_keys[i])
            
        state = self._sub_bytes(state)
        state = self._shift_rows(state)
        state = self._add_round_key(state, round_keys[10])
        return bytes(state)

    def decrypt_block(self, block, key_bytes):
        round_keys = self.key_expansion(key_bytes)
        state = self._add_round_key(list(block), round_keys[10])
        
        for i in range(9, 0, -1):
            state = self._inv_shift_rows(state)
            state = self._inv_sub_bytes(state)
            state = self._add_round_key(state, round_keys[i])
            state = self._inv_mix_columns(state)
            
        state = self._inv_shift_rows(state)
        state = self._inv_sub_bytes(state)
        state = self._add_round_key(state, round_keys[0])
        return bytes(state)
