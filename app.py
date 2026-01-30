import streamlit as st
import numpy as np
import hashlib
import matplotlib.pyplot as plt
from crypto_core import GF256, SBoxGenerator, ECC, CustomAES

# Page configuration
st.set_page_config(page_title="Système de Chiffrement AES-ECDH", layout="wide")

st.title("Système de Chiffrement AES-ECDH")
st.markdown("""
Ce projet implémente un système de chiffrement **AES-128** utilisant une **S-box personnalisée** 
et un échange de clés **ECDH** sur un corps fini $F_{17}$.
""")

# Sidebar for configuration
st.sidebar.header("Paramètres Globaux")
poly_choice = st.sidebar.selectbox("Polynôme Irréductible GF(2^8)", 
                                  options=[0x11D, 0x165, 0x14D, 0x11B],
                                  format_func=lambda x: f"0x{x:02X} (Standard 0x11B)" if x == 0x11B else f"0x{x:02X}")

st.sidebar.markdown("---")
st.sidebar.info("Note : Le corps $F_{17}$ est utilisé pour l'ECDH, tandis que la S-box est générée via un polynôme irréductible dans $GF(2^8)$.")

# Initialize Crypto Core
@st.cache_resource
def get_crypto_core(poly):
    sbox_gen = SBoxGenerator(poly)
    aes = CustomAES(sbox_gen)
    # ECDH: y^2 = x^3 + 3x + 5 mod 17
    ecc = ECC(a=3, b=5, p=17)
    G = (1, 3)
    return sbox_gen, aes, ecc, G

sbox_gen, aes, ecc, G = get_crypto_core(poly_choice)

# Tabs
tab1, tab2, tab3, tab4 = st.tabs(["Échange de Clés ECDH", "Analyse de la S-Box", "Chiffrement AES", "Courbe et Complexité"])

# Tab 1: ECDH
with tab1:
    st.header("Échange de Clés Elliptic Curve Diffie-Hellman sur $F_{17}$")
    st.write("Équation de la courbe : $y^2 = x^3 + 3x + 5 \pmod{17}$ | Point de base $G = (1, 3)$")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Alice")
        alice_priv = st.number_input("Clé privée d'Alice ($a$)", min_value=1, max_value=18, value=5)
        alice_pub = ecc.multiply(alice_priv, G)
        st.info(f"Clé publique d'Alice $A = aG$ : {alice_pub}")
        
    with col2:
        st.subheader("Bob")
        bob_priv = st.number_input("Clé privée de Bob ($b$)", min_value=1, max_value=18, value=7)
        bob_pub = ecc.multiply(bob_priv, G)
        st.info(f"Clé publique de Bob $B = bG$ : {bob_pub}")
        
    st.divider()
    
    shared_alice = ecc.multiply(alice_priv, bob_pub)
    shared_bob = ecc.multiply(bob_priv, alice_pub)
    
    st.subheader("Calcul du Secret Partagé")
    c1, c2 = st.columns(2)
    c1.write(f"Alice calcule $aB$ : {shared_alice}")
    c2.write(f"Bob calcule $bA$ : {shared_bob}")
    
    if shared_alice == shared_bob:
        st.success("Les secrets partagés correspondent.")
        # Derive 128-bit AES key from shared secret point
        shared_bytes = f"{shared_alice[0]},{shared_alice[1]}".encode()
        derived_key = hashlib.sha256(shared_bytes).digest()[:16]
        st.code(f"Clé AES-128 dérivée : {derived_key.hex().upper()}", language="text")
        st.session_state['aes_key'] = derived_key
    else:
        st.error("Erreur dans le calcul du secret partagé.")

# Tab 2: S-Box
with tab2:
    st.header("Analyse de la S-Box Personnalisée")
    st.write(f"Générée avec le polynôme irréductible : 0x{poly_choice:X}")
    
    # Compare with standard
    std_sbox_gen = SBoxGenerator(0x11B)
    
    if st.checkbox("Afficher la table de substitution (S-Box)"):
        # Display as a grid
        sbox_array = np.array(sbox_gen.sbox).reshape(16, 16)
        st.table(sbox_array)

    st.subheader("Comparaison avec le Standard AES")
    diffs = [1 if sbox_gen.sbox[i] != std_sbox_gen.sbox[i] else 0 for i in range(256)]
    num_diffs = sum(diffs)
    
    st.metric("Nombre de différences par rapport à l'AES standard", f"{num_diffs} / 256")
    
    if num_diffs > 0:
        st.write("Le changement de polynôme modifie la structure algébrique de la substitution, ce qui est l'objectif du projet.")

# Tab 3: Encryption
with tab3:
    st.header("Plateforme de Chiffrement AES-128")
    
    if 'aes_key' not in st.session_state:
        st.warning("Veuillez effectuer l'échange ECDH dans le premier onglet pour dériver une clé.")
    else:
        plaintext = st.text_area("Message en clair", value="Message secret avec S-Box personnalisée.")
        
        if st.button("Chiffrer"):
            # Simple padding to 16 bytes
            data = plaintext.encode()
            pad_len = 16 - (len(data) % 16)
            padded_data = data + bytes([pad_len] * pad_len)
            
            # Encryption
            ciphertext = bytearray()
            for i in range(0, len(padded_data), 16):
                block = padded_data[i:i+16]
                enc_block = aes.encrypt_block(block, st.session_state['aes_key'])
                ciphertext.extend(enc_block)
            
            st.subheader("Résultats")
            st.code(f"Ciphertext (HEX) : {ciphertext.hex().upper()}", language="text")
            
            # Decryption
            decrypted_data = bytearray()
            for i in range(0, len(ciphertext), 16):
                block = ciphertext[i:i+16]
                dec_block = aes.decrypt_block(block, st.session_state['aes_key'])
                decrypted_data.extend(dec_block)
            
            # Unpadding
            unpad_len = decrypted_data[-1]
            try:
                final_text = decrypted_data[:-unpad_len].decode()
                st.success(f"Message déchiffré : {final_text}")
            except:
                st.error("Erreur de déchiffrement.")

# Tab 4: Curve and Complexity
with tab4:
    st.header("Analyse Mathématique et Complexité")
    
    col_a, col_b = st.columns(2)
    
    with col_a:
        st.subheader("Points sur la courbe $F_{17}$")
        st.write("Visualisation des points $(x, y)$ satisfaisant $y^2 = x^3 + 3x + 5 \pmod{17}$ :")
        points = []
        for x in range(17):
            for y in range(17):
                if (y**2 - (x**3 + 3*x + 5)) % 17 == 0:
                    points.append((x, y))
        
        # Plotting the points
        fig, ax = plt.subplots(figsize=(6, 4))
        if points:
            px, py = zip(*points)
            ax.scatter(px, py, color='#00d4ff', s=50, edgecolors='white', alpha=0.8)
            
        ax.set_title("Points de la courbe Elliptique sur F17", color='white', fontsize=10)
        ax.set_xlabel("x", color='white')
        ax.set_ylabel("y", color='white')
        ax.set_xlim(-1, 17)
        ax.set_ylim(-1, 17)
        ax.grid(True, linestyle='--', alpha=0.3)
        ax.set_facecolor('#0e1117')
        fig.patch.set_facecolor('#0e1117')
        ax.tick_params(colors='white')
        for spine in ax.spines.values():
            spine.set_color('white')
            
        st.pyplot(fig)
        
        st.write(f"Nombre total de points : {len(points) + 1} (incluant le point à l'infini)")
        with st.expander("Voir la liste des points"):
            st.write(points)

    with col_b:
        st.subheader("Complexité des Algorithmes")
        st.markdown("""
        **1. ECDH sur $F_p$** :
        - Addition de points : $O(\log p)$ opérations sur les bits.
        - Multiplication scalaire : $O(\log k \cdot \log p)$ où $k$ est le scalaire (clé privée).
        - Problème du Logarithme Discret (DLP) : Extrêmement difficile sur de grandes courbes (ex: Curve25519).
        
        **2. AES-128** :
        - Complexité temporelle : $O(N \cdot R)$ où $N$ est le nombre de blocs et $R=10$ est le nombre de rounds.
        - S-box personnalisée : Le calcul d'inverse dans $GF(2^8)$ via l'algorithme d'Euclide étendu a une complexité de $O(m^2)$ avec $m=8$.
        """)

st.markdown("---")
st.caption("SSI 2025/2026 arithméthique modulaire")
