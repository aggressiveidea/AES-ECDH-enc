import streamlit as st
import numpy as np
import hashlib
import matplotlib.pyplot as plt
from crypto_core import GF256, SBoxGenerator, ECC, CustomAES

st.set_page_config(page_title="Système de Chiffrement AES-ECDH", layout="wide")

# Custom CSS for premium look
st.markdown("""
<style>
    .main {
        background-color: #0e1117;
        color: #e0e0e0;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 24px;
        background-color: #161b22;
        padding: 10px 20px;
        border-radius: 10px 10px 0 0;
    }
    .stTabs [data-baseweb="tab"] {
        height: 50px;
        white-space: pre-wrap;
        background-color: transparent;
        border-radius: 4px 4px 0 0;
        gap: 1px;
        padding-top: 10px;
        padding-bottom: 10px;
        color: #8b949e;
        font-weight: 600;
    }
    .stTabs [aria-selected="true"] {
        color: #58a6ff !important;
        border-bottom: 2px solid #58a6ff !important;
    }
    div[data-testid="stMetricValue"] {
        color: #58a6ff;
    }
    .stButton>button {
        background-color: #238636;
        color: white;
        border-radius: 6px;
        border: 1px solid rgba(240,246,252,0.1);
        padding: 10px 24px;
        font-weight: 600;
        transition: 0.3s;
    }
    .stButton>button:hover {
        background-color: #2ea043;
        border-color: #8b949e;
    }
    .stCodeBlock {
        border: 1px solid #30363d;
        border-radius: 6px;
    }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ Système de Chiffrement Hybride AES-ECDH")
st.markdown("""
<div style="background-color: #161b22; padding: 20px; border-radius: 10px; border-left: 5px solid #58a6ff; margin-bottom: 25px;">
    Ce projet implémente un système de chiffrement <b>AES-128</b> utilisant une <b>S-box personnalisée</b> 
    et un échange de clés <b>ECDH</b> sur un corps fini <b>F<sub>17</sub></b>.
</div>
""", unsafe_allow_html=True)


st.sidebar.header("Paramètres Globaux")
poly_choice = st.sidebar.selectbox("Polynôme Irréductible GF(2^8)", 
                                  options=[0x11D, 0x165, 0x14D, 0x11B],
                                  format_func=lambda x: f"0x{x:02X} (Standard 0x11B)" if x == 0x11B else f"0x{x:02X}")

st.sidebar.markdown("---")
st.sidebar.info("Note : Le corps $F_{17}$ est utilisé pour l'ECDH, tandis que la S-box est générée via un polynôme irréductible dans $GF(2^8)$.")


@st.cache_resource
def get_crypto_core(poly):
    sbox_gen = SBoxGenerator(poly)
    aes = CustomAES(sbox_gen)
    
    ecc = ECC(a=2, b=2, p=17)
    G = (5, 1)
    return sbox_gen, aes, ecc, G

sbox_gen, aes, ecc, G = get_crypto_core(poly_choice)

# Tabs
tab1, tab2, tab3, tab4 = st.tabs(["Échange de Clés ECDH", "Analyse de la S-Box", "Chiffrement & Déchiffrement", "Courbe et Complexité"])


with tab1:
    st.header("Échange de Clés Elliptic Curve Diffie-Hellman sur $F_{17}$")
    st.write("Équation de la courbe : $y^2 = x^3 + 2x + 2 \pmod{17}$ | Point de base $G = (5, 1)$")
    
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


with tab2:
    st.header("Analyse de la S-Box Personnalisée")
    st.write(f"Polynôme générateur pour $GF(2^8)$ : **0x{poly_choice:X}**")
    
    st.markdown("""
    **Fondamentaux mathématiques (Corps de Galois) :**
    La S-box est construite dans le corps fini **$GF(2^8)$**, aussi appelé corps de Galois à 256 éléments. 
    Les opérations d'addition sont réalisées par des XOR ($\oplus$) et la multiplication est effectuée modulo le polynôme irréductible choisi.
    
    Propriétés du corps $GF(2^8)$ utilisé :
    - Éléments : Polynômes de degré < 8 sur $GF(2)$.
    - Addition : Addition de coefficients modulo 2 (XOR bit à bit).
    - Inversion : Basée sur l'identité $a^{255} \\equiv 1$ dans $GF(2^8)$, donc $a^{-1} = a^{254}$.
    """)
    
    
    std_sbox_gen = SBoxGenerator(0x11B)
    
    if st.checkbox("Afficher la table de substitution (S-Box)"):
        
        sbox_array = np.array(sbox_gen.sbox).reshape(16, 16)
        st.table(sbox_array)

    st.subheader("Comparaison avec le Standard AES")
    diffs = [1 if sbox_gen.sbox[i] != std_sbox_gen.sbox[i] else 0 for i in range(256)]
    num_diffs = sum(diffs)
    
    st.metric("Nombre de différences par rapport à l'AES standard", f"{num_diffs} / 256")
    
    if num_diffs > 0:
        st.write("Le changement de polynôme modifie la structure algébrique de la substitution, ce qui est l'objectif du projet.")

with tab3:
    st.header("Chiffrement et Déchiffrement AES-128")
    
    if 'aes_key' not in st.session_state:
        st.warning("Veuillez effectuer l'échange ECDH dans le premier onglet pour dériver une clé.")
    else:
        col_enc, col_dec = st.columns(2)
        
        with col_enc:
            st.subheader("Opération de Chiffrement")
            plaintext = st.text_area("Texte en clair à chiffrer", value="Message secret avec S-Box personnalisée.")
            
            if st.button("Lancer le Chiffrement"):
                data = plaintext.encode()
                pad_len = 16 - (len(data) % 16)
                padded_data = data + bytes([pad_len] * pad_len)
                
                ciphertext = bytearray()
                for i in range(0, len(padded_data), 16):
                    block = padded_data[i:i+16]
                    try:
                        enc_block = aes.encrypt_block(block, st.session_state['aes_key'])
                        ciphertext.extend(enc_block)
                    except Exception as e:
                        st.error(f"Erreur lors du chiffrement : {e}")
                        break
                
                if ciphertext:
                    st.session_state['last_ciphertext'] = ciphertext.hex().upper()
                    st.success("Chiffrement terminé.")
                    st.code(f"Résultat (HEX) : {st.session_state['last_ciphertext']}", language="text")
                    
                    with st.expander("🔍 Visualiser les étapes du premier bloc"):
                        first_block = padded_data[0:16]
                        steps = aes.encrypt_block_with_steps(first_block, st.session_state['aes_key'])
                        
                        cols = st.columns(3)
                        for idx, (name, state) in enumerate(steps):
                            with cols[idx % 3]:
                                st.markdown(f"**{name}**")
                                st.code(state.hex().upper(), language="text")

        with col_dec:
            st.subheader("Opération de Déchiffrement")
            default_hex = st.session_state.get('last_ciphertext', "")
            cipher_hex = st.text_area("Texte chiffré (HEX) à déchiffrer", value=default_hex)
            
            if st.button("Lancer le Déchiffrement"):
                if not cipher_hex:
                    st.error("Veuillez entrer une chaîne hexadécimale.")
                else:
                    try:
                        ciphertext_bytes = bytes.fromhex(cipher_hex)
                        if len(ciphertext_bytes) % 16 != 0:
                            st.warning("La longueur doit être un multiple de 16 octets.")
                        
                        decrypted_data = bytearray()
                        for i in range(0, len(ciphertext_bytes), 16):
                            block = ciphertext_bytes[i:i+16]
                            dec_block = aes.decrypt_block(block, st.session_state['aes_key'])
                            decrypted_data.extend(dec_block)
                        
                        unpad_len = decrypted_data[-1]
                        if 1 <= unpad_len <= 16:
                            final_text = decrypted_data[:-unpad_len].decode()
                            st.success("Déchiffrement réussi.")
                            st.write(f"Message extrait : {final_text}")
                        else:
                            st.error("Erreur de padding.")
                    except Exception as e:
                        st.error(f"Erreur lors du déchiffrement : {e}")

with tab4:
    st.header("Analyse Mathématique et Complexité")
    
    col_a, col_b = st.columns(2)
    
    with col_a:
        st.subheader("Points sur la courbe $F_{17}$")
        st.write("Visualisation des points $(x, y)$ satisfaisant $y^2 = x^3 + 2x + 2 \pmod{17}$ :")
        points = []
        for x in range(17):
            for y in range(17):
                if (y**2 - (x**3 + 2*x + 2)) % 17 == 0:
                    points.append((x, y))
        
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
        
        st.write(f"Nombre total de points : {len(points) + 1}")
        with st.expander("Voir la liste des points"):
            st.write(points)

    with col_b:
        st.subheader("Complexité et Structures Algébriques")
        st.markdown("""
        **1. Corps Finis et Échanges (ECDH)** :
        - Le protocole repose sur le corps premier **$F_{17}$**.
        - Addition de points : $O(\log p)$ opérations élémentaires.
        - Multiplication scalaire : Algorithm "double-and-add" en $O(\log k \cdot \log p)$.
        
        **2. Corps d'Extension et S-box (AES)** :
        - Utilisation du corps d'extension **$GF(2^8)$**.
        - Le calcul de l'inverse multiplicatif est l'étape critique de la S-box.
        - Sa complexité est en $O(m^2)$ où $m$ est le degré du polynôme ($m=8$).
        """)

st.markdown("---")
st.caption("SSI 2025/2026 arithméthique modulaire")
