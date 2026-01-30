# Rapport de Projet : Système Cryptographique Hybride AES-ECDH

**Module :** Arithmétique Modulaire  
**Spécialité :** Sécurité des Systèmes Informatiques (SSI)  
**Institution :** Université des Sciences et de la Technologie Houari Boumediene (USTHB)

**Présenté par :**
- IMESSAOUDENE Aldjia
- YAHIAOUI Abderrahmane
- OUBYI Mohamed Yacine

---

## 1. Introduction Générale

Dans le domaine de la sécurité informatique, la protection des données repose sur des piliers mathématiques robustes. Ce projet explore la synergie entre la cryptographie symétrique (AES) et asymétrique (ECDH). L'objectif central est de concevoir un système où la couche de confusion (S-box) de l'AES n'est plus statique, mais générée dynamiquement à partir d'un polynôme irréductible personnalisé dans le corps de Galois $GF(2^8)$.

---

## 2. Fondements Théoriques

### 2.1 Arithmétique dans $GF(2^8)$
Le corps de Galois $GF(2^8)$ est une structure finie de 256 éléments. Chaque élément est représenté par un polynôme de degré 7 sur $GF(2)$.

- **Addition** : Réalisée par l'opération XOR ($\oplus$) bit à bit.
- **Multiplication** : Produit polynomial modulo un polynôme irréductible $P(x)$. Nous utilisons ici :
  $$P(x) = x^8 + x^4 + x^3 + x^2 + 1 \quad (0x11D)$$
- **Inversion** : Opération critique pour la S-box, calculée via l'algorithme d'Euclide étendu ou par $a^{254} \mod P(x)$.

### 2.2 Cryptographie sur Courbes Elliptiques (ECC)
L'échange de clés repose sur une courbe de Weierstrass sur le corps fini $F_{17}$ :
$$y^2 \equiv x^3 + 3x + 5 \pmod{17}$$

**Loi d'addition de points :**
Pour deux points $P(x_1, y_1)$ et $Q(x_2, y_2)$, le point $R = P+Q$ est calculé en trouvant la pente $\lambda$ (tangente ou sécante) et en appliquant les formules de duplication ou d'addition géométrique modulaires.

---

## 3. Architecture du Système

### 3.1 Advanced Encryption Standard (AES)
L'AES-128 utilise une structure en 10 rounds. Notre modification porte sur la **S-Box**.

#### Génération de la S-box :
1. **Inversion** : $b = x^{-1}$ dans $GF(2^8)$ avec le polynôme personnalisé.
2. **Transformation Affine** :
   $$b'_i = b_i \oplus b_{(i+4)\%8} \oplus b_{(i+5)\%8} \oplus b_{(i+6)\%8} \oplus b_{(i+7)\%8} \oplus c_i$$
   Où $c = 0x63$.

### 3.2 Protocole ECDH
Le protocole permet d'établir une clé de 128 bits sans transmission directe :
1. Alice calcule $A = aG$, Bob calcule $B = bG$.
2. Secret partagé $S = aB = bA$.
3. La clé AES est dérivée par $K = \text{SHA256}(S.x, S.y)[:16]$.

---

## 4. Implémentation Logicielle

Le système est écrit en **Python** avec une interface **Streamlit**.

### Extrait de l'arithmétique GF(256) :
```python
def multiply(a, b, poly=0x11D):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= (poly & 0xFF)
        b >>= 1
    return p
```

---

## 5. Analyse et Résultats

### 5.1 Analyse de Complexité
| Opération | Complexité | Domaine |
|-----------|------------|---------|
| Inversion GF | $O(m^2)$ | S-box |
| Mult Scalaire | $O(\log k)$ | ECDH |
| AES Round | $O(N)$ | Chiffrement |

### 5.2 Validation
La réversibilité a été testée sur des milliers de blocs. L'utilisation d'un polynôme personnalisé transforme la S-box mais préserve les propriétés de diffusion/confusion nécessaires à la sécurité de l'algorithme.

**Avantage :** La personnalisation de la S-box rend les attaques basées sur les tables pré-calculées standards inefficaces.

---

## Conclusion
Ce projet démontre la flexibilité des structures algébriques en cryptographie. L'alliance de l'ECC pour le transport de clé et d'un AES à S-box dynamique forme un système hybride moderne, robuste et pédagogiquement riche.
