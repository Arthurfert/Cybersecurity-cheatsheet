# Chiffrement asymétrique - Cheatsheet

> **Important** : Le chiffrement asymétrique utilise une paire de clés : une clé publique (pour chiffrer) et une clé privée (pour déchiffrer). C'est la base de la cryptographie moderne.

## Table des matières

- [Introduction](#introduction)
- [Algorithmes courants](#algorithmes-courants)
  - [RSA](#rsa)
  - [ECC (Elliptic Curve Cryptography)](#ecc-elliptic-curve-cryptography)
  - [Diffie-Hellman](#diffie-hellman)
  - [ElGamal](#elgamal)
- [Cas d'usage](#cas-dusage)
- [Padding et schémas](#padding-et-schémas)
- [Exemples CLI (OpenSSL)](#exemples-cli-openssl)
- [Exemples Python (cryptography)](#exemples-python-cryptography)
- [Bonnes pratiques](#bonnes-pratiques)
- [Outils](#outils)
- [Tableau récapitulatif](#tableau-récapitulatif)
- [Ressources](#ressources)

---

## Introduction

Le chiffrement asymétrique repose sur des problèmes mathématiques difficiles (factorisation, logarithme discret, courbes elliptiques). Contrairement au chiffrement symétrique, il n'est pas nécessaire de partager un secret au préalable.

![Schema chiffrement asymétrique](/assets/Chiffrement_asymétrique.png)

**Principe** :
- **Clé publique** : peut être partagée librement, utilisée pour chiffrer ou vérifier une signature.
- **Clé privée** : doit rester secrète, utilisée pour déchiffrer ou signer.

---

## Algorithmes courants

### RSA

Description
- Rivest-Shamir-Adleman ; basé sur la difficulté de factoriser de grands nombres premiers.
- Tailles de clé courantes : 2048, 3072, 4096 bits.

Avantages
- Très répandu et mature (depuis 1977).
- Large support dans les bibliothèques et protocoles (TLS, SSH, PGP).
- Peut être utilisé pour chiffrement et signature.

Inconvénients
- Clés volumineuses par rapport à ECC pour un niveau de sécurité équivalent.
- Plus lent que les algorithmes symétriques (utilisé pour chiffrer des clés, pas des données volumineuses).
- Vulnérable si mal implémenté (padding, génération de clés).

Recommandation
- Utiliser RSA-OAEP pour le chiffrement, RSA-PSS pour les signatures.
- Clé minimale de 2048 bits (3072+ recommandé pour le long terme).

### ECC (Elliptic Curve Cryptography)

Description
- Basé sur les courbes elliptiques sur corps finis.
- Courbes courantes : P-256 (secp256r1), P-384, P-521, Curve25519, secp256k1 (Bitcoin).

Avantages
- Clés beaucoup plus courtes pour une sécurité équivalente (256 bits ECC ≈ 3072 bits RSA).
- Performances meilleures (signature, échange de clés).
- Adapté aux environnements contraints (IoT, mobile).

Inconvénients
- Implémentation plus complexe (risque de side-channel attacks).
- Certaines courbes NIST sont controversées (backdoors potentiels) ; Curve25519 est préférée.

Recommandation
- Utiliser Curve25519 (X25519 pour échange, Ed25519 pour signatures) ou P-256 si compatibilité requise.

### Diffie-Hellman

Description
- Protocole d'échange de clés (pas de chiffrement direct).
- Permet à deux parties d'établir un secret partagé sur un canal non sécurisé.

Avantages
- Fondement de nombreux protocoles (TLS, SSH, VPN).
- Version elliptique (ECDH) très performante.

Inconvénients
- Vulnérable aux attaques man-in-the-middle si non authentifié.
- DH classique nécessite de grands paramètres (lent).

Recommandation
- Utiliser ECDH (X25519 ou P-256) avec authentification (certificats, signatures).

### ElGamal

Description
- Système de chiffrement basé sur le problème du logarithme discret.
- Utilisé dans PGP/GPG pour le chiffrement.

Avantages
- Sémantiquement sûr (randomisé).
- Alternative à RSA pour certains cas.

Inconvénients
- Ciphertext deux fois plus long que le plaintext.
- Moins courant que RSA ou ECC aujourd'hui.

---

## Cas d'usage

| Cas d'usage | Algorithme recommandé |
|-------------|----------------------|
| Échange de clés | ECDH (X25519), DH |
| Chiffrement de données | RSA-OAEP, ECIES |
| Signatures numériques | Ed25519, RSA-PSS, ECDSA |
| Certificats TLS/SSL | RSA, ECDSA |
| Chiffrement e-mail (PGP) | RSA, ElGamal, ECC |

---

## Padding et schémas

### RSA Padding

| Schéma | Usage | Sécurité |
|--------|-------|----------|
| PKCS#1 v1.5 | Legacy, signatures | Vulnérable à certaines attaques (Bleichenbacher) |
| OAEP | Chiffrement moderne | Recommandé |
| PSS | Signatures modernes | Recommandé |

### Schémas ECC

| Schéma | Usage |
|--------|-------|
| ECDSA | Signatures (TLS, Bitcoin) |
| EdDSA (Ed25519) | Signatures modernes, déterministes |
| ECDH / X25519 | Échange de clés |
| ECIES | Chiffrement hybride (ECC + symétrique) |

---

## Exemples CLI (OpenSSL)

### Générer une paire de clés RSA

```bash
# Générer clé privée RSA 4096 bits
openssl genrsa -out private.pem 4096

# Extraire la clé publique
openssl rsa -in private.pem -pubout -out public.pem
```

### Chiffrer/Déchiffrer avec RSA-OAEP

```bash
# Chiffrer avec la clé publique
openssl pkeyutl -encrypt -pubin -inkey public.pem -in secret.txt -out secret.enc -pkeyopt rsa_padding_mode:oaep

# Déchiffrer avec la clé privée
openssl pkeyutl -decrypt -inkey private.pem -in secret.enc -out secret.txt -pkeyopt rsa_padding_mode:oaep
```

### Générer une paire de clés ECC

```bash
# Générer clé privée EC (P-256)
openssl ecparam -name prime256v1 -genkey -noout -out ec_private.pem

# Extraire la clé publique
openssl ec -in ec_private.pem -pubout -out ec_public.pem
```

### Signer et vérifier avec ECDSA

```bash
# Signer un fichier
openssl dgst -sha256 -sign ec_private.pem -out signature.bin message.txt

# Vérifier la signature
openssl dgst -sha256 -verify ec_public.pem -signature signature.bin message.txt
```

### Générer une clé Ed25519

```bash
# Générer clé Ed25519
openssl genpkey -algorithm Ed25519 -out ed25519_private.pem

# Extraire clé publique
openssl pkey -in ed25519_private.pem -pubout -out ed25519_public.pem
```

---

## Exemples Python (cryptography)

Installer la lib :

```bash
pip install cryptography
```

### RSA - Chiffrement/Déchiffrement

```python
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# Générer une paire de clés
private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
public_key = private_key.public_key()

# Chiffrer
message = b"secret message"
ciphertext = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Déchiffrer
plaintext = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
```

### RSA - Signature

```python
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# Signer
signature = private_key.sign(
    b"message to sign",
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

# Vérifier
public_key.verify(
    signature,
    b"message to sign",
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
```

### Ed25519 - Signature

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Générer clé
private_key = Ed25519PrivateKey.generate()
public_key = private_key.public_key()

# Signer
signature = private_key.sign(b"message")

# Vérifier
public_key.verify(signature, b"message")
```

### X25519 - Échange de clés (ECDH)

```python
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

# Partie A
private_key_a = X25519PrivateKey.generate()
public_key_a = private_key_a.public_key()

# Partie B
private_key_b = X25519PrivateKey.generate()
public_key_b = private_key_b.public_key()

# Échange : chaque partie calcule le même secret partagé
shared_secret_a = private_key_a.exchange(public_key_b)
shared_secret_b = private_key_b.exchange(public_key_a)

assert shared_secret_a == shared_secret_b  # Même secret !
```

---

## Bonnes pratiques

- **Ne jamais chiffrer de grandes quantités de données** directement avec RSA/ECC ; utiliser un schéma hybride (chiffrer une clé symétrique, puis chiffrer les données avec AES-GCM).
- **Utiliser des schémas de padding modernes** : OAEP pour chiffrement RSA, PSS pour signatures RSA.
- **Préférer les courbes modernes** : Curve25519 (X25519, Ed25519) plutôt que les courbes NIST si possible.
- **Protéger les clés privées** : chiffrement par mot de passe, stockage HSM/KMS.
- **Vérifier les certificats** : valider la chaîne de confiance, dates d'expiration, révocations (OCSP, CRL).
- **Taille de clé minimale** : RSA ≥ 2048 bits (3072+ recommandé), ECC ≥ 256 bits.

---

## Outils

- **OpenSSL** : génération de clés, chiffrement, signatures
- **GnuPG (GPG)** : chiffrement et signatures PGP
- **ssh-keygen** : génération de clés SSH (RSA, Ed25519)
- **cryptography** (Python) : bibliothèque complète
- **libsodium / NaCl** : API simple pour X25519, Ed25519

---

## Tableau récapitulatif

| Algorithme | Type | Taille clé | Avantages | Inconvénients |
|------------|------|------------|-----------|---------------|
| RSA | Chiffrement/Signature | 2048-4096 bits | Mature, large support | Clés volumineuses, lent |
| ECDSA | Signature | 256-521 bits | Clés courtes, rapide | Implémentation délicate |
| Ed25519 | Signature | 256 bits | Rapide, sûr, déterministe | Moins répandu (mais en croissance) |
| X25519 | Échange de clés | 256 bits | Très performant, sûr | Usage limité à l'échange |
| ElGamal | Chiffrement | Variable | Randomisé | Ciphertext x2, moins courant |

---

## Ressources

- [RFC 8017 - PKCS #1: RSA Cryptography Specifications](https://datatracker.ietf.org/doc/html/rfc8017)
- [RFC 7748 - Elliptic Curves for Security (X25519, X448)](https://datatracker.ietf.org/doc/html/rfc7748)
- [RFC 8032 - Edwards-Curve Digital Signature Algorithm (Ed25519)](https://datatracker.ietf.org/doc/html/rfc8032)
- [OpenSSL Documentation](https://www.openssl.org/docs/)
- [cryptography — Python library documentation](https://cryptography.io/en/latest/)
- [Wikipedia - Cryptographie asymétrique](https://fr.wikipedia.org/wiki/Cryptographie_asym%C3%A9trique)
- [SafeCurves - Choosing safe curves for elliptic-curve cryptography](https://safecurves.cr.yp.to/)
