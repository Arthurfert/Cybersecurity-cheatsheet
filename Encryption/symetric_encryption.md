# Chiffrement symétrique - Cheatsheet

> **Important** : Le chiffrement symétrique utilise une même clé secrète pour chiffrer et déchiffrer. Ce n'est pas de l'encodage.

## Table des matières

- [Introduction](#introduction)
- [Algorithmes courants](#algorithmes-courants)
  - [AES](#aes)
  - [DES / 3DES](#des--3des)
  - [ChaCha20](#chacha20)
- [Modes d'opération](#modes-dop%C3%A9ration)
  - [ECB, CBC, CTR, GCM, CCM, OCB](#ecb-cbc-ctr-gcm-ccm-ocb)
- [IV / Nonce et gestion des clés](#iv--nonce-et-gestion-des-cl%C3%A9s)
- [Exemples CLI (OpenSSL)](#exemples-cli-openssl)
- [Exemples Python (cryptography)](#exemples-python-cryptography)
- [Bonnes pratiques](#bonnes-pratiques)
- [Outils & Détection](#outils--d%C3%A9tection)
- [Tableau récapitulatif](#tableau-r%C3%A9capitulatif)
- [Ressources](#ressources)

---

## Introduction

Le chiffrement symétrique chiffre des données à l'aide d'une clé secrète partagée. Il est généralement plus rapide que le chiffrement asymétrique et est utilisé pour chiffrer des volumes de données (stockage, canaux TLS, VPN, etc.).

 ![Schema chiffrement symétrique](/assets/Chiffrement_symétrique.png)

---

## Algorithmes courants

### AES

Description
- Advanced Encryption Standard; bloc de 128 bits, clés 128/192/256 bits.

Avantages
- Très sûr lorsqu'il est correctement utilisé (AES-GCM, AES-CTR+HMAC).
- Large support matériel et logiciel (accélération AES-NI).

Inconvénients
- Doit être utilisé avec un mode sécurisé et une gestion correcte de l'IV/nonce.
- Mauvais choix de mode (ECB) entraîne des fuites de patterns.

Recommandation
- Utiliser AES-GCM (authenticité + chiffrement) ou AES-CTR avec HMAC.

### DES / 3DES

Description
- DES : ancien standard (56-bit clé) ; 3DES applique DES trois fois (clé effective ~112 bits).

Avantages
- Historique et présent dans certains anciens systèmes.

Inconvénients
- DES est cassé (clé trop courte).
- 3DES est lent et considéré obsolète pour les nouvelles applications (limites de sécurité).

Recommandation
- Ne pas utiliser pour de nouveaux développements ; migrer vers AES.

### ChaCha20

Description
- Chiffrement par flux moderne (ChaCha20) souvent couplé avec Poly1305 pour l'authentification (ChaCha20-Poly1305).

Avantages
- Haute performance sur CPU sans accélération matérielle (meilleur que AES sur certains appareils mobiles).
- Résistant à certaines attaques de canaux et aux implémentations faibles d'AES.

Inconvénients
- Moins familier que AES mais de plus en plus adopté (TLS, libs). 

Recommandation
- Utiliser ChaCha20-Poly1305 pour environnements sans AES-NI ou pour performance mobile.

---

## Modes d'opération

### ECB
- Description : chiffrement bloc par bloc sans diffusion.
- Inconvénients : fuite des patterns -> à éviter.

### CBC (Cipher Block Chaining)
- Description : chaque bloc XOR avec bloc précédent; nécessite IV aléatoire et unique.
- Avantages : simple et largement supporté.
- Inconvénients : nécessite padding ; vulnérable à padding oracle si mal implémenté.

### CTR (Counter)
- Description : transforme un bloc chiffré en flux via compteur + nonce.
- Avantages : pas de padding, parallélisable.
- Inconvénients : le nonce/compteur doit être unique sinon catastrophique.

### GCM (Galois/Counter Mode)
- Description : mode de chiffrement/authentification (AEAD) basé sur CTR + authentification.
- Avantages : chiffrement + intégrité en une passe, performant.
- Inconvénients : reusage du nonce catastrophique ; mise en oeuvre délicate si on concatène AAD mal géré.

### CCM, OCB
- CCM : AEAD basé sur CBC+CTR, utilisé dans certains protocoles embarqués.
- OCB : efficace mais sujet à restrictions de brevets historiques (moins courant).

---

## IV / Nonce et gestion des clés

- IV/Nonce : doit être unique pour une paire clé/mode ; aléatoire pour CBC, unique et non-réutilisé pour CTR/GCM.
- Clés : stocker dans un module sécurisée (HSM, KMS) ; ne jamais hardcoder.
- Rotation : mettre en place rotation des clés et gestion de la période de vie.
- Longueurs recommandées : AES-128/192/256 ; ChaCha20 utilise 256-bit clé + 96-bit nonce typique.

---

## Exemples CLI (OpenSSL)

Chiffrer avec AES-256-CBC :

```bash
# Chiffrer
openssl enc -aes-256-cbc -salt -in secret.txt -out secret.txt.enc -pass pass:MonMotDePasse
# Déchiffrer
openssl enc -d -aes-256-cbc -in secret.txt.enc -out secret.txt -pass pass:MonMotDePasse
```

Chiffrer avec AES-256-GCM (OpenSSL moderne) :

```bash
# Chiffrement (lecture/écriture avec gestion du tag séparé)
openssl enc -aes-256-gcm -in secret.txt -out secret.txt.enc -pass pass:MonMotDePasse -pbkdf2
# Note: OpenSSL enc GCM peut avoir des limitations pour AAD/tag ; préférer bibliothèques dédiées pour AEAD avancé.
```

ChaCha20-Poly1305 (exemple avec OpenSSL 1.1.0+):

```bash
# Utiliser utilitaires ou bibliothèques ; OpenSSL enc support limité pour chacha20-poly1305 dans certaines versions
openssl pkeyutl -encrypt -pubin -inkey ... # (pour illustration ; préférez libs)
```

Remarque : pour les usages sérieux, privilégier des bibliothèques fournissant AEAD (ex: libsodium, BoringSSL, cryptography).

---

## Exemples Python (cryptography)

Installer la lib :

```bash
pip install cryptography
```

AES-GCM (exemple minimal) :

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

key = AESGCM.generate_key(bit_length=256)
aesgcm = AESGCM(key)
nonce = os.urandom(12)  # 96-bit nonce
plaintext = b"secret message"
aad = b"header"
ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
# decrypt
pt = aesgcm.decrypt(nonce, ciphertext, aad)
```

ChaCha20-Poly1305 :

```python
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import os

key = ChaCha20Poly1305.generate_key()
chacha = ChaCha20Poly1305(key)
nonce = os.urandom(12)
ct = chacha.encrypt(nonce, b"secret", None)
pt = chacha.decrypt(nonce, ct, None)
```

---

## Bonnes pratiques

- Utiliser AEAD (GCM, ChaCha20-Poly1305) quand possible pour assurer confidentialité + intégrité.
- Ne jamais réutiliser un nonce/IV pour la même clé.
- Protéger les clés (KMS, HSM, environment secrets manager).
- Utiliser des clés de longueur recommandée et rotation régulière.
- Valider les bibliothèques et éviter les implémentations maison.

---

## Outils & Détection

- OpenSSL (enc, evp, pkeyutl)
- libsodium / NaCl
- cryptography (Python)
- GnuPG pour casches spécifiques

---

## Tableau récapitulatif

| Algorithme | Type | Taille clé | Avantages | Inconvénients |
|------------|------|------------:|----------|---------------|
| AES-GCM | Bloc/AEAD | 128/192/256 | Très sûr, hardware accel | Nonce reuse -> faille |
| AES-CBC | Bloc | 128/192/256 | Large support | Padding oracle si mal utilisé |
| ChaCha20-Poly1305 | Flux/AEAD | 256 | Rapide sans AES-NI, sécurisé | Moins mature qu'AES historique |
| 3DES | Bloc | ~112 effective | Compatibilité legacy | Lent, obsolète |

---

## Ressources

 - [NIST SP 800-38A - Modes of Operation](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf)
 - [RFC 5116 - An Interface and Algorithms for Authenticated Encryption](https://datatracker.ietf.org/doc/html/rfc5116)
 - [RFC 7539 - ChaCha20 and Poly1305 for IETF Protocols](https://datatracker.ietf.org/doc/html/rfc7539)
 - [OpenSSL Documentation](https://www.openssl.org/docs/)
 - [cryptography - Python library documentation](https://cryptography.io/en/latest/)
 - [Wikipedia - Cryptographie Symétrique](https://fr.wikipedia.org/wiki/Cryptographie_sym%C3%A9trique)
