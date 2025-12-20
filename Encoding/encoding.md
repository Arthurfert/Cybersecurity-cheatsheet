# Encodage - Cheatsheet

> **Important** : L'encodage n'est **PAS** du chiffrement ! L'encodage est réversible sans clé.

## Table des matières

- [Base64](#base64)
- [Hexadécimal (Base16)](#hexadécimal-base16)
- [Base32](#base32)
- [ASCII](#ascii)
- [URL Encoding](#url-encoding)
- [HTML Entities](#html-entities)
- [Unicode](#unicode)
- [Binary](#binary)
- [Outils de détection](#outils-de-détection)

---

## Base64

### Description
Encode des données binaires en caractères ASCII imprimables. Utilise 64 caractères : `A-Z`, `a-z`, `0-9`, `+`, `/` et `=` pour le padding.

### Avantages
- Représente proprement les données binaires en ASCII imprimable.
- Moins verbeux que l'hexadécimal pour des données binaires (ratio 4:3).
- Large support logiciel (e-mails, API, MIME, etc.).

### Inconvénients
- Augmente la taille des données (~+33%).
- Réencodage même pour les données déjà textuelles.
- Peut être confondu avec d'autres formats si mal délimité (padding, alphabet).

### Caractéristiques
| Propriété | Valeur |
|-----------|--------|
| Alphabet | `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/` |
| Padding | `=` (1 ou 2 à la fin) |
| Ratio | 4 caractères encodés pour 3 octets |
| Taille | +33% par rapport à l'original |

### Reconnaissance
- Longueur multiple de 4
- Se termine souvent par `=` ou `==`
- Uniquement caractères alphanumériques + `/` + `+`

### Exemples

```
Texte    : Hello World
Base64   : SGVsbG8gV29ybGQ=

Texte    : admin:password
Base64   : YWRtaW46cGFzc3dvcmQ=
```

### Commandes

```bash
# Encoder
echo -n "Hello World" | base64
# Décoder
echo "SGVsbG8gV29ybGQ=" | base64 -d

# Windows PowerShell
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("Hello World"))
[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("SGVsbG8gV29ybGQ="))
```

### Python

```python
import base64

# Encoder
encoded = base64.b64encode(b"Hello World").decode()
# Décoder
decoded = base64.b64decode("SGVsbG8gV29ybGQ=").decode()
```

### Variantes
| Variante | Différences |
|----------|-------------|
| Base64 URL-safe | Remplace `+` par `-` et `/` par `_` |
| Base64 sans padding | Pas de `=` à la fin |

---

## Hexadécimal (Base16)

### Description
Représente chaque octet par 2 caractères hexadécimaux (0-9, A-F).

### Avantages
- Représentation simple et directe d'octets (facile à lire pour les développeurs).
- Très répandu et bien supporté par les outils (debug, dumps, traces).

### Inconvénients
- Double la taille des données (x2).
- Peu lisible pour de longues séries d'octets sans mise en forme.
- Pas adapté pour l'affichage dans des environnements limités en caractères.

### Caractéristiques
| Propriété | Valeur |
|-----------|--------|
| Alphabet | `0123456789ABCDEF` (ou minuscules) |
| Ratio | 2 caractères pour 1 octet |
| Taille | x2 par rapport à l'original |

### Reconnaissance
- Uniquement `0-9` et `A-F` (ou `a-f`)
- Longueur paire
- Parfois préfixé par `0x` ou `\x`

### Exemples

```
Texte : Hello
Hex   : 48656c6c6f
Hex   : 48 65 6c 6c 6f (avec espaces)
Hex   : 0x48656c6c6f (préfixe)
```

### Commandes

```bash
# Encoder
echo -n "Hello" | xxd -p
# Décoder
echo "48656c6c6f" | xxd -r -p

# Avec od
echo -n "Hello" | od -A n -t x1
```

### Python

```python
# Encoder
"Hello".encode().hex()
# Décoder
bytes.fromhex("48656c6c6f").decode()
```

---

## Binary

### Description
Représentation en base 2 (0 et 1). Chaque caractère ASCII = 8 bits.

### Avantages
- Représentation fondamentale au niveau matériel et utile pour l'analyse bas-niveau.
- Permet d'illustrer précisément l'état des bits (bitmasks, flags).

### Inconvénients
- Très verbeux pour un usage humain (8x plus long que l'octet correspondant).
- Peu pratique pour le stockage ou le transport sans transformation.

### Exemples

```
Caractère : A
Décimal   : 65
Binaire   : 01000001

Texte     : Hi
Binaire   : 01001000 01101001
```

### Python

```python
# Texte vers binaire
' '.join(format(ord(c), '08b') for c in "Hi")
# '01001000 01101001'

# Binaire vers texte
binary = "01001000 01101001"
''.join(chr(int(b, 2)) for b in binary.split())
# 'Hi'
```
---

## Base32

### Description
Similaire à Base64 mais utilise 32 caractères, plus adapté aux systèmes case-insensitive.

### Avantages
- Meilleur ratio que l'hexadécimal pour représenter des octets.
- Alphabet conçu pour être case-insensitive et lisible (utile pour noms de fichiers, OTP, clés).

### Inconvénients
- Plus verbeux que Base64 (~+60%).
- Moins utilisé, donc parfois moins supporté.

### Caractéristiques
| Propriété | Valeur |
|-----------|--------|
| Alphabet | `ABCDEFGHIJKLMNOPQRSTUVWXYZ234567` |
| Padding | `=` (jusqu'à 6) |
| Ratio | 8 caractères pour 5 octets |
| Taille | +60% par rapport à l'original |

### Reconnaissance
- Uniquement majuscules A-Z et chiffres 2-7
- Longueur multiple de 8
- Peut se terminer par plusieurs `=`

### Exemples

```
Texte   : Hello
Base32  : JBSWY3DP
```

### Python

```python
import base64

# Encoder
base64.b32encode(b"Hello").decode()
# Décoder
base64.b32decode("JBSWY3DP").decode()
```

---

## ASCII

### Description
Standard d'encodage de caractères sur 7 bits (128 caractères).

### Avantages
- Standard simple et très répandu pour l'anglais et les protocoles historiques.
- Efficace en espace pour les caractères ASCII (1 octet).

### Inconvénients
- Ne supporte pas les caractères non-latins (limité à 128 ou 256 selon l'implémentation).
- Risque d'erreurs d'encodage si mal utilisé avec UTF-8/Unicode.

### Table ASCII courante

| Décimal | Hex | Caractère | Description |
|---------|-----|-----------|-------------|
| 0 | 0x00 | NUL | Null |
| 10 | 0x0A | LF | Line Feed |
| 13 | 0x0D | CR | Carriage Return |
| 32 | 0x20 | (espace) | Space |
| 48-57 | 0x30-0x39 | 0-9 | Chiffres |
| 65-90 | 0x41-0x5A | A-Z | Majuscules |
| 97-122 | 0x61-0x7A | a-z | Minuscules |

### Conversions

```python
# Caractère vers ASCII
ord('A')  # 65

# ASCII vers caractère
chr(65)   # 'A'

# Chaîne vers liste ASCII
[ord(c) for c in "Hello"]  # [72, 101, 108, 108, 111]
```

---

## URL Encoding

### Description
Encode les caractères spéciaux pour les URLs. Les caractères non-alphanumériques sont remplacés par `%XX` (valeur hexadécimale).

### Caractères encodés courants

| Caractère | Encodé |
|-----------|--------|
| Espace | `%20` ou `+` |
| `!` | `%21` |
| `#` | `%23` |
| `$` | `%24` |
| `%` | `%25` |
| `&` | `%26` |
| `'` | `%27` |
| `/` | `%2F` |
| `:` | `%3A` |
| `=` | `%3D` |
| `?` | `%3F` |
| `@` | `%40` |

### Exemples

```
Original : Hello World!
Encodé   : Hello%20World%21

Original : user=admin&pass=test
Encodé   : user%3Dadmin%26pass%3Dtest
```

### Python

```python
from urllib.parse import quote, unquote

# Encoder
quote("Hello World!")  # 'Hello%20World%21'

# Décoder
unquote("Hello%20World%21")  # 'Hello World!'
```

### Double URL Encoding (bypass WAF)

```
Original      : <script>
Simple        : %3Cscript%3E
Double        : %253Cscript%253E
```

---

## HTML Entities

### Description
Représente des caractères spéciaux en HTML pour éviter les conflits avec la syntaxe.

### Avantages
- Protège contre l'injection HTML en représentant les caractères spéciaux.
- Standard supporté par tous les navigateurs et bibliothèques web.

### Inconvénients
- Peut rendre le contenu moins lisible pour les humains si sur-utilisé.
- Certaines entités moins courantes peuvent être mal interprétées entre navigateurs.

### Entités courantes

| Caractère | Entity Name | Entity Number |
|-----------|-------------|---------------|
| `<` | `&lt;` | `&#60;` |
| `>` | `&gt;` | `&#62;` |
| `&` | `&amp;` | `&#38;` |
| `"` | `&quot;` | `&#34;` |
| `'` | `&apos;` | `&#39;` |
| ` ` | `&nbsp;` | `&#160;` |

### Encodage décimal et hexadécimal

```html
A = &#65;      (décimal)
A = &#x41;     (hexadécimal)
```

### Python

```python
import html

# Encoder
html.escape('<script>alert("XSS")</script>')
# '&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;'

# Décoder
html.unescape('&lt;script&gt;')  # '<script>'
```

---

## Unicode

### Description
Standard universel d'encodage supportant tous les caractères de toutes les langues.

### Avantages
- Permet d'encoder tous les caractères du monde, interopérable entre systèmes.
- UTF-8 est rétrocompatible avec ASCII et économe en espace pour les textes latins.

### Inconvénients
- Complexité de gestion (endianness, BOM, normalisation, combining characters).
- Risque d'homoglyphes et de spoofing si non filtré.

### Formats d'encodage

| Format | Description | Exemple pour 'A' |
|--------|-------------|------------------|
| UTF-8 | Variable (1-4 octets) | `41` |
| UTF-16 | 2 ou 4 octets | `0041` |
| UTF-32 | 4 octets fixes | `00000041` |

### Notations

```
Caractère : €
Unicode   : U+20AC
UTF-8     : E2 82 AC (3 octets)
HTML      : &#8364; ou &#x20AC;
```

### Python

```python
# Obtenir le code point
ord('€')  # 8364

# Code point vers caractère
chr(8364)  # '€'

# Encoder en UTF-8 bytes
'€'.encode('utf-8')  # b'\xe2\x82\xac'
```

### Homoglyphes (attaques visuelles)

```
Caractère normal    : a (U+0061)
Homoglyphe cyrillique : а (U+0430)
```

---

## 🛠️ Outils de détection

### Outils en ligne
- [CyberChef](https://gchq.github.io/CyberChef/) - Le couteau suisse du décodage
- [dCode](https://www.dcode.fr/) - Détection automatique
- [Base64Decode](https://www.base64decode.org/)

### Outils CLI

```bash
# Identifier l'encodage d'un fichier
file -i document.txt

# Convertir l'encodage
iconv -f ISO-8859-1 -t UTF-8 input.txt > output.txt
```

### Script de détection Python

```python
import base64
import re

def detect_encoding(s):
    """Détecte le type d'encodage probable"""
    
    # Hexadécimal
    if re.fullmatch(r'[0-9a-fA-F]+', s) and len(s) % 2 == 0:
        return "Probablement Hexadécimal"
    
    # Base64
    if re.fullmatch(r'[A-Za-z0-9+/]+=*', s) and len(s) % 4 == 0:
        try:
            base64.b64decode(s)
            return "Probablement Base64"
        except:
            pass
    
    # Base32
    if re.fullmatch(r'[A-Z2-7]+=*', s):
        return "Probablement Base32"
    
    # URL Encoded
    if '%' in s and re.search(r'%[0-9A-Fa-f]{2}', s):
        return "Probablement URL Encoded"
    
    # Binaire
    if re.fullmatch(r'[01\s]+', s):
        return "Probablement Binaire"
    
    return "Encodage non reconnu"
```

---

## 📊 Tableau récapitulatif

| Encodage | Alphabet | Taille | Reconnaissance |
|----------|----------|--------|----------------|
| Base64 | A-Za-z0-9+/= | +33% | Finit par `=`, longueur ÷ 4 |
| Base32 | A-Z2-7= | +60% | Majuscules + 2-7, beaucoup de `=` |
| Hex | 0-9A-F | x2 | Uniquement hex, longueur paire |
| URL | %XX | Variable | Contient `%` |
| Binary | 01 | x8 | Que des 0 et 1 |
| ASCII | 0-127 | 1 octet | Limité aux caractères latins |
| HTML Entities | &lt; &gt; &amp; etc. | Variable | Protège le HTML |
| Unicode (UTF-8) | Multi-octets | Variable | Support universel des caractères |

---

## 🔗 Ressources

- [RFC 4648 - Base Encodings](https://tools.ietf.org/html/rfc4648)
- [ASCII Table](https://www.asciitable.com/)
- [Unicode Charts](https://www.unicode.org/charts/)
