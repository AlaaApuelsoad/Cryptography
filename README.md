# Cryptography in Java – Algorithms, Types, and Secure Communication

---

## What is Cryptography?

**Cryptography** is the science of securing data using mathematical techniques. It ensures:

* **Confidentiality** – Only authorized parties can read the information
* **Integrity** – Data is not altered
* **Authentication** – Verifying identities
* **Non-repudiation** – Preventing denial of actions

---

## Types of Cryptography

| Type       | Key Usage                                     | Examples           | Use Cases                               |
| ---------- | --------------------------------------------- | ------------------ | --------------------------------------- |
| Symmetric  | Same key for encryption and decryption        | AES, DES, Blowfish | Fast encryption for large data          |
| Asymmetric | Public key to encrypt, private key to decrypt | RSA, ECC           | Secure key exchange, digital signatures |
| Hashing    | One-way transformation                        | SHA-256, MD5       | Password storage, data integrity checks |
| Hybrid     | Combines symmetric + asymmetric               | RSA + AES          | Secure and fast data transfer           |

---

## Symmetric Encryption

### 🔸 AES (Advanced Encryption Standard)

* Block cipher (128-bit blocks)
* Key sizes: 128, 192, 256 bits
* Modes: CBC, GCM (recommended), ECB (not secure)

#### ✅ Java Example

```java
Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
byte[] encrypted = cipher.doFinal(plainText.getBytes());
```

---

## Asymmetric Encryption

### 🔸 RSA (Rivest-Shamir-Adleman)

* Uses **public/private key pairs**
* Best for small data, like AES key exchange or signatures

#### ✅ Java Example

```java
Cipher cipher = Cipher.getInstance("RSA");
cipher.init(Cipher.ENCRYPT_MODE, publicKey);
byte[] encryptedKey = cipher.doFinal(aesKey.getEncoded());
```

---

## 🔄 Hybrid Encryption

Hybrid cryptography combines the **speed of AES** and **security of RSA**.

### 🔁 Workflow:

1. Sender generates AES key
2. Encrypts data with AES
3. Encrypts AES key with RSA public key
4. Sends:

   * AES-encrypted data
   * RSA-encrypted AES key
   * AES IV
5. Receiver decrypts AES key with private RSA key
6. Decrypts data with AES

