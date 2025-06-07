package Hybrid;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class Main {
    public static void main(String[] args) {

        /*
        using RSA To encrypt AES key and using AES to encrypt data
         */


        try {
            SecretKey aesKey = HybridEncryption.getKeyGenerator();
            System.out.println(Base64.getEncoder().encodeToString(aesKey.getEncoded()));

            KeyPair rsaKeyPair = HybridEncryption.generateKeyPair();
            PublicKey publicKey = rsaKeyPair.getPublic();
            PrivateKey privateKey = rsaKeyPair.getPrivate();

            String encryptedAESKey = HybridEncryption.encryptAESKey(aesKey, publicKey);
            System.out.println("encryptedAESKey " + encryptedAESKey);

            String plaintextData = "Hello world!";
            String cipherTextData = HybridEncryption.encryptData(plaintextData,aesKey);
            System.out.println("cipherTextData " +cipherTextData);

            SecretKey decryptAESKey = HybridEncryption.decryptAESKey(encryptedAESKey,privateKey);
            System.out.println("decryptedAESKey "+Base64.getEncoder().encodeToString(decryptAESKey.getEncoded()));
            String decryptData = HybridEncryption.decryptData(cipherTextData,decryptAESKey);
            System.out.println("decryptData "+decryptData);


        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }
}
