package Asymmetric;

import java.security.*;

public class RSAMain {
    public static void main(String[] args) {


        try {
            String plaintext = "Hello World!";
            KeyPair keyPair = RSA.generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();
            System.out.println("Public Key: " + publicKey);
            System.out.println("Private Key: " + privateKey);

            String cipherText = RSA.encrypt(plaintext,publicKey);
            System.out.println("Cipher Text: " + cipherText);

            String decipherText = RSA.decrypt(cipherText,privateKey);
            System.out.println("Decipher Text: " + decipherText);
        } catch (Exception e){
            System.out.println(e.getMessage());
        }
    }


    /*
    note
    wants to try using it instead of jwt token --> an idea is encrypted JSON with user data
     */
}
