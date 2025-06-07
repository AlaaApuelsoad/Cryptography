package Hybrid;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Base64;

public class HybridEncryption {


    //genera RSA keyPair
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        return keyGen.genKeyPair();
    }


    public static SecretKey getKeyGenerator() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        return keyGen.generateKey();
    }

    public static String encryptAESKey(SecretKey secretKey, PublicKey publicKey) throws NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE,publicKey);
        byte[] encrypted = cipher.doFinal(secretKey.getEncoded());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static SecretKey decryptAESKey(String encryptedKey, PrivateKey privateKey) throws NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE,privateKey);
        byte[] decodeKey = Base64.getDecoder().decode(encryptedKey);
        byte[] decryptKey = cipher.doFinal(decodeKey);
        return new SecretKeySpec(decryptKey,0,decryptKey.length,"AES");
    }

    // AES Encryption
    public static String encryptData(String data, SecretKey aesKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] encrypted = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    // AES Decryption
    public static String decryptData(String encryptedData, SecretKey aesKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, aesKey);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
        return new String(decrypted);
    }



}
