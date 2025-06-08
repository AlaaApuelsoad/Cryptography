package Symmetric;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class AESMain {

    public static void main(String[] args){

        /*
        1.Symmetric key
        same key is ued for enc and dec
        ex: AES,DES
        fast but key distribution is a challenge
         */

        try {
            String plainText = "Hello World!";
            IvParameterSpec iv = AES.generateIv();
            SecretKey secretKey = AES.generateKey();
            AES.printKeyGenerated(secretKey);
            System.out.println( "AESKey--> " + AES.printKeyGenerated(secretKey));

            String cipherText = AES.encrypt(plainText,secretKey);
//            String cipherText = AES.encryptWithIV(plainText,secretKey,iv);
            System.out.println(cipherText);

            String decryptedText = AES.decrypt(cipherText,secretKey);
            System.out.println(decryptedText);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }

    }
}
