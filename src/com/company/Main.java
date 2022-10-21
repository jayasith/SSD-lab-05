package com.company;

import javax.crypto.Cipher;
import java.security.*;
import java.util.Base64;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) {
        try {
            RSA_ENCRYPTION rsa_encryption = new RSA_ENCRYPTION();
            Scanner scanner = new Scanner(System.in);

            while (true) {

                System.out.println("Enter your secret key :");
                String secretKey = scanner.nextLine();
                KeyPair keyPair = rsa_encryption.init(secretKey);
                System.out.println("Enter your message :");
                String message = scanner.nextLine();
                String encryptedMessage = rsa_encryption.encrypt(message, keyPair.getPublic());
                System.out.println("Encrypted Message :" + encryptedMessage + "\n");
                System.out.println("Do you need send this message? [Y-Yes , N-No ] :");
                String answer = scanner.nextLine();

                if (answer.equals("Y")) {
                    boolean valid = true;
                    while (valid) {
                        System.out.println("Enter the secret key :");
                        String Key = scanner.nextLine();
                        if (Key.equals(secretKey)) {
                            String decryptMessage = rsa_encryption.decrypt(encryptedMessage, keyPair.getPrivate());
                            System.out.println("Decrypted Message :" + decryptMessage + "\n");
                            valid = false;
                        } else {
                            //KeyPair secondKeyPair =  rsa_encryption.init(secretKey);
                            System.out.println("invalid secret key");
                        }
                    }
                    System.out.println("Do you need to exit? [Y-Yes, N-No] :");
                    answer = scanner.nextLine();
                    if (answer.equals("Y")) {
                        return;
                    }

                }

            }

        } catch (Exception exception) {
            System.out.println("Exception :" + exception.getMessage());
        }
    }
}

class RSA_ENCRYPTION {


    public KeyPair init(String stringKey) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024, new SecureRandom(stringKey.getBytes()));
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        return keyPair;
    }

    public String encrypt(String data, PublicKey publicKey) throws Exception {
        byte[] dataToBytes = data.getBytes();
        Cipher encryptionCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        encryptionCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = encryptionCipher.doFinal(dataToBytes);
        return encode(encryptedBytes);
    }

    public String decrypt(String encryptedData, PrivateKey privateKey) throws Exception {
        byte[] dataInBytes = decode(encryptedData);
        Cipher decryptionCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        decryptionCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = decryptionCipher.doFinal(dataInBytes);
        return new String(decryptedBytes);
    }

    private String encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    private byte[] decode(String data) {
        return Base64.getDecoder().decode(data);
    }

}
