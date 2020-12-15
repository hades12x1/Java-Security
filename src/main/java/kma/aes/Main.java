package kma.aes;

import java.io.*;

public class Main {

    static void encryptDataAES(String pathFile, String nameFileEncrypt, String key) {
        try (BufferedReader br = new BufferedReader(new FileReader(pathFile))) {
            BufferedWriter bw = new BufferedWriter(new FileWriter(nameFileEncrypt));
            String lineStr = "";
            while ((lineStr = br.readLine()) != null) {
                String encryptedString = AES.encrypt(lineStr, key);
                bw.write(encryptedString + "\n");
            }
            bw.close();
        } catch (Exception ex) {
            System.out.println("Error read file!!!");
        }
        System.out.println("Key: " + key);
        System.out.println("Raw data: " + pathFile);
        System.out.println("File encrypt: " + nameFileEncrypt);
    }

    static void decryptDataAES(String pathFile, String nameFileDecrypt, String key) {
        try (BufferedReader br = new BufferedReader(new FileReader(pathFile))) {
            BufferedWriter bw = new BufferedWriter(new FileWriter(nameFileDecrypt));
            String lineStr = "";
            while ((lineStr = br.readLine()) != null) {
                String encryptedString = AES.decrypt(lineStr, key);
                bw.write(encryptedString + "\n");
            }
            bw.close();
        } catch (Exception ex) {
            System.out.println("Error read file!!!");
        }
        System.out.println("Key: " + key);
        System.out.println("Encrypt data: " + pathFile);
        System.out.println("File decrypt: " + nameFileDecrypt);
    }

    public static void main(String[] args)
    {
        final String secretKey = "kma!!!!";
        final String rawFile = "rsa-raw.txt";
        final String rsaEncryptFile = "aes-encrypt.txt";
        final String rsaDecrypFile = "aes-decrypt.txt";
        encryptDataAES(rawFile, rsaEncryptFile, secretKey);
        decryptDataAES(rsaEncryptFile, rsaDecrypFile, secretKey);
        System.out.println("Done.");
    }
}
