package kma.rsa;

import java.io.IOException;
import java.security.*;
import java.util.Base64;

public class RSAKeyPairGenerator {

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public RSAKeyPairGenerator() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair pair = keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }
    
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        RSAKeyPairGenerator keyPairGenerator = new RSAKeyPairGenerator();
        System.out.println("Public key: " + Base64.getEncoder().encodeToString(keyPairGenerator.getPublicKey().getEncoded()));
        System.out.println("Private key: " + Base64.getEncoder().encodeToString(keyPairGenerator.getPrivateKey().getEncoded()));
    }
}
