import java.io.*;

import java.security.Key;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;

import java.security.KeyFactory;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.RSAPrivateKeySpec;

import java.math.BigInteger;
import java.util.Scanner;
import javax.crypto.Cipher;

public class KeyGenerator {
    public static void main(String[] args) throws Exception {

        //Generate a pair of keys (1 of 2)
        SecureRandom random = new SecureRandom();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024, random);
        KeyPair sender = generator.generateKeyPair();
        Key pubKeyX = sender.getPublic();
        Key privKeyX = sender.getPrivate();

        //Generate a pair of keys (2 of 2)
        random = new SecureRandom();
        generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024, random);
        KeyPair receiver = generator.generateKeyPair();
        Key pubKeyY = receiver.getPublic();
        Key privKeyY = receiver.getPrivate();


        //get the parameters of the keys: modulus and exponet
        KeyFactory factory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec senderPubSpec = factory.getKeySpec(pubKeyX,
                RSAPublicKeySpec.class);
        RSAPrivateKeySpec senderPrivSpec = factory.getKeySpec(privKeyX,
                RSAPrivateKeySpec.class);
        RSAPublicKeySpec receiverPubSpec = factory.getKeySpec(pubKeyY,
                RSAPublicKeySpec.class);
        RSAPrivateKeySpec receiverPrivSpec = factory.getKeySpec(privKeyY,
                RSAPrivateKeySpec.class);


        //save the parameters of the keys to the files
        saveToFile("XPublic.key", senderPubSpec.getModulus(),
                senderPubSpec.getPublicExponent());
        saveToFile("XPrivate.key", senderPrivSpec.getModulus(),
                senderPrivSpec.getPrivateExponent());
        saveToFile("YPublic.key", receiverPubSpec.getModulus(),
                receiverPubSpec.getPublicExponent());
        saveToFile("YPrivate.key", receiverPrivSpec.getModulus(),
                receiverPrivSpec.getPrivateExponent());
        
        // Generate Symetric Keys
        boolean exit = true;
        Scanner input = new Scanner(System.in);
        String userInput;
        do {
            System.out.println("Input 16 Characters:");
            userInput = input.next();
        }
        while (userInput.length() != 16);
        
        System.out.println("This is userinput: " + userInput);
        FileWriter out = new FileWriter("Symmetric.key");
        try {
            out.write(userInput);
        } catch (Exception e) {
            throw new IOException("Unexpected error", e);
        } finally {
            out.close();
        }
    }


    //save the prameters of the public and private keys to file
    public static void saveToFile(String fileName,
                                  BigInteger mod, BigInteger exp) throws IOException {

        System.out.println("Write to " + fileName + ": modulus = " +
                mod.toString() + "\nexponent = " + exp.toString() + "\n");

        ObjectOutputStream oout = new ObjectOutputStream(
                new BufferedOutputStream(new FileOutputStream(fileName)));

        try {
            oout.writeObject(mod);
            oout.writeObject(exp);
        } catch (Exception e) {
            throw new IOException("Unexpected error", e);
        } finally {
            oout.close();
        }
    }


}

