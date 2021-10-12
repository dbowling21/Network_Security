import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Scanner;

public class Sender {
    static String IV = "AAAAAAAAAAAAAAAA";
    static String symmetricKey;
    static byte[] msgArray;
    static String fileName;

    public static void main(String[] args) throws Exception {

        PublicKey YPublic = readPubKeyFromFile("YPublic.key");
        //remove later
        // PrivateKey YPrivate = readPrivKeyFromFile("YPrivate.key");

        //Get the symmetric key from file
        BufferedReader br = new BufferedReader(new FileReader("Symmetric.key"));
        symmetricKey = br.readLine();
        System.out.println("Read from Symmetric.key: " + br.readLine() + "\n");
        System.out.println("---------------------------------------------------------\n");

        //Call the encrypt method which in turn calls the digital digest method
        //the return is the fully encrypted byte array
        byte[] encryptedMsg = encrypt("file.txt", YPublic);
        //decrypt(encryptedMsg, YPrivate);

    }


    public static byte[] getDigitalDigest(String fileName) throws Exception {
        BufferedInputStream inputFile = new BufferedInputStream(new FileInputStream(fileName));
        //gets the estimated number of bytes in the message file
        int size = inputFile.available();

        msgArray = new byte[size];
        //write the message files byte representation to the msgArray
        inputFile.read(msgArray,0, size);
        inputFile.close();

        //create the message digest using the input message
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        DigestInputStream in = new DigestInputStream(inputFile, md);
        md = in.getMessageDigest();
        in.close();

        //Saves the hash value of the message digest to hash
        // This will always have a size of 32 bytes
        byte[] hash = md.digest();

        //Print the hash value to console in hex
        System.out.println("Digital Digest (Hash Value) of M:");
        toHex(hash);

        //Saves the hash value to the file message.dd
        try(BufferedOutputStream saveMD =
                    new BufferedOutputStream(new FileOutputStream("message.dd"))) {
                saveMD.write(hash);
        }
        catch(Exception e) {
            throw new IOException("Unexpected error", e);
        }
        System.out.println("Saved Digital Digest to message.dd\n");
        return hash;
    }

   /* public static byte[] decrypt(byte[] cipher, PrivateKey privKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException, UnsupportedEncodingException {
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.DECRYPT_MODE, privKey);

        byte[] rsaCipherText = rsaCipher.doFinal(cipher);
        //*************************************************
        Cipher AEScipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
        SecretKeySpec key = new SecretKeySpec(symmetricKey.getBytes("UTF-8"), "AES");
        AEScipher.init(Cipher.ENCRYPT_MODE, key);
        //perform the encryption on the digitaldigest hash value
        byte[] encryptedHash = AEScipher.doFinal(rsaCipherText);

        return
    } */

    public static byte[] encrypt(String fileName,PublicKey pubKey) throws Exception {

        //new cipher that uses AES encryption with CBC scheme and no padding
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
        SecretKeySpec key = new SecretKeySpec(symmetricKey.getBytes("UTF-8"), "AES");
        //IvParameterSpec constrains the thing being encrypted to be a multiple of 16 bytes
        cipher.init(Cipher.ENCRYPT_MODE, key,new IvParameterSpec(IV.getBytes("UTF-8")));
        //perform the encryption on the digital digest hash value which is always 32 bytes
        byte[] encryptedHash = cipher.doFinal(getDigitalDigest(fileName));

        //Print out the encrypted value in hex
        System.out.println("AES ciphertext:");
        toHex(encryptedHash);

        // Save the AES cipher to message.add-msg
        try(BufferedOutputStream saveMD =
                    new BufferedOutputStream(new FileOutputStream("message.add-msg"))) {
            //save the encryptedhashvalue as the first 32bytes of message.add-msg
            saveMD.write(encryptedHash);
            //concatenate the above 32bytes with the byte representation of the original message
            //this appears as the original text when opening in intellij if encoding is utf-8
            saveMD.write(msgArray);
        }
        catch(Exception e) {
            throw new IOException("Unexpected error", e);
        }
        System.out.println("Saved AES cipher to message.add-msg\n");

        //*********************** RSA ****************************
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, pubKey);

        byte[] rsaCipherText = rsaCipher.doFinal(encryptedHash);

        System.out.println("cipherText: block size = "
                + rsaCipherText.length + " Bytes");

        toHex(rsaCipherText);


        return rsaCipherText;
    }

    static void toHex(byte[] byteArray) {
        for (int k=0, j=0; k<byteArray.length; k++, j++) {
            System.out.format("%2X ", byteArray[k]) ;
            if (j >= 15) {
                System.out.println("");
                j=-1;
            }
        }
        System.out.println("");
    }

    public static PublicKey readPubKeyFromFile(String keyFileName) throws IOException {

        ObjectInputStream oin = new ObjectInputStream(
                new BufferedInputStream(new FileInputStream(keyFileName)));

        try {
            BigInteger m = (BigInteger) oin.readObject();
            BigInteger e = (BigInteger) oin.readObject();

            System.out.println("Read from " + keyFileName + ":\n modulus = " +
                    m.toString() + ",\n exponent = " + e.toString() + "\n");

            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m, e);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            PublicKey key = factory.generatePublic(keySpec);

            return key;
        } catch (Exception er) {
            throw new RuntimeException("Spurious serialisation error", er);
        }
    }

    public static PrivateKey readPrivKeyFromFile(String keyFileName)
            throws IOException {

        InputStream in =
                RSAConfidentiality.class.getResourceAsStream(keyFileName);
        ObjectInputStream oin =
                new ObjectInputStream(new BufferedInputStream(in));

        try {
            BigInteger m = (BigInteger) oin.readObject();
            BigInteger e = (BigInteger) oin.readObject();

            System.out.println("Read from " + keyFileName + ": modulus = " +
                    m.toString() + ", exponent = " + e.toString() + "\n");

            RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(m, e);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            PrivateKey key = factory.generatePrivate(keySpec);

            return key;
        } catch (Exception e) {
            throw new RuntimeException("Spurious serialisation error", e);
        } finally {
            oin.close();
        }
    }


}
