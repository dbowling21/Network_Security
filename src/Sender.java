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
        PublicKey pubKey = readPubKeyFromFile("YPublic.key");
        //Get the symmetric key from file
        BufferedReader br = new BufferedReader(new FileReader("Symmetric.key"));
        symmetricKey = br.readLine();
        System.out.println("Read from Symmetric.key: " + br.readLine() + "\n");
        System.out.println("---------------------------------------------------------\n");

        //todo  Display a prompt “Input the name of the message file" to get inputfile
        //Call the encrypt method which in turn calls the digital digest method
        //the return is void but creates the message.rsacipher file
        encrypt("file.txt", pubKey);
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

    public static void encrypt(String fileName,PublicKey pubKey) throws Exception {

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

        //rsa cipher instance that uses padding and whose plaintext block must be 117 bytes
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, pubKey);

        //pull input from the message.add-msg and create output stream for rsa result
        BufferedInputStream inputFile = new BufferedInputStream(new FileInputStream("message.add-msg"));
        BufferedOutputStream RSAout = new BufferedOutputStream(new FileOutputStream("message.rsacipher"));
        int size = inputFile.available(); //uncomment to check how many bytes message.add-msg is

        //create array to store 117 byte piece of message.add-msg
        byte[] piece = new byte[117];
        long position = 0;
        int i;
        do {
            //todo test if this skip is actually making .read use the next 117 piece
            inputFile.skip(position);
            i = inputFile.read(piece,0, 117);
            // if the piece that was read was a full 117 bytes
            if (i == 117){
                //write that piece to message.rsacipher
                RSAout.write(rsaCipher.doFinal(piece));
                //update position to be the beginning of the next 117 byte piece of message.add-msg
                position += 117;
            }
            //if the piece isn't a full 117 bytes but has at least 1 byte
            else if (i != -1){
                //create a new array of whatever size the piece actually was
                byte[] smallPiece = new byte[i];
                //fill the new small array with the elements that were fed to the big array by inputFile.read line 131
                for (int j = 0; j < i; j++) {
                    smallPiece[j] = piece[j];
                }
                //perform encryption on the small piece (I assume this pads it) and write to file
                RSAout.write(rsaCipher.doFinal(smallPiece));
            }
        } while (i == 117); //if the piece wasn't a full 117 then its the end of the input file
        inputFile.close();
        RSAout.close();
        System.out.println("Saved RSA cipher to message.rsacipher\n");

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
        } finally {
            oin.close();
        }

    }
}
