import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.security.DigestInputStream;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Scanner;

public class Sender {
    static String IV = "AAAAAAAAAAAAAAAA";
    static BufferedReader br;
    static String symmetricKey;
    static String fileName;
    
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
    

        public static String getDigitalDigest(String f) throws Exception {

            int BUFFER_SIZE = 32 * 1024;
            BufferedInputStream file = new BufferedInputStream(new FileInputStream(f));
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            DigestInputStream in = new DigestInputStream(file, md);
            int i;
            byte[] buffer = new byte[BUFFER_SIZE];
            do {
                i = in.read(buffer, 0, BUFFER_SIZE);
            } while (i == BUFFER_SIZE);
            md = in.getMessageDigest();
            in.close();

            byte[] hash = md.digest();

            System.out.println("Digital Digest (Hash Value) of M:");
            for (int k=0, j=0; k<hash.length; k++, j++) {
                System.out.format("%2X ", hash[k]) ;
                if (j >= 15) {
                    System.out.println("");
                    j=-1;
                }
            }
            System.out.println("");

            String messageDigest = new String(hash);
            System.out.println(messageDigest);
            try(BufferedOutputStream boi =
                 new BufferedOutputStream(new FileOutputStream("message.dd"))) {
                boi.write(hash);
            }
            catch(Exception e) {
                throw new IOException("Unexpected error", e);
            }
            System.out.println("Saved Digital Digest to message.dd");
            return messageDigest;
        }
    
    public static byte[] encrypt() throws Exception {
        
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding", "SunJCE");
        SecretKeySpec key = new SecretKeySpec(symmetricKey.getBytes("UTF-8"), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(getDigitalDigest(fileName).getBytes("UTF-8"));
    }


    public static void main(String[] args) throws Exception {

        PublicKey YPublic = readPubKeyFromFile("YPublic.key");
        br = new BufferedReader(new FileReader("Symmetric.key"));
        symmetricKey = br.readLine();
        System.out.println("Read from Symmetric.key: " + br.readLine() + "\n");

        System.out.println("---------------------------------------------------------\n");

        System.out.println("Input the name of the message file: ");
        Scanner scanner = new Scanner(System.in);
        fileName = scanner.nextLine();
        //encrypt();
        getDigitalDigest(fileName);
        
        BufferedInputStream testinput = new BufferedInputStream(new FileInputStream("message.dd"));
        System.out.println(testinput.read());

        


    }

}
