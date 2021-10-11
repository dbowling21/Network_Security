import java.io.*;
import java.math.BigInteger;
import java.security.DigestInputStream;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Scanner;

public class Sender {


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
            BufferedOutputStream boi = new BufferedOutputStream(new FileOutputStream("message.dd"));
            System.out.println("Saved Digital Digest to message.dd");
            return messageDigest;
        }


    public static void main(String[] args) throws Exception {

        PublicKey YPublic = readPubKeyFromFile("YPublic.key");
        BufferedReader br = new BufferedReader(new FileReader("Symmetric.key"));
        System.out.println("Read from Symmetric.key: " + br.readLine() + "\n");

        System.out.println("---------------------------------------------------------\n");

        System.out.println("Input the name of the message file: ");
        Scanner scanner = new Scanner(System.in);
        String fileName = scanner.nextLine();
        getDigitalDigest(fileName);




    }

}
