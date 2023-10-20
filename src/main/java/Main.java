import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;
import java.util.concurrent.TimeUnit;

public class Main {

    public static String parseToBlocks(byte[] value, int blocks)
    {
        StringBuilder sb = new StringBuilder();
        for(int i = 0; i < value.length; i++) {
            if(i % blocks == 0) sb.append("\n\t");
            sb.append(String.format("%02X", value[i]));
        }
        return sb.toString();
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

//        Scanner scanner = new Scanner(System.in);
//        String plaintext = scanner.nextLine();
        String plaintext = "bardzo tajne hasło kurcze kto to wymyślał jezu chryste ja juz nie moge";

        System.out.println("\nPLAINTEXT: ");
        System.out.println(parseToBlocks(plaintext.getBytes(), AESEncoding.BLOCK_SIZE));


        byte[] ciphertext = AESEncoding.encrypt(plaintext);
        System.out.println("\nCIPHERTEXT:");
        System.out.println(parseToBlocks(ciphertext, AESEncoding.BLOCK_SIZE));

        BlindDecryptor blindDecryptor = new BlindDecryptor();
        long start = System.nanoTime();
        byte[] decryptedValue = blindDecryptor.decrypt(ciphertext);
        long diff = TimeUnit.MILLISECONDS.convert(System.nanoTime() - start, TimeUnit.NANOSECONDS);
        System.out.println("\nDECRYPTED CIPHERTEXT:");
        System.out.println(parseToBlocks(decryptedValue, AESEncoding.BLOCK_SIZE));
        System.out.println("\nDecrypting took: " + diff + " milliseconds");

        System.out.printf("%n%s", new String(decryptedValue));
    }
}