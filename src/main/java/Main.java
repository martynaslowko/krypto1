import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

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

        byte[] ciphertext = AESEncoding.encrypt(plaintext);
        System.out.println(parseToBlocks(ciphertext, AESEncoding.BLOCK_SIZE));

        BlindDecryptor blindDecryptor = new BlindDecryptor();
        byte[] decryptedValue = blindDecryptor.decrypt(ciphertext);
        System.out.println(parseToBlocks(decryptedValue, AESEncoding.BLOCK_SIZE));

        System.out.printf("%n%s", new String(decryptedValue));
    }
}