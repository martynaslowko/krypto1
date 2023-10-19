import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

public class AESEncoding {
    private static final int keyLength = 32;
    private static final SecureRandom random = new SecureRandom();

    private static SecretKey key;
    private static IvParameterSpec iv;

    public static void printByteArr(byte[] arr) {
        for (int i = 0; i < arr.length; i++) {
            System.out.printf(i == 0 ? "%d" : ",%d", (arr[i] & 0xFF));
        }
        System.out.println("\n");
    }

    public static byte [] encrypt(String plaintext) throws Exception {
        key = generateKey();

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
        iv = generateIV(cipher);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        System.out.println(
                Base64.getEncoder().withoutPadding()
                        .encodeToString(key.getEncoded())
        );
        printByteArr(iv.getIV());
        return cipher.doFinal(plaintext.getBytes());
    }

    public static String decrypt(byte [] ciphertext) throws Exception {
        printByteArr(ciphertext);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        return new String(cipher.doFinal(ciphertext));
    }

    public static SecretKey generateKey() throws Exception {
        byte[] keyBytes = new byte[keyLength];
        random.nextBytes(keyBytes);
        return new SecretKeySpec(keyBytes, "AES");
    }

    public static IvParameterSpec generateIV(Cipher cipher) throws Exception {
        byte [] ivBytes = new byte[cipher.getBlockSize()];
        random.nextBytes(ivBytes);
        return new IvParameterSpec(ivBytes);
    }
}
