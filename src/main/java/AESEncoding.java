import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

public class AESEncoding {
    public static final int BLOCK_SIZE = 16;
    private static final int keyLength = 32;
    private static final SecureRandom random = new SecureRandom();

    private static SecretKey key;
    private static IvParameterSpec iv;

    public static byte [] encrypt(String plaintext) throws Exception {
        key = generateKey();
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
        iv = generateIV(cipher);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return cipher.doFinal(plaintext.getBytes());
    }

    public static void decrypt(byte[] ciphertext) throws BadPaddingException {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
            cipher.doFinal(ciphertext);
        } catch (BadPaddingException e) {
            throw e;
        } catch (Exception e) {
            //ignore
        }
    }

    public static SecretKey generateKey() {
        byte[] keyBytes = new byte[keyLength];
        random.nextBytes(keyBytes);
        return new SecretKeySpec(keyBytes, "AES");
    }

    public static IvParameterSpec generateIV(Cipher cipher) {
        byte [] ivBytes = new byte[cipher.getBlockSize()];
        random.nextBytes(ivBytes);
        return new IvParameterSpec(ivBytes);
    }
}
