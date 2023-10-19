import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

public class Main {

    public static void main(String [] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        String plaintext = "hello world";
        byte [] ciphertext = AESEncoding.encrypt(plaintext);
        String recoveredPlaintext = AESEncoding.decrypt(ciphertext);

        System.out.println(recoveredPlaintext);
    }
}