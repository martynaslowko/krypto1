import javax.crypto.BadPaddingException;
import java.util.Arrays;

public class BlindDecryptor {
    public byte[] decrypt(byte[] encryptedValue)
    {
        byte[][] encryptedBlocks = parseBlocks(encryptedValue);
        byte[][] decryptedBlocks = new byte[encryptedBlocks.length][AESEncoding.BLOCK_SIZE];
        for (int i = encryptedBlocks.length - 1; i >= 1; i--) {
            byte[] encryptedBlock = encryptedBlocks[i - 1].clone();
            byte[] decryptedBlock = new byte[AESEncoding.BLOCK_SIZE];
            for (int j = AESEncoding.BLOCK_SIZE - 1; j >= 0; j--) {
                byte padding = (byte) (AESEncoding.BLOCK_SIZE - j);
                if (j < AESEncoding.BLOCK_SIZE - 1) {
                    for (int k = j + 1; k < AESEncoding.BLOCK_SIZE; k++) {
                        encryptedBlock[k] = xor(
                                encryptedBlocks[i - 1][k],
                                decryptedBlock[k],
                                padding
                        );
                    }
                }
                byte prime = findPrime(encryptedBlock.clone(), encryptedBlocks[i], j);
                decryptedBlock[j] = xor(encryptedBlock[j], prime, padding);
            }
            decryptedBlocks[i] = decryptedBlock;
        }
        return joinBytes(decryptedBlocks);
    }

    private byte xor(byte... bytes)
    {
        if (bytes == null)
            return '\000';
        byte result = bytes[0];
        if (bytes.length >= 2) {
            for (int i = 1; i < bytes.length; i++)
                result ^= bytes[i];
        }
        return result;
    }

    private byte findPrime(byte[] prevBlock, byte[] thisBlock, int idx)
    {
        byte original = prevBlock[idx];
        for (byte b = Byte.MIN_VALUE; b < Byte.MAX_VALUE; b++)
        {
            if (original == b) continue;
            prevBlock[idx] = b;
            try {
                AESEncoding.decrypt(joinBytes(prevBlock, thisBlock));
            } catch (BadPaddingException e) {
                continue;
            }
            return b;
        }
        return original;
    }

    private byte[][] parseBlocks(byte[] encryptedValue)
    {
        int qty = encryptedValue.length / AESEncoding.BLOCK_SIZE;
        byte[][] result = new byte[qty][AESEncoding.BLOCK_SIZE];

        for (int i = 0; i * AESEncoding.BLOCK_SIZE < encryptedValue.length; i++) {
            result[i] = Arrays.copyOfRange(encryptedValue,
                    i * AESEncoding.BLOCK_SIZE,
                    i * AESEncoding.BLOCK_SIZE + AESEncoding.BLOCK_SIZE);
        }

        return result;
    }

    private byte[] joinBytes(byte[]... values)
    {
        int size = Arrays.stream(values).mapToInt(v -> v.length).sum();
        byte[] joined = new byte[size];
        int idx = 0;
        for (byte[] value : values) {
            for (byte b : value) {
                joined[idx++] = b;
            }
        }
        return joined;
    }
}
