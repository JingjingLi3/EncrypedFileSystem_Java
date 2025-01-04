import java.io.File;
import java.nio.file.Files;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public abstract class Utility {

    public Utility() {}

    public abstract void create(String fileName, String userName, String password) throws Exception;

    public abstract String findUser(String fileName) throws Exception;

    public abstract int length(String fileName, String password) throws Exception;

    public abstract byte[] read(String fileName, int sPos, int len, String password) throws Exception;

    public abstract void write(String fileName, int sPos, byte[] content, String password) throws Exception;

    public abstract boolean checkIntegrity(String fileName, String password) throws Exception;

    public byte[] readFromFile(File file) throws Exception {
        return Files.readAllBytes(file.toPath());
    }

    public void saveToFile(byte[] s, File file) throws Exception {
        Files.write(file.toPath(), s);
    }

    public static byte[] encryptAes(byte[] plainText, byte [] key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");

        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(plainText);
    }

    public static byte[] decryptAes(byte[] cipherText, byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");

        SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] pt = new byte[cipherText.length];

        System.arraycopy(cipherText, 0, pt, 0, cipherText.length);

        return cipher.doFinal(pt);
    }

    public static byte[] hashSha256(byte[] message) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(message);
    }

    public static byte[] hashSha384(byte[] message) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-384");
        return digest.digest(message);
    }

    public static byte[] hashSha512(byte[] message) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-512");
        return digest.digest(message);
    }
}
