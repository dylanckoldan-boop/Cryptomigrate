import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;

public class LegacyCrypto {
    byte[] encrypt(byte[] key, byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        Cipher d = Cipher.getInstance("DES");
        SecretKeyFactory f = SecretKeyFactory.getInstance("DESede");
        DESedeKeySpec spec = new DESedeKeySpec(key);
        return c.doFinal(data);
    }
}
