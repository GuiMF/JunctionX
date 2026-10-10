import java.security.MessageDigest;
import javax.crypto.Cipher;

final class Unknown {
    void selected(String name, String transformation) throws Exception {
        MessageDigest digest = MessageDigest.getInstance(name);
        Cipher cipher = Cipher.getInstance(transformation);
    }
}
