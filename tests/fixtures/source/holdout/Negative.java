import java.security.MessageDigest;
import javax.crypto.Cipher;

final class Negative {
    String text = "MessageDigest.getInstance(\"MD5\")";
    // Cipher.getInstance("AES/ECB/PKCS5Padding");
    Object unrelated() {
        return CustomDigest.getInstance("MD5");
    }
}
