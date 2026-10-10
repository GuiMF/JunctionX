import java.security.MessageDigest;
import java.security.KeyPairGenerator;
import java.security.Signature;
import javax.crypto.Cipher;
import javax.crypto.Mac;

final class Positive {
    void examples() throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-512");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        Mac tag = Mac.getInstance("HmacSHA256");
        KeyPairGenerator keys = KeyPairGenerator.getInstance("RSA");
        keys.initialize(2048);
        Signature signature = Signature.getInstance("SHA1withRSA");
    }
}
