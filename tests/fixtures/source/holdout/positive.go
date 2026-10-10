package fixture
import (
    digest "crypto/sha256"
    "crypto/md5"
    "crypto/hmac"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rsa"
    "crypto/ed25519"
    "crypto/rand"
)
func examples() {
    _ = digest.Sum256([]byte("fixture"))
    _ = md5.Sum([]byte("fixture"))
    _ = hmac.New(digest.New, []byte("fixture"))
    key := make([]byte, 32)
    block, _ := aes.NewCipher(key)
    _, _ = cipher.NewGCM(block)
    _, _ = rsa.GenerateKey(rand.Reader, 1024)
    _, _, _ = ed25519.GenerateKey(rand.Reader)
}
