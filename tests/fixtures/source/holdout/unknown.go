package fixture
import (
    "crypto/aes"
    "crypto/rsa"
    "crypto/rand"
)
func selected(key []byte, bits int) {
    _, _ = aes.NewCipher(key)
    _, _ = rsa.GenerateKey(rand.Reader, bits)
}
