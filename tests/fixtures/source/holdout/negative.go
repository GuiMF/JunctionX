package fixture
import "crypto/md5"
// md5.Sum([]byte("fixture"))
var text = `md5.Sum([]byte("fixture"))`
var reference = md5.New
func unrelated() {
    _ = custom.Sum([]byte("fixture"))
}
