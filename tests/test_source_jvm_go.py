"""API and conservative dataflow regression tests independent of corpus labels."""
import pytest

from adapters.source_common import SourceParseError
from adapters.source_jvm_go import detect_go, detect_java


def java(body, imports="java.security.MessageDigest", params=""):
    return "".join(f"import {i};\n" for i in imports.split(",")) + f"class Demo {{ void f({params}) {{\n{body}\n}} }}"


def go(body, imports='"crypto/sha256"', params=""):
    return f"package example\nimport ({imports})\nfunc f({params}) {{\n{body}\n}}"


def test_java_imports_comments_literals_and_lookalikes():
    text = java('''// MessageDigest.getInstance("MD5");
String sample = "MessageDigest.getInstance(\\\"MD5\\\")";
String block = """\nMessageDigest.getInstance("MD5")\n""";
Fake.MessageDigest.getInstance("MD5");
MessageDigest.getInstance("SHA-256");''')
    found = detect_java(text)
    assert [(f.algorithm, f.usage) for f in found] == [("SHA-256", "hash")]
    assert detect_java("class T { void f(){ MessageDigest.getInstance(\"MD5\"); }}") == []


def test_java_dynamic_algorithm_is_unknown():
    found = detect_java(java('MessageDigest.getInstance(algorithm);', params="String algorithm"))
    assert found[0].algorithm == "unknown"
    assert found[0].parameters.key_bits is None


def test_java_constants_order_and_reassignment():
    found = detect_java(java('''MessageDigest.getInstance(ALGO);
String ALGO = "MD5";
MessageDigest.getInstance(ALGO);
ALGO = dynamic();
MessageDigest.getInstance(ALGO);'''))
    assert [f.algorithm for f in found] == ["unknown", "MD5", "unknown"]


def test_java_import_parameter_shadow_is_local():
    text = '''import java.security.MessageDigest;
class T {
 void a(Object MessageDigest) { MessageDigest.getInstance("MD5"); }
 void b() { MessageDigest.getInstance("SHA-256"); }
}'''
    assert [f.algorithm for f in detect_java(text)] == ["SHA-256"]


def test_java_import_local_shadow_and_reassignment():
    text = java('Object MessageDigest = custom(); MessageDigest.getInstance("MD5");')
    assert detect_java(text) == []


def test_java_rsa_direct_receiver_bits_not_signature_bits():
    text = java('''KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
g.initialize(1024);
Signature s = Signature.getInstance("SHA1withRSA");''', "java.security.KeyPairGenerator,java.security.Signature")
    found = detect_java(text)
    assert [(f.algorithm, f.usage) for f in found] == [("RSA", "unknown"), ("RSA", "signature")]
    assert found[0].parameters.key_bits == 1024
    assert found[1].parameters.key_bits is None
    assert found[1].parameters.hash_algorithm == "SHA-1"


def test_java_receiver_rebinding_prevents_false_size():
    text = java('''KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
g = other();
g.initialize(4096);''', "java.security.KeyPairGenerator")
    assert detect_java(text)[0].parameters.key_bits is None


def test_java_aes_and_pbkdf2_units():
    text = java('''byte[] key = new byte[32];
SecretKeySpec ks = new SecretKeySpec(key, "AES");
Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
c.init(Cipher.ENCRYPT_MODE, ks);
PBEKeySpec p = new PBEKeySpec(password, salt, 600_000, 256);
SecretKeyFactory kdf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
kdf.generateSecret(p);''', "javax.crypto.Cipher,javax.crypto.spec.SecretKeySpec,javax.crypto.spec.PBEKeySpec,javax.crypto.SecretKeyFactory")
    found = detect_java(text)
    assert [f.algorithm for f in found] == ["AES", "PBKDF2"]
    assert found[0].parameters.key_bits == 256
    assert found[0].parameters.mode == "GCM"
    assert found[1].parameters.key_bits == 256
    assert found[1].parameters.iterations == 600000


def test_java_no_cross_function_size_propagation():
    text = '''import javax.crypto.KeyGenerator; import javax.crypto.Cipher;
class T {
 void a() { KeyGenerator g = KeyGenerator.getInstance("AES"); g.init(256); }
 void b() { Cipher c = Cipher.getInstance("AES/GCM/NoPadding"); }
}'''
    found = detect_java(text)
    assert found[0].parameters.key_bits == 256
    assert found[1].parameters.key_bits is None


def test_java_qualified_api_and_ed25519():
    found = detect_java('class T { void f() { java.security.KeyPairGenerator.getInstance("Ed25519"); }}')
    assert (found[0].algorithm, found[0].usage) == ("Ed25519", "signature")


def test_go_aliases_no_import_only_or_literal_findings():
    text = go('''// digest.New()
s := `digest.New()`
_ = s
digest.Sum256(data)
sha256.New()
''', 'digest "crypto/sha256"')
    found = detect_go(text)
    assert [(f.algorithm, f.usage) for f in found] == [("SHA-256", "hash")]
    assert detect_go(go("")) == []


def test_go_parameter_shadow_is_local():
    text = '''package p
import "crypto/md5"
func a(md5 Object) { md5.Sum(data) }
func b() { md5.Sum(data) }
'''
    assert len(detect_go(text)) == 1


def test_go_rebinding_import():
    assert detect_go(go('sha256 := custom()\nsha256.New()')) == []
    assert detect_go(go('var sha256 custom\nsha256.New()')) == []


def test_go_hmac_reference_not_separate_hash_call():
    found = detect_go(go('hmac.New(sha256.New, key)', '"crypto/hmac"; "crypto/sha256"'))
    assert [(f.algorithm, f.usage) for f in found] == [("HMAC", "mac")]
    assert found[0].parameters.hash_algorithm == "SHA-256"


def test_go_nested_hash_calls_are_separate():
    found = detect_go(go('hmac.New(sha256.New(), key)', '"crypto/hmac"; "crypto/sha256"'))
    assert [f.algorithm for f in found] == ["HMAC", "SHA-256"]


def test_go_aes_local_length_and_gcm_evidence():
    found = detect_go(go('''const n = 32
key := make([]byte, n)
block, err := aes.NewCipher(key)
_, _ = cipher.NewGCM(block)
''', '"crypto/aes"; "crypto/cipher"'))
    assert len(found) == 1
    assert found[0].parameters.key_bits == 256
    assert found[0].parameters.mode == "GCM"


def test_go_bare_aes_has_no_mode_or_cross_function_size():
    text = '''package p
import "crypto/aes"
const keyLen = 32
func gen() []byte { return make([]byte, keyLen) }
func encrypt(key []byte) { aes.NewCipher(key) }
'''
    found = detect_go(text)
    assert found[0].parameters.mode is None
    assert found[0].parameters.key_bits is None


def test_go_literal_bytes_are_converted_once():
    found = detect_go(go('aes.NewCipher([]byte("0123456789ABCDEF"))', '"crypto/aes"'))
    assert found[0].parameters.key_bits == 128


def test_go_pbkdf2_alias_constants_and_byte_units():
    text = '''package p
import ( kdf "golang.org/x/crypto/pbkdf2"; h "crypto/sha256" )
const (
 iterations = 600_000
 length = 32
)
func f() { kdf.Key(password, salt, iterations, length, h.New) }
'''
    found = detect_go(text)
    assert len(found) == 1
    assert found[0].algorithm == "PBKDF2"
    assert found[0].parameters.model_dump(exclude_none=True) == {"iterations": 600000, "key_bits": 256, "hash_algorithm": "SHA-256"}


def test_go_rsa_signing_hash_and_ed25519():
    text = go('''rsa.GenerateKey(reader, 1024)
rsa.SignPKCS1v15(reader, key, crypto.SHA1, digest)
ed25519.GenerateKey(reader)
ed25519.Sign(key, message)''', '"crypto"; "crypto/rsa"; "crypto/ed25519"')
    found = detect_go(text)
    assert [(f.algorithm, f.usage) for f in found] == [("RSA", "unknown"), ("RSA", "signature"), ("Ed25519", "signature"), ("Ed25519", "signature")]
    assert found[0].parameters.key_bits == 1024
    assert found[1].parameters.hash_algorithm == "SHA-1"
    assert found[1].parameters.key_bits is None


@pytest.mark.parametrize("parser", [detect_java, detect_go])
@pytest.mark.parametrize("text", ['/* private secret', '"private secret', 'func f() {', ')'])
def test_lexical_errors_are_sanitized(parser, text):
    with pytest.raises(SourceParseError) as error:
        parser(text)
    assert "private secret" not in str(error.value)


def test_java_conditional_and_conflicting_receiver_parameters_are_unknown():
    imports = "java.security.KeyPairGenerator"
    for body in [
        'g.initialize(1024); g.initialize(2048);',
        'if (condition) { g.initialize(2048); }',
        'g.initialize(1024); if (condition) { g.initialize(2048); }',
    ]:
        text = java('KeyPairGenerator g = KeyPairGenerator.getInstance("RSA"); ' + body, imports)
        assert detect_java(text)[0].parameters.key_bits is None


def test_go_conditional_mode_is_unknown():
    text = go('''block, err := aes.NewCipher(key)
if condition { cipher.NewGCM(block) }
''', '"crypto/aes"; "crypto/cipher"')
    assert detect_go(text)[0].parameters.mode is None


@pytest.mark.parametrize("charset,bits", [('StandardCharsets.UTF_8', 128), ('StandardCharsets.US_ASCII', 128), ('StandardCharsets.UTF_16', None), ('unknownCharset', None), ('', None)])
def test_java_getbytes_encoding_must_be_known(charset, bits):
    text = java(f'''byte[] key = "0123456789ABCDEF".getBytes({charset});
SecretKeySpec spec = new SecretKeySpec(key, "AES");
Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
c.init(Cipher.ENCRYPT_MODE, spec);''', 'javax.crypto.Cipher,javax.crypto.spec.SecretKeySpec')
    assert detect_java(text)[0].parameters.key_bits == bits


@pytest.mark.parametrize("parser,text", [(detect_java, java('KeyPairGenerator g = KeyPairGenerator.getInstance("RSA"); g.initialize(01024);', 'java.security.KeyPairGenerator')), (detect_go, go('rsa.GenerateKey(reader, 01024)', '"crypto/rsa"'))])
def test_unsupported_numeric_forms_remain_unknown(parser, text):
    assert parser(text)[0].parameters.key_bits is None


def test_mutable_outer_values_are_not_assumed_inside_functions():
    java_text = '''import java.security.MessageDigest;
class T { static String algorithm = "MD5";
void f() { MessageDigest.getInstance(algorithm); }
}'''
    assert detect_java(java_text)[0].algorithm == "unknown"
    go_text = '''package p
import "crypto/rsa"
var size = 1024
func f() { rsa.GenerateKey(reader, size) }
'''
    assert detect_go(go_text)[0].parameters.key_bits is None


@pytest.mark.parametrize("parser,text", [(detect_java, java('fake().MessageDigest.getInstance("MD5");')), (detect_go, go('fake().sha256.New()'))])
def test_member_lookalikes_do_not_resolve_as_imports(parser, text):
    assert parser(text) == []


def test_modern_go_pbkdf2_parameter_order():
    found = detect_go(go('pbkdf2.Key(sha256.New, password, salt, 600000, 32)', '"crypto/pbkdf2"; "crypto/sha256"'))
    assert found[0].parameters.model_dump(exclude_none=True) == {"key_bits": 256, "hash_algorithm": "SHA-256", "iterations": 600000}


def test_java_unbraced_conditional_configuration_is_unknown():
    text = java('KeyPairGenerator g = KeyPairGenerator.getInstance("RSA"); if (condition) g.initialize(1024);', 'java.security.KeyPairGenerator')
    assert detect_java(text)[0].parameters.key_bits is None


@pytest.mark.parametrize("escaped", [r'\xff', r'\377'])
def test_go_byte_escapes_do_not_expand_key_size(escaped):
    text = go('aes.NewCipher([]byte("' + escaped * 16 + '"))', '"crypto/aes"')
    assert detect_go(text)[0].parameters.key_bits is None


def test_go_method_parameter_and_receiver_shadow_imports():
    text = '''package p
import "crypto/md5"
type Fake struct {}
func (x Fake) New() {}
func (x Fake) test(md5 Fake) { md5.New() }
func (md5 Fake) other() { md5.New() }
func good() { md5.New() }
'''
    assert [(f.algorithm, f.line) for f in detect_go(text)] == [("MD5", 7)]


@pytest.mark.parametrize("offset,length,bits", [(0, 16, 128), (16, 16, 128), (17, 16, None), (-1, 16, None), (0, 0, None)])
def test_java_secret_key_spec_slice_overload(offset, length, bits):
    text = java(f'''byte[] key = new byte[32];
SecretKeySpec spec = new SecretKeySpec(key, {offset}, {length}, "AES");
Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
c.init(Cipher.ENCRYPT_MODE, spec);''', 'javax.crypto.Cipher,javax.crypto.spec.SecretKeySpec')
    assert detect_java(text)[0].parameters.key_bits == bits
