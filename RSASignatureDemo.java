import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

/** Demonstrates RSA signing and verification using SHA256withRSA. */
public class RSASignatureDemo {
    private static byte[] sign(String message, java.security.PrivateKey key)
            throws Exception {
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(key);
        signer.update(message.getBytes(StandardCharsets.UTF_8));
        return signer.sign();
    }

    private static boolean verify(String message, byte[] signature, PublicKey key)
            throws Exception {
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(key);
        verifier.update(message.getBytes(StandardCharsets.UTF_8));
        return verifier.verify(signature);
    }

    public static void main(String[] args) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(3072);
        KeyPair alice = generator.generateKeyPair();
        KeyPair anotherUser = generator.generateKeyPair();

        String original = "Transfer $1000 to Mark";
        String modified = "Transfer $1000 to Oscar";
        byte[] signature = sign(original, alice.getPrivate());

        System.out.println("Algorithm: SHA256withRSA");
        System.out.println("RSA key size: 3072 bits");
        System.out.println("Original message: " + original);
        System.out.println("Signature (Base64): " + Base64.getEncoder().encodeToString(signature));
        System.out.println("Original message verified: " + verify(original, signature, alice.getPublic()));
        System.out.println("Modified message verified: " + verify(modified, signature, alice.getPublic()));
        System.out.println("Wrong public key verified: " + verify(original, signature, anotherUser.getPublic()));
    }
}
