// Code from : https://gist.github.com/nielsutrecht/855f3bef0cf559d8d23e94e2aecd4ede
import javax.crypto.Cipher;
import java.io.InputStream;
import java.security.*;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Base64.*;

class main{
    public static KeyPair getKeyPairFromKeyStore() throws Exception {
        //Generated with:
        // keytool -genkeypair -alias SecurityTest -keyalg RSA -storepass s3cr3t -keypass s3cr3t -keystore keystore2.jks -keysize 2048
        // keytool -export -alias SecurityTest -file certfile.cer -keystore keystore2.jks
        //keytool -printcert -rfc -file certfile.cer
        InputStream ins = main.class.getResourceAsStream("keystore2.jks");

        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(ins, "s3cr3t".toCharArray());   //Keystore password
        KeyStore.PasswordProtection keyPassword =       //Key password
                new KeyStore.PasswordProtection("s3cr3t".toCharArray());

        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry("SecurityTest", keyPassword);

        java.security.cert.Certificate cert = keyStore.getCertificate("SecurityTest");
        PublicKey publicKey = cert.getPublicKey();
        PrivateKey privateKey = privateKeyEntry.getPrivateKey();

        return new KeyPair(publicKey, privateKey);
    }

    public static String encrypt(String plainText, PublicKey publicKey) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] cipherText = encryptCipher.doFinal(plainText.getBytes(UTF_8));

        return getEncoder().encodeToString(cipherText);
    }

    public static String decrypt(String cipherText, PrivateKey privateKey) throws Exception {
        byte[] bytes = getDecoder().decode(cipherText);

        Cipher decriptCipher = Cipher.getInstance("RSA");
        decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);

        return new String(decriptCipher.doFinal(bytes), UTF_8);
    }

    public static void main(String[] args) throws Exception {
        System.out.println("Hello World!");

        //get keypair
        KeyPair pair = null;
        try {
            pair = getKeyPairFromKeyStore();
        } catch (Exception e) {
            e.printStackTrace();
        }

        // String to encrypt
        String message = "username:test,password:test";

        //Encrypt the message
        String cipherText = encrypt(message, pair.getPublic());

        System.out.println("Encrypted :"+cipherText);
        //Decrypt it
        String decipheredMessage = decrypt(cipherText, pair.getPrivate());
        System.out.println("Decrypted :"+decipheredMessage);
    }
}
