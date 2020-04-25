package link.linxun.rsa.cipher;

import link.linxun.rsa.config.RSASize;

import java.security.*;
import java.util.Base64;

/**
 * 生成秘钥对
 *
 * @author lin-xun
 * @version 2020/4/24 19:47
 */
public class RSAKeyPairGenerator {
    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    public RSAKeyPairGenerator(RSASize rsaSize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSACipher.getKeyAlgorithm());
        keyPairGenerator.initialize(rsaSize.getInitializeLength());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    public RSAKeyPairGenerator() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSACipher.getKeyAlgorithm());
        keyPairGenerator.initialize(RSACipher.getRsaSize().getInitializeLength());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public String getPrivateKeyByString() {
        return Base64.getEncoder().encodeToString(privateKey.getEncoded());
    }

    public String getPublicKeyByString() {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }
}
