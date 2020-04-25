package link.linxun.rsa.test;

import link.linxun.rsa.RSAUtils;
import link.linxun.rsa.cipher.RSAKeyPairGenerator;
import link.linxun.rsa.config.RSAPadding;
import link.linxun.rsa.config.RSASignatureAlgorithm;

import java.util.Base64;

/**
 * @author lin-xun
 * @version 2020/4/25 20:22
 */
public class Main {
    public static void main(String[] args) throws Exception {
        String data = "linxun.link";
        RSAKeyPairGenerator key = RSAUtils.getRSAKey();
        String privateKey = key.getPrivateKeyByString();
        String publicKey = key.getPublicKeyByString();
        RSAUtils.setting(RSAPadding.RSA_DEFAULT);
        RSAUtils.setting(RSASignatureAlgorithm.RSA_SHA1);
        System.out.println(privateKey);
        System.out.println(publicKey);
        System.out.println("开始加密");
        String enc = RSAUtils.encryptByPrivateKey(data, privateKey);
        System.out.println(enc);
        System.out.println("开始解密");
        String dec = RSAUtils.decryptByPublicKey(enc, publicKey);
        System.out.println(dec);
    }
}
