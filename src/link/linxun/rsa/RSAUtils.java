package link.linxun.rsa;

import link.linxun.rsa.cipher.RSA;
import link.linxun.rsa.cipher.RSACipher;
import link.linxun.rsa.cipher.RSAKeyPairGenerator;
import link.linxun.rsa.config.RSAPadding;
import link.linxun.rsa.config.RSASignatureAlgorithm;
import link.linxun.rsa.config.RSASize;

import java.security.NoSuchAlgorithmException;

/**
 * @author lin-xun
 * @version 2020/4/25 1:24
 */
public class RSAUtils {
    /**
     * RSA参数设置
     *
     * @param rsaSize      RSA位数
     * @param algorithm    签名算法
     * @param RSAPadding 加密方式
     */
    public static void setting(RSASize rsaSize, RSASignatureAlgorithm algorithm, RSAPadding RSAPadding) {
        RSA.setting(rsaSize, algorithm, RSAPadding);
    }

    /**
     * RSA参数设置
     *
     * @param rsaSize RSA位数
     */
    public static void setting(RSASize rsaSize) {
        RSA.setting(rsaSize);
    }

    /**
     * RSA参数设置
     *
     * @param algorithm 签名算法
     */
    public static void setting(RSASignatureAlgorithm algorithm) {
        RSA.setting(algorithm);
    }

    /**
     * RSA参数设置
     *
     * @param RSAPadding 加密方式
     */
    public static void setting(RSAPadding RSAPadding) {
        RSA.setting(RSAPadding);
    }

    /**
     * 获取key
     *
     * @return key
     */
    public static RSAKeyPairGenerator getRSAKey() {
        try {
            return new RSAKeyPairGenerator(RSACipher.getRsaSize());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 私钥签名
     *
     * @param data       加密的数据
     * @param privateKey 私钥
     * @return sign
     */
    public static String sign(String data, String privateKey) {
        return RSA.sign(data, privateKey);
    }


    /**
     * 效验签名
     *
     * @param data      加密的数据
     * @param publicKey 公钥
     * @param sign      签名数据data
     * @return 效验结果
     */
    public static boolean verify(String data, String publicKey, String sign) {
        return RSA.verify(data, publicKey, sign);
    }

    /**
     * 私钥解密
     *
     * @param encryptedData 加密数据
     * @param privateKey    私钥
     * @return encryptedData
     */
    public static String decryptByPrivateKey(String encryptedData, String privateKey) {
        return RSA.decryptByPrivateKey(encryptedData, privateKey);
    }

    /**
     * 公钥解密
     *
     * @param encryptedData 加密数据
     * @param publicKey     私钥
     * @return encryptedData
     */
    public static String decryptByPublicKey(String encryptedData, String publicKey) {
        return RSA.decryptByPublicKey(encryptedData, publicKey);
    }

    /**
     * 私钥加密
     *
     * @param data       数据
     * @param privateKey 私钥
     * @return 加密后的数据
     */
    public static String encryptByPrivateKey(String data, String privateKey) {
        return RSA.encryptByPrivateKey(data, privateKey);
    }

    /**
     * 公钥加密
     *
     * @param data      数据
     * @param publicKey 私钥
     * @return 加密后的数据
     */
    public static String encryptByPublicKey(String data, String publicKey) {
        return RSA.encryptByPublicKey(data, publicKey);
    }
}
