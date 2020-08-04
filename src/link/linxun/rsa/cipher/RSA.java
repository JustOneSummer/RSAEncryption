package link.linxun.rsa.cipher;

import link.linxun.rsa.config.RSAPadding;
import link.linxun.rsa.config.RSASignatureAlgorithm;
import link.linxun.rsa.config.RSASize;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

/**
 * rsa工具类
 *
 * @author lin-xun
 * @version 2020/4/24 20:38
 */
public class RSA {
    public static final Charset CHARSETS = StandardCharsets.UTF_8;

    /**
     * RSA参数设置
     *
     * @param rsaSize    RSA位数
     * @param algorithm  签名算法
     * @param RSAPadding 加密方式
     */
    public static void setting(RSASize rsaSize, RSASignatureAlgorithm algorithm, RSAPadding RSAPadding) {
        RSACipher.setParameterAll(rsaSize, algorithm, RSAPadding);
    }

    /**
     * RSA参数设置
     *
     * @param rsaSize RSA位数
     */
    public static void setting(RSASize rsaSize) {
        RSACipher.setParameterRSASize(rsaSize);
    }

    /**
     * RSA参数设置
     *
     * @param algorithm 签名算法
     */
    public static void setting(RSASignatureAlgorithm algorithm) {
        RSACipher.setParameterSignatureAlgorithm(algorithm);
    }

    /**
     * RSA参数设置
     *
     * @param RSAPadding 加密方式
     */
    public static void setting(RSAPadding RSAPadding) {
        RSACipher.setParameterPKCS1Padding(RSAPadding);
    }

    /**
     * 私钥签名
     *
     * @param data       加密的数据
     * @param privateKey 私钥
     * @return sign
     */
    public static String sign(String data, String privateKey) {
        try {
            return RSACipher.sign(data.getBytes(CHARSETS), privateKey);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }
        return null;
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
        try {
            return RSACipher.verify(data.getBytes(CHARSETS), publicKey, sign);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }
        return false;
    }

    /**
     * 私钥解密
     *
     * @param encryptedData 加密数据
     * @param privateKey    私钥
     * @return encryptedData
     */
    public static String decryptByPrivateKey(String encryptedData, String privateKey) {
        try {
            return new String(RSACipher.decryptByPrivateKey(Base64.getDecoder().decode(encryptedData), privateKey), CHARSETS);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 公钥解密
     *
     * @param encryptedData 加密数据
     * @param publicKey     私钥
     * @return encryptedData
     */
    public static String decryptByPublicKey(String encryptedData, String publicKey) {
        try {
            return new String(RSACipher.decryptByPublicKey(Base64.getDecoder().decode(encryptedData), publicKey), CHARSETS);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 私钥加密
     *
     * @param data       数据
     * @param privateKey 私钥
     * @return 加密后的数据
     */
    public static String encryptByPrivateKey(String data, String privateKey) {
        try {
            return Base64.getEncoder().encodeToString(RSACipher.encryptByPrivateKey(data.getBytes(CHARSETS), privateKey));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 公钥加密
     *
     * @param data      数据
     * @param publicKey 私钥
     * @return 加密后的数据
     */
    public static String encryptByPublicKey(String data, String publicKey) {
        try {
            return Base64.getEncoder().encodeToString(RSACipher.encryptByPublicKey(data.getBytes(CHARSETS), publicKey));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException | IOException e) {
            e.printStackTrace();
        }
        return null;
    }
}