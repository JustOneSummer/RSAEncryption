package link.linxun.rsa.cipher;

import link.linxun.rsa.config.RSAPadding;
import link.linxun.rsa.config.RSASignatureAlgorithm;
import link.linxun.rsa.config.RSASize;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * rsa
 *
 * @author lin-xun
 * @version 2020/4/24 18:40
 */
public class RSACipher {
    /**
     * 加密算法RSA
     */
    private static final String KEY_ALGORITHM = "RSA";
    /**
     * 默认加密位数
     */
    private static RSASize rsaSize = RSASize.MAX_4096;
    /**
     * 默认签名算法
     */
    private static RSASignatureAlgorithm rsaSignatureAlgorithm = RSASignatureAlgorithm.RSA_SHA_256;
    /**
     * 默认加密方式
     */
    private static RSAPadding rsaPadding = RSAPadding.RSA_ECB_PKCS1;

    /**
     * 获取加密名称
     *
     * @return KEY_ALGORITHM
     */
    public static String getKeyAlgorithm() {
        return KEY_ALGORITHM;
    }

    /**
     * 获取RSA位数
     *
     * @return RSA位数
     */
    public static RSASize getRsaSize() {
        return rsaSize;
    }

    /**
     * 获取RSA签名算法
     *
     * @return 签名算法
     */
    public static RSASignatureAlgorithm getRSASignatureAlgorithm() {
        return rsaSignatureAlgorithm;
    }

    /**
     * 获取RSA加密方式
     *
     * @return RSA加密方式
     */
    public static RSAPadding getRSAPadding() {
        return rsaPadding;
    }

    /**
     * RSA参数设置
     *
     * @param rsaSize               RSA位数
     * @param rsaSignatureAlgorithm 签名算法
     * @param RSAPadding            加密方式
     */
    public static void setParameterAll(RSASize rsaSize, RSASignatureAlgorithm rsaSignatureAlgorithm, RSAPadding RSAPadding) {
        RSACipher.rsaSize = rsaSize == null ? RSACipher.rsaSize : rsaSize;
        RSACipher.rsaSignatureAlgorithm = rsaSignatureAlgorithm == null ? RSACipher.rsaSignatureAlgorithm : rsaSignatureAlgorithm;
        RSACipher.rsaPadding = RSAPadding == null ? RSACipher.rsaPadding : RSAPadding;
    }

    /**
     * RSA参数设置
     *
     * @param rsaSize RSA位数
     */
    public static void setParameterRSASize(RSASize rsaSize) {
        RSACipher.rsaSize = rsaSize;
    }

    /**
     * RSA参数设置
     *
     * @param rsaSignatureAlgorithm 签名算法
     */
    public static void setParameterSignatureAlgorithm(RSASignatureAlgorithm rsaSignatureAlgorithm) {
        RSACipher.rsaSignatureAlgorithm = rsaSignatureAlgorithm;
    }

    /**
     * RSA参数设置
     *
     * @param RSAPadding 加密方式
     */
    public static void setParameterPKCS1Padding(RSAPadding RSAPadding) {
        RSACipher.rsaPadding = RSAPadding;
    }

    /**
     * 用私钥对信息生成数字签名
     *
     * @param data       已加密数据
     * @param privateKey 私钥(BASE64编码)
     * @return sign
     * @throws NoSuchAlgorithmException nae
     * @throws InvalidKeySpecException  ie
     * @throws InvalidKeyException      ike
     * @throws SignatureException       se
     */
    public static String sign(byte[] data, String privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        byte[] keyBytes = Base64.getDecoder().decode(privateKey);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        PrivateKey privateK = keyFactory.generatePrivate(pkcs8KeySpec);
        Signature signature = Signature.getInstance(rsaSignatureAlgorithm.getAlgorithm());
        signature.initSign(privateK);
        signature.update(data);
        return Base64.getEncoder().encodeToString(signature.sign());
    }

    /**
     * 校验数字签名
     *
     * @param data      已加密数据
     * @param publicKey 公钥(BASE64编码)
     * @param sign      数字签名
     * @return 效验结果
     * @throws NoSuchAlgorithmException nae
     * @throws InvalidKeySpecException  ie
     * @throws InvalidKeyException      ike
     * @throws SignatureException       se
     */
    public static boolean verify(byte[] data, String publicKey, String sign) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        byte[] keyBytes = Base64.getDecoder().decode(publicKey);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        PublicKey publicK = keyFactory.generatePublic(keySpec);
        Signature signature = Signature.getInstance(rsaSignatureAlgorithm.getAlgorithm());
        signature.initVerify(publicK);
        signature.update(data);
        return signature.verify(Base64.getDecoder().decode(sign));
    }

    /**
     * 私钥解密
     *
     * @param encryptedData 已加密数据
     * @param privateKey    私钥(BASE64编码)
     * @throws NoSuchAlgorithmException  nae
     * @throws InvalidKeySpecException   ie
     * @throws NoSuchPaddingException    npe
     * @throws InvalidKeyException       ike
     * @throws BadPaddingException       be
     * @throws IllegalBlockSizeException ise
     * @throws IOException               io
     */
    public static byte[] decryptByPrivateKey(byte[] encryptedData, String privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException {
        byte[] keyBytes = Base64.getDecoder().decode(privateKey);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, privateK);
        return decryptCipher(cipher, encryptedData);
    }

    /**
     * 公钥解密
     *
     * @param encryptedData 已加密数据
     * @param publicKey     公钥(BASE64编码)
     * @throws NoSuchAlgorithmException  nae
     * @throws InvalidKeySpecException   ie
     * @throws NoSuchPaddingException    npe
     * @throws InvalidKeyException       ike
     * @throws BadPaddingException       be
     * @throws IllegalBlockSizeException ise
     * @throws IOException               io
     */
    public static byte[] decryptByPublicKey(byte[] encryptedData, String publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException {
        byte[] keyBytes = Base64.getDecoder().decode(publicKey);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key publicK = keyFactory.generatePublic(x509KeySpec);
        Cipher cipher = Cipher.getInstance(rsaPadding.getPadding());
        cipher.init(Cipher.DECRYPT_MODE, publicK);
        return decryptCipher(cipher, encryptedData);
    }

    /**
     * 公钥加密
     *
     * @param data      源数据
     * @param publicKey 公钥(BASE64编码)
     * @throws NoSuchAlgorithmException  nae
     * @throws InvalidKeySpecException   ie
     * @throws NoSuchPaddingException    npe
     * @throws InvalidKeyException       ike
     * @throws BadPaddingException       be
     * @throws IllegalBlockSizeException ise
     * @throws IOException               io
     */
    public static byte[] encryptByPublicKey(byte[] data, String publicKey) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException {
        byte[] keyBytes = Base64.getDecoder().decode(publicKey);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key publicK = keyFactory.generatePublic(x509KeySpec);
        // 对数据加密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, publicK);
        return encryptCipher(cipher, data);
    }

    /**
     * 私钥加密
     *
     * @param data       源数据
     * @param privateKey 私钥(BASE64编码)
     * @throws NoSuchAlgorithmException  nae
     * @throws InvalidKeySpecException   ie
     * @throws NoSuchPaddingException    npe
     * @throws InvalidKeyException       ike
     * @throws BadPaddingException       be
     * @throws IllegalBlockSizeException ise
     * @throws IOException               io
     */
    public static byte[] encryptByPrivateKey(byte[] data, String privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException {
        byte[] keyBytes = Base64.getDecoder().decode(privateKey);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);
        Cipher cipher = Cipher.getInstance(rsaPadding.getPadding());
        cipher.init(Cipher.ENCRYPT_MODE, privateK);
        return encryptCipher(cipher, data);
    }

    /**
     * cipher处理
     *
     * @param cipher        Cipher
     * @param encryptedData bytes
     * @return 解密后的数据
     * @throws BadPaddingException       b
     * @throws IllegalBlockSizeException i
     * @throws IOException               io
     */
    private static byte[] decryptCipher(Cipher cipher, byte[] encryptedData) throws BadPaddingException, IllegalBlockSizeException, IOException {
        int inputLen = encryptedData.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段解密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > rsaSize.getMaxDecryptBlock()) {
                cache = cipher.doFinal(encryptedData, offSet, rsaSize.getMaxDecryptBlock());
            } else {
                cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * rsaSize.getMaxDecryptBlock();
        }
        byte[] decryptedData = out.toByteArray();
        out.close();
        return decryptedData;
    }

    /**
     * cipher处理
     *
     * @param cipher Cipher
     * @param data   bytes
     * @return 加密后的数据
     * @throws BadPaddingException       b
     * @throws IllegalBlockSizeException i
     * @throws IOException               io
     */
    private static byte[] encryptCipher(Cipher cipher, byte[] data) throws BadPaddingException, IllegalBlockSizeException, IOException {
        int inputLen = data.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段加密
        while (inputLen - offSet > 0) {
            if (inputLen - offSet > rsaSize.getMaxEncryptBlock()) {
                cache = cipher.doFinal(data, offSet, rsaSize.getMaxEncryptBlock());
            } else {
                cache = cipher.doFinal(data, offSet, inputLen - offSet);
            }
            out.write(cache, 0, cache.length);
            i++;
            offSet = i * rsaSize.getMaxEncryptBlock();
        }
        byte[] encryptedData = out.toByteArray();
        out.close();
        return encryptedData;
    }

}
