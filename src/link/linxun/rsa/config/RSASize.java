package link.linxun.rsa.config;

/**
 * @author lin-xun
 * @version 2020/4/24 20:44
 */
public enum RSASize {
    MAX_1024(1024, 128, 117),
    MAX_2048(2048, 256, 245),
    MAX_4096(4096, 512, 490);

    RSASize(int initializeLength, int maxDecryptBlock, int maxEncryptBlock) {
        this.initializeLength = initializeLength;
        this.maxDecryptBlock = maxDecryptBlock;
        this.maxEncryptBlock = maxEncryptBlock;
    }

    /**
     * RSA 位数
     */
    private final int initializeLength;
    /**
     * RSA最大解密密文大小
     */
    private final int maxDecryptBlock;
    /**
     * RSA最大加密明文大小
     */
    private final int maxEncryptBlock;

    public int getInitializeLength() {
        return initializeLength;
    }

    public int getMaxDecryptBlock() {
        return maxDecryptBlock;
    }

    public int getMaxEncryptBlock() {
        return maxEncryptBlock;
    }
}