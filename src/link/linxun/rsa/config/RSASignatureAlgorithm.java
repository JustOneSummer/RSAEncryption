package link.linxun.rsa.config;

/**
 * @author lin-xun
 * @version 2020/4/24 21:24
 */
public enum RSASignatureAlgorithm {
    RSA_MD5("MD5withRSA"),
    RSA_SHA_256("SHA256withRSA"),
    RSA_SHA1("SHA1withRSAandMGF1"),
    RSA_SHA1_PSS("SHA1withRSA/PSS");

    RSASignatureAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    private final String algorithm;

    public String getAlgorithm() {
        return algorithm;
    }
}
