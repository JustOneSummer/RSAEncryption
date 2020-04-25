package link.linxun.rsa.config;

/**
 * @author lin-xun
 * @version 2020/4/24 20:58
 */
public enum RSAPadding {
//    RSA_ECC_OAEP_SHA_256("RSA/ECB/OAEPWithSHA-256AndMGF1Padding"),
//    RSA_ECC_OAEP_MD5("RSA/ECB/OAEPWithMD5AndMGF1Padding"),
//    RSA_ECB_OAEP_SHA1("RSA/ECB/OAEPWithSHA1AndMGF1Padding"),
//RSA_ECB_OAEP("RSA/ECB/OAEPPadding"),
    RSA_ECB_PKCS1("RSA/ECB/PKCS1Padding"),
    RSA_DEFAULT("RSA");

    RSAPadding(String padding) {
        this.padding = padding;
    }

    private final String padding;

    public String getPadding() {
        return padding;
    }
}
