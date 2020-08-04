package link.linxun.rsa.config;

/**
 * @author lin-xun
 * @version 2020/4/24 20:58
 */
public enum RSAPadding {
    //加密填充方式
    RSA_ECB_PKCS1("RSA/ECB/PKCS1Padding");

    RSAPadding(String padding) {
        this.padding = padding;
    }

    private final String padding;

    public String getPadding() {
        return padding;
    }
}
