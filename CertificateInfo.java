package cn.gengms;

import java.util.Date;

/**
 * @Author: snlh_gms
 * @Date: 2024-2-22 10:06
 * @Description:
 */
public class CertificateInfo {
    /**
     * 证书文件名
     */
    private String fileName;
    /**
     * 颁发对象
     */
    private CertificateOrganization subject;
    /**
     * 颁发者
     */
    private CertificateOrganization issuer;
    /**
     * 颁发日期
     */
    private Date issueDate;
    /**
     * 截至日期
     */
    private Date expiryDate;
    /**
     * SHA-256指纹
     */
    private String sha256;
    /**
     * SHA-1指纹
     */
    private String sha1;
    /**
     * 公钥
     */
    private String publicKey;
    /**
     * p12证书对应的密码
     */
    private String password;

    /**
     * 拓展签名
     */
    private String extensions;

    public String getExtensions() {
        return extensions;
    }

    public void setExtensions(String extensions) {
        this.extensions = extensions;
    }
    
    @Override
    public String toString() {
        return "CertificateInfo{" +
                "fileName='" + fileName + '\'' +
                ", issueTarget=" + subject +
                ", issuer=" + issuer +
                ", issueDate=" + issueDate +
                ", expiryDate=" + expiryDate +
                ", sha256='" + sha256 + '\'' +
                ", sha1='" + sha1 + '\'' +
                ", publicKey='" + publicKey + '\'' +
                ", password='" + password + '\'' +
                '}';
    }

    public CertificateInfo(String fileName, CertificateOrganization issueTarget, CertificateOrganization issuer, Date issueDate, Date expiryDate, String sha256, String sha1, String publicKey, String password) {
        this.fileName = fileName;
        this.subject = issueTarget;
        this.issuer = issuer;
        this.issueDate = issueDate;
        this.expiryDate = expiryDate;
        this.sha256 = sha256;
        this.sha1 = sha1;
        this.publicKey = publicKey;
        this.password = password;
    }

    public CertificateInfo() {
    }

    public String getFileName() {
        return fileName;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    public CertificateOrganization getSubject() {
        return subject;
    }

    public void setSubject(CertificateOrganization subject) {
        this.subject = subject;
    }

    public CertificateOrganization getIssuer() {
        return issuer;
    }

    public void setIssuer(CertificateOrganization issuer) {
        this.issuer = issuer;
    }

    public Date getIssueDate() {
        return issueDate;
    }

    public void setIssueDate(Date issueDate) {
        this.issueDate = issueDate;
    }

    public Date getExpiryDate() {
        return expiryDate;
    }

    public void setExpiryDate(Date expiryDate) {
        this.expiryDate = expiryDate;
    }

    public String getSha256() {
        return sha256;
    }

    public void setSha256(String sha256) {
        this.sha256 = sha256;
    }

    public String getSha1() {
        return sha1;
    }

    public void setSha1(String sha1) {
        this.sha1 = sha1;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}