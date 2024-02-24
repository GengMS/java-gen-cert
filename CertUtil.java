package cn.gengms;

import sun.security.x509.*;
import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.stream.Collectors;

/**
 * @Author: snlh_gms
 * @Date: 2024-2-21 10:01
 * @Description:
 */
public class CertUtil {
    private static final String KEY_PAIR_ALGORITHM = "RSA";
    private static final String P12_ALGORITHM = "SHA1withRSA";
    private static final String P12_SIGN_ALGORITHM = "SHA256withRSA";
    private static final String P12_ENCRYPTION_STANDARD = "PKCS12";

    /**
     * @apiNote 子证书认证
     * @param childPath
     * @param childPassword
     * @param rootPath
     * @param rootPassword
     * @return boolean
     * @author snlh_gms
     * @since  11:53 2024-2-22
     **/
    public static boolean verifyChild(String childPath, String childPassword, String rootPath, String rootPassword) {
        CertificateInfo p12Certificate = getP12Certificate(childPath, childPassword);
        KeyPair rootKeyPair = getP12KeyPair(rootPath, rootPassword);
        return verify(p12Certificate.getPublicKey(), publicKeyToStr(rootKeyPair.getPublic()), p12Certificate.getExtensions().substring(8));
    }

    /**
     * @apiNote 生成P12类型证书
     * @param p12FilePath
     * @param p12Password
     * @param subjectInfo
     * @param issuerInfo
     * @param expireDate
     * @return void
     * @author snlh_gms
     * @since  11:53 2024-2-22
     **/
    public static void GeneratePKCS12(String p12FilePath, String p12Password, CertificateOrganization subjectInfo, CertificateOrganization issuerInfo, Date expireDate){
        // 生成密钥对
        KeyPair keyPair = getKeyPair();
        CertificateInfo certificateInfo = new CertificateInfo();
        certificateInfo.setSubject(subjectInfo);
        certificateInfo.setIssuer(issuerInfo);
        certificateInfo.setExpiryDate(expireDate);
        // 生成证书
        X509CertInfo certInfo = getX509CertInfo(certificateInfo, keyPair);

        //保存到证书文件
        saveCert(p12FilePath, p12Password, certInfo, keyPair);
    }

    /**
     * @apiNote 生成子证书
     * @param type
     * @param childPath
     * @param childPassword
     * @param rootP12CertPath
     * @param rootP12CertPassword
     * @param childInfo
     * @param expireDate
     * @return void
     * @author snlh_gms
     * @since  11:56 2024-2-22
     **/
    public static void generateChildCert(String childPath, String childPassword, String rootP12CertPath, String rootP12CertPassword, CertificateOrganization childInfo, Date expireDate) {
        CertificateInfo rootCertInfo = getP12Certificate(rootP12CertPath, rootP12CertPassword);
        KeyPair childKeyPair = getKeyPair();
        KeyPair rootKeyPair = getP12KeyPair(rootP12CertPath, rootP12CertPassword);
        String rootPrivateKey = privateKeyToStr(rootKeyPair.getPrivate());
        String childPublicKey = publicKeyToStr(childKeyPair.getPublic());
        String signStr = sign(childPublicKey, rootPrivateKey);

        CertificateInfo childCertificateInfo = new CertificateInfo();
        childCertificateInfo.setIssuer(rootCertInfo.getSubject());
        childCertificateInfo.setSubject(childInfo);
        childCertificateInfo.setPassword(childPassword);
        childCertificateInfo.setExtensions(signStr);
        childCertificateInfo.setExpiryDate(expireDate);
        generateChildP12Cert(childKeyPair, childCertificateInfo ,childPath);
    }

    /**
     * @apiNote 获取p12类型证书信息
     * @param filePath
     * @param password
     * @return cn.gengms.CertificateInfo
     * @author snlh_gms
     * @since  11:55 2024-2-22
     **/
    public static CertificateInfo getP12Certificate(String filePath, String password) {
        // 创建KeyStore实例并加载P12证书
        KeyStore keyStore = null;
        try {
            // 加载P12证书为KeyStore实例
            keyStore = KeyStore.getInstance(P12_ENCRYPTION_STANDARD);
            if(password != null){
                keyStore.load(new FileInputStream(filePath), password.toCharArray());
            } else{
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                FileInputStream in1 = new FileInputStream(filePath);
                Certificate c = cf.generateCertificate(in1);
                X509Certificate x509Cert = (X509Certificate) c;
                return getCertificateInfo(new File(filePath).getName(), x509Cert);
            }
            // 获取证书中的所有证书和私钥
            Enumeration<String> aliasEnum = keyStore.aliases();
            while (aliasEnum.hasMoreElements()) {
                String alias = aliasEnum.nextElement();
                Certificate certificate = keyStore.getCertificate(alias);

                if (certificate instanceof X509Certificate) {
                    return getCertificateInfo(new File(filePath).getName(), (X509Certificate) certificate);
                } else {
                    throw new RuntimeException("证书非X509证书，暂不支持");
                }
            }
        } catch (CertificateException | KeyStoreException | IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return new CertificateInfo();
    }

   /**
    * @apiNote 签名
    * @param content
    * @param privateKey
    * @return java.lang.String
    * @author snlh_gms
    * @since  11:55 2024-2-22
    **/
    public static String sign(String content, String privateKey) {
        Signature privateSignature = null;
        try {
            privateSignature = Signature.getInstance(P12_SIGN_ALGORITHM);
            privateSignature.initSign(loadPrivateKey(privateKey, "RSA"));
            byte[] data = content.getBytes();
            privateSignature.update(data);
            byte[] signatureBytes = privateSignature.sign();
            return Base64.getEncoder().encodeToString(signatureBytes);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * @apiNote 验签
     * @param content
     * @param publicKey
     * @param signStr
     * @return boolean
     * @author snlh_gms
     * @since  11:55 2024-2-22
     **/
    public static boolean verify(String content, String publicKey, String signStr) {
        Signature p12PublicVerify = null;
        try {
            p12PublicVerify = Signature.getInstance(P12_SIGN_ALGORITHM);
            p12PublicVerify.initVerify(loadPublicKey(publicKey, "RSA"));
            p12PublicVerify.update(content.getBytes());
            byte[] signBytes = Base64.getDecoder().decode(signStr);
            return p12PublicVerify.verify(signBytes);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    public static PrivateKey loadPrivateKey(String content, String algorithm) {
        // 移除掉Pem文件的开头和结尾 转换成私钥
        String privateKeyPem = content.replaceAll("-----BEGIN PRIVATE KEY-----", "")
                .replaceAll("-----END PRIVATE KEY-----", "").replaceAll("\n", "");

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyPem));
        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        try {
            return keyFactory.generatePrivate(keySpec);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        throw new RuntimeException();
    }

    public static PublicKey loadPublicKey(String publicKeyString, String algorithm) {
        PublicKey publicKey = null;
        try {
            X509EncodedKeySpec bobPubKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyString));
            KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
            publicKey = keyFactory.generatePublic(bobPubKeySpec);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return publicKey;
    }

    public static KeyPair getP12KeyPair(String certPath, String p12Password) {
        PrivateKey privateKey = null;
        PublicKey publicKey = null;
        try {
            FileInputStream fis = new FileInputStream(certPath);
            KeyStore ks = KeyStore.getInstance(P12_ENCRYPTION_STANDARD);
            ks.load(fis, p12Password.toCharArray());
            fis.close();

            String alias = ks.aliases().nextElement();
            privateKey = (PrivateKey) ks.getKey(alias, p12Password.toCharArray());
            publicKey = ks.getCertificate(alias).getPublicKey();
            return new KeyPair(publicKey, privateKey);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * @apiNote 生成p12类型子证书
     * @param childKeyPair
     * @param childCertificateInfo
     * @param childPath
     * @return void
     * @author snlh_gms
     * @since  11:54 2024-2-22
     **/
    private static void generateChildP12Cert(KeyPair childKeyPair, CertificateInfo childCertificateInfo, String childPath) {
        X509CertInfo certInfo = getX509CertInfo(childCertificateInfo, childKeyPair);
        saveCert(childPath, childCertificateInfo.getPassword(), certInfo, childKeyPair);
    }

    /**
     * @apiNote 解析SHA256证书指纹
     * @param certificate
     * @return java.lang.String
     * @author snlh_gms
     * @since  11:54 2024-2-22
     **/
    private static String getSHA256Fingerprint(X509Certificate certificate) throws NoSuchAlgorithmException, CertificateEncodingException {
        byte[] encoded = certificate.getEncoded();
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(encoded);
        return bytesToHex(hash);
    }

    /**
     * @apiNote 解析SHA1证书指纹
     * @param certificate
     * @return java.lang.String
     * @author snlh_gms
     * @since  11:54 2024-2-22
     **/
    private static String getSHA1Fingerprint(X509Certificate certificate) throws NoSuchAlgorithmException, CertificateEncodingException {
        byte[] encoded = certificate.getEncoded();
        MessageDigest digest = MessageDigest.getInstance("SHA-1");
        byte[] hash = digest.digest(encoded);
        return bytesToHex(hash);
    }

    private static void saveCert(String p12FilePath, String p12Password, X509CertInfo certInfo, KeyPair keyPair){
        try{
            fileCreate(p12FilePath);
            boolean p12Type = new File(p12FilePath).getName().endsWith("p12");
            X509CertImpl cert = new X509CertImpl(certInfo);
            cert.sign(keyPair.getPrivate(), P12_ALGORITHM);
            if(!p12Type){
                new FileOutputStream(p12FilePath).write(cert.getEncoded());
                return;
            }
            // 创建KeyStore并保存证书
            KeyStore keyStore = KeyStore.getInstance(P12_ENCRYPTION_STANDARD);
            keyStore.load(null, null);
            keyStore.setKeyEntry(certInfo.getName(), keyPair.getPrivate(), p12Password.toCharArray(), new X509Certificate[]{cert});
            FileOutputStream fos = new FileOutputStream(p12FilePath);
            keyStore.store(fos, p12Password.toCharArray());
            fos.close();
        }catch (Exception e){
            e.printStackTrace();
            throw new RuntimeException("保存证书失败");
        }
    }

    private static X509CertInfo getX509CertInfo(CertificateInfo certificateInfo, KeyPair keyPair) {
        try {
            CertificateOrganization subject = certificateInfo.getSubject();
            CertificateOrganization issuer = certificateInfo.getIssuer();
            X509CertInfo certInfo = new X509CertInfo();
            certInfo.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
            certInfo.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(new Random().nextInt() & 0x7fffffff));
            certInfo.set(X509CertInfo.SUBJECT, getX500NameEntity(subject));
            certInfo.set(X509CertInfo.ISSUER, getX500NameEntity(issuer));
            certInfo.set(X509CertInfo.VALIDITY, new CertificateValidity(new Date(), certificateInfo.getExpiryDate()));
            certInfo.set(X509CertInfo.KEY, new CertificateX509Key(keyPair.getPublic()));
            certInfo.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(AlgorithmId.get(P12_ALGORITHM)));
            if(certificateInfo.getExtensions() != null){
                String extensions = certificateInfo.getExtensions();
                CertificateExtensions certificateExtensions = new CertificateExtensions();
                certificateExtensions.set(SubjectKeyIdentifierExtension.NAME, new SubjectKeyIdentifierExtension(extensions.getBytes()));
                certInfo.set(X509CertInfo.EXTENSIONS, certificateExtensions);
            }
            return certInfo;
        }catch (Exception e){
            e.printStackTrace();
            throw new RuntimeException("组装证书信息失败");
        }
    }

    //---------------------------公用部分 START-----------------------------------------------------------
    /**
     * @apiNote 获取证书文件信息ByX509Certificate
     * @param certificateFileName
     * @param x509Certificate
     * @return cn.gengms.CertificateInfo
     * @author snlh_gms
     * @since  10:25 2024-2-22
     **/
    private static CertificateInfo getCertificateInfo(String certificateFileName, X509Certificate x509Certificate) throws NoSuchAlgorithmException, CertificateEncodingException {
        CertificateInfo vo = new CertificateInfo();
        vo.setFileName(certificateFileName); // 证书文件名
        vo.setSubject(parseCertificateSubjectIssuerInfo(x509Certificate.getSubjectDN())); // 颁发对象
        vo.setIssuer(parseCertificateSubjectIssuerInfo(x509Certificate.getIssuerDN())); // 颁发者
        vo.setIssueDate(new Date(x509Certificate.getNotBefore().getTime()));  // 颁发日期
        vo.setExpiryDate(new Date(x509Certificate.getNotAfter().getTime())); // 截至日期
        vo.setSha256(getSHA256Fingerprint(x509Certificate));  // SHA-256指纹
        vo.setSha1(getSHA1Fingerprint(x509Certificate));  // SHA-256指纹
        vo.setPublicKey(publicKeyToStr(x509Certificate.getPublicKey()));
        Set<String> nonCriticalExtensionOIDs = x509Certificate.getNonCriticalExtensionOIDs();
        if(nonCriticalExtensionOIDs != null && nonCriticalExtensionOIDs.size() > 0){
            String extensionValue = "";
            for (String nonCriticalExtensionOID : nonCriticalExtensionOIDs) {
                extensionValue = new String(x509Certificate.getExtensionValue(nonCriticalExtensionOID));
                break;
            }
            vo.setExtensions(extensionValue);
        }
        return vo;
    }
    /**
     * @apiNote 解密证书组织信息
     * @param certificate
     * @return cn.gengms.CertificateOrganization
     * @author snlh_gms
     * @since  10:23 2024-2-22
     **/
    private static CertificateOrganization parseCertificateSubjectIssuerInfo(Principal certificate) {
        List<String> subjectDn = Arrays.asList(certificate.getName().split(","));
        subjectDn = subjectDn.stream()
                .map(s -> s.split("=", 2)[1]) // 使用split方法分割字符串，并只取等号后面的部分
                .collect(Collectors.toList()); // 将结果收集到一个新的列表中
        String publicName = subjectDn.get(0); // 公用名(CN)通常是第一个元素
        String organization = subjectDn.get(1); // 组织(O)通常是第二个元素
        String organizationUnit = subjectDn.size() > 2 ? subjectDn.get(2) : null; // 组织单位(OU)通常是第三个元素
        String location = subjectDn.size() > 3 ? subjectDn.get(3) : null; // 地址信息(L)通常是第四个元素
        String state = subjectDn.size() > 4 ? subjectDn.get(4) : null; // 省份(ST)通常是第五个元素
        String country = subjectDn.size() > 5 ? subjectDn.get(5) : null; // 国家(C)通常是第六个元素
        return new CertificateOrganization(subjectDn.get(0), subjectDn.get(1), organizationUnit, location, state, country);
    }

    /**
     * @apiNote 获取证书主体信息实体类
     * @param info
     * @return sun.security.x509.X500Name
     * @author snlh_gms
     * @since  10:19 2024-2-22
     **/
    private static X500Name getX500NameEntity(CertificateOrganization info) throws IOException {
        String x500NameStr = "CN=" + info.getPublicName() + ", O=" + info.getOrganization() + ", OU=" + info.getOrganizationUnit() + ", L=" + info.getLocation() + ", ST=" + info.getState() + ", C=" + info.getCountry();
        return new X500Name(x500NameStr);
    }

    /**
     * @apiNote 生成密钥对
     * @return java.security.KeyPair
     * @author snlh_gms
     * @since  10:14 2024-2-22
     **/
    private static KeyPair getKeyPair(){
        try {
            /*
              目前了解到支持的算法:
              DiffieHellman （ DiffieHellman ）
              DSA （ DSA ）
              RSA （ RSA ）
             */
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_PAIR_ALGORITHM);
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        }catch (Exception e){
            e.printStackTrace();
            throw new RuntimeException("获取密钥对失败");
        }
    }

    /**
     * @apiNote 创建文件
     * @param filepath
     * @return void
     * @author snlh_gms
     * @since  10:09 2024-2-22
     **/
    private static void fileCreate(String filepath) {
        try {

            File file = new File(filepath);
            if (!file.getParentFile().exists()) {
                file.getParentFile().mkdirs();
            }
            if (!file.exists()) {
                file.createNewFile();
            }
        } catch (Exception e) {
            throw new RuntimeException("创建文件出错！");

        }
    }

    /**
     * @apiNote 字节转Hex
     * @param bytes
     * @return java.lang.String
     * @author snlh_gms
     * @since  10:10 2024-2-22
     **/
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * @apiNote 私钥转Base64字符串
     * @param privateKey
     * @return java.lang.String
     * @author snlh_gms
     * @since  10:11 2024-2-22
     **/
    private static String privateKeyToStr(PrivateKey privateKey) {
        return new String(Base64.getEncoder().encode(privateKey.getEncoded()));
    }

    /**
     * @apiNote 公钥转Base64字符串
     * @param publicKey
     * @return java.lang.String
     * @author snlh_gms
     * @since  10:11 2024-2-22
     **/
    private static String publicKeyToStr(PublicKey publicKey) {
        return new String(Base64.getEncoder().encode(publicKey.getEncoded()));
    }
    //---------------------------公用部分 END-------------------------------------------------------------
}