package cn.gengms;

import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;

/**
 * @Author: snlh_gms
 * @Date: 2024-2-22 11:30
 * @Description:
 */
public class CertUtilTest {
    private static final String password = "200303";
    public static void main(String[] args) {
        testGenP12();
        testGenP12Child();
        testVerifyChild();
        testGetP12Info();
    }
    static void testVerifyChild(){
        System.out.println(CertUtil.verifyChild("E:\\geng_test\\child-1.crt", null, "E:\\geng_test\\root-1.p12", password));
//        System.out.println(CertUtil.verifyChild("E:\\geng_test\\child.p12", password, "E:\\geng_test\\root.p12", password));
    }
    static void testGenP12(){
        CertificateOrganization issuer = new CertificateOrganization();
        issuer.setPublicName("org.apache");
        issuer.setCountry("UC");
        issuer.setState("UC.A");
        issuer.setLocation("UC.A.B");
        issuer.setOrganization("007");
        issuer.setOrganizationUnit("007.die");
        CertificateOrganization subject = new CertificateOrganization();
        subject.setPublicName("cn.gengms");
        subject.setCountry("china");
        subject.setState("HeBei");
        subject.setLocation("ShiJiaZhuang");
        subject.setOrganization("996");
        subject.setOrganizationUnit("996.icu");
        CertUtil.GeneratePKCS12("E:\\geng_test\\root-1.p12", password, subject, issuer, new Date());
    }
    static void testGenP12Child(){
        CertificateOrganization childInfo = new CertificateOrganization();
        childInfo.setPublicName("cn.gengms.child");
        childInfo.setCountry("china");
        childInfo.setState("HeBei");
        childInfo.setLocation("ShiJiaZhuang");
        childInfo.setOrganization("996.child");
        childInfo.setOrganizationUnit("996.icu.child");
        CertUtil.generateChildCert( "E:\\geng_test\\child-1.crt", null, "E:\\geng_test\\root-1.p12", password, childInfo, new Date());
    }
    static void testGetP12Info(){
        System.out.println(CertUtil.getP12Certificate("E:\\geng_test\\child-1.crt", null));
    }
}