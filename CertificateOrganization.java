package cn.gengms;

/**
 * @Author: snlh_gms
 * @Date: 2024-2-22 10:05
 * @Description:
 */
public class CertificateOrganization {
    /*
     * 公用名(CN)
     */
    private String publicName;
    /**
     * 组织(O)
     */
    private String organization;
    /**
     * 组织单位(OU)
     */
    private String organizationUnit;
    /**
     * 地点，通常用于表示组织的位置信息
     */
    private String location;
    /**
     * 即州或省份，用于描述地理位置中的行政区域
     */
    private String state;
    /**
     * 即国家，用于描述地理位置中的国家信息
     */
    private String country;

    public CertificateOrganization() {
    }

    public CertificateOrganization(String publicName, String organization, String organizationUnit, String location, String state, String country) {
        this.publicName = publicName;
        this.organization = organization;
        this.organizationUnit = organizationUnit;
        this.location = location;
        this.state = state;
        this.country = country;
    }

    public String getPublicName() {
        return publicName;
    }

    public void setPublicName(String publicName) {
        this.publicName = publicName;
    }

    public String getOrganization() {
        return organization;
    }

    public void setOrganization(String organization) {
        this.organization = organization;
    }

    public String getOrganizationUnit() {
        return organizationUnit;
    }

    public void setOrganizationUnit(String organizationUnit) {
        this.organizationUnit = organizationUnit;
    }

    public String getLocation() {
        return location;
    }

    public void setLocation(String location) {
        this.location = location;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getCountry() {
        return country;
    }

    public void setCountry(String country) {
        this.country = country;
    }

    @Override
    public String toString() {
        return "CertificateOrganization{" +
                "publicName='" + publicName + '\'' +
                ", organization='" + organization + '\'' +
                ", organizationUnit='" + organizationUnit + '\'' +
                ", location='" + location + '\'' +
                ", state='" + state + '\'' +
                ", country='" + country + '\'' +
                '}';
    }
}