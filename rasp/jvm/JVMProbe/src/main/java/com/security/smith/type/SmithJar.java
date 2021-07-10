package com.security.smith.type;

public class SmithJar {
    @Override
    public int hashCode() {
        return path.hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }

        if (obj instanceof SmithJar) {
            return ((SmithJar) obj).getPath().equals(path);
        }

        return false;
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public String getImplementationTitle() {
        return implementationTitle;
    }

    public void setImplementationTitle(String implementationTitle) {
        this.implementationTitle = implementationTitle;
    }

    public String getImplementationVersion() {
        return implementationVersion;
    }

    public void setImplementationVersion(String implementationVersion) {
        this.implementationVersion = implementationVersion;
    }

    public String getSpecificationTitle() {
        return specificationTitle;
    }

    public void setSpecificationTitle(String specificationTitle) {
        this.specificationTitle = specificationTitle;
    }

    public String getSpecificationVersion() {
        return specificationVersion;
    }

    public void setSpecificationVersion(String specificationVersion) {
        this.specificationVersion = specificationVersion;
    }

    private String path;
    private String implementationTitle;
    private String implementationVersion;
    private String specificationTitle;
    private String specificationVersion;
}
