package com.security.smith.client.message;

import java.net.URL;

public class Patch {
    private String className;
    private URL url;

    public String getClassName() {
        return className;
    }

    public void setClassName(String className) {
        this.className = className;
    }

    public URL getUrl() {
        return url;
    }

    public void setUrl(URL url) {
        this.url = url;
    }
}
