package com.security.smith.type;

import java.util.List;

public class SmithClass {
    private String name;
    private int id;
    private List<SmithMethod> methods;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public List<SmithMethod> getMethods() {
        return methods;
    }

    public void setMethods(List<SmithMethod> methods) {
        this.methods = methods;
    }

    public void clear() {
        methods.clear();
    }
}
