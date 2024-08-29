package com.security.smith.rulemgr;

public class StackRule {
    public Integer ruleId;
    public Integer ruleType;
    public Integer ruleVer;
    public StackItem[] blackItems;
    public StackItem[] whiteItems;

    public void setRuleId(Integer ruleId) {
        this.ruleId = ruleId;
    }

    public Integer getRuleId() {
        return this.ruleId;
    }

    public void setRuleType(Integer ruleType) {
        this.ruleType = ruleType;
    }

    public Integer getRuleType() {
        return this.ruleType;
    }

    public void setRuleVer(Integer ruleVer) {
        this.ruleVer = ruleVer;
    }

    public Integer getRuleVer() {
        return this.ruleVer;
    }

    public void setBlackItems(StackItem[] blackItems) {
        this.blackItems = blackItems;
    }

    public StackItem[] getBlackItems() {
        return this.blackItems;
    }

    public void setWhiteItems(StackItem[] whiteItems) {
        this.whiteItems = whiteItems;
    }

    public StackItem[] getWhiteItems() {
        return this.whiteItems;
    }

    public void addBlackItems(StackItem stackItem) {
        if (blackItems== null) {
            blackItems = new StackItem[1];
            blackItems[0] = stackItem;
        } else {
            StackItem[] temp = new StackItem[blackItems.length + 1];
            for (int i = 0; i < blackItems.length; i++) {
                temp[i] = blackItems[i];
            }
            temp[blackItems.length] = stackItem;
            blackItems = temp;
        }
    }

    public void addWhiteItems(StackItem stackItem) {
        if (whiteItems== null) {
            whiteItems = new StackItem[1];
            whiteItems[0] = stackItem;
        } else {
            StackItem[] temp = new StackItem[whiteItems.length + 1];
            for (int i = 0; i < whiteItems.length; i++) {
                temp[i] = whiteItems[i];
            }
            temp[whiteItems.length] = stackItem;
            whiteItems = temp;
        }
    }

    public void removeBlackStackRule() {
        if (blackItems != null) {
            for (int i = 0; i < blackItems.length; i++) {
                blackItems[i] = null;
            }
            blackItems = null;
        }
    }

    public void removeWhiteStackRule() {
        if (whiteItems!= null) {
            for (int i = 0; i < whiteItems.length; i++) {
                whiteItems[i] = null;
            }
            whiteItems = null;
        }
    }

    public void clear() {
        this.ruleId = null;
        this.ruleType = null;
        this.ruleVer = null;
        removeWhiteStackRule();
        removeBlackStackRule();
    }
}

