package com.security.smith.client;

import java.lang.reflect.Type;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;


class Message {
    static final int PROTOCOL_HEADER_SIZE = 4;
    static final int MAX_PAYLOAD_SIZE = 10240;

    private int operate;
    private JsonElement  data;

    int getOperate() {
        return operate;
    }

    public void setOperate(int operate) {
        this.operate = operate;
    }

    public JsonElement getData() {
        return data;
    }

    public void setData(JsonElement data) {
        this.data = data;
    }
}

