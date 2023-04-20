package com.security.smith.client;

import com.security.smith.client.message.*;

public interface MessageHandler {
    void onConfig(String config);
    void onControl(int action);
    void onDetect();
    void onFilter(FilterConfig config);
    void onBlock(BlockConfig config);
    void onLimit(LimitConfig config);
    void onPatch(PatchConfig config);
}
