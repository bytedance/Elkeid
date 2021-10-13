package com.security.smith.client;

import com.security.smith.type.SmithBlock;
import com.security.smith.type.SmithFilter;

public interface ProbeNotify {
    void onConnect();
    void onDisconnect();
    void onConfig(String config);
    void onControl(int action);
    void onDetect();
    void onFilter(SmithFilter[] filters);
    void onBlock(SmithBlock[] blocks);
}
