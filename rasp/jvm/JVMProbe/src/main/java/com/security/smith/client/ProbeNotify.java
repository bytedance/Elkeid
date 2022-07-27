package com.security.smith.client;

import com.security.smith.type.SmithBlock;
import com.security.smith.type.SmithFilter;
import com.security.smith.type.SmithLimit;
import com.security.smith.type.SmithPatch;

public interface ProbeNotify {
    void onConnect();
    void onDisconnect();
    void onConfig(String config);
    void onControl(int action);
    void onDetect();
    void onFilter(SmithFilter[] filters);
    void onBlock(SmithBlock[] blocks);
    void onLimit(SmithLimit[] limits);
    void onPatch(SmithPatch[] patches);
}
