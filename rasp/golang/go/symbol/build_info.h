#ifndef GO_PROBE_BUILD_INFO_H
#define GO_PROBE_BUILD_INFO_H

#include <client/smith_message.h>
#include <string>
#include <elfio/elfio.hpp>
#include <go/type/basic.h>
#include <list>
#include <vector>
#include <zero/singleton.h>

class BuildInfo {
#define gBuildInfo zero::Singleton<BuildInfo>::getInstance()
public:
    bool load();
    bool load(const std::string& file);
    bool load(const std::string& file, unsigned long base);

private:
    bool readModuleInfo(const go::string &info);

public:
    go::endian mEndian;
    unsigned long mPtrSize;

public:
    bool mRegisterBased{false};

public:
    std::string mVersion;
    ModuleInfo mModuleInfo;
};


#endif //GO_PROBE_BUILD_INFO_H
