#include "build_info.h"
#include <common/log.h>
#include <common/utils/path.h>
#include <common/utils/process.h>

constexpr auto GO_BUILD_INFO = "buildinfo";
constexpr auto GO_BUILD_INFO_MAGIC = "\xff Go buildinf:";
constexpr auto GO_BUILD_VERSION_OFFSET = 16;

bool CBuildInfo::load(const std::string &file) {
    ELFIO::elfio reader;

    if (!reader.load(file)) {
        LOG_ERROR("open elf failed: %s", file.c_str());
        return false;
    }

    auto it = std::find_if(
            reader.sections.begin(),
            reader.sections.end(),
            [](const auto& s) {
                return CStringHelper::findStringIC(s->get_name(), GO_BUILD_INFO);
            });

    if (it == reader.sections.end()) {
        LOG_ERROR("can't find go build info section");
        return false;
    }

    auto data = (char *)(*it)->get_address();
    auto magicSize = strlen(GO_BUILD_INFO_MAGIC);

    if (reader.get_type() != ET_EXEC) {
        CProcessMap processMap;

        if (!CProcess::getFileMemoryBase(getpid(), file, processMap))
            return false;

        auto sit = std::find_if(
                reader.segments.begin(),
                reader.segments.end(),
                [](const auto& s) {
                    return s->get_type() == PT_LOAD;
                });

        if (sit == reader.segments.end())
            return false;

        data += processMap.start - (*sit)->get_virtual_address();
    }

    if (memcmp(data, GO_BUILD_INFO_MAGIC, magicSize) != 0) {
        LOG_ERROR("go build info magic error");
        return false;
    }

    mPtrSize = (unsigned char)data[magicSize];
    mEndian = (go::endian)data[magicSize + 1];

    auto buildVersion = *(go::string **)&data[GO_BUILD_VERSION_OFFSET];
    auto modInfo = *(go::string **)&data[GO_BUILD_VERSION_OFFSET + mPtrSize];

    mVersion = buildVersion->toSTDString();

    if (modInfo->empty()) {
        LOG_INFO("module info empty");
        return true;
    }

    return readModuleInfo(modInfo);
}

bool CBuildInfo::load() {
    return load(CPath::getAPPPath());
}

bool CBuildInfo::readModuleInfo(const go::string *modInfo) {
    if (modInfo->length < 32) {
        LOG_ERROR("module info invalid");
        return false;
    }

    auto info = std::string(modInfo->data + 16, modInfo->length - 32);
    auto mods = CStringHelper::split(info, '\n');

    auto readEntry = [](const std::string &m, CModule &module) {
        auto tokens = CStringHelper::split(m, '\t');

        if (tokens.size() < 3)
            return false;

        module.path = tokens[1];
        module.version = tokens[2];

        if (tokens.size() == 4)
            module.sum = tokens[3];

        return true;
    };

    for (const auto &m: mods) {
        if (CStringHelper::startsWith(m, "path")) {
            auto tokens = CStringHelper::split(m, '\t');

            if (tokens.size() != 2)
                continue;

            mModuleInfo.path = tokens[1];
        } else if (CStringHelper::startsWith(m, "mod")) {
            CModule module = {};

            if (!readEntry(m, module))
                continue;

            mModuleInfo.main = module;
        } else if (CStringHelper::startsWith(m, "dep")) {
            CModule module = {};

            if (!readEntry(m, module))
                continue;

            mModuleInfo.deps.push_back(module);
        } else if (CStringHelper::startsWith(m, "=>")) {
            CModule module = {};

            if (!readEntry(m, module))
                continue;

            mModuleInfo.deps.back().replace = new CModule(module);
        }
    }

    return true;
}
