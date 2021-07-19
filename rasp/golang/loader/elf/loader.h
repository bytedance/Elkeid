#ifndef GO_PROBE_LOADER_H
#define GO_PROBE_LOADER_H

#include <string>
#include <elfio/elfio.hpp>

class ELFLoader {
public:
    ELFLoader();

public:
    bool load(const std::string& file);

public:
    void jump(int argc, char **argv, char **env);

private:
    bool loadInterpreter(const char *interpreter);

private:
    unsigned long loadSegments(const ELFIO::elfio &reader);

private:
    unsigned long roundPage(unsigned long address) const;
    unsigned long truncatePage(unsigned long address) const;

private:
    unsigned long mPagesize;

public:
    unsigned long mProgramBase{};
    unsigned long mProgramEntry{};
    unsigned long mProgramHeader{};
    unsigned long mProgramHeaderNum{};
    unsigned long mProgramHeaderSize{};

public:
    unsigned long mInterpreterBase{};
    unsigned long mInterpreterEntry{};
};


#endif //GO_PROBE_LOADER_H
