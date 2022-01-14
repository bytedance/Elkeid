#ifndef GO_PROBE_FUNC_H
#define GO_PROBE_FUNC_H

#include <cstdint>
#include <iterator>

struct CFuncEntry {
    uintptr_t entry;
    unsigned long offset;
};

class CFuncTablePtr {
public:
    using difference_type = std::ptrdiff_t;
    using value_type = CFuncEntry;
    using pointer = value_type*;
    using reference = value_type&;
    using iterator_category = std::random_access_iterator_tag;

public:
    explicit CFuncTablePtr(const char *table, unsigned int size);

public:
    CFuncTablePtr &operator++();
    CFuncTablePtr &operator--();
    CFuncTablePtr &operator+=(std::ptrdiff_t offset);
    CFuncTablePtr operator+(unsigned int offset);
    CFuncTablePtr operator-(unsigned int offset);
    std::ptrdiff_t operator-(const CFuncTablePtr &ptr);

public:
    const CFuncEntry &operator*();
    const CFuncEntry *operator->();
    CFuncEntry operator[](unsigned int index);

public:
    bool operator==(const CFuncTablePtr &ptr);
    bool operator!=(const CFuncTablePtr &ptr);

private:
    CFuncEntry mEntry{};

private:
    unsigned int mSize;
    const char *mTable;
};

class CLineTable;

class CFunc {
public:
    uintptr_t getEntry() const;
    const char *getName() const;

public:
    int getFrameSize(uintptr_t pc) const;
    int getSourceLine(uintptr_t pc) const;
    const char *getSourceFile(uintptr_t pc) const;

public:
    bool isStackTop() const;

private:
    unsigned int field(unsigned int n) const;

private:
    unsigned int getNameOffset() const;
    unsigned int getPCSp() const;
    unsigned int getPCFile() const;
    unsigned int getPCLine() const;
    unsigned int getCuOffset() const;

public:
    const char *mFuncData;
    const CLineTable *mLineTable;
};

#endif //GO_PROBE_FUNC_H
