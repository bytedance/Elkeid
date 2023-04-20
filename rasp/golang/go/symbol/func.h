#ifndef GO_PROBE_FUNC_H
#define GO_PROBE_FUNC_H

#include <cstdint>
#include <iterator>

struct FuncEntry {
    uintptr_t entry;
    unsigned long offset;
};

class FuncTablePtr {
public:
    using difference_type = std::ptrdiff_t;
    using value_type = FuncEntry;
    using pointer = value_type*;
    using reference = value_type&;
    using iterator_category = std::random_access_iterator_tag;

public:
    explicit FuncTablePtr(const char *table, unsigned int size);

public:
    FuncTablePtr &operator++();
    FuncTablePtr &operator--();
    FuncTablePtr &operator+=(std::ptrdiff_t offset);
    FuncTablePtr operator+(unsigned int offset);
    FuncTablePtr operator-(unsigned int offset);
    std::ptrdiff_t operator-(const FuncTablePtr &ptr);

public:
    const FuncEntry &operator*();
    const FuncEntry *operator->();
    FuncEntry operator[](unsigned int index);

public:
    bool operator==(const FuncTablePtr &ptr);
    bool operator!=(const FuncTablePtr &ptr);

private:
    FuncEntry mEntry{};

private:
    unsigned int mSize;
    const char *mTable;
};

class LineTable;

class Func {
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
    const LineTable *mLineTable;
};

#endif //GO_PROBE_FUNC_H
