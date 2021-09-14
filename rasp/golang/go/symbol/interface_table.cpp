#include "interface_table.h"
#include "line_table.h"
#include <common/log.h>
#include <common/utils/process.h>
#include <elfio/elfio.hpp>
#include <sys/user.h>

constexpr auto GO_INTERFACE_TABLE = "itablink";

bool CInterfaceTable::load() {
    return load(CPath::getAPPPath());
}

bool CInterfaceTable::load(const std::string &file) {
    CProcessMap processMap;

    if (!CProcess::getFileMemoryBase(getpid(), file, processMap))
        return false;

    return load(file, processMap.start);
}

bool CInterfaceTable::load(const std::string &file, unsigned long base) {
    ELFIO::elfio reader;

    if (!reader.load(file))
        return false;

    auto it = std::find_if(
            reader.sections.begin(),
            reader.sections.end(),
            [](const auto& s) {
                return CStringHelper::findStringIC(s->get_name(), GO_INTERFACE_TABLE);
            });

    if (it == reader.sections.end()) {
        LOG_ERROR("can't find interface table section");
        return false;
    }

    mNumber = (*it)->get_size() / sizeof(go::interface_item **);

    if (reader.get_type() == ET_EXEC) {
        mTable = (go::interface_item **)(*it)->get_address();
        return true;
    }

    std::vector<ELFIO::segment *> loads;

    std::copy_if(
            reader.segments.begin(),
            reader.segments.end(),
            std::back_inserter(loads),
            [](const auto &i){
                return i->get_type() == PT_LOAD;
            });

    auto minElement = std::min_element(
            loads.begin(),
            loads.end(),
            [](const auto &i, const auto &j) {
                return i->get_virtual_address() < j->get_virtual_address();
            });

    mTable = (go::interface_item **)((char *)base + (*it)->get_address() - ((*minElement)->get_virtual_address() & ~(PAGE_SIZE - 1)));

    return true;
}

bool CInterfaceTable::findByFuncName(const char *name, go::interface_item **item) {
    if (mNumber == 0)
        return false;

    auto begin = mTable;
    auto end = begin + mNumber;

    auto it = std::find_if(begin, end, [=](const auto &i) {
        CFunction func = {};

        if (!gLineTable->findFunc((void *)i->func[0], func))
            return false;

        return strcmp(func.getName(), name) == 0;
    });

    if (it == end)
        return false;

    *item = *it;

    return true;
}
