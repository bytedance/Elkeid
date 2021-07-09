#ifndef GO_PROBE_WORKSPACE_H
#define GO_PROBE_WORKSPACE_H

#include <sys/user.h>
#include <common/singleton.h>
#include <common/utils/circular_buffer.h>

constexpr auto WORKSPACE_SIZE = PAGE_SIZE * 16;
constexpr auto WORKSPACE_COUNT = 20;

extern "C" {
void *new_workspace();
void free_workspace(void *ptr);
}

class CWorkspace {
#define gWorkspace SINGLETON_(CWorkspace)
public:
    bool init();
    bool destroy();

public:
    void *acquire();
    void release(void *ptr);

private:
    CCircularBuffer<void *, WORKSPACE_COUNT> mWorkspaces;
};

#endif //GO_PROBE_WORKSPACE_H
