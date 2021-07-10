#include "workspace.h"
#include <sys/mman.h>

void *new_workspace() {
    return gWorkspace->acquire();
}

void free_workspace(void *ptr) {
    gWorkspace->release(ptr);
}

bool CWorkspace::init() {
    for (int i = 0; i < WORKSPACE_COUNT - 1; i++) {
        void *workspace = mmap(
                nullptr,
                WORKSPACE_SIZE,
                PROT_READ | PROT_WRITE,
                MAP_ANONYMOUS | MAP_PRIVATE,
                -1,
                0);

        if (workspace == MAP_FAILED)
            return false;

        mWorkspaces.enqueue(workspace);
    }

    return true;
}

bool CWorkspace::destroy() {
    auto size = mWorkspaces.size();

    for (int i = 0; i < size; i++) {
        void *workspace = nullptr;

        if (!mWorkspaces.dequeue(workspace))
            continue;

        if (!workspace)
            continue;

        munmap(workspace, WORKSPACE_SIZE);
    }

    return true;
}

void *CWorkspace::acquire() {
    if (mWorkspaces.empty())
        return nullptr;

    void *workspace = nullptr;

    if (!mWorkspaces.dequeue(workspace))
        return nullptr;

    return workspace;
}

void CWorkspace::release(void *ptr) {
    mWorkspaces.enqueue(ptr);
}
