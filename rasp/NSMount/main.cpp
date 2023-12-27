#include <zero/log.h>
#include <zero/cmdline.h>
#include <sys/mount.h>

enum FSType {
    Overlay,
    devicemapper
};

std::string find_rootfs_overlay(const std::string& workdir) {
    std::filesystem::path mountinfo_path = std::filesystem::path("/proc/mounts");
    std::ifstream stream_path(mountinfo_path);

    if (!stream_path.is_open()) {
        LOG_ERROR("failed to open %s information[%d]", mountinfo_path.u8string().c_str(), stream_path.rdstate());
        return "";
    }

    std::string line_root;
    std::string rootdir;

     while (std::getline(stream_path, line_root)) {
        std::vector<std::string> tokens = zero::strings::split(line_root, " ", 5);

        if (tokens.size() != 6)
            continue;

        if (tokens[3].find(workdir) != std::string::npos) {
            rootdir = tokens[1];
            break;
        }
    }
    return rootdir;
}

std::string find_rootfs_devicemapper(const std::string& workdir) {
    std::filesystem::path mountinfo_path = std::filesystem::path("/proc/mounts");
    std::ifstream stream_path(mountinfo_path);

    if (!stream_path.is_open()) {
        LOG_ERROR("failed to open %s information[%d]", mountinfo_path.u8string().c_str(), stream_path.rdstate());
        return "";
    }

    std::string line_root;
    std::string rootdir;

     while (std::getline(stream_path, line_root)) {
        std::vector<std::string> tokens = zero::strings::split(line_root, " ", 5);

        if (tokens.size() != 6)
            continue;

        if (tokens[0] == workdir) {
            rootdir = tokens[1];
            rootdir += "/rootfs";
            break;
        }
    }
    return rootdir;
}

std::string find_workdir_overlayfs(int pid) {
    std::filesystem::path path = std::filesystem::path("/proc") / std::to_string(pid) / "mounts";
    std::ifstream stream(path);

    if (!stream.is_open()) {
        LOG_ERROR("failed to open %s information[%d]", path.u8string().c_str(), stream.rdstate());
        return "";
    }

    std::string line;
    std::string workdir;

    while (std::getline(stream, line)) {
        std::vector<std::string> tokens = zero::strings::split(line, " ", 5);

        if (tokens.size() != 6)
            continue;
        // overlay fs, from linux kernel 3.18
        if (tokens[0] == "overlay" && tokens[1] == "/") {
            tokens = zero::strings::split(tokens[3], ",");

            auto it = std::find_if(tokens.begin(), tokens.end(), [](const auto &option) {
                return zero::strings::startsWith(option, "workdir=");
            });

            if (it == tokens.end())
                continue;

            workdir = it->substr(8);
            break;
        }
    }
    return workdir;
}

std::string find_workdir_devicemapper(int pid) {
    std::filesystem::path path = std::filesystem::path("/proc") / std::to_string(pid) / "mounts";
    std::ifstream stream(path);

    if (!stream.is_open()) {
        LOG_ERROR("failed to open %s information[%d]", path.u8string().c_str(), stream.rdstate());
        return  "";
    }

    std::string line;
    std::string workdir;

    while (std::getline(stream, line)) {
        std::vector<std::string> tokens = zero::strings::split(line, " ", 5);
        
        if (tokens.size() != 6)
            continue;
        // devicemapper, form linux kernel 2.6.9
        if (tokens[1] == "/") {
            workdir = tokens[0];
            break;
        }
    }
    return workdir;
}

int main(int argc, char *argv[]) {
    INIT_CONSOLE_LOG(zero::INFO_LEVEL);

    zero::Cmdline cmdline;

    FSType fs_type;

    cmdline.add<int>("pid", "target process id");
    cmdline.add<std::filesystem::path>("src", "source path");
    cmdline.add<std::filesystem::path>("dst", "destination path");

    cmdline.parse(argc, argv);

    auto pid = cmdline.get<int>("pid");
    auto src = cmdline.get<std::filesystem::path>("src");
    auto dst = cmdline.get<std::filesystem::path>("dst");

    std::error_code ec;

    if (!std::filesystem::exists(src, ec)) {
        LOG_ERROR("source path %s not exists[%s]", src.u8string().c_str(), ec.message().c_str());
        return -1;
    }

    std::string workdir = find_workdir_overlayfs(pid);

    if (workdir.empty()) {
        workdir = find_workdir_devicemapper(pid);
        if (workdir.empty()) {
            LOG_ERROR("failed to find workdir of devicemapper and overlay filesystem");
            return -1;
        } else {
            fs_type = FSType::devicemapper;
        }
    } else {
        fs_type = FSType::Overlay;
    }

    LOG_INFO("workdir: %s", workdir.c_str());

    std::string root_path;

    if (fs_type == FSType::Overlay) {
        root_path = find_rootfs_overlay(workdir);
    } else {
        root_path = find_rootfs_devicemapper(workdir);
    }

    if (root_path.empty()) {
        LOG_ERROR("failed to find rootfs of overlay filesystem, workdir : %s", workdir.c_str());
        return -1;
    }

    LOG_INFO("rootdir: %s", root_path.c_str());

    std::filesystem::path merged = root_path;

    if (!std::filesystem::exists(merged, ec)) {
        LOG_WARNING("directory %s not exists: %s", merged.u8string().c_str(), ec.message().c_str());
        return -1;
    }

    dst = merged / dst.relative_path();
    
    // when container restart, the directory is exist but empty
    if (std::filesystem::exists(dst, ec) && !std::filesystem::is_empty(dst)) {
        LOG_WARNING("directory %s already exists and not empty", dst.u8string().c_str());
        return 0;
    }

    LOG_INFO("bind %s -> %s", src.u8string().c_str(), dst.u8string().c_str());
    if (!std::filesystem::exists(dst)) {
        if (!std::filesystem::create_directories(dst, ec)) {
            LOG_ERROR("create directory %s failed[%s]", dst.u8string().c_str(), ec.message().c_str());
            return -1;
        }
    }

    if (mount(src.u8string().c_str(), dst.u8string().c_str(), "ext4", MS_BIND, nullptr) < 0) {
        LOG_ERROR("bind failed[%s]", strerror(errno));
        return -1;
    }

    return 0;
}
