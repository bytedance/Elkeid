#include <zero/log.h>
#include <zero/cmdline.h>
#include <sys/mount.h>

int main(int argc, char *argv[]) {
    INIT_CONSOLE_LOG(zero::INFO_LEVEL);

    zero::Cmdline cmdline;

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

    std::filesystem::path path = std::filesystem::path("/proc") / std::to_string(pid) / "mounts";
    std::ifstream stream(path);

    if (!stream.is_open()) {
        LOG_ERROR("failed to open %s information[%d]", path.u8string().c_str(), stream.rdstate());
        return -1;
    }

    std::string line;
    std::optional<std::filesystem::path> workdir;

    while (std::getline(stream, line)) {
        std::vector<std::string> tokens = zero::strings::split(line, " ", 5);

        if (tokens.size() != 6)
            continue;

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

    if (!workdir) {
        LOG_ERROR("failed to find workdir of overlay filesystem");
        return -1;
    }

    LOG_INFO("workdir: %s", workdir->u8string().c_str());

    std::filesystem::path merged = workdir->parent_path() / "merged";

    if (!std::filesystem::exists(merged, ec)) {
        LOG_ERROR("directory %s not exists[%s]", merged.u8string().c_str(), ec.message().c_str());
        return -1;
    }

    dst = merged / dst.relative_path();

    if (std::filesystem::exists(dst, ec)) {
        LOG_WARNING("directory %s already exists", dst.u8string().c_str());
        return 0;
    }

    LOG_INFO("bind %s -> %s", src.u8string().c_str(), dst.u8string().c_str());

    if (!std::filesystem::create_directories(dst, ec)) {
        LOG_ERROR("create directory %s failed[%s]", dst.u8string().c_str(), ec.message().c_str());
        return -1;
    }

    if (mount(src.u8string().c_str(), dst.u8string().c_str(), "ext4", MS_BIND, nullptr) < 0) {
        LOG_ERROR("bind failed[%s]", strerror(errno));
        return -1;
    }

    return 0;
}
