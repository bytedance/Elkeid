import glob
import os
import shutil
import errno


def search_files():
    for root, dirs, files in os.walk("../"):
        if "hub/" in root:
            continue
        if ".github" in root:
            continue
        if "driver/" in root:
            continue
        if "sources/" in root:
            continue
        for file in files :
            if "CODE_OF_CONDUCT.md" in file:
                continue
            if file.endswith(".md") or file.endswith("png") or file.endswith("jpg"):
                yield (root, file)

if __name__ == "__main__":
    prefix = "sources/fake"
    for p, f in search_files():
        print(p, f)
        path = "{}/{}".format(prefix, p)
        if not os.access(path, os.F_OK):
            try:
                os.makedirs(path)
            except OSError as e:
                if e.errno == errno.EEXIST:
                    print('Directory not created.')
                else:
                    raise
        file_src = "{}/{}".format(p,f)
        file_dst = "{}/{}/{}".format(prefix, p, f)
        shutil.copy(file_src, file_dst)

