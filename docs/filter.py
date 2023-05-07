# coding: utf-8
import json
import sys


ignore = [
    "[English](README.md) | 简体中文",
    "English | [简体中文](README-zh_CN.md)"
]

def log(s):
    sys.stderr.write(s)
    sys.stderr.write("\n")
    sys.stderr.flush()

def replace(src):
    for i in ignore:
        src = src.replace(i, "")
    return src

if __name__ == '__main__':
    if len(sys.argv) > 1: # we check if we received any argument
        if sys.argv[1] == "supports":
            # then we are good to return an exit status code of 0, since the other argument will just be the renderer's name
            sys.exit(0)

    # load both the context and the book representations from stdin
    context, book = json.load(sys.stdin)
    # and now, we can just modify the content of the first chapter
    sections = []
    for section in book['sections']:
        content = section['Chapter']['content']
        section['Chapter'].update({"content":  replace(content)})
        sub_items = section['Chapter']['sub_items']
        for sub in sub_items:
            content = sub['Chapter']['content']
            sub['Chapter'].update({"content": replace(content)})
            sub_items_level2 = sub['Chapter']['sub_items']
            for sub2 in sub_items_level2:
                content = sub2['Chapter']['content']
                sub2['Chapter'].update({"content": replace(content)})
    # book['sections'][0]['Chapter']['content'] = '# Hello'
    # we are done with the book's modification, we can just print it to stdout
    print(json.dumps(book))
