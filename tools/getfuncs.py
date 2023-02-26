#!/usr/bin/python3
#  -*- coding: utf-8 -*-

import re
import os
import sys

rproc = r"((?<=[\s:~])(\w+)\s*\(([\w\s,<>\[\].=&':/*]*?)\)\s*(const)?\s*(?={))"
cppwords = ['if', 'while', 'do', 'for', 'switch']
watch_api_list = set()

def get_funcs_file (file_name):
    if (not file_name.endswith('.c')):
        return
    f = open(file_name)
    txt = ''.join(f.readlines())
    f.close()
    for i in re.finditer(rproc, txt):
        if (i.group(2) in cppwords):
            continue
        watch_api_list.add(i.group(2))

if __name__ == '__main__':
    argc = len(sys.argv)
    if (argc != 2):
        print("Usage: {} <file or directory>\n".format(sys.argv[0]))
        exit(-1)

    for i in range(1, argc):
        dirname = sys.argv[i]
        file_fullname = os.getcwd() + "/" + dirname
        print("full name {}".format(file_fullname))
        if (os.path.isfile(file_fullname)):
            get_funcs_file(file_fullname)
        elif (os.path.isdir(file_fullname)):
            file_list = os.listdir(file_fullname)
            for this_file in file_list:
                get_funcs_file(file_fullname + '/' + this_file)

    with open ("/tmp/bp_list.txt", 'w') as fp:
        print("Generate IOSd API breakpoint file...")
        for api in watch_api_list:
            print("self:"+api+" 1", file=fp)
    print("Generated /tmp/bp_list.txt, can be used with -b bp_list.txt")

