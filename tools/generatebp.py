#!/usr/bin/python3
#  -*- coding: utf-8 -*-
import os
from argparse import ArgumentParser
from sys import argv, exit, stdout

so_binary = ""
app_binary = ""

class api_info:
    def __init__ (self, name, offset):
       self.name = name
       self.offset = offset

    def print_api (self, fp):
        if (len(app_binary)):
            fp.write("self:" + self.name + " " + self.offset + "\n")
        else:
            so_name = os.path.basename(so_binary)
            fp.write(so_name + ":" + self.name + " " + self.offset + "\n")

    def print_so (self, fp):
        if (len(app_binary)):
            fp.write("self:" + self.name + "\n")
        else:
            so_name = os.path.basename(so_binary)
            fp.write(so_name + ":" + self.name + "\n");

def load_one_file_apis (file_path, api_set, proc_info):
    print("Reading symbols from {} ...".format(file_path))
    cmd_line = "readelf -Ws " + file_path
    p = os.popen(cmd_line)
    for line in p.readlines():
        line_info = line.split()
        if len(line_info) != 8:
           continue
        if line_info[3] != "FUNC" or line_info[6] == 'UND':
            continue
        api_name = line_info[7]
        if api_name.startswith("__be_"):
            api_name = api_name[5:]
        new_api = api_info(api_name, line_info[1])
        api_set[api_name] = new_api
    print("done.");

if __name__ == '__main__':
    parser = ArgumentParser(description='Usage:')
    parser.add_argument('-s', '--target_so', type=str, required=False, help="so library file")
    parser.add_argument('-b', '--binary', type=str, required=False, help="application file")
    args = parser.parse_args()

    if args.target_so != None and os.path.isfile(args.target_so):
        binary = args.target_so
        so_binary = binary
    elif args.binary != None and os.path.isfile(args.binary):
        binary = args.binary
        app_binary = binary
    else:
        # For linux app please use ./ibut -p xx -o xx -g to generate configure file
        print("Please provide a so library (-s) or an application (-b) for example:")
        print("    python {} -b /proc/<pid>/exe".format(os.sys.argv[0]))
        exit(-1)

    all_apis = {}
    proc_info = {}
    load_one_file_apis(binary, all_apis, proc_info)

    with open ("/tmp/api_list.txt", 'w') as fp:
        print("Generate API file /tmp/api_list.txt , it needs a few minutes...")
        for api in all_apis:
            all_apis[api].print_api(fp)
    with open ("/tmp/bp_list.txt", 'w') as fp:
        print("Generate API file /tmp/bp_list.txt , it needs a few minutes...")
        for api in all_apis:
            all_apis[api].print_so(fp)
    if len(proc_info) != 0:
        with open ("/tmp/proc_list.txt", 'w') as fp:
            print("Generate process info file /tmp/proc_list.txt , it needs a few minutes...")
            for key, value in proc_info.items():
                fp.write(key + " " + value + "\n")
    print("Generated /tmp/api_list.txt, can be used with -s api_list.txt")
