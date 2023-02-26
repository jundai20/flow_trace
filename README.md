More information:
1. generatebp.py: generate API's offset list by ELF file or process id.
   Usage example:
    tools/generatebp.py -b test_mt
    or
    tools/generateb.py -s glibc.so 
    This tool will generate a API offset list, by default it is /tmp/api_list.txt.
    The generated file can be used by following ibut tool.

2. getfunc.py: generate API list.
   Usage example:
   tools/getfunc.py test/test_mt.c 
   This tool generate a API list, by default it is /tmp/bp_list.txt. Each API can has a flag, it indicate what level of information will be provided when it is triggered.

   The generated file is what you interested in. When those API triggered, ibut will emit log. Or you can implement a plugin to mointor those APIs.

3. ibut: With input of above two tools, can monitor API call flow dynamically
   Usage example:
   Step 1. Run test_mt
   Step 2. Open another console, mointor how test_mt 
   ./ibut -p `pidof test_mt` -b /tmp/bp_list.txt -s /tmp/api_list.txt
   When APIs in /tmp/bp_list.txt is triggerd, print out it. If you want to know generate a mini coredump or customize output when API was triggered, can implement a plugin.  Example: ibut_plugin.c.

ibut functions:
1. Monitor invoked APIs
   If flag & 1, tool output API name in real time. This is default flag
2. When API triggered, provide backtrace by adjust flag accordingly.
   If flag & 2, when API triggered, output backtrace
3. When API triggered, customize output by implement a plugin
   If API has a enter_xxx or exit_xxx API in plugin file, then plugin API will be triggered.
4. When API triggered, generate a mini coredump file then continue by ajdust flag accordling.
   If flag & 0x04, will generate core file then continue when invoked.

