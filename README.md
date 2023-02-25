Tools:
generatebp.py: generate API's offset list by ELF file or process id.
getfunc.py: generate API list.
ibut: With input of above two tools, can monitor API call flow dynamically 

Functions:
1. Monitor invoked APIs
2. When API triggered, provide backtrace remotely
3. When API triggered, invoke plugin code
4. When API triggered, generate a mini coredump file then continue
