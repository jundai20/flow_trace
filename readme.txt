Purpose:
Set breakpoint set, minic set breakpoint and show backtrace when hit breakpoint

How to build:
e.g.
sudo apt-get install libunwind-dev libyaml-dev -y
make

How to run:

Example 1. when hit, bar, print
E.g. Assume you have a running process, process id = 12345, you want to 
./spy -p 12345 -c func_info.txt

The func_info.txt contains all APIs for the target process. example as below.  The debug_flag = 1 means, want to set breakpoint of this API. 
breakpoints:
 - host_offset: 0000000009a4afe0
   func_name: foo 
 - host_offset: 000000001405f6a0
   func_name: bar 
   debug_flag: 1
 - host_offset: 000000001405f6a0
   func_name: bzz
   debug_flag: 1

Exmple 2. use addon.txt to provide addtional breakpoints
Sometimes, you don't want to manually modify above func_info.txt to add debug_flag, then you can provide a separate file, for exmaple addon.txt, in that file, add any function name in it.
./spy -p 12345 -c func_info.txt -b addon.txt

addon.txt can be like following:
bar
bzz


