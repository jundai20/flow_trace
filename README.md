# flow_trace
Trace API calls of a runing process. Similar as gdb set lots of breakpoints and print backtrace when hit it. You use extract call backtrace and API parameters and do whatever you want.




Example:


Step 1. generate a file describing all API about a process.

You can use whatever tool like readelf, objdump etc to generate breakpoint decription file, or as following.


Console 1:

lnx@lnx:~/github/flow_trace$ ./test

To generate api information file: ./spy -p 5354 -g -o func_info.txt

To trace this application: ./spy -p 5354 -c func_info.txt -b test.bp


Console 2:

lnx@lnx:~/github/flow_trace$ ./spy -p 5397 -g -o func_info.txt

Welcome to kludge debugger, compiled @ May 26 2022:21:48:04
pid = 5397


Step 2. Monitor test, use test as an example.

Console 1:

lnx@lnx:~/github/flow_trace$ ./test

To generate api information file: ./spy -p 5408 -g -o func_info.txt

To trace this application: ./spy -p 5408 -c func_info.txt -b test.bp



Console 2:

lnx@lnx:~/github/flow_trace$ sudo ./spy -p 5408 -c func_info.txt -b test.bp
Welcome to kludge debugger, compiled @ May 26 2022:21:48:04
pid = 5408
Initializing, be patient please...
Loading extra watch API list from test.bp for pid 5408


In total requesting 2 breakpoints
Inserted 2 breakpoints successfully


