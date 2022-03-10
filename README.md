CAFEBABE (placeholder)
-------------------------
Version 1.44 (as of 10th March '22) 

coming back to this project in over a month i have made some notable changes:
  - Allocations added to the memory struct in memory.h are actually freed
  - Some changes to STDOUT (guaranteed to change as im very indecisive when it comes to this)
  - threading has been removed in place of asynchronous packet capture via a socket ring buffer

The last change greatly improves performance, however theres still some kinks that need straightening.  
Ver. 1.5 will be the next big update so this is just kind of like a "prelease" of sorts as the next update  
should make the project more well rounded and include more features, hopefully.

Install
-------
before compiling, edit `COMMON_PATH` in main.c to the path where you cloned the repo
compile.py (formerly install.py) no longer moves the compiled binary so its
up to you where it goes.

*_Tested on Kali Linux & Android_*
