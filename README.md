# linux_tcp_connection_hider
kernel rootkit module to hide connections from attacker ip (ssh, reverse shells, etc...).

## Base source
The base source of this code is from [Xcellerator/linux-kernel-hacking](https://github.com/xcellerator/linux_kernel_hacking/tree/master/3_RootkitTechniques/3.6_hiding_ports) project, a kernel module to hide connections of certain tcp port,  **I have addapted the code adding a function and remove/edit some lines in the kernel hooked function to hide connections from an attacker ip** address and not from tcp port connection as the original base source do.

## How to use
* Edit the `IP_ADDRESS_TO_HIDE` variable in rootkit.c file at line 10
* Build with `make`
* Load with `insmod rootkit.ko`
* At this moment any tcp connection from/to the attacker ip dissapear in "netstat" output command

![Capture](https://github.com/elefr3n/linux_tcp_connection_hider/blob/main/Capture.PNG?raw=true)
