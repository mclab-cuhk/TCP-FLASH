# TCP-FLASH
This project presents the source code of FLASH congestion control algorithm, which has been accepted by IEEE ACCESS (TCP-FLASH - A Fast Reacting TCP for Modern Networks)
# Requirement for the kernel version >= 5.0 (Most of the 4.x kernel version also support FLASH)
1. Put both Makefile and flash_release.c under the same dir.
2. Compile the flash_release.c file with command "make".
3. You may need to install some libraries as indicated in the cmd, if you failed in executing the second step.
4. If everything goes well, under the same dir you will see several new files generated, flash_release.ko is one of them.
5. Then install the flash_release.ko module into your machine by "install flash_release.ko /lib/modules/$your-kernel-version$"
6. sudo depmod
7. sudo modprobe flash_release  (Make sure the 'secure boot' is disable)
8. No output means that you have successfully installed the module into you system. Otherwise likely memory allocation failed (unlikely though)
9. Run flash as the congestion control algorithm by "sysctl net.ipv4.tcp_congestion_control=flash_release3".
10. Double check by "sysctl net.ipv4.tcp_congestion_control", if the output is "flash_release3", congratulation! 
11. Enjoy the speedup!
