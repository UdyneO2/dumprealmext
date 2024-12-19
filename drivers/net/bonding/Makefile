#
# Makefile for the Ethernet Bonding driver
#

obj-$(CONFIG_BONDING) += bonding.o

<<<<<<< HEAD
bonding-objs := bond_main.o bond_3ad.o bond_alb.o bond_sysfs.o bond_sysfs_slave.o bond_debugfs.o bond_netlink.o bond_options.o
=======
bonding-objs := bond_main.o bond_3ad.o bond_alb.o bond_sysfs.o bond_sysfs_slave.o bond_netlink.o bond_options.o

bonding-$(CONFIG_DEBUG_FS) += bond_debugfs.o
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533

proc-$(CONFIG_PROC_FS) += bond_procfs.o
bonding-objs += $(proc-y)

