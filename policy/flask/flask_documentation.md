## File

The common file permissions that are inherited by a number of object classes.

**append** - Write to a file opened with O\_APPEND.

**audit\_access** - Used in dontaudit rule. If a process calls access() or faccessat() and SELinux denies their request there will be a check for a dontaudit rule on the audit\_access permission. If there is a dontaudit rule on audit\_access an AVC event will not be written. If there is nodontaudit rule an AVC event will be written for the permissions requested (read, write, or exec).

**create** - Create a new file.

**execmod** - Execute memory-mapped files that have been modified in the process memory. This permission check is useful in keeping shared libraries from being modified within a process.

**execute** - Execute.

**getattr** - Get file attributes for file, such as access mode. (e.g. stat, some ioctls. ...)

**ioctl** - IO control system call requests not addressed by other permissions.

**link** - Create another hard link to file.

**lock** - Set and unset file locks.

**map** - Map files into memory.

**mounton** - Use as mount point; only useful for directories and files in Linux.

**open** - Open a file.

**quotaon** - Use as a quota file.

**read** - Read file contents.

**relabelfrom** - Change the security context based on the existing type.

**relabelto** - Change the security context based on the new type.

**rename** - Rename a file.

**setattr** - Change file attributes for file such as access mode. (e.g. chmod, some ioctls, ...)

**swapon** - Allows file to be used for paging/swapping space.

**unlink** - Remove hard link (delete).

**watch** - Set a watch on a filesystem object.

**watch\_mount** - Set a watch on filesystem objects within the same mount.

**watch\_reads** - Required to receive notifications from read-exclusive events on filesystem objects. These events include accessing a file for the purpose of reading and closing a file which has been opened read-only.

**watch\_sb** - Set a watch on filesystem objects within the same filesystem. Superblock watches further require the filesystem watch permission to the superblock.

**watch\_with\_perm** - Set a watch for fanotify "permission events" (blocking events that make a request to the receiving application whether or not given action may be completed).

**write** - Write to a file.

---

## socket

The common socket permissions that are inherited by a number of object classes.

**accept** - Accept a connection.

**append** - Write to open fd marked with O\_APPEND.

**bind** - Bind a name to the socket.

**connect** - Initiate connection.

**create** - Create new socket.

**getattr** - Get socket attributes, e.g. fstat.

**getopt** - Get socket options.

**ioctl** - IO control system call requests not addressed by other permissions.

**listen** - Listen for connections.

**lock** - Apply file lock on a socket.

**map** - Allow a file to be memory mapped via mmap(2).

**name\_bind** - Associate with port or file; for AF\_INET sockets, controls relationship between a socket and it's port number; for AF\_UNIX sockets, controls relationship between a socket and it's file.

**recv\_msg** - Obsolete.

**recvfrom** - Legacy NetLabel check; obsoleted by peer recv.

**relabelfrom** - Change the security context based on the existing type.

**relabelto** - Change the security context based on the new type.

**send\_msg** - Legacy check; no longer present.

**sendto** - Send to socket.

**setattr** - Change socket attributes.

**setopt** - Set socket options.

**shutdown** - Shutdown connection.

**write** - Write to socket.

---

## IPC

The common IPC permissions that are inherited by a number of object classes.

**associate** - Associate a key.

**create** - Create.

**destroy** - Destroy.

**getattr** - Get information from IPC object.

**read** - Read.

**setattr** - Change attributes, e.g. IPC\_SET.

**unix\_read** - Generic read access.

**unix\_write** - Generic write access.

**write** - Write.

---

## database

The common database permissions that are inherited by a number of object classes.

**create** - Create a new database object.

**drop** - Remove a database object.

**getattr** - Get the attributes of a database object.

**relabelfrom** - Change the security context based on the existing type.

**relabelto** - Change the security context based on the new type

**setattr** - Set the attributes of a database object.

---

## x\_device

The common x\_device permissions that are inherited by the X-Window x\_keyboard and x\_pointer object classes.

**add**

**bell**

**create**

**destroy**

**force\_cursor** - Get window focus.

**freeze**

**get\_property** - Required to create a device context. (source code)

**getattr**

**getfocus**

**grab** - Set window focus.

**list\_property**

**manage**

**read**

**remove**

**set\_property**

**setattr**

**setfocus**

**use**

**write**

---

## class filesystem

A mounted filesystem.

**associate** - Associate a file to the filesystem.

**getattr** - Get filesystem attributes.

**mount** - Mount the filesystem.

**quotaget** - Get quota information.

**quotamod** - Modify quota information.

**relabelfrom** - Change the security context based on existing type.

**relabelto** - Change the security context based on the new type.

**remount** - Remount existing mount.

**transition** - Transition to a new SID (change security context).

**unmount** - Unmount the filesystem.

**watch** - Set a watch on a filesystem.

---

## class dir

Directory.

*inherits file*

**add\_name** - Add a file to the directory.

**remove\_name** - Remove a file from the directory.

**reparent** - Rename into a different parent directory (change parent directory).

**rmdir** - Remove the directory.

**search** - Search directory.

---

## class file

Ordinary file.

*inherits file*

**entrypoint** - Can be executed as the entry point of the new domain in a transition.

**execute\_no\_trans** - Execute a file in the callers domain.

---

## class lnk\_file

Symbolic links.

*inherits file*

---

## class chr\_file

Character files.

*inherits file*

**entrypoint** - Can be executed as the entry point of the new domain in a transition.

**execute\_no\_trans** - Execute a file in the callers domain.

**execmod** - Execute memory-mapped files that have been modified in the process memory. This permission check is useful in keeping shared libraries from being modified within a process.

**open** - Open a character device file.

---

## class blk\_file

Block files.

*inherits file*

---

## class sock\_file

UNIX domain sockets.

*inherits file*

---

## class fifo\_file

Named pipes.

*inherits file*

---

## class fd

File descriptors.

**use** - Permission to use an inherited file descriptor.

---

## class node

IP address or range of IP addresses.

**dccp\_recv** - Receive DCCP (Datagram Congestion Control Protocol) packet.

**dccp\_send** - Send DCCP (Datagram Congestion Control Protocol) packet.

**enforce\_dest** - Ensure that the destination node can enforce restrictions on the destination socket. Never used in mainline Linux.

**rawip\_recv** - Receive raw IP packet.

**rawip\_send** - Send a raw IP packet.

**recvfrom** - Network interface and address check permission for use with the ingress permission.

**sendto** - Network interface and address check permission for use with the egress permission.

**tcp\_recv** - Receive TCP packet.

**tcp\_send** - Send a TCP packet.

**udp\_recv** - Receive UDP packet.

**udp\_send** - Send a UDP packet.

---

## class netif

Network Interface (e.g. eth0).

**dccp\_recv** - Receive DCCP packet.

**dccp\_send** - Send a DCCP packet.

**egress** - Each packet leaving the system must pass an egress access control. Also requires the node sendto permission.

**ingress** - Each packet entering the system must pass an ingress access control. Also requires the node recvfrom permission.

**rawip\_recv** - Receive raw IP packet.

**rawip\_send** - Send a raw IP packet.

**tcp\_recv** - Receive TCP packet.

**tcp\_send** - Send a TCP packet.

**udp\_recv** - Receive UDP packet.

**udp\_send** - Send a UDP packet.

---

## class anon\_inode

Anonymous inode.

*inherits file*

---

## class socket

Socket that is not part of any other specific SELinux socket object class.

*inherits socket*

---

## class tcp\_socket

Protocol: PF\_INET, PF\_INET6 Family Type:SOCK\_STREAM

*inherits socket*

**acceptfrom** - Accept connection from client socket.

**connectto** - Connect to the server socket.

**name\_connect** - Connect to a specific port number.

**newconn** - Create a new socket for connection.

**node\_bind** - Ability to bind to a node.

---

## class udp\_socket

Protocol: PF\_INET, PF\_INET6 Family Type:SOCK\_DGRAM

*inherits socket*

**node\_bind** - Ability to bind to a node.

---

## class rawip\_socket

Protocol: PF\_INET, PF\_INET6 Family Type:SOCK\_RAW

*inherits socket*

**node\_bind** - Ability to bind to a node.

---

## class packet\_socket

Protocol: PF\_PACKET Family Type: All

*inherits socket*

---

## class unix\_stream\_socket

Communicate with processes on the same machine. Protocol: PF\_STREAM Family Type: SOCK\_STREAM

*inherits socket*

**acceptfrom** - Accept connection from client socket.

**connectto** - Connect to the server socket.

**newconn** - Create a new socket for connection.

---

## class unix\_dgram\_socket

Communicate with processes on the same machine. Protocol: PF\_STREAM Family Type: SOCK\_DGRAM

*inherits socket*

---

## class tun\_socket

TUN is Virtual Point-to-Point network device driver to support IP tunneling.

*inherits socket*

**attach\_queue** - Approve requests to attach to a TUN queue via TUNSETQUEUE.

---

## class association

IPSec security association.

**polmatch** - Match an IPSEC policy entry.

**recvfrom** - Receive from an IPSEC association.

**sendto** - Send to an IPSEC association.

**setcontext** - Set the context of an IPSEC association on creation.

---

## class key\_socket

IPSec key management. Protocol: PF\_KEY FamilyType: All

*inherits socket*

---

## class netlink\_xfrm\_socket

Netlink socket to maintain IPSec parameters.

*inherits socket*

**nlmsg\_read** - Read xfrm configuration state.

**nlmsg\_write** - Write xfrm configuration state.

---

## class netlink\_socket

Netlink socket that is not part of any specific SELinux Netlink socket class. Protocol: PF\_NETLINK Family Type: All other types that are not part of any other specific netlink object class.

*inherits socket*

---

## class netlink\_route\_socket

Netlink socket to manage and control network resources.

*inherits socket*

**nlmsg\_read** - Read kernel routing table.

**nlmsg\_write** - Write kernel routing table.

---

## class netlink\_firewall\_socket

Netlink socket for firewall filters.

*inherits socket*

**nlmsg\_read** - Read firewall configuration state.

**nlmsg\_write** - Write firewall configuration state.

---

## class netlink\_tcpdiag\_socket

Netlink socket to monitor TCP connections.

*inherits socket*

**nlmsg\_read** - Read tcp diagnostics.

**nlmsg\_write** - Write a netlink message. Unused.

---

## class netlink\_nflog\_socket

Netlink socket for Netfilter logging.

*inherits socket*

---

## class netlink\_selinux\_socket

Netlink socket to receive SELinux events such as a policy or boolean change.

*inherits socket*

---

## class netlink\_audit\_socket

Netlink socket for audit service.

*inherits socket*

**nlmsg\_read** - Read audit subsystem state (e.g. AUDIT\_GET).

**nlmsg\_readpriv** - Read security-sensitive audit subsystem state.

**nlmsg\_relay** - Send user space audit messages to the kernel audit system.

**nlmsg\_tty\_audit** - Control TTY auditing.

**nlmsg\_write** - Write audit subsystem state (e.g. AUDIT\_SET).

---

## class netlink\_ip6fw\_socket

Netlink socket for IPv6 firewall filters.

*inherits socket*

**nlmsg\_read** - Read netlink message.

**nlmsg\_write** - Write a netlink message.

---

## class netlink\_dnrt\_socket

Netlink socket for DECnet routing.

*inherits socket*

*Updated Netlink class for KOBJECT\_UEVENT family.*

---

## class netlink\_kobject\_uevent\_socket

*inherits socket*

---

## class netlink\_iscsi\_socket

Netlink socket for iSCSI.

*inherits socket*

---

## class netlink\_fib\_lookup\_socket

Netlink socket used for access to forwarding table lookup from userspace.

*inherits socket*

---

## class netlink\_connector\_socket

Netlink socket for Kernel connector, easy to use communication module used for inter-process communication between kernel space and userspace.

*inherits socket*

---

## class netlink\_netfilter\_socket

Netlink socket for netfilter.

*inherits socket*

---

## class netlink\_generic\_socket

Netlink socket for Generic netlink family.

*inherits socket*

---

## class netlink\_scsitransport\_socket

*inherits socket*

---

## class netlink\_rdma\_socket

Netlink socket for Remote Direct Memory Access.

*inherits socket*

---

## class netlink\_crypto\_socket

Netlink interface to request information and manage ciphers registered with the kernel crypto API.

*inherits socket*

---

## class peer

NetLabel and Labeled IPsec have separate access controls, the network peer label consolidates these two access controls into a single one (see http://paulmoore.livejournal.com/1863.html for details).

**recv** - Receive packets from a labeled networking peer.

---

## class packet

Supports 'secmark' services where packets are labeled using iptables to select and label packets, SELinux then enforces policy using these packet labels.

**flow\_in** - Receive external packets. (deprecated)

**flow\_out** - Send packets externally. (deprecated)

**forward\_in** - Allow inbound forwarded packets.

**forward\_out** - Allow outbound forwarded packets.

**receive** - Receive a packet.

**relabelto** - Set a labeling rule to the specified type.

**send** - Send a packet.

---

## class appletalk\_socket

Appletalk socket.

*inherits socket*

---

## class dccp\_socket

Datagram Congestion Control Protocol (DCCP)

*inherits socket*

**acceptfrom** - Accept connection from client socket.

**connectto** - Connect to the server socket.

**name\_connect** - Connect to a specific port number.

**newconn** - Create a new socket for connection.

**node\_bind** - Ability to bind to a node.

*Define the access vector interpretation for the new socket classes enabled by the extended\_socket\_class policy capability.*

---

## class sctp\_socket

Socket for Stream Control Transmission Protocol.

*inherits socket*

**association** - Set up between two endpoints.

**name\_connect** - Connect to a specific port number.

**node\_bind** - Ability to bind to a node.

---

## class icmp\_socket

Socket for Internet Control Message Protocol.

*inherits socket*

**node\_bind** - Ability to bind to a node.

## class ax25\_socket

Socket for AX25 amateur packet radio protocol.

*inherits socket*

---

## class ipx\_socket

Socket for Internetwork Packet Exchange protocol.

*inherits socket*

---

## class netrom\_socket

Socket for NET/ROM amateur packet radio protocol.

*inherits socket*

---

## class bridge\_socket

*inherits socket*

---

## class atmpvc\_socket

Socket for ATM Permanent Virtual Circuits.

*inherits socket*

---

## class x25\_socket

Socket for X.25 packet layer protocol.

*inherits socket*

---

## class rose\_socket

Rose amateur packet radio protocol.

*inherits socket*

---

## class decnet\_socket

Socket for Decnet network protocol family.

*inherits socket*

---

## class atmsvc\_socket

Socket for ATM Switched Virtual Circuits.

*inherits socket*

---

## class rds\_socket

Reliable Datagram Socket (RDS) is a high-performance and low latency connectionless protocol that is used for communication over Infiniband to transfer data between a client and media server.

*inherits socket*

---

## class irda\_socket

Socket interface over IrDA (infrared) .

*inherits socket*

---

## class pppox\_socket

Socket for generic PPP transport layer.

*inherits socket*

---

## class llc\_socket

Socket for Logical link control (IEEE 802.2 LLC) protocol.

*inherits socket*

---

## class ib\_socket

Socket for InfiniBand native addressing.

*inherits socket*

---

## class mpls\_socket

Socket for Multiprotocol Label Switching.

*inherits socket*

---

## class can\_socket

Socket for Controller Area Network automotive bus protocol.

*inherits socket*

---

## class tipc\_socket

Cluster domain sockets.

*inherits socket*

---

## class bluetooth\_socket

Bluetooth low-level socket protocol.

*inherits socket*

---

## class iucv\_socket

Socket for IUCV (inter-user communication vehicle) z/VM protocol for hypervisor-guest interaction.

*inherits socket*

---

## class rxrpc\_socket

Socket for RxRPC protocol.

*inherits socket*

---

## class isdn\_socket

Socket for New "modular ISDN" driver interface protocol.

*inherits socket*

---

## class phonet\_socket

Socket for Nokia cellular modem IPC/RPC interface.

*inherits socket*

---

## class ieee802154\_socket

Socket for IEEE 802.15.4 WPAN (wireless personal area network) raw packet protocol.

*inherits socket*

---

## class caif\_socket

Socket for Ericsson's Communication CPU to Application CPU interface (CAIF) protocol.

*inherits socket*

---

## class alg\_socket

Interface to kernel crypto API.

*inherits socket*

---

## class nfc\_socket

Socket for Near-Field Communication.

*inherits socket*

---

## class vsock\_socket

Socket for VMWare VSockets protocol for hypervisor-guest interaction.

*inherits socket*

---

## class kcm\_socket

Socket for KCM (kernel connection multiplexer) interface.

*inherits socket*

---

## class qipcrtr\_socket

Socket for Qualcomm IPC router interface protocol.

*inherits socket*

---

## class smc\_socket

Socket for SMC-R (shared memory communications over RDMA) protocol.

*inherits socket*

---

## class xdp\_socket

Socket for XDP (express data path) interface.

*inherits socket*

---

## class ipc

Interprocess communications.

*inherits ipc*

---

## class sem

Semaphores.

*inherits ipc*

---

## class msgq

IPC Message queues.

*inherits ipc*

**enqueue** - Message can be added to a queue.

---

## class msg

Message in a queue.

**receive** - Remove a message from a queue.

**send** - Add a message to a queue.

---

## class shm

Shared memory segment.

*inherits ipc*

**lock** - Lock or unlock shared memory.

---

## class process

An object is instantiated for each process created by the system.

**dyntransition** - Dynamically transition to a new context.

**execheap** - Make the heap executable.

**execmem** - Make executable an anonymous mapping or private file mapping that is writable.

**execstack** - Make the main process stack executable.

**fork** - Fork into two processes.

**getattr** - Get attributes of a process.

**getcap** - Get Linux capabilities.

**getpgid** - Get group Process ID of another process.

**getrlimit** - Get process rlimit information.

**getsched** - Get priority of another process.

**getsession** - Get session ID of another process.

**noatsecure** - Disable secure mode environment cleansing (AT\_SECURE).

**ptrace** - Attach to another process for tracing.

**rlimitinh** - Inherit resource limits from the caller.

**setcap** - Set Linux capabilities.

**setcurrent** - Set the current process context.

**setexec** - Override the default context for the next exec().

**setfscreate** - Override the default context for file creation.

**setkeycreate** - Override the default context for key creation.

**setpgid** - Set group Process ID of a process.

**setrlimit** - Change process hard limits.

**setsched** - Set priority of a process.

**setsockcreate** - Override the default context for socket creation.

**share** - Allow state sharing with cloned or forked processes.

**sigchld** - Send SIGCHLD signal.

**siginh** - Inherit signal state from caller.

**sigkill** - Send SIGKILL signal.

**signal** - Send a signal other than SIGKILL, SIGSTOP, or SIGCHLD.

**signull** - Test for the existence of another process without sending a signal.

**sigstop** - Send SIGSTOP signal.

**transition** - Transition to a new context on exec().

---

## class process2

**nnp\_transition** - Transition to a more privileged domain even if no\_new\_privs kernel flag is set.

**nosuid\_transition** - Transition to a new domain based on setuid flag even if the file system is marked nosuid.

---

## class security

This is the security server object and there is only one instance of this object (for the SELinux security server).

**check\_context** - Write context in selinuxfs.

**compute\_av** - Compute an access vector given a source/target/class.

**compute\_create** - Get create info in selinuxfs.

**compute\_member** - Determines the context to use when selecting a member of a polyinstantiated object.

**compute\_relabel** - Get relabel info in selinuxfs.

**compute\_user** - Get user info in selinuxfs.

**load\_policy** - Load the security policy.

**read\_policy** - Read the kernel policy to userspace.

**setbool** - Set a boolean value.

**setcheckreqprot** - Set if SELinux will check original protection mode or modified protection mode (read-implies-exec) for mmap/mprotect.

**setenforce** - Change the enforcement state of SELinux.

**setsecparam** - Set kernel access vector cache tuning parameters.

**validate\_trans** - Validate a transition. (This determines whether a transition from *scon* to *newcon* using *tcon* as the target for object class tclass is valid in the loaded policy.)

---

## class system

This is the overall system object and there is only one instance of this object.

**disable** - Allow services to be disabled.

**enable** - Allow services to be enabled.

**halt** - Allow the system to be halted.

**ipc\_info** - Get info for an ipc socket.

**module\_load** - Load kernel module.

**module\_request** - Request the kernel to load a module.

**reboot** - Allow system to be rebooted.

**reload** - Allow services to be reloaded.

**start** - Start system.

**status** - Get system status information.

**stop** - Stop system.

**syslog\_console** - Perform console logging. 

**syslog\_mod** - Perform syslog operation other than syslog\_read or console logging.

**syslog\_read** - Perform syslog read.

**undefined** - Allow an undefined operation.

*these are overloaded userspace permissions from systemd*

---

## class kernel\_service

Used to add kernel services.

**create\_files\_as** - Grant a process the right to nominate a file creation label for a kernel service to use.

**use\_as\_override** - Grant a process the right to nominate an alternate process security ID for the kernel to use as an override for the SELinux subjective security when accessing stuff on behalf of another process.

---

## class binder

This is a kernel object to manage the Binder IPC service.

**call** - Perform a binder IPC to a given target process (can A call B?).

**impersonate** - Perform a binder IPC on behalf of another process (can A impersonate B on an IPC?). Not currently used in policy but kernel (selinux/hooks.c) checks permission in selinux\_binder\_transaction call.

**set\_context\_mgr** - Register self as the Binder Context Manager aka servicemanager (global name service). Can A set the context manager to B, where normally A == B. See policy module servicemanager.te.

**transfer** - Transfer a binder reference to another process (can A transfer binder reference to B?).

---

## cap

Used to manage the Linux capabilities granted to root processes. Taken from the header file: /usr/include/linux/capability.h.

**audit\_control** - Control kernel audit configuration/rules. Set login UID.

**audit\_write** - Generate audit messages from user space.

**chown** - Override restrictions on changing file ownership and group ownership.

**dac\_override** - Override all DAC access restrictions. 

**dac\_read\_search** - Override DAC read/search access restrictions.

**fowner** - Override all file owner requirements (e.g. for chmod, setxattr) except where fsetid applies.

**fsetid** - Override file owner and group requirements when setting setuid or setgid bits on a file. Can be checked as a side effect on chmod and write operations; dontaudit candidate.

**ipc\_lock** - Allow locking shared memory segments and mlock/mlockall.

**ipc\_owner** - Override IPC ownership checks.

**kill** - Overrides the restriction that the real or effective user ID of a process sending a signal must match the real or effective user ID of the process receiving the signal.

**lease** - Grants ability to take leases on a file. For details on what leases are see fcntl(2).

**linux\_immutable** - Grant privilege to modify S\_IMMUTABLE and S\_APPEND file attributes on supporting filesystems.

**mknod** - Allows creation of character and block device nodes.

**net\_admin** - Allows all networking configurations and modifications. See linux/capability.h for details.

**net\_bind\_service** - Allow low port binding. Port < 1024 for TCP/UDP. VCI < 32 for ATM.

**net\_broadcast** - Grant network broadcasting and listening to incoming multicasts.

**net\_raw** - Allows opening of raw sockets and packet sockets.

**setfcap** - Set file capabilities.

**setgid** - Allow setgid(2) or setgroups(2) or forged gids on credentials passed over a socket.

**setpcap** - Add capability from bounding set to inheritable set, drop capability from bounding set, modify secure bits.

**setuid** - Allow setuid, seteuid, setreuid. Allow passing of forged ids on credentials passed over a socket.

**sys\_admin** - Allow the following: configuration of the secure attention key; administration of the random device; examination and configuration of disk quotas; configuring the kernel's syslog; setting the domain name; setting the hostname; calling bdflush(); mount() and umount(), setting up new smb connection; some autofs root ioctls; nfsservctl; VM86\_REQUEST\_IRQ; to read/write pci config on alpha; irix\_prctl on mips (setstacksize); flushing all cache on m68k (sys\_cacheflush); removing semaphores; locking/unlocking of shared memory segment; turning swap on/off; forged pids on socket credentials passing; setting readahead and flushing buffers on block devices; setting geometry in floppy driver; turning DMA on/off in xd driver; administration of md devices; tuning the ide driver; access to the nvram device; administration of apm\_bios, serial and bttv (TV) device; manufacturer commands in isdn CAPI support driver; reading non-standardized portions of pci configuration space; DDI debug ioctl on sbpcd driver; setting up serialports; sending raw qic-117 commands; enabling/disabling tagged queuing on SCSI controllers and sending arbitrary SCSI commands; setting encryption key on loopback filesystem; setting zone reclaim policy.

**sys\_boot** - Grant ability to reboot the system.

**sys\_chroot** - Allow use of the chroot(2) call.

**sys\_module** - Allow unrestricted kernel modification including but not limited to loading and removing kernel modules. Allows modification of kernels bounding capability mask. See sysctl.

**sys\_nice** - Grants privilege to change priority of any process, or scheduling algorithm used by any process.

**sys\_pacct** - Allow modification of accounting for any process.

**sys\_ptrace** - Allow a ptrace of any process.

**sys\_rawio** - Grant permission to use ioperm(2) and iopl(2) as well as the ability to send messages to USB devices via /proc/bus/usb.

**sys\_resource** - Override the following: resource limits; quota limits; reserved space on ext2 filesystem; size restrictions on IPC message queues; max number of consoles on console allocation; max number of keymaps. Set resource limits. Modify data journaling mode on ext3 filesystem. Allow more than 64hz interrupts from the real-time clock.

**sys\_time** - Grant permission to set system time and to set the real-time lock.

**sys\_tty\_config** - Grant permission to configure tty devices. Allow vhangup(2) call on a tty.

---

## cap2

**audit\_read** - Read audit messages from user space.

**block\_suspend** - Prevent system suspends.

**bpf** - Grant ability to perform the basic operations related to extended Berkeley Packet Filters.

**checkpoint\_restore** - Grant permission to checkpointing and restoring a process.

**mac\_admin** - Change MAC configuration, unused by SELinux.

**mac\_override** - Override MAC restrictions, unused by SELinux.

**perfmon** - Provide access to system performance monitoring and observability operations.

**syslog** - Allow configuration of kernel syslog (printk behaviour).

**wake\_alarm** - Trigger the system to wake up.

**epolwakeup** - Renamed to block\_suspend - left here so that ordering of capabilities doesn't change.

---

*SE-X Window stuff*

## class x\_drawable

The drawable parameter specifies the area into which the text will be drawn. It may be either a pixmap or a window.Some of the permission information has been extracted from an email describing them in terms of an MLS system.

**add\_child** - Add a new window. Normally SystemLow for MLS systems.

**blend** - There are two cases: 1) Allow a non-root window to have a transparent background. 2) The application is redirecting the contents of the window and its sub-windows into a memory buffer when using the Composite Extension. Only SystemHigh processes should have the blend permission on the root window.

**create** - Create a Drawable object.

**destroy** - Destroy a Drawable.

**get\_property** - Read property information. Normally SystemLow for MLS systems.

**getattr** - Get attributes from a drawable object. Most applications will need this so SystemLow.

**hide** - Hide a drawable object. Not applicable to the root windows as it cannot be hidden.

**list\_child** - Allows all child window IDs to be returned. From the root window it will show the client that owns the window and their stacking order. If hiding this information is required then processes should be SystemHigh.

**list\_property** - List property associated with a window. Normally SystemLow for MLS systems.

**manage** - Required to create a context, move and resize windows. Not applicable to the root windows as it cannot be resized etc.

**override** - Allow setting the override-redirect bit on the window. Not Applicable to the root windows as it cannot be overridden.

**read** - Read window contents. Note that this will also give read permission to all child windows, therefore (for MLS), only SystemHigh processes should have read permission on the root window.

**receive** - Allow receiving of events. Normally SystemLow for MLS systems (butcould leak information between clients running at different levels,therefore needs investigation).

**remove\_child** - Remove child window. Normally SystemLow for MLS systems.

**send** - Allow sending of events. Normally SystemLow for MLS systems (butcould leak information between clients running at different levels,therefore needs investigation).

**set\_property** - Set property. Normally SystemLow for MLS systems (but could leak information between clients running at different levels, therefore needs investigation. Polyinstantiation may be required).

**setattr** - Allow window attributes to be set. This permission protects operations on the root window such as setting the background image or colour, setting the colormap and setting the mouse cursor to display when the cursor is in the window, therefore only SystemHigh processes should have thesetattr permission.

**show** - Show a drawable object.

**write** - Draw within a window. Note that this will also give write permission to all child windows, therefore (for MLS), only SystemHigh processes should have write permission on the root window.

---

## class x\_screen

The specific screen available to the display. (X-server)(hostname:display\_number.screen)

**getattr** - Get attributes from a specific screen.

**hide\_cursor** - Hide cursor.

**saver\_getattr** - Get attributes from a screen saver.

**saver\_hide** - Hide saver.

**saver\_setattr** - Set the attributes to be used the next time the external screensaver is activated.

**saver\_show** - Show saver.

**setattr** - Set attributes of the specific screen.

**show\_cursor** - Show cursor.

---

## class x\_gc

The graphics contexts allow the X-server to cache information about how graphics requests should be interpreted. It reduces the network traffic.

**create** - Create Graphic Contexts object.

**destroy** - Free (dereference) a Graphics Contexts object.

**getattr** - Get attributes for Graphic Contexts object.

**setattr** - Set attributes for Graphic Contexts object.

**use** - Allow GC contexts to be used.

---

## class x\_font

An X-server resource for managing the different fonts.

**add\_glyph** - Create glyph for cursor.

**create** - Load a font.

**destroy** - Free (dereference) a font.

**getattr** - Obtain font names, path, etc.

**remove\_glyph** - Free glyph

**use** - Use a font for drawing.

---

## class x\_colormap

An X-server resource for managing colour mapping. A new colormap can be created using XCreateColormap.

**add\_color** - Add a colour.

**create** - Create a new Colormap.

**destroy** - Free a Colormap.

**getattr** - Get the color gamut of a screen.

**install** - Copy a virtual colormap into the display hardware.

**read** - Read color cells of colormap.

**remove\_color** - Remove a colour.

**uninstall** - Remove a virtual colormap from the display hardware.

**use** - Use a colormap.

**write** - Change color cells in colormap

---

## class x\_property

An InterClient Communications (ICC) service where each property has a name and ID (or Atom). Properties are attached to windows and can be uniquely identified by the window ID and property ID. XSELinux supports polyinstantiation of properties.

**append** - Append a property.

**create** - Create property object.

**destroy** - Free (dereference) a property object.

**getattr** - Get the attributes of a property.

**read** - Read a property.

**setattr** - Set the attributes of a property.

**write** - Write a property.

---

## class x\_selection

An InterClient Communications (ICC) service that allows two parties to communicate about passing information. The Information uses properties to define the format (e.g. whether text or graphics). XSELinux supports polyinstantiation of selections.

**getattr** - Get selection owner (XGetSelectionOwner).

**read** - Read the information from the selection owner.

**setattr** - Set the selection owner (XSetSelectionOwner).

**write** - Send the information to the selection requestor.

---

## class x\_cursor

The cursor on the screen.

**create** - Create an arbitrary cursor object.

**destroy** - Delete a cursor object.

**getattr** - Get attributes of the cursor.

**read** - Read the cursor.

**setattr** - Set attributes of the cursor.

**use** - Associate a cursor object with a window.

**write** - Write a cursor.

---

## class x\_client

The X-client connecting to the X-server.

**destroy** - Close down a client.

**getattr** - Get the attributes of an X client.

**manage** - Required to create an X-client context. (source code)

**setattr** - Set the attributes of an X client.

---

## class x\_device

These are any other devices used by the X-server as the keyboard and pointer devices have their own object classes.

*inherits x\_device*

---

## class x\_server

The X-server that manages the display, keyboard and pointer.

**debug** - Debug server.

**getattr** - Get input device attributes, such as keyboard mapping, pointer controls, etc.

**grab** - Grab server input, mouse or keyboard.

**manage** - Required to create a context. (source code)

**record** - Record server output.

**setattr** - Set input device attributes.

---

## class x\_extension

An X-Window extension that can be added to the X-server (such as the XSELinux object manager itself).

**query** - Query for an extension.

**use** - Use the extensions services.

---

## class x\_resource

These consist of Windows, Pixmaps, Fonts,Colormaps etc. that are classed as resources.

**read** - Allow reading a resource.

**write** - Allow writing to a resource.

---

## class x\_event

Manage X-server events.

**receive** - Receive an event.

**send** - Send an even.

---

## class x\_synthetic\_event

Manage some X-server events (e.g.config notify). Note the x\_event permissions will still be required (It's magic).

**receive** - Receive an event.

**send** - Send an event.

---

## class x\_application\_data

Not specifically used by XSELinux, however is used by userspace applications that need to manage copy and paste services (such as the CUT\_BUFFERs).

**copy** - Copy the data.

**paste** - Paste the data.

**paste\_after\_confirm** - Need to confirm that the paste is allowed.

---

## class x\_pointer

The mouse or other pointing device managed by the X-server.

*inherits x\_device*

---

## class x\_keyboard

The keyboard managed by the X-server.

*inherits x\_device*

---

## class db\_database

*inherits database*

**access** - Required to connect to the database - this is the minimum permission required by an SE-PostgreSQL client.

**install\_module** - Required to install a dynamic link library

**load\_module** - Required to load a dynamic link library.

**get\_param** - Deprecated.

**set\_param** - Deprecated.

---

## class db\_table

Table objects.

*inherits database*

**delete** - Required to delete from a table with a DELETE statement, or when removing the table contents with a TRUNCATE statement.

**insert** - Required to insert into a table with an INSERT statement, or when restoring it with a COPY FROM statement.

**lock** - Required to get a table lock with a LOCK statement.

**select** - Required to refer to a table with a SELECT statement or to dump the table contents with a COPY TO statement.

**update** - Required to update a table with an UPDATE statement.

---

## class db\_schema

Temporary scheme objects.

*inherits database*

**add\_name** - Add an object to the schema.

**remove\_name** - Remove an object from the schema.

**search** - Search for an object in the schema.

---

## class db\_procedure

*inherits database*

**entrypoint** - Execute as a trusted procedure.

**execute** - Execute a stored procedure.

**install** - Install a procedure.

---

## class db\_column

*inherits database*

**insert** - Required to insert a new entry using the INSERT statement.

**select** - Required to reference columns.

**update** - Required to update a table with an UPDATE statement.

---

## class db\_tuple

Tuple objects.

**delete** - Required to delete entries with a DELETE or TRUNCATE statement.

**insert** - Required when inserting a entry with an INSERT statement, or restoring tables with a COPY FROM statement.

**relabelfrom** & **relabelto** - The security context of an entry can be changed with an UPDATE to the security\_context column at which time relabel from and relabel to permission is evaluated. The client must have relabel from permission to the security context before the entry is changed, and relabel to permission to the security context after the entry is changed.

**select** - Required when: reading entries with a SELECT statement, returning entries that are subjects for updating queries with a RETURNING clause,or dumping tables with a COPY TO statement. Entries that the client does not have select permission on will be filtered from the result set.

**update** - Required when updating an entry with an UPDATE statement. Entries that the client does not have update permission on will not be updated.

**use** - Controls usage of system objects that require permission to "use" objects such as data types, table spaces and operators.

---

## class db\_blob

Binary large objects.

*inherits database*

**export** - Export a binary large object by calling the lo\_export() function.

**import** - Import a file as a binary large object by calling the lo\_import()function.

**read** - Read a binary large object using the loread() function.

**write** - Write a binary large object with the lowrite() function.

---

## class db\_view

*inherits database*

**expand** - Allows the expansion of a 'view'.

---

## class db\_sequence

A sequential number generator.

*inherits database*

**get\_value** - Get a value from the sequence generator object.

**next\_value** - Get and increment value.

**set\_value** - Set an arbitrary value.

---

## class db\_language

Support for script languages such as Perl and Tcl for SQL Procedures.

*inherits database*

**execute** - Allow the execution of a code block using a 'DO' statement.

**implement** - Checked when a procedure is constructed on this procedural language.

---

## class passwd

This is a userspace object for controlling changes to passwd information.

**chfn** - Change finger information. e.g real name, work room and phone and home phone.

**chsh** - Change login shell.

**crontab** - crontab on another user.

**passwd** - Update user password.

**rootok** - Allow update if the user is root and the process has the rootok PAM permission.

---

## class nscd

This is a userspace object for the Name Service Cache Daemon.

**admin** - Allow the nscd daemon to be shut down.

**getgrp** - Get group information.

**gethost** - Get host information.

**getnetgrp**

**getpwd** - Get password information.

**getserv**

**getstat** - Get the AVC stats from the nscd daemon.

**shmemgrp** - Get shmem group file descriptor.

**shmemhost** - Get shmem host descriptor.

**shmemnetgrp**

**shmempwd**

**shmemserv**

---

## class dbus

This is a userspace object for the D-BUS Messaging service that is required to run various services.

**acquire\_svc** - Open a virtual circuit (communications channel).

**send\_msg** - Send a message on the bus.

---

## class context

This is a userspace object for the translation daemon mcstransd. These permissions are required to allow translation and querying of level and ranges for MCS and MLS systems.

**contains** - Calculate a MLS subset.

**translate** - Translate a raw MLS label.

---

## class key

This is a kernel object to manage Keyrings.

**create** - Create a keyring.

**link** - Link a key into the keyring.

**read** - Read a keyring.

**search** - Search a keyring.

**setattr** - Change permissions on a keyring.

**view** - View a keyring.

**write** - Add a key to the keyring.

---

## class memprotect

This is a kernel object to protect lower memory blocks.

**mmap\_zero** - Mmap the first page of memory.

---

## class service

This is a userspace object to manage systemd services.

**disable** - Disable services.

**enable** - Enable services.

**reload** - Restart systemd services.

**start** - Start systemd services.

**status** - Read service status.

**stop** - Stop systemd services.

---

## class proxy

This is a userspace object for gssd services.

**read** - Read credentials.

*Define the access vector interpretation for controlling capabilities in user namespaces.*

---

## class infiniband\_pkey

A unique ID assigned to an InfiniBand partition.

**access** - Access to a InfiniBand partition.

---

## class infiniband\_endport

InfiniBand endport.

**manage\_subnet** - Manage the InfiniBand subnet.

---

## class cap\_userns

Define the access vector interpretation for controlling capabilities in user namespaces.

*inherits cap*

---

## class cap2\_userns

*inherits cap2*

---

## class bpf

Used to perform the basic operations related to extended Berkeley Packet Filters.

**map\_create** - Create a map and return a file descriptor that refers to the map.

**map\_read** - Look up an element by key in a specified map and return its value.

**map\_write** - Create or update an element (key/value pair) in a specified map.

**prog\_load** - Verify and load an eBPF program, returning a new file descriptor associated with the program.

**prog\_run** - Run an eBPF program

---

## class perf\_event

Used to manage access while attaching BPF programs to tracepoints, perf profiling and other operations from userspace.

**cpu** - Set up monitoring of CPU events.

**kernel** - Set up monitoring of kernel events.

**open** - Set up performance monitoring.

**read** - Called from the read(2) and mmap(2) syscalls for the event.

**tracepoint** - Set up tracepoint monitoring.

**write** - Called from the ioctl(2) syscalls for the event.

---

## class lockdown

*deprecated*

**integrity**

**confidentiality**

---

## class io\_uring

Used to control the ability to use special io\_uring features by the process. See also [the original kernel commit](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=740b03414b20e7f1879cd99aae27d8c401bbcbf9) for more details.

**override_creds** - Allow *source* to override its credentials to *target*.

**sqpoll** - Allow *source* to create an io\_uring kernel polling thread. *target* is always equal to *source*.

**cmd** - Allow *source* to pass commands to special file *target* (`IORING_OP_URING_CMD`). The semantics of the commands are defined by the kernel subsystem/module implementing the special file's operations and may be subject to other access checks. See also kernel commits [2a5840124009](https://git.kernel.org/torvalds/c/2a5840124009) and [f4d653dcaa4e](https://git.kernel.org/torvalds/c/f4d653dcaa4e).

---

## class user\_namespace

This class is used to control over the observability and access control over
user namespace creation.

See also kernel commits
[7cd4c5c2101c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=7cd4c5c2101cb092db00f61f69d24380cf7a0ee8) and
[ed5d44d42c95](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=ed5d44d42c95e8a13bb54e614d2269c8740667f9).

**create** - Allow *source* to create a user namespace object
