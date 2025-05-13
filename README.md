# Fedora SELinux policy

This is SELinux policy based on [refpolicy](https://github.com/SELinuxProject/refpolicy) used in Fedora, Red Hat Enterprise Linux and CentOS Stream.

## Installation

The installation process is described in [INSTALL](INSTALL).

The default policy is installed to `/etc/selinux/fedora-selinux` and `/var/lib/selinux/fedora-selinux`.

The name and other options can be changed using variables like `NAME`, `TYPE`, ... variables, for more details see [README.build](README.build).
E.g. Fedora `targeted` policy uses the following options:

    DISTRO=redhat UBAC=n DIRECT_INITRC=n MONOLITHIC=n MLS_CATS=1024 MCS_CATS=1024 UNK_PERMS=allow NAME=targeted TYPE=mcs

## Contributing

There are several ways how to contribute:

### Report bugs

Either open issue in this project or file a bug in [Fedora Bugzilla](https://bugzilla.redhat.com)

### Pull requests

You can fork this repo and open a PR. Please use  good practices and use descriptive commit messages.
