# Authors: Karl MacMillan <kmacmillan@mentalrootkit.com>
#
# Copyright (C) 2006,2007,2008 Red Hat, Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#

"""Access control for setroubleshoot. For now this is only used for
determining which users are allowed to connect to the server: see
UserServerAccess for more information."""

import struct
import socket as Socket

from setroubleshoot.config import get_config
from setroubleshoot.log import *

__all__ = [
    'ServerAccess',
    ]
           

# SO_PEERCRED is not defined by the socket class unless patched
# SO_PEERCRED's value is architecture dependent
# alpha, mips:    18
# parisc:         0x4011
# powerpc:        21
# sparc, sparc64: 0x0040
# default:        17
try:
    SO_PEERCRED = Socket.SO_PEERCRED
except AttributeError:
    import os
    import re
    machine = os.uname()[4]
    if   re.search(r'^i\d86',           machine): SO_PEERCRED = 17     # i386,i486,i586,i686, etc.
    elif re.search(r'^x86_64',          machine): SO_PEERCRED = 17     # x86_64
    elif re.search(r'^(ppc|powerpc)',   machine): SO_PEERCRED = 21     # ppc
    elif re.search(r'^(alpha|mips)',    machine): SO_PEERCRED = 18     # alpha, mips
    elif re.search(r'^sparc',           machine): SO_PEERCRED = 0x0040 # sparc
    elif re.search(r'^parisc',          machine): SO_PEERCRED = 0x4011 # parisc
    else: SO_PEERCRED = 17 
    #print "hardcoding SO_PEERCRED=%s" % SO_PEERCRED


class ServerAccess:
    """
    Determine if a user should be given access to the server based
    on the configuration file.
    """

    privileges = {'client' : {'wildcard':True},
                  'fix_cmd': {'wildcard':False},
                 }
    
    def __init__(self):
        # No attempt is made to validate the user name is valid. This
        # makes the configuration file more relaxed. Additionally, the
        # server (which we assume is the only user of this class) will
        # be getting uids from the kernel, so there shouldn't be access
        # requested from invalid uids

        self.privileges = {}
        for privilege in ServerAccess.privileges.keys():
            self.privileges[privilege] = self.init_privilege(privilege)

    def init_privilege(self, privilege):
        cfg_names = [name.strip() for name in \
                     get_config('access', '%s_users' % privilege).split(',')]
        return cfg_names

    def valid_privilege(self, privilege):
        valid = ServerAccess.privileges.has_key(privilege)
        if valid: return True
        log_program.error("unknown access privilege (%s)", privilege)
        return False

    def unrestricted_privilege(self, privilege):
        if not self.valid_privilege(privilege): return False

        if not ServerAccess.privileges[privilege]['wildcard']:
            return False
        return '*' in self.privileges[privilege]

    def user_allowed(self, privilege, user):
        """
        Determine if the given user name is allowed access.
        Returns True if access should be given, False if not.
        """
        if not self.valid_privilege(privilege): return False

        if self.unrestricted_privilege(privilege):
            return True
        if user in self.privileges[privilege]:
            return True
        else:
            return False

    def uid_allowed(self, privilege, uid):
        """
        Determine if the given uid is allowed access. No error
        is returned if the uid is invalid (False is returned).
        Returns True if access should be given, False if not.
        """

        if not self.valid_privilege(privilege): return False

        if self.unrestricted_privilege(privilege):
            return True
        try:
            import pwd
            pwd_entry = pwd.getpwuid(uid)
        except KeyError:
            # Not a valid uid - so they don't get access. This
            # is not an error.
            return False

        return self.user_allowed(privilege, pwd_entry[0])

    def get_credentials(self, sock):
        """Obtain the effective user and group IDs of the process on
        the other end of a socket. SO_PEERCRED is used so the information
        returned is generally trustworthy (though root processes can
        impersonate any uid/gid)."""
        
        pid = uid = gid = None
        try:
            # socket attributes family,type,proto,timeout available only in Python >= 2.5
            family = sock.family
            if family != Socket.AF_UNIX:
                return uid, gid
        except AttributeError:
            # rely on pid,uid,gid being -1 if family is not AF_UNIX
            pass

        format_ucred = 'III' # pid_t, uid_t, gid_t
        sizeof_ucred = struct.calcsize(format_ucred)

        try:
            ucred = sock.getsockopt(Socket.SOL_SOCKET, SO_PEERCRED, sizeof_ucred)
            pid, uid, gid = struct.unpack(format_ucred, ucred)
            if pid == -1: pid = None
            if uid == -1: uid = None
            if gid == -1: gid = None
        except Exception, e:
            pid = uid = gid = None
            log_program.error("get_credentials(): %s", e)

        return uid, gid


