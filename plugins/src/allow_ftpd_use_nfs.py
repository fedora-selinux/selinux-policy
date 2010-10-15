#
# Authors: Karl MacMillan <kmacmillan@mentalrootkit.com>
#
# Copyright (C) 2006 Red Hat, Inc.
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

import gettext
translation=gettext.translation('setroubleshoot-plugins', fallback=True)
_=translation.ugettext

from setroubleshoot.util import *
from setroubleshoot.Plugin import Plugin

class plugin(Plugin):
    summary = _('''
    SELinux prevented the ftp daemon from $ACCESS files stored on a NFS filesytem.
    ''')
    
    problem_description = _('''
    SELinux prevented the ftp daemon from $ACCESS files stored on a NFS filesystem.
    NFS (Network Filesystem) is a network filesystem commonly used on Unix / Linux
    systems.
    
    The ftp daemon attempted to read one or more files or directories from
    a mounted filesystem of this type.  As NFS filesystems do not support
    fine-grained SELinux labeling, all files and directories in the
    filesystem will have the same security context.
    
    If you have not configured the ftp daemon to read files from a NFS filesystem
    this access attempt could signal an intrusion attempt.
    ''')
    
    fix_description = _('''
    Changing the "allow_ftpd_use_nfs" boolean to true will allow this access:
    "setsebool -P allow_ftpd_use_nfs=1."
    ''')
    
    fix_cmd = 'setsebool -P allow_ftpd_use_nfs=1'
    
    rw_fix_description = _(''' Changing the "allow_ftpd_use_nfs" and
    "$WRITE_BOOLEAN" booleans to true will allow this access:
    "setsebool -P allow_ftpd_use_nfs=1 $WRITE_BOOLEAN=1".
    warning: setting the "$WRITE_BOOLEAN" boolean to true will
    allow the ftp daemon to write to all public content (files and
    directories with type public_content_t) in addition to writing to
    files and directories on NFS filesystems.  ''')
    
    rw_fix_cmd = 'setsebool -P allow_ftpd_use_nfs=1 $WRITE_BOOLEAN=1'
     
    if_text = _("you want to allow ftpd to write to nfs file systems")
    then_text = _("you must tell SELinux about this")
    do_text = 'setsebool -P allow_ftpd_use_nfs=1 allow_ftpd_anon_write=1'
            
    def __init__(self):
        Plugin.__init__(self, __name__)

    def analyze(self, avc):
        if avc.matches_source_types(['ftpd_t']) and \
           avc.matches_target_types(['nfs_t'])  and \
           avc.has_tclass_in(['file', 'dir']):
            # If only read access is requested then only the
            # allow_ftp_use_nfs boolean needs to be set. Write
            # access also requires the allow_ftpd_anon_write
            if avc.all_accesses_are_in(avc.create_file_perms + avc.rw_dir_perms):
                return self.report(args=("allow_ftpd_use_nfs", "allow_ftpd_anon_write"))
        return None
