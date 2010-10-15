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
    SELinux prevented $SOURCE from mounting on the file or directory
    "$TARGET_PATH" (type "$TARGET_TYPE").
    ''')

    problem_description = _('''
    SELinux prevented $SOURCE from mounting a filesystem on the file
    or directory "$TARGET_PATH" of type "$TARGET_TYPE". By default
    SELinux limits the mounting of filesystems to only some files or
    directories (those with types that have the mountpoint attribute). The
    type "$TARGET_TYPE" does not have this attribute. You can change the 
    label of the file or directory.
    ''')

    fix_description = _('''
    Changing the file_context to mnt_t will allow mount to mount the file system:
    "chcon -t mnt_t '$TARGET_PATH'."
    You must also change the default file context files on the system in order to preserve them even on a full relabel.  "semanage fcontext -a -t mnt_t '$FIX_TARGET_PATH'"
    ''')
    if_text = _("you want to allow $SOURCE_PATH to mount on $TARGET_PATH.")
    then_text = _("you must change the labeling on $TARGET_PATH.")
    do_text = """# semanage fcontext -a -t mnt_t '$FIX_TARGET_PATH'
# restorecon -v $TARGET_PATH"""

    fix_cmd = "chcon -t mnt_t '$TARGET_PATH'"
    
    def __init__(self):
        Plugin.__init__(self, __name__)

    def analyze(self, avc):
        if avc.matches_source_types(['mount_t'])  and \
           avc.has_any_access_in(['mounton'])     and \
           avc.path_is_not_standard_directory():
            # MATCH
            return self.report()
        else:
            return None
