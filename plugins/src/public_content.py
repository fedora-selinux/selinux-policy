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
    summary =_('''
    SELinux is preventing $SOURCE_PATH "$ACCESS" access to $TARGET_PATH.
    ''')

    problem_description = _('''
    SELinux denied access to $TARGET_PATH requested by $SOURCE.
    $TARGET_PATH has a context used for sharing by a different program. If you
    would like to share $TARGET_PATH from $SOURCE also, you need to
    change its file context to public_content_t.  If you did not intend to
    allow this access, this could signal an intrusion attempt.
    ''')

    fix_description = _('''
    You can alter the file context by executing chcon -t public_content_t '$TARGET_PATH'
    You must also change the default file context files on the system in order to preserve them even on a full relabel.  "semanage fcontext -a -t public_content_t '$FIX_TARGET_PATH'"
    ''')

    fix_cmd = "chcon -t public_content_t '$TARGET_PATH'"
    
    def __init__(self):
        Plugin.__init__(self, __name__)
        self.set_priority(8)

    if_text=_("you want to allow want to treat $TARGET_PATH as pubic content")
    then_text = _("You need to change the label on 'TARGET_PATH' to public_content_t or public_content_rw_t.")
    do_text = """# semanage fcontext -a -t public_content_t '$FIX_TARGET_PATH'
# restorecon -v '$FIX_TARGET_PATH'"""


    def analyze(self, avc):
        if avc.matches_source_types(['smbd_t', 'httpd_t', 'ftpd_t', 'httpd_sys_script_t', 'nfsd_t', 'rsync_t'])  and \
           avc.matches_target_types(['samba_share_t', 'httpd_.*_content_t', 'rsync_data_t'])                     and \
           avc.all_accesses_are_in(avc.r_file_perms + avc.r_dir_perms):
            # MATCH
            return self.report()
        else:
            return None

