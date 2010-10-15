#
# Copyright (C) 2006,2008 Red Hat, Inc.
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
    SELinux is preventing Samba ($SOURCE_PATH) "$ACCESS" access to $TARGET_PATH.
    ''')

    problem_description = _('''
    SELinux denied samba access to $TARGET_PATH.
    If you want to share this directory with samba it has to have a file context label of
    samba_share_t. If you did not intend to use $TARGET_PATH as a samba repository
    it could indicate either a bug or it could signal a intrusion attempt.
    Please refer to 'man samba_selinux' for more information on setting up Samba and SELinux.
    ''')

    fix_description = _('''
    You can alter the file context by executing chcon -R -t samba_share_t '$TARGET_PATH'
    You must also change the default file context files on the system in order to preserve them even on a full relabel.  "semanage fcontext -a -t samba_share_t '$FIX_TARGET_PATH'"
    ''')

    fix_cmd = "chcon -R -t samba_share_t '$TARGET_PATH'"
    then_text = _("You need to change the label on '$FIX_TARGET_PATH'")
    def get_do_text(self, avc, tclass):
        dpath = ""
        rflag = ""
        if tclass == "dir":
            dpath = "(/.*)?"
            rflag = "-R"
            
        return _("""# semanage fcontext -a -t samba_share_t '$FIX_TARGET_PATH%s'
# restorecon %s -v '$FIX_TARGET_PATH'""") % (dpath, rflag)

    def __init__(self):
        Plugin.__init__(self, __name__)
        self.set_priority(51)

    def analyze(self, avc):
        if avc.matches_source_types(['smbd_t'])                                                                              and \
           not avc.matches_target_types(['httpd_.*_content_t', 'rsync_data_t', 'home_root_t', '.*_home_dir_t', '.*_home_t']) and \
           avc.all_accesses_are_in(avc.create_file_perms + avc.create_dir_perms)                                             and \
           avc.has_tclass_in(['file', 'dir'])                                                                                and \
           avc.path_is_not_standard_directory():
            # MATCH
            return self.report(avc.tclass)
        else:
            return None

