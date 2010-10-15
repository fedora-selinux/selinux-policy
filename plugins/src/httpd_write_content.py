#
# Authors: Dan Walsh <dwalsh@redhat.com>
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

    problem_description = _('''
    SELinux prevented httpd $ACCESS access to $TARGET_PATH.

    httpd scripts are not allowed to write to content without explicit 
    labeling of all files.  If $TARGET_PATH is writable content. it needs 
    to be labeled httpd_sys_rw_content_t or if all you need is append you can label it httpd_sys_ra_content_t.   Please refer to 'man httpd_selinux' for more information on setting up httpd and selinux.
    ''')
    
    fix_cmd = "chcon -R -t httpd_sys_rw_content_t '$TARGET_PATH'"
    
    then_text = _("You need to change the label on '$FIX_TARGET_PATH'")
    do_text = """# semanage fcontext -a -t httpd_sys_rw_content_t '$FIX_TARGET_PATH'
# restorecon -v '$FIX_TARGET_PATH'"""

    def __init__(self):
        Plugin.__init__(self, __name__)
        self.set_priority(100)
        
    def analyze(self, avc):
        if avc.matches_source_types(['httpd_t', 'httpd_sys_script_t'])  and \
           avc.matches_target_types(['httpd_sys_content_t'])                     and \
           avc.has_tclass_in(['file', 'dir']):

            if avc.all_accesses_are_in(avc.create_file_perms + avc.rw_dir_perms):
                return self.report()

        return None
