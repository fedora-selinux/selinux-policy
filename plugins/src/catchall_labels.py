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
    SELinux has denied the $SOURCE access to potentially
    mislabeled files $TARGET_PATH.  This means that SELinux will not
    allow httpd to use these files. If httpd should be allowed this access to these files you should change the file context to one of the following types, %s.
    Many third party apps install html files
    in directories that SELinux policy cannot predict.  These directories
    have to be labeled with a file context which httpd can access.
    ''')

    then_text = _("You need to change the label on '$FIX_TARGET_PATH")

    def get_do_text(self, avc, args):
        return _("""# semanage fcontext -a -t FILE_TYPE '$FIX_TARGET_PATH'
where FILE_TYPE is one of the following: %s. 
Then execute: 
restorecon -v '$FIX_TARGET_PATH'""") % ", ".join(args)

    def __init__(self):
        Plugin.__init__(self, __name__)
        self.set_priority(5)

    def analyze(self, avc):
        if avc.matches_target_types(['file_t', 'unlabeled_t', 'usr_t', 'etc_t', 'mnt_t', 'var_t', 'var_lib_t', 'default_t']) and \
                avc.has_tclass_in(['dir', 'file', 'lnk_file', 'sock_file']):
            return self.report(avc.allowed_target_types())
        return None
