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
    SELinux is preventing $SOURCE_PATH "$ACCESS" to $TARGET_PATH.
    ''')

    problem_description = _('''
    SELinux denied $SOURCE access to $TARGET_PATH.
    If this is a swapfile it has to have a file context label of
    swapfile_t. If you did not intend to use
    $TARGET_PATH as a swapfile it probably indicates a bug, however it could also
    signal a intrusion attempt.
    ''')

    fix_description = _('''
    You can alter the file context by executing chcon -t swapfile_t '$TARGET_PATH'
    You must also change the default file context files on the system in order to preserve them even on a full relabel.  "semanage fcontext -a -t swapfile_t '$FIX_TARGET_PATH'"
    ''')

    fix_cmd = "chcon -t swapfile_t '$TARGET_PATH'"

    then_text = _("You need to change the label on '$FIX_TARGET_PATH'")
    do_text = """# semanage fcontext -a -t swapfile_t '$FIX_TARGET_PATH'
# restorecon -v '$FIX_TARGET_PATH'"""
    def __init__(self):
        Plugin.__init__(self, __name__)
        self.level="green"

    def analyze(self, avc):
        if avc.matches_source_types(['fsadm_t'])                           and \
           avc.all_accesses_are_in(['read', 'write', 'getattr', 'swapon']) and \
           avc.has_tclass_in(['file']):
            # MATCH
            return self.report()
        else:
            return None

