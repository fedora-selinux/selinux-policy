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
    SELinux is preventing the $SOURCE_PATH from executing potentially mislabeled files $TARGET_PATH.
    ''')

    problem_description = _('''
    SELinux has denied the $SOURCE_PATH from executing potentially
    mislabeled files $TARGET_PATH.  Automounter can be setup to execute
    configuration files. If $TARGET_PATH is an automount executable
    configuration file it needs to have a file label of bin_t.
    If automounter is trying to execute something that it is not supposed to, this could indicate an intrusion attempt.
    ''')

    fix_description = _('''
    If you want to change the file context of $TARGET_PATH so that the automounter can execute it you can execute "chcon -t bin_t $TARGET_PATH".  If you want this to survive a relabel, you need to permanently change the file context: execute  "semanage fcontext -a -t bin_t '$FIX_TARGET_PATH'".
    ''')

    fix_cmd = 'chcon -t bin_t $TARGET_PATH'

    then_text = "You need to change the label on '$FIX_TARGET_PATH'"

    do_text = "chcon -t bin_t '$FIX_TARGET_PATH'"

    def __init__(self):
        Plugin.__init__(self, __name__)

    def analyze(self, avc):
        if avc.matches_source_types(['automount_t'])                 and \
           avc.all_accesses_are_in(['execute', 'execute_no_trans'])  and \
           avc.has_tclass_in(['file']):
            # MATCH
            return self.report()
        return None

