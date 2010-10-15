#
# Authors: Dan Walsh <dwalsh@redhat.com>
#
# Copyright (C) 2010 Red Hat, Inc.
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
import os 
from stat import *

import selinux
class plugin(Plugin):
    summary = _('''
    SELinux is preventing $SOURCE_PATH "$ACCESS" access to $TARGET_PATH.
    ''')

    problem_description = _('''
    SELinux denied access requested by $SOURCE. $TARGET_PATH may
    be a mislabeled. sshd is allowed to read content in /root/.ssh directory if it 
    is labeled correctly.
    ''')

    fix_description = _('''
    You can restore the default system context to this file by executing the
    restorecon command.  restorecon restore using restorecon -R /root/.ssh.
    ''')

    then_text = _('you must fix the labels.')
    do_text = "/sbin/restorecon -Rv /root/.ssh"

    def __init__(self):
        Plugin.__init__(self, __name__)
        self.level="yellow"
        self.fixable=True
        self.button_text=_("Restore Context")

    def analyze(self, avc):
        if avc.matches_source_types(['sshd_t'])           and \
                avc.matches_target_types(['admin_home_t'])            and \
                avc.all_accesses_are_in(avc.read_file_perms)  and \
                avc.has_tclass_in(['file', 'dir']):

            return self.report()

        return None
        
