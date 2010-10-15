# @author Thomas Liu <tliu@redhat.com>
#
# Copyright (C) 2009 Red Hat, Inc.
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

if_text = _("you did not directly cause this AVC through testing.")
then_text = _("if you think that you might have been hacked")
do_text = _("Contact your security administrator and report this issue.")

class plugin(Plugin):
    summary =_('''
    Your system may be seriously compromised! $SOURCE_PATH tried to modify SELinux enforcement.
    ''')

    problem_description = _('''
    SELinux has prevented $SOURCE from writing to a file under /selinux.
    Files under /selinux control the way SELinux is configured.
    All programs that need to write to files under /selinux should have already had policy
    written for them. If a compromised application tries to turn off SELinux
    this AVC will be generated. This is a serious issue. Your system may very
    well be compromised.
    ''')

    fix_description = "Contact your security administrator and report this issue." 
    fix_cmd = ""

    if_text = _("you believe $SOURCE_PATH tried to disable SELinux.")
    then_text = _("you may be under attack by a hacker, since confined applications should never need this access.")
    do_text = _("Contact your security administrator and report this issue.")

    def __init__(self):
        Plugin.__init__(self, __name__)
        self.level="red"

    def analyze(self, avc):
        if avc.has_any_access_in(['write'])        and \
           avc.matches_target_types(['security_t']):
            # MATCH
            return self.report()
        return None
