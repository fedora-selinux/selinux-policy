# @author Dan Walsh <dwalsh@redhat.com>
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
import re
import os, commands

class plugin(Plugin):
    summary =_('''
Ignore if IPV6 is disabled.
    ''')

    problem_description = ""

    fix_description = ""

    fix_cmd = ""

    def __init__(self):
        Plugin.__init__(self, __name__)
        self.level = "white"

    def analyze(self, avc):
        if avc.has_any_access_in(['module_request']) and avc.kmod == "net-pf-10":
            if (commands.getstatusoutput("egrep 'blacklist[ \t].*ipv6' /etc/modprobe.d/ -R")[0] == 0):
                # MATCH, White means ignore avc
                return self.report()
        return None
