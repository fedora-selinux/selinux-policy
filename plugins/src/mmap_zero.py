# @author Thomas Liu <tliu@redhat.com>
# @author Dan Walsh <dwalsh@redhat.com>
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

class plugin(Plugin):
    summary =_('''
    Your system may be seriously compromised! $SOURCE_PATH attempted to mmap low kernel memory.
    ''')

    problem_description = _('''
    SELinux has denied the $SOURCE the ability to mmap low area of the kernel 
    address space.  The ability to mmap a low area of the address space, as 
    configured by /proc/sys/kernel/mmap_min_addr.  Preventing such mappings 
    helps protect against exploiting null deref bugs in the kernel. All 
    applications that need this access should have already had policy written 
    for them.  If a compromised application tries modify the kernel this AVC 
    would be generated. This is a serious issue. Your system may very well be 
    compromised.
    ''')

    fix_description = ("Contact your security administrator and report this issue.")
    fix_cmd = ""
    if_text = _("you do not think $SOURCE_PATH should need to mmap low memory in the kernel.")
    then_text = _("you may be under attack by a hacker, this is a very dangerous access.")
    do_text = _("Contact your security administrator and report this issue.")
    def __init__(self):
        Plugin.__init__(self, __name__)
        self.set_priority(10)
        self.level="red"
    def analyze(self, avc):
        if avc.has_any_access_in(['mmap_zero']):
            # MATCH
            return self.report()
        return None
