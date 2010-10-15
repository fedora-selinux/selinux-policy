# @author Miroslav Grepl<mgrepl@redhat.com>
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

class plugin(Plugin):
    summary =_('''
    SELinux is preventing $SOURCE_PATH the "sys_resource" capability. 
    ''')

    problem_description = _('''
    Confined domains should not require "sys_resource". This usually means that     your system is running out of disk space. Please clear up the disk and this
    AVC message should go away. If this AVC continues after you clear up the disk space, please report this as a bug. 
    ''')

    fix_description = "Clear up your disk." 
    fix_cmd = ""
    if_text = _("you do not want to get this AVC any longer. These AVC's are caused by running out of resources, usually disk space on your / partition.")
    then_text = _("you must cleanup diskspace or make sure you are not running too many processes.")
    do_text = "Clear up your disk." 

    def __init__(self):
        Plugin.__init__(self, __name__)
        self.level="green"

    def analyze(self, avc):
        if avc.has_any_access_in(['sys_resource']):
            # MATCH
            return self.report()
        return None
