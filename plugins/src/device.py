#
# Authors: Karl MacMillan <kmacmillan@mentalrootkit.com>
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
    summary = _('''
    SELinux is preventing $SOURCE_PATH "$ACCESS" access to device $TARGET_PATH. 
    ''')

    problem_description = _('''

    SELinux has denied $SOURCE "$ACCESS" access to device $TARGET_PATH.
    $TARGET_PATH is mislabeled, this device has the default label of the /dev directory, which should not
    happen.  All Character and/or Block Devices should have a label.

    You can attempt to change the label of the file using

    restorecon -v '$TARGET_PATH'.

    If this device remains labeled device_t, then this is a bug in SELinux policy.

    Please file a bg report.

    If you look at the other similar devices labels, ls -lZ /dev/SIMILAR, and find a type that would work for $TARGET_PATH,
    you can use chcon -t SIMILAR_TYPE '$TARGET_PATH', If this fixes the problem, you can make this permanent by executing
    semanage fcontext -a -t SIMILAR_TYPE '$FIX_TARGET_PATH'

    If the restorecon changes the context, this indicates that the application that created the device, created it without
    using SELinux APIs.  If you can figure out which application created the device, please file a bug report against this application.
    
    ''')

    fix_description = _('''
    Attempt restorecon -v '$TARGET_PATH' or chcon -t SIMILAR_TYPE '$TARGET_PATH'
    ''')

    then_text = _("You need to change the label on $TARGET_PATH to a type of a similar device.")
    do_text = _("""# semanage fcontext -a -t SIMILAR_TYPE '$FIX_TARGET_PATH'
# restorecon -v '$FIX_TARGET_PATH'""")

    fix_cmd = ''
    
    def __init__(self):
        Plugin.__init__(self, __name__)

    def analyze(self, avc):
        if avc.matches_target_types(['device_t']) and \
           avc.has_tclass_in(['chr_file', 'blk_file']):
            # MATCH
            return self.report()
        return None
