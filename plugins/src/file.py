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
    SELinux is preventing access to files with the label, file_t.
    ''')

    problem_description = _('''
    SELinux permission checks on files labeled file_t are being
    denied.  file_t is the context the SELinux kernel gives to files
    that do not have a label. This indicates a serious labeling
    problem. No files on an SELinux box should ever be labeled file_t.
    If you have just added a disk drive to the system you can
    relabel it using the restorecon command.  For example if you saved the 
home directory from a previous installation that did not use SELinux, 'restorecon -R -v /home' will fix the labels.  Otherwise you should
    relabel the entire file system.
    ''')

    fix_description = _('''
    You can execute the following command as root to relabel your
    computer system: "touch /.autorelabel; reboot"
    ''')

    if_text = _('this is a newly created file system.')
    then_text = _('you need to add labels to it.')
    do_text = '/sbin/restorecon -v $TARGET_PATH'
    
    def __init__(self):
        Plugin.__init__(self,__name__)
        self.level="green"

    def analyze(self, avc):
        if avc.matches_target_types(['file_t']):
            # MATCH
            return self.report()
        else:
            return None
