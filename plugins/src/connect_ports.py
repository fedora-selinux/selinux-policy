#
# Copyright (C) 2006-2010 Red Hat, Inc.
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
    SELinux is preventing $SOURCE_PATH from connecting to port $PORT_NUMBER.
    ''')

    problem_description = _('''
    SELinux has denied $SOURCE from connecting to a network port $PORT_NUMBER which does not have an SELinux type associated with it.
    If $SOURCE should be allowed to connect on $PORT_NUMBER, use the <i>semanage</i> command to assign $PORT_NUMBER to a port type that $SOURCE_TYPE can connect to (%s). 
    \n\nIf $SOURCE is not supposed
    to connect to $PORT_NUMBER, this could signal a intrusion attempt.
    ''')
    

    fix_description = _('''
    If you want to allow $SOURCE to connect to $PORT_NUMBER, you can execute \n
    # semanage port -a -t PORT_TYPE -p %s $PORT_NUMBER\n
    where PORT_TYPE is one of the following: %s.
    ''')

    fix_cmd = ''
    if_text = 'you want to allow $SOURCE_PATH to connect to network port $PORT_NUMBER'
    then_text = 'you need to modify the port type.'
    
    def get_do_text(self, avc, option):
        return _("""# semanage port -a -t PORT_TYPE -p %s $PORT_NUMBER
    where PORT_TYPE is one of the following: %s.""") % option
    
    def __init__(self):
        Plugin.__init__(self, __name__)
        self.set_priority(100)

    def analyze(self, avc):
        if avc.matches_target_types(['hi_reserved_port_t','reserved_port_t', 'port_t']) and \
           avc.has_any_access_in(['name_connect']):
            # MATCH
            target_types = ", ".join(avc.allowed_target_types())
            return self.report( (avc.tclass.split("_")[0], target_types))

        return None



