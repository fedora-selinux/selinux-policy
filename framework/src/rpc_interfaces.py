# Authors: John Dennis <jdennis@redhat.com>
#
# Copyright (C) 2006,2007,2008 Red Hat, Inc.
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

from setroubleshoot.rpc import rpc_method, rpc_arg_type, rpc_callback, rpc_signal
from setroubleshoot.signature import *

__all__ = [
    'SETroubleshootServerInterface',
    'SETroubleshootDatabaseInterface',
    'SETroubleshootDatabaseNotifyInterface',
    'SEAlertInterface',
    ]

#-----------------------------------------------------------------------------

class SETroubleshootServerInterface:

    #
    # database_bind
    #
    @rpc_method('SETroubleshootServer')
    def database_bind(self, database_name):
        pass

    @rpc_callback('SETroubleshootServer', 'database_bind')
    @rpc_arg_type('SETroubleshootServer', SEDatabaseProperties)
    def database_bind_callback(self, properties):
        pass

    #
    # logon
    #
    @rpc_method('SETroubleshootServer')
    def logon(self, type, username, password):
        pass

    @rpc_callback('SETroubleshootServer', 'logon')
    def logon_callback(pkg_version, rpc_version):
        pass


    #
    # email_recipients
    #
    @rpc_method('SETroubleshootServer')
    def query_email_recipients(self):
        pass

    @rpc_callback('SETroubleshootServer', 'query_email_recipients')
    @rpc_arg_type('SETroubleshootServer', SEEmailRecipientSet)
    def query_email_recipients_callback(self, recipients):
        pass

    @rpc_method('SETroubleshootServer')
    @rpc_arg_type('SETroubleshootServer', SEEmailRecipientSet)
    def set_email_recipients(self, recipients):
        pass


#-----------------------------------------------------------------------------

class SETroubleshootDatabaseInterface:
    #
    # delete_signature
    #
    @rpc_method('SETroubleshootDatabase')
    @rpc_arg_type('SETroubleshootDatabase', SEFaultSignature)
    def delete_signature(self, sig):
        pass

    #
    # evaluate_alert_filter
    #
    @rpc_method('SETroubleshootDatabase')
    @rpc_arg_type('SETroubleshootDatabase', SEFaultSignature, str)
    def evaluate_alert_filter(self, sig, username):
        pass

    @rpc_callback('SETroubleshootDatabase', 'evaluate_alert_filter')
    def evaluate_alert_filter_callback(self, result):
        pass

    #
    # get_properties
    #
    @rpc_method('SETroubleshootDatabase')
    def get_properties(self):
        pass

    @rpc_callback('SETroubleshootDatabase', 'get_properties')
    @rpc_arg_type('SETroubleshootDatabase', SEDatabaseProperties)
    def get_properties_callback(self, properties):
        pass

    #
    # lookup_local_id
    #
    @rpc_method('SETroubleshootDatabase')
    def lookup_local_id(self, local_id):
        pass

    @rpc_callback('SETroubleshootDatabase', 'lookup_local_id')
    @rpc_arg_type('SETroubleshootDatabase', SEFaultSignatureInfo)
    def lookup_local_id_callback(self, siginfo):
        pass

    #
    # query_alerts
    #
    @rpc_method('SETroubleshootDatabase')
    def query_alerts(self, criteria):
        pass

    @rpc_callback('SETroubleshootDatabase', 'query_alerts')
    @rpc_arg_type('SETroubleshootDatabase', SEFaultSignatureSet)
    def query_alerts_callback(self, sigs):
        pass

    #
    # set_filter
    #
    @rpc_method('SETroubleshootDatabase')
    @rpc_arg_type('SETroubleshootDatabase', SEFaultSignature, str, int, str)
    def set_filter(self, sig, username, filter_type, data):
        pass

    #
    # set_user_data
    #
    @rpc_method('SETroubleshootDatabase')
    @rpc_arg_type('SETroubleshootDatabase', SEFaultSignature, str, str, str)
    def set_user_data(self, sig, username, key, value):
        pass


#-----------------------------------------------------------------------------
class SETroubleshootDatabaseNotifyInterface:
    #
    # signatures_updated
    #
    @rpc_signal('SETroubleshootDatabaseNotify')
    def signatures_updated(type, item):
        pass

#-----------------------------------------------------------------------------

class SEAlertInterface:

    #
    # alert
    #
    @rpc_signal('SEAlert')
    @rpc_arg_type('SEAlert', SEFaultSignatureInfo)
    def alert(siginfo):
        pass


