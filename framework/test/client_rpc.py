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

__all__ = [
    'ServerConnectionHandler',
]

import gobject
import socket as Socket

from setroubleshoot.config import parse_config_setting, get_config
from setroubleshoot.rpc import *
from setroubleshoot.log import *
from setroubleshoot.rpc_interfaces import *
from setroubleshoot.signature import *
from setroubleshoot.util import *

class TestDatabaseInterface:
    #
    # bogus
    #
    @rpc_method('SETroubleshootDatabase')
    def bogus(self):
        pass

    @rpc_callback('SETroubleshootDatabase', 'bogus')
    def bogus_callback(self, sigs):
        pass

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
    def get_properties(self, bogus_param):
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


class ServerConnectionHandler(RpcChannel,
                              SETroubleshootServerInterface,
                              TestDatabaseInterface,
                              gobject.GObject):
    __gsignals__ = {
        'alert':
        (gobject.SIGNAL_RUN_LAST, gobject.TYPE_NONE, (gobject.TYPE_PYOBJECT,)),
        'connection_state_changed': # callback(connection_state, flags, flags_added, flags_removed):
        (gobject.SIGNAL_RUN_LAST, gobject.TYPE_NONE, (gobject.TYPE_PYOBJECT, gobject.TYPE_INT, gobject.TYPE_INT, gobject.TYPE_INT)),
        'signatures_updated': 
        (gobject.SIGNAL_RUN_LAST, gobject.TYPE_NONE, (gobject.TYPE_PYOBJECT, gobject.TYPE_PYOBJECT)),
        'database_bind': 
        (gobject.SIGNAL_RUN_LAST, gobject.TYPE_NONE, (gobject.TYPE_PYOBJECT, gobject.TYPE_PYOBJECT)),
        'async-error': # callback(method, errno, strerror)
        (gobject.SIGNAL_RUN_LAST, gobject.TYPE_NONE, (gobject.TYPE_STRING, gobject.TYPE_INT, gobject.TYPE_STRING)),
        }

    def __init__(self, username):
        RpcChannel.__init__(self, channel_type = 'sealert')
        gobject.GObject.__init__(self)
        self.connection_state.connect('changed', self.on_connection_state_change)

        self.connect_rpc_interface('SEAlert', self)
        self.connect_rpc_interface('SETroubleshootDatabaseNotify', self)

        self.pkg_version = get_config('general','pkg_version')
        self.rpc_version = get_config('general','rpc_version')
        self.username = username
        self.retry_connection_if_closed = False
        self.connection_retry = Retry(self.retry_connection, self.get_connection_retry_interval, notify_interval=1.0)
        self.report_connect_failure = True
        self.database_name = 'audit_listener'

    def on_connection_state_change(self, connection_state, flags, flags_added, flags_removed):
        if debug:
            log_program.debug("%s.on_connection_state_change: connection_state=%s flags_added=%s flags_removed=%s address=%s",
                              self.__class__.__name__, connection_state,
                              connection_state.flags_to_string(flags_added), connection_state.flags_to_string(flags_removed),
                              self.socket_address)
        self.emit('connection_state_changed', connection_state, flags, flags_added, flags_removed)

        if (flags_removed & ConnectionState.OPEN) or (flags_added & (ConnectionState.HUP | ConnectionState.ERROR)):
            if self.retry_connection_if_closed and not (flags & ConnectionState.RETRY):
                self.connection_state.update(ConnectionState.RETRY)
                self.connection_retry.start()

    # Retry Behavior:
    #
    # Started when:
    # Connection lost is detected, however must not start if deliberate close is requested
    # Stopped when:
    # 1) successful open
    # 2) deliberate close

    def open(self, socket_address = None):
        if debug:
            log_communication.debug("%s.open: new addr = %s, existing %s %s",
                                    self.__class__.__name__, socket_address, self.socket_address, self.connection_state)

        if socket_address is not None:
            self.socket_address = socket_address

        if self.connection_state.flags & ConnectionState.OPEN:
            return True

        try:
            self.connection_state.update(ConnectionState.CONNECTING, ConnectionState.OPEN | ConnectionState.ERROR)

            self.socket_address.socket = Socket.socket(self.socket_address.family, self.socket_address.type)
            if debug:
                log_communication.debug("%s.open: %s", self.__class__.__name__, self.socket_address)
            self.socket_address.socket.connect(self.socket_address.get_py_address())
            self.io_watch_add(self.handle_client_io)
            self.connection_state.update(ConnectionState.OPEN, ConnectionState.CONNECTING | ConnectionState.RETRY)
            self.connection_retry.stop()
            self.report_connect_failure = True
            self.do_logon()
        except Socket.error, e:
            errno, strerror = get_error_from_socket_exception(e)
            if self.report_connect_failure == True:
                log_rpc.error("attempt to open server connection failed: %s", strerror)
                self.report_connect_failure = False
            if errno == Errno.EPIPE:
                add_flags = ConnectionState.HUP
            else:
                add_flags = ConnectionState.ERROR
            self.close_connection(add_flags, ConnectionState.CONNECTING, errno, strerror)
            return False
        return True
            
    def retry_connection(self, retry, user_data):
        if self.open(self.socket_address):
            return True
        else:
            return False
        
    def get_connection_retry_interval(self, retry, user_data):
        if retry.failed_attempts < 5:
            return 10
        else:
            return 60

    def bind(self):
        def database_bind_callback(properties):
            if debug:
                log_rpc.debug('database_bind_callback properties = %s', str(properties))
            self.emit('database_bind', self, properties)

        def database_bind_error(method, errno, strerror):
            log_rpc.error('database bind: %s', strerror)

        async_rpc = self.database_bind(self.database_name)
        async_rpc.add_callback(database_bind_callback)
        async_rpc.add_errback(database_bind_error)

    def evaluate_server_version(self, pkg_version, rpc_version):
        if pkg_version != self.pkg_version:
            if debug:
                log_program.debug("server pkg_version(%s) != client pkg_version(%s)",
                                  pkg_version, self.pkg_version)

    def do_logon(self):
        def logon_callback(pkg_version, rpc_version):
            if debug:
                log_program.debug("logon_callback(): pkg_version=%s rpc_version=%s", pkg_version, rpc_version)
            self.evaluate_server_version(pkg_version, rpc_version)
            self.connection_state.update(ConnectionState.AUTHENTICATED)

        def logon_error(method, errno, strerror):
            log_program.error("%s: %s", method, strerror)

        if debug:
            log_program.debug("logon: %s", self.username)

        self.channel_name = self.username
        async_rpc = self.logon(self.channel_type, self.username, 'passwd')
        async_rpc.add_callback(logon_callback)
        async_rpc.add_errback(logon_error)

    # ------

    def alert(self, siginfo):
        if debug:
            log_alert.debug("received alert")
        self.emit('alert', siginfo)

    def signatures_updated(self, type, item):
        if debug:
            log_rpc.debug('signatures_updated() alert client: type=%s item=%s', type, item)
        self.emit('signatures_updated', type, item)
        
gobject.type_register(ServerConnectionHandler)

