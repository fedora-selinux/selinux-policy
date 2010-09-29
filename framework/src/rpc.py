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

import libxml2
import re

import errno as Errno
import gobject
import os
import socket as Socket
import fcntl
import threading
from types import *

from setroubleshoot.config import get_config
from setroubleshoot.errcode import *
from setroubleshoot.log import *
from setroubleshoot.xml_serialize import xml_child_elements, xml_get_child_elements_by_name
from setroubleshoot.util import *

__all__ = [
    'rpc_method',
    'rpc_arg_type',
    'rpc_callback',
    'rpc_signal',
    'interface_registry',
    
    'parse_socket_address_list',
    'get_default_port',
    'get_socket_list_from_config',
    'get_local_server_socket_address',

    'ConnectionState',
    'RpcManage',
    'RpcChannel',
    'ListeningServer',
    'SocketAddress',
    ]

#--------------------------------- Variables ---------------------------------

verbose = False
content_length_re = re.compile("content-length:(\d+)")
header_end_re = re.compile("\r\n\r\n")
header_field_re = re.compile("([a-zA-Z0-9_-]+):(.*)\r\n")
i18n_encoding = get_config('general', 'i18n_encoding')

#------------------------------ Utility Functions -----------------------------

def parse_socket_address_list(addr_string, default_port=None):
    socket_addresses = []
    family_re = re.compile('\s*{(unix|inet)}(.+)')

    if debug:
        log_communication.debug("parse_socket_address_list: input='%s'", addr_string)
    if not addr_string: return socket_addresses
    addrs = re.split('[\s,]+', addr_string)
    for cfg_addr in addrs:
        if not cfg_addr: continue
        match = family_re.search(cfg_addr)
        if match:
            family_tag = match.group(1).lower()
            address = match.group(2)

            family = SocketAddress.map_family(family_tag)
            if family is None:
                log_communication.warning("unknown socket family - %s in address %s", family_tag, cfg_addr)
                continue
        else:
            family = Socket.AF_INET
            address = cfg_addr

        socket_address = SocketAddress(family, address, default_port)
        socket_addresses.append(socket_address)
    if debug:
        log_communication.debug("parse_socket_address_list: %s --> %s", cfg_addr, socket_address)
    return socket_addresses

def get_default_port():
    default_port = get_config('connection','default_port', int)
    return default_port

def get_socket_list_from_config(cfg_section):
    addr_string = addr_string = get_config(cfg_section, 'address_list')
    socket_addresses = parse_socket_address_list(addr_string)
    return socket_addresses

def get_local_server_socket_address():
    addr_list = get_socket_list_from_config('client_connect_to')
    if len(addr_list) == 0: return None
    return addr_list[0]

def io_condition_to_string(io_condition):
    names = []

    if io_condition & gobject.IO_IN:
        names.append('IN')
    if io_condition & gobject.IO_OUT:
        names.append('OUT')
    if io_condition & gobject.IO_PRI:
        names.append('PRI')
    if io_condition & gobject.IO_ERR:
        names.append('ERR')
    if io_condition & gobject.IO_HUP:
        names.append('HUP')
    if io_condition & gobject.IO_NVAL:
        names.append('NVAL')

    return '(%d)[%s]' % (io_condition, ','.join(names))


def rpc_header(body, **kwds):
    hdr = "content-length: %d\r\n" % len(body)
    for key,value in kwds.items():
        hdr += "%s: %s\r\n" % (key, value)
    hdr += "\r\n"
    return hdr

def rpc_message(rpc_id, type, body):
    hdr = rpc_header(body, rpc_id=rpc_id, type=type)
    return hdr+body
    
def convert_rpc_xml_to_args(cmd):
    interface = method = args = doc = None
    try:
        doc = libxml2.parseDoc(cmd)
        cmd = doc.getRootElement()

        interface = cmd.prop('interface')
        method    = cmd.prop('method')

        # FIXME: If the interface.method is not known you get back a dummy
        # rpc_def with zero parameters defined, but if the incoming call has
        # parameters we'll try to iterate through them generating an IndexError
        # exception when this code executes: rpc_def.positional_args[arg_position]
        #
        # We either need to detect and report the failed rpc_def lookup earlier
        # and/or we need to not iterate on unknown parameters.
        rpc_def = interface_registry.get_rpc_def(interface, method)

        arg_nodes = xml_get_child_elements_by_name(cmd, 'arg')
        args = preextend_list(len(arg_nodes))
        for arg_node in arg_nodes:
            arg_name      = arg_node.prop('name')
            arg_type      = arg_node.prop('type')
            arg_position  = int(arg_node.prop('position'))
            rpc_arg       = rpc_def.positional_args[arg_position]
            if rpc_arg.obj_type is not None:
                if arg_type == 'xml':
                    arg_value = rpc_arg.obj_type(arg_node, obj_name=arg_name)
                else:
                    arg_value = rpc_arg.obj_type(arg_node.content)
            else:
                arg_value = arg_node.content
            args[arg_position] = arg_value

    finally:
        if doc is not None:
            doc.freeDoc()

    return interface, method, args

def convert_rpc_to_xml(rpc_id, rpc_def, *args):
    text_doc = doc = None
    try:
        interface = rpc_def.interface
        method = rpc_def.method

        doc = libxml2.newDoc('1.0')
        root = libxml2.newNode('cmd')
        root.setProp('interface', interface)
        root.setProp('method', method)
        doc.setRootElement(root)

        position = 0
        for rpc_arg in rpc_def.positional_args:
            arg_name = rpc_arg.name
            arg_value = args[position]
            arg_node = libxml2.newNode('arg')
            root.addChild(arg_node)
            arg_node.setProp('name', arg_name)
            arg_node.setProp('position', str(position))
            if isinstance(arg_value, libxml2.xmlNode):
                arg_node.setProp('type', 'xml')
                arg_node.addChild(arg_value)
            elif hasattr(arg_value, 'get_xml_nodes'):
                arg_node.setProp('type', 'xml')
                arg_node.addChild(arg_value.get_xml_nodes(doc, arg_name))
            else:
                arg_node.setProp('type', 'string')
                arg_node.addContent(str(arg_value))
            position += 1
        root.setProp('arg_count',str(position))
        text_doc = doc.serialize(encoding=i18n_encoding, format=1)
    finally:
        if doc is not None:
            doc.freeDoc()

    return text_doc

#-----------------------------------------------------------------------------

class ConnectionState(gobject.GObject):
    CONNECTING    = (1 << 1)
    OPEN          = (1 << 2)
    AUTHENTICATED = (1 << 3)
    HUP           = (1 << 4)
    ERROR         = (1 << 5)
    TIMEOUT       = (1 << 6)
    RETRY         = (1 << 7)

    ALL_FLAGS = CONNECTING | OPEN | AUTHENTICATED | HUP | ERROR | TIMEOUT | RETRY
    GOOD_FLAGS = OPEN | AUTHENTICATED
    PROBLEM_FLAGS = HUP | ERROR | TIMEOUT | RETRY

    map_connection_enum_to_string = {
        CONNECTING    : 'CONNECTING',
        OPEN          : 'OPEN',
        AUTHENTICATED : 'AUTHENTICATED',
        HUP           : 'HUP',
        ERROR         : 'ERROR',
        TIMEOUT       : 'TIMEOUT',
        RETRY         : 'RETRY',
    }

    connection_states = [CONNECTING, OPEN, AUTHENTICATED, HUP, ERROR, TIMEOUT, RETRY]

    __gsignals__ = {
        'changed': # callback(connection_state, flags, flags_added, flags_removed):
        (gobject.SIGNAL_RUN_LAST, gobject.TYPE_NONE, (gobject.TYPE_INT, gobject.TYPE_INT, gobject.TYPE_INT)),
        }
    def __init__(self):
        gobject.GObject.__init__(self)
        self.flags = 0
        self.result_code = None
        self.result_msg = None
        self.clear_result()

    def __str__(self):
        return "flags=%s, result_code=%d, result_msg=%s" % \
               (self.flags_to_string(self.flags), self.result_code, self.result_msg)
    
    def clear(self):
        self.update(0, self.ALL_FLAGS)

    def flags_to_string(self, val):
        if val is None: val = 0
        names = []
        for state in ConnectionState.connection_states:
            if val & state: names.append(ConnectionState.map_connection_enum_to_string[state])
        return ','.join(names)

    def clear_result(self):
        self.result_code = 0
        self.result_msg = ''

    def set_result(self, result_code, result_msg):
        self.result_code = result_code
        self.result_msg = result_msg

    def get_result(self):
        return(self.result_code, self.result_msg)

    def update(self, add_flags=0, remove_flags=0, result_code=0, result_msg=''):
        if debug and False:
            log_communication.debug("%s.update: %s add_flags=%s, remove_flags=%s", self.__class__.__name__,
                                    self, self.flags_to_string(add_flags), self.flags_to_string(remove_flags))
        previous_flags = self.flags

        self.flags |= add_flags
        self.flags &= ~remove_flags

        self.result_code = result_code
        self.result_msg = result_msg

        difference = previous_flags ^ self.flags
        flags_added = self.flags & difference
        flags_removed = previous_flags & difference

        # Send signal if anything changed
        if difference:
            self.emit('changed', self.flags, flags_added, flags_removed)

gobject.type_register(ConnectionState)

#-----------------------------------------------------------------------------

class RpcArg(object):
    def __init__(self, name=None, obj_type=None):
        self.name = name
        self.obj_type = obj_type

    def __str__(self):
        if self.name is None:
            name = 'name_undefined'
        else:
            name = self.name
        if self.obj_type is None:
            return name
        else:
            return "%s:%s" % (name, self.obj_type)

error_positional_args = [RpcArg('method', str), RpcArg('err_code', int), RpcArg('err_msg', str)]

#-----------------------------------------------------------------------------

class RpcDefinition(object):
    def __init__(self, type, interface, method, rpc_args):
        self.type = type
        self.interface = interface
        self.method = method
        self.callback = None
        if rpc_args is None:
            self.positional_args = []
        else:
            self.positional_args = rpc_args

    def __str__(self):
        args = []
        if self.positional_args is not None:
            for rpc_arg in self.positional_args:
                if rpc_arg.obj_type is not None:
                    args.append("%s:%s" % (rpc_arg.name, rpc_arg.obj_type))
                else:
                    args.append(rpc_arg.name)
        text = "[%s] %s:%s (%s)" % (self.type, self.interface, self.method, ','.join(args))
        if self.type == 'method':
            text += ' callback=%s' % (self.callback)
        return text

    def set_type(self, type):
        self.type = type

    def set_callback(self, callback):
        if self.callback is not None:
            interface_dict = interface_registry.get_interface(self.interface)
            del(interface_dict[self.callback])
        self.callback = callback

    def get_callback_def(self):
        if self.type != 'method':
            raise ValueError("%s rpc types do not have callbacks" % self.type)
        if self.callback is None:
            callback_name = '%s_default_callback' % self.method
            callback_def = RpcDefinition('method_return', self.interface, callback_name, None)
            interface_registry.register_rpc_def(self.interface, callback_name, callback_def)
            self.callback = callback_name
            return callback_def
        return interface_registry.get_rpc_def(self.interface, self.callback)
        
    def set_positional_args(self, arg_names):
        if arg_names is not None:
            self.positional_args = preextend_list(len(arg_names), self.positional_args, RpcArg)
            position = 0
            for arg_name in arg_names:
                rpc_arg = self.positional_args[position]
                rpc_arg.name = arg_name
                position += 1
        
    def set_arg_obj_types(self, *obj_types):
        if obj_types is not None:
            self.positional_args = preextend_list(len(obj_types), self.positional_args, RpcArg)
            position = 0
            for obj_type in obj_types:
                rpc_arg = self.positional_args[position]
                rpc_arg.obj_type = obj_type
                position += 1
        
    def get_positional_arg_names(self):
        return [rpc_arg.name for rpc_arg in self.positional_args]

#-----------------------------------------------------------------------------

class InterfaceRegistry(object):
    def __init__(self):
        self.interfaces = {}

    def new_interface(self, interface):
        error_return_def = RpcDefinition('error_return', interface, '_error_return', error_positional_args)
        return {'_error_return' : error_return_def}

    def get_interface(self, interface_name):
        interface = self.interfaces.get(interface_name)
        if interface is None:
            interface = self.new_interface(interface_name)
            self.interfaces[interface_name] = interface
        return interface

    def set_rpc_def(self, type, interface, method_ptr):
        import inspect
        method = method_ptr.__name__
        positional_args = inspect.getargspec(method_ptr)[0]
        if positional_args[0] == 'self':
            del(positional_args[0])

        rpc_def = self.get_rpc_def(interface, method)
        rpc_def.set_type(type)
        rpc_def.set_positional_args(positional_args)
        return rpc_def

    def get_rpc_def(self, interface, method):
        interface_dict = self.get_interface(interface)
        if type(method) == MethodType:
            method = method.__name__
        rpc_def = interface_dict.get(method)
        if rpc_def is None:
            rpc_def = RpcDefinition(None, interface, method, None)
            self.register_rpc_def(interface, method, rpc_def)
        return rpc_def
        
    def register_rpc_def(self, interface, method, rpc_def):
        interface_dict = self.get_interface(interface)
        if type(method) == MethodType:
            method = method.__name__
        interface_dict[method] = rpc_def
        
    def get_error_rpc_def(self, interface):
        interface_dict = self.get_interface(interface)
        return interface_dict['_error_return']

    def dump_interfaces(self):
        interface_names = self.interfaces.keys()
        interface_names.sort()
        for interface_name in interface_names:
            interface = self.interfaces[interface_name]
            print "Interface: %s" % interface_name
            method_names = interface.keys()
            method_names.sort()
            for method_name in method_names:
                method = interface[method_name]
                print "    %s" % str(method)

interface_registry = InterfaceRegistry()

#-------------------------------- Decorators ---------------------------------
    
def rpc_method(interface):
    def decorator(method_ptr):
        rpc_def = interface_registry.set_rpc_def('method', interface, method_ptr)
        method = method_ptr.__name__
        if debug and verbose:
            log_rpc.debug("@rpc_method() interface=%s method=%s positional_args=%s",
                          rpc_def.interface, method, rpc_def.get_positional_arg_names())
        def rpc_func(self, *args):
            rpc_id = self.new_rpc_id()
            rpc_def = interface_registry.get_rpc_def(interface, method)
            async_rpc = AsyncRpc(rpc_def, rpc_id)
            self.async_rpc_cache[rpc_id] = async_rpc
            self.emit_rpc(rpc_id, 'method', rpc_def, *args)
            return async_rpc
        method_ptr._rpc_definition = True
        return rpc_func
    return decorator

def rpc_arg_type(interface, *arg_types):
    def decorator(method_ptr):
        method = method_ptr.__name__
        rpc_def = interface_registry.get_rpc_def(interface, method)
        rpc_def.set_arg_obj_types(*arg_types)
        if debug and verbose:
            log_rpc.debug("@rpc_arg_types() interface=%s method=%s arg_types=%s",
                          rpc_def.interface, rpc_def.method, arg_types)
        return method_ptr
    return decorator

def rpc_callback(interface, method):
    def decorator(method_ptr):
        rpc_callback_def = interface_registry.set_rpc_def('method_return', interface, method_ptr)
        if debug and verbose:
            log_rpc.debug("@rpc_callback() interface=%s method=%s positional_args=%s",
                          rpc_callback_def.interface, rpc_callback_def.method, rpc_callback_def.get_positional_arg_names())
        rpc_def = interface_registry.get_rpc_def(interface, method)
        rpc_def.set_callback(rpc_callback_def.method)
        method_ptr._rpc_definition = True
        return method_ptr
    return decorator


def rpc_signal(interface):
    def decorator(method_ptr):
        rpc_def = interface_registry.set_rpc_def('signal', interface, method_ptr)
        method = method_ptr.__name__
        if debug and verbose:
            log_rpc.debug("interface=%s method=%s positional_args=%s",
                          rpc_def.interface, method, rpc_def.get_positional_arg_names())
        def rpc_func(self, *args):
            rpc_id = self.new_rpc_id()
            rpc_def = interface_registry.get_rpc_def(interface, method)
            self.emit_rpc(rpc_id, 'signal', rpc_def, *args)
        method_ptr._rpc_definition = True
        return rpc_func
    return decorator

#------------------------------------------------------------------------------

class SocketAddress(object):
    def __init__(self, family=None, address=None, default_port=get_default_port(), friendly_name=None):
        self.family = SocketAddress.map_family(family)
        self.address = address
        self.port = default_port
        self.default_port = default_port
        self.type = Socket.SOCK_STREAM
        self.socket = None
        self.friendly_name = friendly_name

        if address is not None:
            self.parse(self.family, address)

    def __str__(self):
        socket_repr = re.sub('^.+ at (0x[0-9A-Fa-f]+)>$', '\\1', repr(self.socket))
        if self.family is None:
            return "None"
        elif self.family is Socket.AF_UNIX:
            return "{unix}%s socket=%s" % (self.address, socket_repr)
        elif self.family is Socket.AF_INET:
            return "{inet}%s:%s socket=%s" % (self.address, self.port, socket_repr)
        else:
            return "unknown"

    def _get_default_friendly_name(self):
        if self.family is None:
            return "None"
        elif self.family is Socket.AF_UNIX:
            return "%s" % (self.address)
        elif self.family is Socket.AF_INET:
            return "%s:%s" % (self.address, self.port)
        else:
            return _("Unknown")

    def get_friendly_name(self):
        if self.friendly_name is None:
            return self._get_default_friendly_name()
        return self.friendly_name

    def copy(self):
        import copy
        return copy.copy(self)

    def get_py_address(self):
        if self.family is Socket.AF_UNIX:
            return self.address
        elif self.family is Socket.AF_INET:
            return (self.address, self.port)
        else:
            return None

    @staticmethod
    def map_family(family):
        if type(family) is str:
            family = family.lower()
            family = {'unix' : Socket.AF_UNIX, 'inet' : Socket.AF_INET}.get(family)
            return family
        return family

    def parse(self, family, addr):
        self.family = family
        if family is Socket.AF_UNIX:
            self.address = addr
            self.port = None
        elif family is Socket.AF_INET:
            self.parse_inet_addr(addr)

    def parse_inet_addr(self, addr):
        match = re.search('^\s*([^:\s]+)\s*(:\s*([^\s]+))?', addr)
        if match:
            addr = match.group(1)
            port = match.group(3)
            if port is None:
                port = self.default_port

            if addr == 'hostname':
                addr = get_hostname()

            self.address = addr
            self.port = port
        else:
            self.address = None
            self.port = None

#-----------------------------------------------------------------------------

class ConnectionIO(object):
    io_input_conditions = gobject.IO_IN | gobject.IO_HUP | gobject.IO_ERR | gobject.IO_NVAL

    def __init__(self, channel_type=None, channel_name=None, socket_address=SocketAddress()):
        self.connection_state = ConnectionState()
        self.socket_address = socket_address
        self.channel_type = channel_type
        self.channel_name = channel_name
        self.io_watch_id = None


    def io_watch_add(self, callback):
        '''callback signature: (io_object, io_condition)'''
        self.io_watch_remove()
        self.io_watch_id = gobject.io_add_watch(self.socket_address.socket,
                                                self.io_input_conditions, callback)
        
    def io_watch_remove(self):
        if self.io_watch_id is not None:
            gobject.source_remove(self.io_watch_id)
            self.io_watch_id = None

    def valid_io_condition(self, io_condition):
        if io_condition & (gobject.IO_HUP | gobject.IO_ERR | gobject.IO_NVAL):
            if io_condition & gobject.IO_HUP:
                errno = ERR_SOCKET_HUP
                strerror = get_strerror(errno)
                self.close_connection(ConnectionState.HUP, 0, errno, strerror)

            if io_condition & gobject.IO_ERR:
                errno = ERR_SOCKET_ERROR
                strerror = get_strerror(errno)
                self.close_connection(ConnectionState.ERROR, 0, errno, strerror)

            if io_condition & gobject.IO_NVAL:
                errno = ERR_IO_INVALID
                strerror = get_strerror(errno)
                self.close_connection(ConnectionState.ERROR, 0, errno, strerror)

            return False
        else:
            return True
        
#-----------------------------------------------------------------------------

class ListeningServer(ConnectionIO):

    allow_reuse_address = False
    request_queue_size = 5

    def __init__(self, socket_address, client_connection_handler_class):
        ConnectionIO.__init__(self, channel_type='listening', channel_name='server_listening', socket_address=socket_address)
        self.client_connection_handler_class = client_connection_handler_class

    def new_listening_socket(self, socket_address):
        self.socket_address = socket_address
        if self.socket_address.family == Socket.AF_UNIX:
            # Unix domain socket, delete the socket if left from before
            if os.path.exists(self.socket_address.address):
                os.remove(self.socket_address.address)

        if debug:
            log_communication.debug("new_listening_socket: %s", self.socket_address)

        self.socket_address.socket = Socket.socket(self.socket_address.family, self.socket_address.type)
        fcntl.fcntl(self.socket_address.socket.fileno(), fcntl.F_SETFD, fcntl.FD_CLOEXEC)
        if self.allow_reuse_address:
            self.socket_address.socket.setsockopt(Socket.SOL_SOCKET, Socket.SO_REUSEADDR, 1)
        self.socket_address.socket.bind(self.socket_address.get_py_address())
        if self.socket_address.family == Socket.AF_UNIX:
            os.chmod(self.socket_address.address, 0666)
        self.socket_address.socket.listen(self.request_queue_size)

        return self.socket_address.socket


    def open(self):
        try:
            self.socket_address.socket = self.new_listening_socket(self.socket_address)
            self.io_watch_add(self.handle_client_connect)
        except Exception, e:
            self.connection_state.update(ConnectionState.ERROR, ConnectionState.OPEN, -1, str(e))
            return False
        return True

    def handle_client_connect(self, socket, io_condition):
        if debug:
            #log_rpc.debug("handle_client_connect(): io_condition=%s", io_condition_to_string(io_condition))
            pass

        try:
            if not self.valid_io_condition(io_condition):
                return False

            if io_condition & gobject.IO_IN:
                try:
                    client_socket, client_address = socket.accept()
                    fcntl.fcntl(client_socket.fileno(), fcntl.F_SETFD, fcntl.FD_CLOEXEC)
                    client_handler = self.client_connection_handler_class(self.socket_address)
                    client_handler.open(client_socket, client_address)
                    self.connection_state.update(0, ConnectionState.PROBLEM_FLAGS)

                except Socket.error, e:
                    errno, strerror = get_error_from_socket_exception(e)
                    log_rpc.error("closing client connection due to socket error(%s): %s", self.socket_address, strerror)
                    if errno == Errno.EPIPE:
                        add_flags = ConnectionState.HUP
                    else:
                        add_flags = ConnectionState.ERROR
                    self.connection_state.update(add_flags, 0, errno, strerror)

        except Exception, e:
            log_rpc.exception("exception %s: %s",e.__class__.__name__, str(e))
            self.connection_state.update(ConnectionState.ERROR, 0, -1, str(e))

        return True

#-----------------------------------------------------------------------------

class RequestReceiver:
    def __init__(self, dispatchFunc):
        self.dispatchFunc = dispatchFunc
        self.reset()
    
    def reset(self):
        self.headerLen = -1
        self.bodyLen = 0
        self.header = None
        self.body = ''
        self.feed_buf = ''
        
    def process(self):
        if len(self.feed_buf) == 0:
            # No data, nothing to process
            return
        while True:
            if self.headerLen < 0:
                # Have not seen the end of the header yet, is it there now?
                match = header_end_re.search(self.feed_buf)
                if match:
                    # Yes, header is complete, convert to dict, mark header end
                    self.headerLen = match.end()
                    self.parse_header()
                    continue
                else:
                    # Can't read header till more data arrives
                    break
            if len(self.feed_buf) >= self.headerLen + self.bodyLen:
                # Read entire request, dispatch request, reset for next request
                bodyBegin = self.headerLen
                bodyEnd   = self.headerLen+self.bodyLen
                self.body = self.feed_buf[bodyBegin:bodyEnd]
                self.feed_buf = self.feed_buf[bodyEnd:]
                self.headerLen = -1
                self.bodyLen = -1
                if debug:
                    #log_rpc.debug("dispatch msg: header=%s body=%s", self.header, self.body)
                    pass
                self.dispatchFunc(self.header, self.body)
                continue
            # Have neither a full header nor a full body.
            # Exit till more data is available.
            break

    def feed(self, data):
        self.feed_buf += data
        self.process()

    def parse_header(self):
        self.header = {}
        begin = 0
        while 1:
            match = header_field_re.search(self.feed_buf, begin, self.headerLen+1)
            if match:
                key = match.group(1)
                value = match.group(2).strip()
                self.header[key] = value
                begin = match.end()
            else:
                break
        self.bodyLen = int(self.header['content-length'])

#-----------------------------------------------------------------------------

class RpcManage(object):
    def __init__(self):
	self.async_rpc_cache = {}
        self.rpc_handlers = {}
        self.rpc_id = 0

    def new_rpc_id(self):
        self.rpc_id +=1
        return str(self.rpc_id)
    
    def dump_async_rpc_cache(self):
        log_rpc.debug("async_rpc_cache: %d entries, cur rpc_id=%s", len(self.async_rpc_cache), self.rpc_id)
        rpc_ids = self.async_rpc_cache.keys()
        rpc_ids.sort()
        for rpc_id in rpc_ids:
            log_rpc.debug("%s: %s", rpc_id, self.async_rpc_cache[rpc_id])

    def flush_async_rpc_cache(self):
        self.async_rpc_cache.clear()

    def default_errback(self, method, err_code, err_msg):
        log_rpc.error("[%s] %d %s", method, err_code, err_msg)

    def process_async_return(self, async_rpc):
        if async_rpc is None:
            log_rpc.error("process_async_return(): rpc_id=%s not in async_rpc_cache", rpc_id)
            return
        if async_rpc.return_type == 'method_return':
            for callback in async_rpc.callbacks:
                callback(*async_rpc.return_args)
        elif async_rpc.return_type == 'error_return':
            if len(async_rpc.errbacks) > 0:
                for callback in async_rpc.errbacks:
                    callback(*async_rpc.return_args)
            else:
                self.default_errback(*async_rpc.return_args)

    def connect_rpc_interface(self, interface, handler):
        self.rpc_handlers[interface] = handler
        
#-----------------------------------------------------------------------------

class RpcChannel(ConnectionIO, RpcManage):
    socket_buf_size = get_config('socket','buf_size', int)
    socket_timeout  = get_config('socket','timeout', int)

    def __init__(self, channel_type=None, channel_name=None):
        ConnectionIO.__init__(self, channel_type=channel_type, channel_name=channel_name, socket_address=None)
        RpcManage.__init__(self)
        self.write_lock = threading.Lock()
        self.receiver = RequestReceiver(self.default_request_handler)

    def __str__(self):
        return "channel: name=%s addr=%s type=%s" % (self.channel_name, self.socket_address, self.channel_type)

    def acquire_write_lock(self):
        self.write_lock.acquire()

    def release_write_lock(self):
        self.write_lock.release()
        
    def set_channel_type(self, channel_type):
        self.channel_type = channel_type
        
    def get_channel_type(self):
        return self.channel_type

    def close_connection(self, add_flags=0, remove_flags=0, result_code=0, result_msg=''):
        if debug:
            log_communication.debug("close_connection: %s", self.socket_address)
            self.dump_async_rpc_cache()
        self.flush_async_rpc_cache()
        if self.socket_address.socket is None:
            return
        if self.socket_address.socket is not None:
            try:
                self.socket_address.socket.shutdown(Socket.SHUT_RDWR)
                self.socket_address.socket.close()
                self.socket_address.socket = None
            except Socket.error, e:
                self.socket_address.socket = None

        self.connection_state.update(add_flags, remove_flags | ConnectionState.GOOD_FLAGS,
                                     result_code, result_msg)
        self.io_watch_remove()

    def get_method_implementation(self, interface, method):
        handler_obj = self.rpc_handlers.get(interface, None)
        if handler_obj is None:
            return None
        method_ptr = getattr(handler_obj, method, None)
        return method_ptr

    def emit_rpc(self, rpc_id, type, rpc_def, *args):
        if len(rpc_def.positional_args) != len(args):
            log_rpc.error("emit_rpc() arg length=%s does not match rpc_def(%s)", len(args), rpc_def)
            return
        rpc_xml = convert_rpc_to_xml(rpc_id, rpc_def, *args)
        rpc_data = rpc_message(rpc_id, type, rpc_xml)
        self.send_data(rpc_data)

    def send_data(self, data):
        if not (self.connection_state.flags & ConnectionState.OPEN):
            return
        if debug:
            #log_rpc.debug("send_data() data=%s", data)
            pass
        self.acquire_write_lock()
        try:
            totalSent = 0
            while totalSent < len(data):
                sent = self.socket_address.socket.send(data[totalSent:])
                if sent == 0:
                    self.close_connection(ConnectionState.HUP)
                    raise ProgramError(ERR_SOCKET_HUP, detail=self.connection_state)
                totalSent = totalSent + sent
        except Socket.timeout, e:
            log_rpc.error("socket timeout: (%s)", self.socket_address)
            self.release_write_lock()
            self.connection_state.update(ConnectionState.TIMEOUT)
            return
        except Socket.error, e:
            errno, strerror = get_error_from_socket_exception(e)
            log_rpc.error("could not send data on socket (%s): %s", self.socket_address, strerror)
            self.release_write_lock()
            if errno == Errno.EPIPE:
                add_flags = ConnectionState.HUP
            else:
                add_flags = ConnectionState.ERROR
            self.close_connection(add_flags, 0, errno, strerror)
            return
        self.connection_state.update(0, ConnectionState.PROBLEM_FLAGS)
        self.release_write_lock()

    def handle_client_io(self, socket, io_condition):
        if debug:
            #log_rpc.debug("handle_client_io(): io_condition=%s", io_condition_to_string(io_condition))
            pass

        try:
            if not self.valid_io_condition(io_condition):
                return False

            if io_condition & gobject.IO_IN:
                try:
                    data = socket.recv(self.socket_buf_size)
                    if len(data) == 0:
                        self.close_connection(ConnectionState.HUP)
                        return False
                except Socket.error, e:
                    errno, strerror = get_error_from_socket_exception(e)
                    log_rpc.error("socket error (%s): %s", self.socket_address, strerror)
                    if errno == Errno.EPIPE:
                        add_flags = ConnectionState.HUP
                    else:
                        add_flags = ConnectionState.ERROR
                    self.close_connection(add_flags, 0, errno, strerror)
                    return False

                self.connection_state.update(0, ConnectionState.PROBLEM_FLAGS)
                self.receiver.feed(data)
        except Exception, e:
            log_rpc.exception("exception %s: %s",e.__class__.__name__, str(e))
            self.close_connection(ConnectionState.ERROR, 0, -1, str(e))
            return False

        return True

    def handle_return(self, type, rpc_id, body):
        async_rpc = self.async_rpc_cache.pop(rpc_id, None)
        if async_rpc is None:
            log_rpc.error("handle_return(): rpc_id=%s not in async_rpc_cache", rpc_id)
            return

        if debug and verbose:
            log_rpc.debug("%s.handle_return: rpc_id=%s type=%s %s.%s, {%s}",
                          self.__class__.__name__, rpc_id, type, async_rpc.rpc_def.interface, async_rpc.rpc_def.method, body)

        interface, method, args = convert_rpc_xml_to_args(body)
        async_rpc.return_type = type
        async_rpc.return_args = args
        self.process_async_return(async_rpc)

    def default_request_handler(self, header, body):
	rpc_id    = header.get('rpc_id', 0)
	type      = header.get('type', None)

        if debug and verbose:
            log_rpc.debug("%s.default_request_handler: rpc_id=%s type=%s {%s}",
                          self.__class__.__name__, rpc_id, type, body)

	if type == 'error_return' or type == 'method_return':
            self.handle_return(type, rpc_id, body)
        elif type == 'method':
            interface, method, args = convert_rpc_xml_to_args(body)
            method_ptr = self.get_method_implementation(interface, method)
            if method_ptr:
                try:
                    return_args = method_ptr(*args)
                    if return_args is None: return_args = []
                    rpc_method_def   = interface_registry.get_rpc_def(interface, method)
                    rpc_callback_def = rpc_method_def.get_callback_def()
                    self.emit_rpc(rpc_id, 'method_return', rpc_callback_def, *return_args)
                except ProgramError, e:
                    rpc_error_def = interface_registry.get_error_rpc_def(interface)
                    self.emit_rpc(rpc_id, 'error_return', rpc_error_def, method, e.errno, e.strerror)
            else:
                err_code = Errno.ENOSYS
                err_msg = "method '%s' is not implemented in class '%s'" % (method, self.__class__.__name__)
                rpc_error_def = interface_registry.get_error_rpc_def(interface)
                self.emit_rpc(rpc_id, 'error_return', rpc_error_def, method, err_code, err_msg)
        elif type == 'signal':
            interface, method, args = convert_rpc_xml_to_args(body)
            method_ptr = self.get_method_implementation(interface, method)
            if method_ptr:
                try:
                    method_ptr(*args)
                except ProgramError, e:
                    rpc_error_def = interface_registry.get_error_rpc_def(interface)
            else:
                err_code = Errno.ENOSYS
                err_msg = "method '%s' is not implemented in class '%s'" % (method, self.__class__.__name__)
                rpc_error_def = interface_registry.get_error_rpc_def(interface)
                self.emit_rpc(rpc_id, 'error_return', rpc_error_def, method, err_code, err_msg)
        else:
            raise ValueError("unknown type(%s) for %s:%s" % (type, interface, method))

#-----------------------------------------------------------------------------

class AsyncRpc(object):
    def __init__(self, rpc_def, rpc_id):
        self.rpc_def = rpc_def
        self.rpc_id = rpc_id
        self.return_args = None
        self.return_type = None
        self.callbacks = []
        self.errbacks = []
        
    def add_callback(self, callback):
        self.callbacks.append(callback)

    def add_errback(self, errback):
        self.errbacks.append(errback)

#-----------------------------------------------------------------------------


