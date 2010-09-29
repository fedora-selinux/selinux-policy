# Authors: John Dennis <jdennis@redhat.com>
#          Thomas Liu <tliu@redhat.com
# Copyright (C) 2007-2010 Red Hat, Inc.
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

__all__ = ['derive_record_format',
           'parse_audit_record_text',
           
           'AvcContext',
           'AVC',
           'AuditEventID',
           'AuditEvent',
           'AuditRecord',
           'AuditRecordReader',
           
           ]

import audit
import struct
import os,errno
import re
import selinux
import base64
from types import *
import selinux.audit2why as audit2why

from setroubleshoot.log import *
from setroubleshoot.util import *
from setroubleshoot.html_util import *
from setroubleshoot.xml_serialize import *
from setroubleshoot.sesearch import *

O_ACCMODE = 00000003

#-----------------------------------------------------------------------------

standard_directories = get_standard_directories()

#-----------------------------------------------------------------------------

def audit_record_from_text(text):
    parse_succeeded, record_type, event_id, body_text = parse_audit_record_text(text)
    audit_record = AuditRecord(record_type, event_id, body_text)
    return audit_record

#-----------------------------------------------------------------------------

def derive_record_format(socket_path):
    if re.search('/audispd_events$', socket_path):
        return AuditRecordReader.TEXT_FORMAT
    if re.search('/audit_events$', socket_path):
        return AuditRecordReader.BINARY_FORMAT
    return AuditRecordReader.TEXT_FORMAT                       # assume new format


# regular expression to find message like this:
# msg=audit(1152828325.857:123085): avc:  denied  { append } for  pid=14205 ...
# Note, messages arriving directly from the audit system omit
# 'msg=', but messages in log files prepend 'msg='
# group 1  is the optional "node=XXX "
# group 2  is the node if node=XXX is present
# group 3  is the optional "type=XXX "
# group 4  is the type if type=XXX is present
# group 5  is the optional 'msg='
# group 6  is the complete event id
# group 7  is the seconds component of the timestamp
# group 8  is the millisconds component of the timestamp
# group 9  is the timestamp unique number
# group 10 is the body of the message appearing after the event id
audit_input_re = re.compile('(node=(\S+)\s+)?(type=(\S+)\s+)?(msg=)?audit\(((\d+)\.(\d+):(\d+))\):\s*(.*)')


def parse_audit_record_text(input):
    parse_succeeded = False
    host = None
    record_type = None
    event_id = None
    body_text = None

    match = audit_input_re.search(input)
    if match is not None:
        parse_succeeded = True

        if match.group(2):
            host = match.group(2)

        if match.group(4):
            record_type = match.group(4)

        if match.group(6):
            seconds = int(match.group(7))
            milli   = int(match.group(8))
            serial  = int(match.group(9))
            event_id = AuditEventID(seconds, milli, serial, host)

        body_text = match.group(10)

    return (parse_succeeded, record_type, event_id, body_text)

audit_binary_input_re = re.compile('audit\(((\d+)\.(\d+):(\d+))\):\s*(.*)')

def parse_audit_binary_text(input):
    parse_succeeded = False
    event_id = None
    body_text = None

    match = audit_binary_input_re.search(input)
    if match is not None:
        parse_succeeded = True

        if match.group(1):
            seconds = int(match.group(2))
            milli   = int(match.group(3))
            serial  = int(match.group(4))
            event_id = AuditEventID(seconds, milli, serial)

        body_text = match.group(5)

    return (parse_succeeded, event_id, body_text)

#------------------------------------------------------------------------


class AvcContext(XmlSerialize):
    _xml_info = {
    'user'      : {'XMLForm'     : 'attribute' },
    'role'      : {'XMLForm'     : 'attribute' },
    'type'      : {'XMLForm'     : 'attribute' },
    'mls'       : {'XMLForm'     : 'attribute' },
    }
    def __init__(self, data):
        super(AvcContext, self).__init__()
        if type(data) is StringType:
            fields = data.split(':')
            if len(fields) >= 3:
                self.user = fields[0]
                self.role = fields[1]
                self.type = fields[2]
                if len(fields) > 3:
                    self.mls = ':'.join(fields[3:])
                else:
                    self.mls = 's0'
        
    def __str__(self):
        return '%s:%s:%s:%s' % (self.user, self.role, self.type, self.mls)

    def format(self):
        # FIXME, what does selinux_raw_to_trans_context() do and why do we need it?
        (rc, trans) = selinux.selinux_raw_to_trans_context(str(self))
        return trans

    def __ne__(self, other):
        return not self.__eq__(other)

    def __eq__(self, other):
        for name in self._xml_info.keys():
            if getattr(self, name) != getattr(other, name):
                return False
        return True
        

#-----------------------------------------------------------------------------

class AuditEventID(XmlSerialize):
    _xml_info = {
    'seconds' : {'XMLForm':'attribute', 'import_typecast':int },
    'milli'   : {'XMLForm':'attribute', 'import_typecast':int },
    'serial'  : {'XMLForm':'attribute', 'import_typecast':int },
    'host'    : {'XMLForm':'attribute' },
    }

    def __init__(self, seconds, milli, serial, host=None):
        super(AuditEventID, self).__init__()
        self.seconds = seconds
        self.milli   = milli
        self.serial  = serial
        if host is not None:
            self.host    = host

    def __eq__(self, other):
        if self.host    != other.host:          return False
        if self.seconds != other.seconds:       return False
        if self.milli   != other.milli:         return False
        if self.serial  != other.serial:        return False
        return True

    def __cmp__(self, other):
        if self.host != other.host:
            raise ValueError("cannot compare two %s objects whose host values differ (%s!=%s)" \
                             % (self.__class__.__name__, self.host, other.host))

        result = cmp(self.seconds, other.seconds)
        if result != 0: return result

        result = cmp(self.milli, other.milli)
        if result != 0: return result

        result = cmp(self.serial, other.serial)
        if result != 0: return result

        return 0
    
    def copy(self):
        import copy
        return copy.copy(self)

    time = property(lambda self: float(self.sec) + self.milli / 1000.0)

    def __str__(self):
        return "audit(%d.%d:%d)" % (self.seconds, self.milli, self.serial)

    def is_valid(self):
        if self.seconds is None: return False
        if self.milli   is None: return False
        if self.serial  is None: return False
        return True
    
#-----------------------------------------------------------------------------

class AuditRecord(XmlSerialize):
    _xml_info = {
    'record_type'   : {'XMLForm':'attribute', },
    'event_id'      : {'XMLForm':'element', 'import_typecast':AuditEventID },
    'body_text'     : {'XMLForm':'element' },
    'line_number'   : {'XMLForm':'attribute', 'import_typecast':int },
    }

    binary_version = 0
    binary_header_format="iiii"
    binary_header_size = struct.calcsize(binary_header_format)
    key_value_pair_re = re.compile("([^ \t]+)\s*=\s*([^ \t]+)")
    avc_re = re.compile("avc:\s+([^\s]+)\s+{([^}]+)}\s+for\s+")
    exec_arg_re = re.compile(r'^a\d+$')

    def __init__(self, record_type, event_id, body_text, fields=None, line_number=None):
        super(AuditRecord, self).__init__()
        # Header
        self.record_type = record_type
        self.event_id = event_id
        self.body_text = body_text
        self.fields = fields
        self.line_number = line_number
        self._init_postprocess()
        
    def _init_postprocess(self):
        if getattr(self, 'fields', None) is None:
            self.set_fields_from_text(self.body_text)

        if self.record_type in ['AVC', 'USER_AVC']:
            if not self.fields.has_key('seresult'):
                match = AuditRecord.avc_re.search(self.body_text)
                if match:
                    seresult = match.group(1)
                    self.fields['seresult'] = seresult

                    seperms = match.group(2)
                    self.fields['seperms'] = seperms.split()

    def __str__(self):
        return self.to_host_text()

    def audispd_rectify(self):
        self.line_number = None
        if self.event_id.host is None:
            self.event_id.host = get_hostname()

    def is_valid(self):
        if not self.event_id.is_valid(): return False
        if self.record_type is None:     return False
        if self.message is None:         return False
        return True

    def decode_fields(self):
	encoded_fields = ['acct', 'cmd', 'comm', 'cwd', 'data', 'dir', 'exe',
			  'file', 'host', 'key', 'msg', 'name', 'new', 'ocomm'
			  'old', 'path', 'watch']

	for field in encoded_fields:
	    if self.fields.has_key(field):
		if self.record_type == 'AVC' and field == 'saddr': continue
		value = self.fields[field]
		decoded_value = audit_msg_decode(value)
		self.fields[field] = decoded_value

	if self.record_type == 'EXECVE':
	    for field, value in self.fields.items():
		if self.exec_arg_re.search(field):
		    value = self.fields[field]
		    decoded_value = audit_msg_decode(value)
		    self.fields[field] = decoded_value
		    
		
    def translate_path(self, path):
        try:
            t = path.decode("hex")
            if t[0].encode("hex") == "00":
                tpath = "@"
            else:
                tpath = t[0]

            for i in range(len(t))[1:]:
                if t[i].encode("hex") != "00":
                    tpath = tpath + t[i]
                else:
                    break
        except:
            return path
        return tpath

    def set_fields_from_text(self, body_text):
        self.fields_ord = []
        self.fields = {}
        
        for match in AuditRecord.key_value_pair_re.finditer(body_text):
            key   = match.group(1)
            value = match.group(2)
            value = value.strip('"')
            try:
                if key == "arch":
                    i = audit.audit_elf_to_machine(int(value,16))
                    value = audit.audit_machine_to_name(i)

                if key == "path":
                    value = '"%s"' % self.translate_path(value)

                if key == "exit":
                    value = errno.errorcode[abs(int(value))]

                if key == "syscall":
                    value = audit.audit_syscall_to_name(int(value),audit.audit_detect_machine())
            except ValueError:
                pass
            self.fields[key] = value
            self.fields_ord.append(key)

    def get_field(self, name):
        return self.fields.get(name)

    def get_binary_header(self, msg):
        msg_length = len(msg)
        return struct.pack(AuditRecord.binary_header_format, AuditRecord.binary_version,
                           AuditRecord.binary_header_size, self.record_type, msg_length)

    def fields_to_text(self):
        if self.fields is None: return ''
        if self.record_type == 'AVC':
            buf = "type=%s msg=%s: avc: denied { %s } " % (self.record_type, self.event_id, ' '.join(self.access))
        else:
            buf = "type=%s msg=%s: " % (self.record_type, self.event_id)
        buf += ' '.join(["%s=%s" % (k, self.fields[k]) for k in self.fields_ord]) + "\n"
        return buf
    def to_text(self):
        return "type=%s msg=%s: %s\n" % (self.record_type, self.event_id, self.body_text)

    def to_host_text(self):
        if self.event_id.host is not None:
            return "node=%s type=%s msg=%s: %s\n" % \
                   (self.event_id.host, self.record_type, self.event_id, self.body_text)
        else:
            return self.to_text()

    def to_binary(self):
        record = "%s: %s" % (self.event_id, self.body_text)
        return self.get_binary_header(record) + record

#-----------------------------------------------------------------------------

class AuditRecordReader:
    BINARY_FORMAT = 1
    TEXT_FORMAT = 2

    def __init__(self, record_format):
        self.record_format = record_format
        self._input_buffer = ''
        self.line_number = 0
        
        if self.record_format == self.TEXT_FORMAT:
            self.feed = self.feed_text
        elif self.record_format == self.BINARY_FORMAT:
            self.feed = self.feed_binary
        else:
            raise ValueError("unknown record format (%s) in %s" % (record_format, self.__class__.__name__))

    def feed_binary(self, new_data):
        if len(new_data) <= 0:
            return
        self._input_buffer += new_data

        # Now process as much of the buffer as we can, iterating over complete
        # messages.

        while True:

            # To read a complete message there must be a complete header and
            # all the data the header specified via the header.length
            if len(self._input_buffer) < AuditRecord.binary_header_size:
                return

            binary_version, binary_header_size, record_type, msg_length = \
                            struct.unpack(AuditRecord.binary_header_format,
                                          self._input_buffer[0:AuditRecord.binary_header_size])

            total_len = AuditRecord.binary_header_size + msg_length

            if len(self._input_buffer) < total_len:
                return

            text = self._input_buffer[AuditRecord.binary_header_size:total_len]
            parse_succeeded, event_id, body_text = parse_audit_binary_text(text)
            self._input_buffer = self._input_buffer[total_len:]

            if parse_succeeded:
                yield (audit.audit_msg_type_to_name(record_type), event_id, body_text, None, 0)

        return

    def feed_text(self, new_data):
        if len(new_data) <= 0:
            return
        self._input_buffer += new_data

        # Now process as much of the buffer as we can, iterating over complete
        # messages.

        # To read a complete message we must see a line ending
        start = 0
        end = self._input_buffer.find('\n', start)
        while end >= 0:
            self.line_number += 1
            end += 1                # include newline
            line = self._input_buffer[start:end]
            parse_succeeded, record_type, event_id, body_text = parse_audit_record_text(line)
            if parse_succeeded:
                yield (record_type, event_id, body_text, None, self.line_number)
            start = end
            end = self._input_buffer.find('\n', start)

        self._input_buffer = self._input_buffer[start:]

        return

#-----------------------------------------------------------------------------

class AuditEvent(XmlSerialize):
    _xml_info = {
    'records'      : {'XMLForm':'element', 'list':'audit_record', 'import_typecast':AuditRecord, },
    'event_id'     : {'XMLForm':'element', 'import_typecast':AuditEventID },
    }

    def __init__(self):
        super(AuditEvent, self).__init__()
        self.event_id     = None
        self.records      = []
        self.record_types = {}
        self.timestamp = None

    def _init_postprocess(self):
        if getattr(self, 'record_types', None) is None:
            self.record_types = {}
            
        for record in self.records:
            self.process_record(record)

    def __str__(self):
        line_numbers = self.line_numbers
        line_numbers.sort()
        return "%s: is_avc=%s, is_granted=%s: line_numbers=[%s]\n%s" % \
               (self.event_id, self.is_avc(), self.is_granted(),
                ",".join([str(x) for x in line_numbers]),
                "\n".join(["    %s" % record for record in self.records]))

    def format(self, separator='\n'):
        return separator.join([str(record) for record in self.records])

    def num_records(self):
        return len(self.records)

    line_numbers = property(lambda self: [record.line_number for record in self.records if record.line_number])

    def add_record(self, record):
        self.records.append(record)
        self.process_record(record)

    def process_record(self, record):
        if self.event_id is None:
            self.event_id = record.event_id.copy()
            self.timestamp = float(self.event_id.seconds) + (self.event_id.milli / 1000.0)
        else:
            if not self.event_id == record.event_id:
                raise ValueError("cannot add audit record to audit event, event_id mismatch %s != %s" % \
                                 (self.event_id, record.event_id))

        record_list = self.record_types.setdefault(record.record_type, [])
        record_list.append(record)

    def get_field(self, name, record_type=None):
        '''Return list of (value, record_type) tuples.
        In other words return the value matching name for every record_type.
        If record_type is not specified then all records are searched.
        Note: it is possible to have more than one record of a given type
        thus it is always possible to have multiple values returned.'''
        items = []
        if record_type is None:
            records = self.records
        else:
            records = self.get_records_of_type(record_type)

        for record in records:
            value = record.fields.get(name)
            if value is None: continue
            items.append((value, record.type))

        return items

    def get_record_of_type(self, type):
        record = None
        records = self.record_types.get(type)
        if records: record = records[0]
        return record

    def get_records_of_type(self, type):
        return self.record_types.get(type, [])

    def get_avc_record(self):
        record = self.get_record_of_type('AVC')
        if not record:
            record = self.get_record_of_type('USER_AVC')
        return record

    def is_avc(self):
        return self.get_avc_record() is not None

    def is_granted(self):
        avc_record = self.get_avc_record()
        if avc_record is None:
            return False
        seresult = avc_record.fields['seresult']
        if seresult == 'denied':
            return False
        if seresult == 'granted':
            return True
        log.avc.warn("unknown value for seresult ('%s')", seresult)
        return False

#------------------------------------------------------------------------------

class AVC:
    # These are the perm sets from the reference policy for file, dirs, and filesystems.
    # They are here to be used below in the access matching functions.
    stat_file_perms     = ['getattr']
    x_file_perms        = ['getattr', 'execute']
    r_file_perms        = ['open', 'read', 'getattr', 'lock', 'ioctl']
    rx_file_perms       = ['open', 'read', 'getattr', 'lock', 'execute', 'ioctl']
    ra_file_perms       = ['open', 'ioctl', 'read', 'getattr', 'lock', 'append']
    link_file_perms     = ['getattr', 'link', 'unlink', 'rename']
    create_lnk_perms    = ['create', 'read', 'getattr', 'setattr', 'link', 'unlink', 'rename']
    create_file_perms   = ['open', 'create', 'ioctl', 'read', 'getattr', 'lock', 'write', 'setattr', 'append',
                           'link', 'unlink', 'rename']
    r_dir_perms         = ['open', 'read', 'getattr', 'lock', 'search', 'ioctl']
    rw_dir_perms        = ['open', 'read', 'getattr', 'lock', 'search', 'ioctl', 'add_name', 'remove_name', 'write']
    ra_dir_perms        = ['open', 'read', 'getattr', 'lock', 'search', 'ioctl', 'add_name', 'write']
    create_dir_perms    = ['open', 'create', 'read', 'getattr', 'lock', 'setattr', 'ioctl', 'link', 'unlink',
                           'rename', 'search', 'add_name', 'remove_name', 'reparent', 'write', 'rmdir']
    mount_fs_perms      = ['mount', 'remount', 'unmount', 'getattr']
    search_dir_perms    = ['getattr', 'search']
    getattr_dir_perms   = ['getattr']
    setattr_dir_perms   = ['setattr']
    list_dir_perms      = ['open', 'getattr', 'search', 'read', 'lock', 'ioctl']
    add_entry_dir_perms = ['open', 'getattr', 'search', 'lock', 'ioctl', 'write', 'add_name']
    del_entry_dir_perms = ['open', 'getattr', 'search', 'lock', 'ioctl', 'write', 'remove_name']
    manage_dir_perms    = ['open', 'create', 'getattr', 'setattr', 'read', 'write', 'link', 'unlink', 'rename',
                           'search', 'add_name', 'remove_name', 'reparent', 'rmdir', 'lock', 'ioctl']
    getattr_file_perms  = ['getattr']
    setattr_file_perms  = ['setattr']
    read_file_perms     = ['open', 'getattr', 'read', 'lock', 'ioctl']
    append_file_perms   = ['open', 'getattr', 'append', 'lock', 'ioctl']
    write_file_perms    = ['open', 'getattr', 'write', 'append', 'lock', 'ioctl']
    rw_file_perms       = ['open', 'getattr', 'read', 'write', 'append', 'ioctl', 'lock']
    delete_file_perms   = ['getattr', 'unlink']
    manage_file_perms   = ['open', 'create', 'getattr', 'setattr', 'read', 'write', 'append', 'rename', 'link',
                           'unlink', 'ioctl', 'lock']

    pipe_instance_path_re = re.compile(r'^(\w+):\[([^\]]*)\]')
    proc_pid_instance_re = re.compile(r'^(/proc/)(\d+)(.*)')

    def __init__(self, audit_event, query_environment=True):
        self.audit_event = audit_event
        self.query_environment = query_environment
#        if audit_event.timestamp is None:
#            self.audit_event.timestamp = TimeStamp()
        self.template_substitutions = {}
        self.tpath = None
        self.spath = None
        self.source = None
        self.source_pkg = None
        self.access = None
        self.scontext = None
        self.tcontext = None
        self.tclass = None
        self.port = None
        self.src_rpms=[]
        self.tgt_rpms=[]
        self.host = None
        self.kmod = None
        self.syscall = None
        self.why = None
        self.bools = []
        self.derive_avc_info_from_audit_event()

    def __str__(self):
        return self.format_avc()

    def format_avc(self):
        text = ''
        text += 'scontext=%s ' % self.scontext
        text += 'tcontext=%s ' % self.tcontext
        text += 'access=%s '   % self.access
        text += 'tclass=%s '   % self.tclass
        text += 'tpath=%s '    % self.tpath

        return text

    # Below are helper functions to get values that might be
    # stored in one or more fields in an AVC.
    
    def has_any_access_in(self, access_list):
        'Returns true if the AVC contains _any_ of the permissions in the access list.'

        if self.access is None: return False
        for a in self.access:
            if a in access_list:
                return True
                
        return False

    def all_accesses_are_in(self, access_list):
        """Returns true if _every_ access in the AVC matches at
        least one of the permissions in the access list."""

        if self.access is None: return False
        for a in self.access:
            if a not in access_list:
                return False
                
        return True
    
    def allowed_target_types(self):
        return map(lambda x: x[TCONTEXT], sesearch([ALLOW], {SCONTEXT: self.scontext.type, CLASS: self.tclass, PERMS: self.access}))
        

    def open_with_write(self):
        if self.has_any_access_in(['open']):
            try:
                if self.a1 and (int(self.a1) & O_ACCMODE) != os.O_RDONLY:
                    return True
            except:
                pass
        return False


    def __typeMatch(self, context, type_list):
        for type in type_list:
            if re.match(type, context.type):
                return True
        return False

    def matches_source_types(self, type_list):
        """Returns true if the type in the source context of the
        avc regular expression matches any of the types in the type list."""
        if self.scontext is None: return False
        return self.__typeMatch(self.scontext, type_list)

    def matches_target_types(self, type_list):
        """Returns true if the type in the target context of the
        avc regular expression matches any of the types in the type list."""
        if self.tcontext is None: return False
        return self.__typeMatch(self.tcontext, type_list)


    def has_tclass_in(self, tclass_list):
        if self.tclass is None: return False
        return self.tclass in tclass_list

    def update(self):
        self.derive_environmental_info()
        self.update_derived_template_substitutions()

    def path_is_not_standard_directory(self):
        if self.tpath is None: return True
        return self.tpath not in standard_directories

    def _set_tpath(self):
        '''Derive the target path.

        If path information is available the avc record will have a path field
        and no name field because the path field is more specific and supercedes
        name. The name field is typically the directory entry.

        For some special files the kernel embeds instance information
        into the file name. For example 'pipe:[1234]' or 'socket:[1234]'
        where the number inside the brackets is the inode number. The proc
        pseudo file system has the process pid embedded in the name, for
        example '/proc/1234/mem'. These numbers are ephemeral and do not
        contribute meaningful information for our reports. Plus we may use
        the path information to decide if an alert is identical to a
        previous alert, we coalesce them if they are. The presence of an
        instance specific number in the path confuses this comparision.
        For these reasons we strip any instance information out of the
        path,

        Example input and output:

        pipe:[1234]    --> pipe
        socket:[1234]  --> socket
        /proc/1234/fd  --> /proc/<pid>/fd
        ./foo          --> ./foo
        /etc/sysconfig --> /etc/sysconfig
        '''

        path = None
        name = None

        # First try to get the path from the AVC record, new kernel
        # versions put it there rather than in AVC_PATH

        path = self.avc_record.get_field('path')
        inodestr = self.avc_record.get_field("ino")

        if path is None:
            avc_path_record = self.audit_event.get_record_of_type('PATH')
            if avc_path_record:
                path = avc_path_record.get_field('name')
            
        if path is None:
            # No path field, so try and use the name field instead
            name = self.avc_record.get_field('name')
            if name is not None:
                # Use the class to be smart about formatting the name 
                tclass = self.avc_record.get_field('tclass')
                if tclass   == 'file':
                    # file name is not a full path so make it appear relative
                    path = '%s' % name
                elif tclass == 'dir':
                    # directory component is not a full path so make it appear
                    # relative, but only if it's not the root
                    if name == '/':
                        path = name
                    else:
                        path = '%s' % name
                else:
                    # just use the bare name
                    path = name

        if path is not None:

            if path == "/"  and inodestr:
                matches = []
                try:
                    dev_rdev = 0
                    dev = self.avc_record.get_field('dev')
                    if os.path.exists("/dev/"+dev):
                        dev_rdev = os.lstat("/dev/"+dev).st_rdev

                    ino = int(inodestr)
                    fd=open("/proc/mounts", "r")
                    for i in fd.read().split("\n"):
                        x = i.split()
                        if len(x) and x[1][0] == '/':
                            try:
                                if (dev_rdev == 0 or os.stat(x[0]).st_rdev == dev_rdev) and int(os.lstat(x[1]).st_ino) == ino:
                                    matches.append(x[:3])
                            except OSError:
                                continue 
                    fd.close()
                    if len(matches) == 1:
                        path = matches[0][1]
                    elif len(matches) > 1:
                        for i in matches:
                             if i[0] == ("/dev/%s" % dev) or i[2] == dev:
                                 path = i[1]
                                 break
                             else:
                                 try:
                                     if dev_rdev != 0 and os.lstat(i[0]).st_rdev == dev_rdev:
                                         path = i[1]
                                         break
                                 except OSError:
                                     pass
                except TypeError:
                    path = "unknown mountpoint"
                    pass
                except OSError:
                    path = "unknown mountpoint"
                    pass

            else:
                if path.startswith("/") == False and inodestr:
                    import commands
                    command = "locate -b '\%s'" % path 
                    rc, output = commands.getstatusoutput(command)
                    if rc == 0:
                        ino = int(inodestr)
                        for file in output.split("\n"):
                            try:
                                if int(os.lstat(file).st_ino) == ino:
                                    path = file
                                    break
                            except:
                                pass

        if path is not None:
            if path.startswith('/'):
                # Fully qualified path
                # map /proc/1234/ to /proc/<pid>, replacing numeric pid with <pid>
                path = self.proc_pid_instance_re.sub(r'\1<pid>\3', path)
            else:
                # map pipe:[1234] to pipe, stripping out inode instance (e.g. [1234])
                # applies to socket as well
                match = self.pipe_instance_path_re.search(path)
                if match:
                    path = self.tclass

        try:
            t = path.decode("hex")
            if t[0].encode("hex") == "00":
                self.tpath = "@"
            else:
                self.tpath = t[0]

            for i in range(len(t))[1:]:
                if t[i].encode("hex") != "00":
                    self.tpath = self.tpath + t[i]
                else:
                    break
        except:
            self.tpath = path

        if self.tpath is None:
            self.tpath = _("port %s") % self.port
            
    def derive_avc_info_from_audit_event(self):
        self.tpath = None
        self.spath = None
        self.source = None
        self.a1 = None
        self.success = False
        self.syscall_paths = []
        exe = comm = arch = syscall = None

        self.avc_record = self.audit_event.get_avc_record()
        syscall_record = self.audit_event.get_record_of_type('SYSCALL')

        self.access = self.avc_record.get_field('seperms')
        if not isinstance(self.scontext, AvcContext):
            self.scontext = AvcContext(self.avc_record.get_field('scontext'))

        if not isinstance(self.tcontext, AvcContext):
            self.tcontext = AvcContext(self.avc_record.get_field('tcontext'))

        self.tclass = self.avc_record.get_field('tclass')

        if self.avc_record.get_field('dest') is None:
            self.port = self.avc_record.get_field('src')
        else:
            self.port = self.avc_record.get_field('dest')

        self._set_tpath()

        self.kmod = self.avc_record.get_field('kmod')

        # exe, cwd, name, path, key, dir, comm, ocomm, key_desc

        if syscall_record:
            exe     = syscall_record.get_field('exe')
            try:
                exe.decode("hex")
            except:
                pass
            comm    = syscall_record.get_field('comm')
            self.syscall = syscall_record.get_field('syscall')
            self.success = (syscall_record.get_field('success') == "yes")
            self.a1 = syscall_record.get_field('a1')

        if comm is None:
            comm = self.avc_record.get_field('comm')
        if exe is None:
            exe = self.avc_record.get_field('exe')

        try:
            self.spath = exe.decode("hex")
        except:
            self.spath = exe

        if comm:
            self.source = comm
        elif exe:
            self.source = self.spath

        if not self.spath:
            self.spath = self.source

        cwd_record = self.audit_event.get_record_of_type('CWD')
        if cwd_record:
            cwd = cwd_record.get_field('cwd')
        else:
            cwd = None

        path_records = self.audit_event.get_records_of_type('PATH')
        for path_record in path_records:
            path = path_record.get_field('name')
            if os.path.isabs(path) or not cwd:
                self.syscall_paths.append(path)
            else:
                self.syscall_paths.append(os.path.join(cwd, path))


        self.src_rpms=[]
        self.tgt_rpms=[]

        self.host = self.audit_event.event_id.host

        self.why, bools = audit2why.analyze(str(self.scontext), str(self.tcontext), str(self.tclass), self.access)
        if self.why == audit2why.ALLOW:
            raise ValueError(_("%s \n**** Invalid AVC allowed in current policy ***\n") %  self.avc_record)
        if self.why == audit2why.DONTAUDIT:
            raise ValueError(_("%s \n**** Invalid AVC dontaudited in current policy.  'semodule -B' will turn on dontaudit rules. ***\n") %  self.avc_record)
        if self.why == audit2why.NOPOLICY:
            raise ValueError(_("Must call policy_init first"))
        if self.why == audit2why.BADTCON:
            raise ValueError(_("%s \n**** Invalid AVC bad target context. ***\n") % self.avc_record)
        if self.why == audit2why.BADSCON:
            raise ValueError(_("%s \n**** Invalid AVC bad source context. ***\n") % self.avc_record)
        if self.why == audit2why.BADSCON:
            raise ValueError(_("%s \n**** Invalid AVC bad type class ***\n") % self.avc_record)
        if self.why == audit2why.BADPERM:
            raise ValueError(_("%s \n**** Invalid AVC bad permission ***\n") % self.avc_record)
        if self.why == audit2why.BADCOMPUTE:
            raise ValueError(_("Error during access vector computation"))
        if self.why == audit2why.BOOLEAN:
            self.bools = bools

    def derive_environmental_info(self):
        if self.query_environment:
            if self.spath:
                self.source_pkg = get_rpm_nvr_by_file_path(self.spath)
                if self.source_pkg:
                    self.src_rpms.append(self.source_pkg)
        
            if self.tpath:
                rpm = get_rpm_nvr_by_file_path(self.tpath)
                if rpm:
                    self.tgt_rpms.append(rpm)


    def set_alt_path(self, path):
        if self.tpath is None:
            self.tpath = path

    def set_template_substitutions(self, **kwds):
        for key, value in kwds.items():
            if value:
                self.template_substitutions[key] = value

    def update_derived_template_substitutions(self):
        self.template_substitutions["SOURCE_TYPE"] = escape_html(self.scontext.type)
        self.template_substitutions["TARGET_TYPE"] = escape_html(self.tcontext.type)
        self.template_substitutions["SOURCE"]      = escape_html(self.source)
        self.template_substitutions["SOURCE_PATH"] = escape_html(self.spath)
        if self.spath:
            self.template_substitutions["FIX_SOURCE_PATH"] = re.sub(" ",".",escape_html(self.spath))
        self.template_substitutions["TARGET_PATH"] = escape_html(self.tpath)
        if self.tpath:
            self.template_substitutions["FIX_TARGET_PATH"] = re.sub(" ",".",escape_html(self.tpath))

        if self.tpath is None:
            self.template_substitutions["TARGET_DIR"] = None
        else:
            if self.tclass == 'dir':
                self.template_substitutions["TARGET_DIR"] = escape_html(self.tpath)
            elif self.tclass == 'file':
                self.template_substitutions["TARGET_DIR"] = escape_html(os.path.dirname(self.tpath))
            else:
                self.template_substitutions["TARGET_DIR"] = None

        self.template_substitutions["TARGET_CLASS"] = escape_html(self.tclass)

        if self.access is None:
            self.template_substitutions["ACCESS"] = None
        else:
            self.template_substitutions["ACCESS"] = escape_html(' '.join(self.access))

        self.template_substitutions["SOURCE_PACKAGE"] = escape_html(self.source_pkg)
        self.template_substitutions["PORT_NUMBER"] = escape_html(self.port)


    def validate_template_substitutions(self):
        # validate, replace any None values with friendly string
        for key, value in self.template_substitutions.items():
            if value is None:
                self.template_substitutions[key] = escape_html(default_text(value))
