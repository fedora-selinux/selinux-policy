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
    'AuditSocketReceiverThread',
    'AuditRecordReceiver',              # FIXME, do we really want to export this?
    'verify_avc', 
    ]

import audit
import select
import selinux
import socket as Socket
import fcntl
import thread
import threading
import time

from setroubleshoot.config import get_config
from setroubleshoot.errcode import *
from setroubleshoot.log import *
from setroubleshoot.util import *
from setroubleshoot.audit_data import *

try:
    getattr(audit, 'AUDIT_EOE')
except AttributeError:
    audit.AUDIT_EOE = 1320

#------------------------------------------------------------------------------

my_context = AvcContext(selinux.getcon()[1])
def verify_avc(avc):
    if avc.scontext.type == None or avc.tcontext.type == None:
        return False

    if my_context.type == avc.scontext.type:
        log_program.error( "setroubleshoot generated AVC, exiting to avoid recursion, context=%s, AVC scontext=%s", my_context, avc.scontext)
        log_program.error( "audit event\n%s", avc.audit_event.format())
        import sys
        sys.exit(0)

    return True

#------------------------------------------------------------------------------

class AuditRecordReceiver:
    """
    The audit system emits messages about a single event
    independently. Thus one single auditable event may be composed
    from one or more individual audit messages. Each audit message is
    prefixed with a unique event id, which includes a timestamp. The
    last audit message associated with an event is not marked in any
    fashion. Audit messages for a specific event may arrive
    interleaved with audit messages for other events. It is the job of
    higher level software (this code) to assemble the audit messages
    into events. The AuditEvent class is used for assembly. When a new
    event id is seen a new AuditEvent object is created, then
    every time an audit message arrives with that event id it is added
    to that object. The AuditEvent object contains the timestamp
    associated with the audit event as well as other data items useful
    for processing and handling the event.

    The audit system does not tell us when the last message belonging
    to an event has been emitted so we have no explicit way of knowing
    when the audit event has been fully assembled from its constituent
    message parts. We use the heuristic if a sufficient length of
    time has expired since we last saw a message for this event, then
    it must be complete

    Thus when audit events are created we place them in a cache where
    they will reside until their time to live has expired at which
    point we will assume they are complete and emit the event.

    Events are expired in the flush_cache() method. The events
    resident in the cache are sorted by their timestamps. A time
    threshold is established. Any events in the cache older than the
    time threshold are flushed from the cache as complete events.

    When should flushes be performed? The moment when a new message is
    added would seem a likely candidate moment to perform a sweep of
    the cache. But this is costly and does not improve how quickly
    events are expired. We could wait some interval of time (something
    much greater than how long we expect it would take for messages
    percolate) and this has good behavior, except for the following
    case. Sometimes messages are emitted by audit in rapid
    succession. If we swept the cache once a second then the cache may
    have grown quite large. Since it is very likely that any given audit
    event is complete by the time the next several events start
    arriving we can optimize by tracking how many messages have
    arrived since the last time we swept the cache.

    The the heuristic for when to sweep the cache becomes:

    If we've seen a sufficient number of messages then sweep -or- if
    a sufficient length of time has elapsed then we sweep

    Note that when audit messages are injected via log file scanning
    elapsed wall clock time has no meaning relative to when to perform
    the cache sweep. However, the timestamp for an event remains a
    critical factor when deciding if an event is complete (have we
    scanned far enough ahead such we're confident we won't see any
    more messages for this event?). Thus the threshold for when to
    expire an event from the cache during static log file scanning is
    determined not by wall clock time but rather by the oldest
    timestamp in the cache (e.g.there is enough spread between
    timestamps in the cache its reasonable to assume the event is
    complete). One might ask in the case of log file scanning why not
    fill the cache until EOF is reached and then sweep the cache?
    Because in log files it is not unusual to have thousands or tens
    of thousands of events and the cache would grown needlessly
    large. Because we have to deal with the real time case we already
    have code to keep only the most recent events in the cache so we
    might as well use that logic, keep the code paths the same and
    minimize resource usage.
    """

    # number of seconds an event must reside in the cache until its
    # considered complete
    cache_time_to_live = 0.005

    def __init__(self):
        self.flush_size = 30
        self.flush_count = 0
        self.cache = {}
        self.events = []
        self.reset_statistics()

    def num_cached_events(self):
        return len(self.cache)

    def reset_statistics(self):
        self.max_cache_length = 0
        self.event_count = 0

    def insert_new_event(self, record):
        audit_event = AuditEvent()
        self.cache[str(record.event_id)] = audit_event
        return audit_event

    def get_event_from_record(self, record):
        return self.cache.get(str(record.event_id), None)

    def add_record_to_cache(self, record):
        if debug:
            log_avc.debug("%s.add_record_to_cache(): %s", self.__class__.__name__, record)
        
        audit_event = self.get_event_from_record(record)
        if record.record_type == 'EOE':
            if audit_event:
                self.flush_event(audit_event)
            return
        if audit_event is None:
            audit_event = self.insert_new_event(record)
        audit_event.add_record(record)

    def emit_event(self, audit_event):
        self.event_count += 1
        self.events.insert(0, audit_event)

    def flush_event(self, audit_event):
        self.emit_event(audit_event)
        del(self.cache[str(audit_event.event_id)])

    def flush_cache(self, threshold_age=None):
        '''Flush events from the cache if they are older than the threshold age.
        If the threshold age is None then the threshold age is set to the age
        of the newest event in the cache minus the cache time to live, in other
        words anything in the cache which is older than the time to live relative
        to the most current event is flushed.
        '''

        # no events, nothing to do
        if len(self.cache) == 0:
            return

        if len(self.cache) > self.max_cache_length:
            self.max_cache_length = len(self.cache)
            
        event_ids = self.cache.keys()

        # flush everything
        if threshold_age == 0:
            for event_id in event_ids:
                audit_event = self.cache[event_id]
                self.flush_event(audit_event)
            return

        # flush old events
        event_ids.sort(lambda a,b: cmp(self.cache[a].timestamp, self.cache[b].timestamp))
        if threshold_age is None:
            threshold_age = self.cache[event_ids[-1]].timestamp - self.cache_time_to_live

        for event_id in event_ids:
            audit_event = self.cache[event_id]
            if audit_event.timestamp < threshold_age:
                self.flush_event(audit_event)

    def flush(self, threshold_age=None):
        self.flush_cache(threshold_age)
        self.flush_count = 0
        while len(self.events) > 0:
            audit_event = self.events.pop()
            yield audit_event

    def close(self):
        """Emit every event in the cache irrespective of its
        timestamp. This means we're done, nothing should remain buffered."""
        
        for audit_event in self.flush(0):
            yield audit_event

    def feed(self, record):
        'Accept a new audit record into the system for processing.'
        if debug:
            log_avc.debug("%s.feed() got %s'", self.__class__.__name__, record)

        self.flush_count += 1
        if record.record_type in ('AVC', 'AVC_PATH', 'SYSCALL', 'CWD', 'PATH', 'EOE'):
            self.add_record_to_cache(record)

        # If we've seen enough messages then sweep the event cache and flush what we can
        if self.flush_count > self.flush_size:
            for audit_event in self.flush():
                yield audit_event

        while len(self.events) > 0:
            audit_event = self.events.pop()
            yield audit_event

#------------------------------------------------------------------------------

class AuditSocketReceiverThread(threading.Thread):
    def __init__(self, queue, report_receiver):
        # parent class constructor
        threading.Thread.__init__(self)
        self.queue = queue
        self.report_receiver = report_receiver
        self.record_receiver = AuditRecordReceiver()
        self.retry_interval = get_config('audit','retry_interval', int)
        self.get_socket_paths()
        self.timeout_interval = 2
        self.has_audit_eoe = False


    def get_socket_paths(self):
        self.audit_socket_paths = []

        audit_socket_path = get_config('audit','text_protocol_socket_path')
        self.audit_socket_paths.append(audit_socket_path)

        audit_socket_path = get_config('audit','binary_protocol_socket_path')
        self.audit_socket_paths.append(audit_socket_path)

    def connect(self):
        while True:
            try:
                for self.audit_socket_path in self.audit_socket_paths:
                    if self.audit_socket_path is not None:
                        try:
                            record_format = derive_record_format(self.audit_socket_path)
                            self.record_reader = AuditRecordReader(record_format)
                            self.audit_socket=Socket.socket(Socket.AF_UNIX,Socket.SOCK_STREAM)
                            fcntl.fcntl(self.audit_socket.fileno(), fcntl.F_SETFD, fcntl.FD_CLOEXEC)
                            self.audit_socket.connect(self.audit_socket_path)
                            self.audit_socket_fd = self.audit_socket.makefile()
                            log_avc.info("audit socket (%s) connected", self.audit_socket_path)
                            return
                        except Socket.error, e:
                            errno, strerror = get_error_from_socket_exception(e)
                            log_avc.info("attempt to open audit socket (%s) failed, error='%s'",
                                         self.audit_socket_path, strerror)

                log_avc.warning("could not open any audit sockets (%s), retry in %d seconds",
                                ', '.join(self.audit_socket_paths), self.retry_interval)

            except Socket.error, e:
                errno, strerror = get_error_from_socket_exception(e)
                log_avc.warning("audit socket (%s) failed, error='%s', retry in %d seconds",
                                self.audit_socket_path, strerror, self.retry_interval)
                
            except OSError, e:
                log_avc.warning("audit socket (%s) failed, error='%s', retry in %d seconds",
                                self.audit_socket_path, e[1], self.retry_interval)

            time.sleep(self.retry_interval)

    def new_audit_record_handler(self, record_type, event_id, body_text, fields, line_number):
        'called to enter a new audit record'

        audit_record = AuditRecord(record_type, event_id, body_text, fields, line_number)
        audit_record.audispd_rectify()
        for audit_event in self.record_receiver.feed(audit_record):
            self.new_audit_event_handler(audit_event)

    def new_audit_event_handler(self, audit_event):
        if debug:
            log_avc.debug("new_audit_event_handler: event=%s", audit_event)

        if audit_event.is_avc() and not audit_event.is_granted() and audit_event.num_records() > 0:
            avc = AVC(audit_event)
            if verify_avc(avc):
                self.queue.put((avc, self.report_receiver))


    def run(self):
        self.connect()
        
        timeout = self.timeout_interval
        while True:
            inList, outList, errList = select.select([self.audit_socket],[], [], timeout)
            try:
                if self.audit_socket in inList:
                    import os
                    new_data = os.read(self.audit_socket_fd.fileno(), 1024)
                    if new_data == '':
                        if debug:
                            log_avc.debug("audit socket connection dropped")
                        self.connect()
                    else:
                        if debug:
                            log_avc.debug("cached audit event count = %d", self.record_receiver.num_cached_events())
                        if not self.has_audit_eoe:
                            timeout = self.timeout_interval
                        for (record_type, event_id, body_text, fields, line_number) in self.record_reader.feed(new_data):
                            if record_type == 'EOE':
                                self.has_audit_eoe = True
                                timeout = None
                            self.new_audit_record_handler(record_type, event_id, body_text, fields, line_number)
                else:
                    # timeout, anything waiting in our event cache?
                    for audit_event in self.record_receiver.flush(time.time()-self.timeout_interval):
                        self.new_audit_event_handler(audit_event)
                    if self.record_receiver.num_cached_events() == 0:
                        timeout = None

            except KeyboardInterrupt, e:
                if debug:
                    log_avc.debug("KeyboardInterrupt exception in %s", self.__class__.__name__)
                thread.interrupt_main()

            except SystemExit, e:
                if debug:
                    log_avc.debug("SystemExit exception in %s", self.__class__.__name__)
                thread.interrupt_main()

            except Exception, e:
                log_avc.exception("exception %s: %s",e.__class__.__name__, str(e))
                return

