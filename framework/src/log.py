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

'''
The python logging module gives us loggers and handlers, sometimes
that's a bit obscure, we rename this concepts to be more friendly:

loggers  --> log_categories
handlers --> log_output

loggers are organized in a tree structure with a single root
logger. handlers may be attached to to any logger in the logger tree
(for example if you wanted to direct output from one category to a
specific place). When a handler wishes to output it walks the tree up
to the root calling each handler it finds. For simplicity sake by
default we attach all our handlers to the root logger. Thus all the
output handlers have equal opportunity to output a logging message
from one of the loggers.

Messages may be filtered by specifying a level. There are 3 places a
level may be set: 

1) on the logger
2) on the handler
3) on the root logger (special case of item 1, global level)

A message has a level attached to it. The decision process of when to
emit a message works like this:

1) The path in the logger tree is walked from the logger to the root
   logger. The first logger encountered with a level other than NOTSET
   defines the effective level, if the message level is greater than
   or equal to the effective level it is accepted for output. If only
   NOTSET is found this becomes the effective level and the message is
   accepted for output.

2) If the message passes the logging (category) level test then every
   logger in the path from the logger to the root logger is given an
   opportunity to emit the message by iterating over its list of
   output handlers. If the message level is greater than or equal to
   tbe level of the output handler it is output.

One consequence of this is that if an output handler is bound to both
the category logger and the root logger it will be emitted
twice. However, if you bind distinct output loggers to tbe category
logger and the root logger then each output logger may have its own
level and destination.

Note: the logging modules provides for propagation flags which stop
traversal to the root as well as filters for more complex filtering
then simple level testing, this offers more fine grained control.

Thus for a message to be output it must:

1) first pass the level test for the logging category.

2) secondly also pass the level test for every output handler bound to
   every level in the path from the logger to the root.

It is tempting to want to set the global level on the root logger and
default the level on any category logger to NOTSET. This would cause
the root logger's level to take effect for any category logger without
an explicit level (e.g. the root logger is the default global
level). The notion of inheriting a level from your ancestors is nice,
but in practice its difficult to meet expectations using level
inheritance, instead we set a level on every logger and forego
inheritance, here's why:

If the root level was higher than an explicitly set category level the
message would be filtered. This would be counter to the expectation if
an explict level was set for any category it would be respected and
would be output. To get around this one could set the level on the
root logger to pass everything (e.g. NOTSET). This would allow
explicitly set category levels to be respected.  However, if a
category did not have an explicit level set it would default to NOTSET
which would pass the message to the root, which being NOTSET would
pass the message to all of its output handlers. The effect would be
any category without an explicit level set would always output, this
also is not what is expected. The solution is not to try and set the
default global level on the root logger and depend on inheritance, but
rather explicitly set the level of every logger, either to the level
requested for that category, or to the default global level if an
explicit level is absent for the category.

Why is there a global debug flag that is checked before any call to
log_xxx.debug()? The logger.debug() function will check the levels and
not output anything if the level settings would prohibit the debug
message, clearly the debug flag is unnecessary, right? This is true,
however, if one considers the amount of work the logging library does
just to determine the log message will be discarded and observe that
in most all cases debug logging will be turned off this consititues a
performance hit, especially considering the large number of
logger.debug() calls throughout the code. In 'C' or similar languages
one could use preprocessor macros to eliminate debug logging in
production code, but this option is not available in python so we wrap
all logger.debug() calls in an 'if debug:' test to prevent spending
cycles on an operation which will be thrown away. Having a global
debug flag does require reevaluatiing it anytime the level of any
logging category changes because if any category is set for debug
logging the flag must be true so the loggers can be given a chance to
evaluate the message for their category.

'''

__all__ = ['log_init',
           'debug',
           'profile',
           'set_default_category_level',
           'set_category_level',
           'enable_log_output',
           'set_log_output_level',
           'dump_log_levels',
          ]

import os
import logging
import logging.handlers
import re
import sys
from types import *

from setroubleshoot.config import *

log_init_done = False
loggers = {}
log_handlers = {}
config_category_level = {}

min_logger_level = logging.CRITICAL
global_level = logging.NOTSET
debug = False
profile = False

# Get the root logger
root_logger = logging.getLogger()

def log_init(program_name, options=None):
    global log_init_done, global_level, debug, profile
    if log_init_done:
        return
    log_init_done = True
    pkg_name = get_config('general','pkg_name')
    syslog_format = '%s: [%%(name)s.%%(levelname)s] %%(message)s' % (pkg_name)

    # The root logger always outputs the message if it's reached.
    root_logger.setLevel(logging.NOTSET)

    # Create syslog handler before doing anything else, just in case we have to report
    # error messages from the logging init
    try:
        syslog_handler = logging.handlers.SysLogHandler(address='/dev/log') 
        syslog_handler.setLevel(logging.ERROR)
        log_handlers['syslog'] = syslog_handler
        syslog_formatter = logging.Formatter(syslog_format)
        syslog_handler.setFormatter(syslog_formatter)
        enable_log_output('syslog')
    except Exception, e:
        print >> sys.stderr, "exception when creating syslog handler: %s" % (e)
        log_handlers['syslog'] = None

    # Get the logging configuration options.
    program_name = os.path.basename(program_name)
    config_section = '%s_log' % program_name

    global_level   = map_level(get_option(config_section, 'level', 'warning', options))
    filename       = get_option(config_section, 'filename', None, options)
    filemode       = get_option(config_section, 'filemode', 'w', options)
    format         = get_option(config_section, 'format', None, options, 'raw')
    cfg_categories = get_option(config_section, 'categories', ','.join(LOG_CATEGORIES), options)
    console_flag   = get_option(config_section, 'console', False, options, bool)
    profile        = get_option(config_section, 'profile', False, options, bool)

    if filename:
        filename = os.path.expandvars(os.path.expanduser(filename))
    
    formatter = logging.Formatter(format)

    # Create console handler
    try:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.NOTSET)
        log_handlers['console'] = console_handler
        console_handler.setFormatter(formatter)
    except IOError:
        log_handlers['console'] = None

    # Create file handler
    if filename:
        try:
            file_handler = logging.FileHandler(filename, filemode)
            file_handler.setLevel(logging.NOTSET)
            log_handlers['file'] = file_handler
            file_handler.setFormatter(formatter)
            enable_log_output('file')
        except IOError, e:
            # Could not open the log file - use console instead
            log_handlers['file'] = None
            enable_log_output('console')
            logging.error("Could not open log file (%s) - using stderr", filename)
    else:
        log_handlers['file'] = None

    # Note: levels NOTSET=0, DEBUG=10, INFO=20, WARNING=30, ERROR=40, CRITICAL=50

    # Iterate through categories defined in the config file.
    # For each category in the config file record the level specified for it

    for category_name, category_level in parse_log_categories(cfg_categories):
        config_category_level[category_name] = map_level(category_level)

    # Iterate over all the category loggers, create them and install
    # their name as an exported symbol of tbis module.

    g = globals()
    for category_name in LOG_CATEGORIES:
        # Generate the exported symbol name of this category logger
        logger_obj_name = "log_%s" % (category_name)
        # Create the logger object, name it after it's category
        logger_obj = logging.getLogger(category_name)
        # Remember this category logger
        loggers[category_name] = logger_obj

        # Insert this category logger into this modules namespace under the exported symbol name.
        g[logger_obj_name] = logger_obj
        __all__.append(logger_obj_name)

        # Set the level for the category, defaulting to NOTSET, otherwise overridden by the config
        # setting for this logger.
        set_category_level(config_category_level.get(category_name, logging.NOTSET), category_name)

    if profile:
        log_stats.setLevel(logging.INFO)

    if console_flag:
        enable_log_output('console')

    set_default_category_level(global_level)
    #dump_log_levels()

def map_level(map_str):
    'Parse a string representing a level, map it to a number'
    if map_str is None:
        return logging.NOTSET
    try:
        level = int(map_str)
    except ValueError:
        map_str = map_str.upper()
        if map_str not in ['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG', 'NOTSET']:
            return logging.NOTSET
        level = logging.getLevelName(map_str)
    return level

def parse_log_categories(str):
    '''Iteratate over a category list in a string, return an array of pairs (name,level)'''
    result = []
    category_re = re.compile('^\s*(~\s*)?([^:\s]+)(\s*:\s*([^:\s]+))?\s*$')
    categories = str.split(',')
    for category in categories:
        match = category_re.search(category)
        if match:
            negate = match.group(1)
            category_name = match.group(2)
            category_level = match.group(4)
            if negate:
                category_level = logging.CRITICAL
            result.append((category_name, category_level))
    return result


def set_debug_flag():
    '''If one or more logging categories are at debug level turn the
    global debug flag on.'''
    global debug

    min_logger_level = get_min_category_level()
    category_level = min(min_logger_level, global_level)
    if category_level < logging.INFO:
        debug = True
    else:
        debug = False
        

def set_category_level(requested_level, category):
    requested_level = map_level(requested_level)

    cfg_level = config_category_level.get(category)
    if cfg_level:
        category_level = cfg_level
    else:
        category_level = requested_level

    logger_obj = loggers.get(category)
    if not logger_obj: return
    logger_obj.setLevel(category_level)
    set_debug_flag()

def set_default_category_level(requested_level):
    for logger_name, logger_obj in loggers.items():
        set_category_level(requested_level, logger_name)
        
def get_min_category_level():
    min_logger_level = logging.CRITICAL
    for logger_obj in loggers.values():
        category_level = logger_obj.level
        if category_level != logging.NOTSET and category_level < min_logger_level:
            min_logger_level = category_level

    return min_logger_level

def enable_log_output(output_name, enable=True, logger=root_logger):
    handler = log_handlers.get(output_name)
    if not handler: return
    if enable:
        if handler not in logger.handlers:
            logger.addHandler(handler)
    else:
        if handler in logger.handlers:
            logger.removeHandler(handler)

def set_log_output_level(requested_level, handlers=None):
    requested_level = map_level(requested_level)

    if handlers is None:
        handlers = ['file', 'console']

    if not (type(handlers) is ListType or type(handlers) is TupleType):
        handlers = [handlers]

    for handler_name in handlers:
        handler_obj = log_handlers.get(handler_name)
        if handler_obj is not None:
            handler_obj.setLevel(requested_level)

def dump_log_levels():
    print "Logging global_level=%s debug=%s" % (logging.getLevelName(global_level), debug)
    print "Loggers:"
    logger_names = loggers.keys()
    logger_names.sort()
    for logger_name in logger_names:
        level = logging.getLevelName(loggers[logger_name].level)
        print "    %-20s %s" % (logger_name, level)

    print "Handlers:"
    handler_names = log_handlers.keys()
    handler_names.sort()
    for handler_name in handler_names:
        if log_handlers[handler_name]:
            level = logging.getLevelName(log_handlers[handler_name].level)
        else:
            level = 'no handler'
        print "    %-20s %s" % (handler_name, level)
