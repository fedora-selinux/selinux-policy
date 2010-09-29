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
    'ProgramError',
    'get_strerror'
    ]

#-----------------------------------------------------------------------------

errcode = {}
strerror = {}
ERROR_BASE = 1000

#-----------------------------------------------------------------------------

def get_strerror(errno):
    str = strerror.get(errno, None)
    if str is None:
        import os
        str = os.strerror(errno)
    return str

def err(num, name, str):
    global errcode, strerror

    errno = ERROR_BASE + num
    globals()[name] = errno
    errcode[name] = errno
    __all__.append(name)
    strerror[errno] = str


#-----------------------------------------------------------------------------

class ProgramError(Exception):
    def __init__(self, errno, strerror=None, detail=None):
        self.errno = errno
        if strerror is None:
            self.strerror = get_strerror(errno)
        else:
            self.strerror = strerror
        if detail is not None:
            self.strerror += ' ' + detail

    def __str__(self):
        return "[Errno %d] %s" % (self.errno, self.strerror)


#-----------------------------------------------------------------------------

err(  1, 'ERR_NO_SIGNATURE_MATCH',       _('signature not found'))
err(  2, 'ERR_MULTIPLE_SIGNATURE_MATCH', _('multiple signatures matched'))
err(  3, 'ERR_SIGNATURE_ID_NOT_FOUND',   _('id not found'))
err(  4, 'ERR_DATABASE_NOT_FOUND',       _('database not found'))
err(  5, 'ERR_NOT_MEMBER',               _('item is not a member'))
err(  6, 'ERR_ILLEGAL_USER_CHANGE',      _('illegal to change user'))
err(  7, 'ERR_METHOD_NOT_FOUND',         _('method not found'))
err(  8, 'ERR_CANNOT_CREATE_GUI',        _('cannot create GUI'))
err(  9, 'ERR_UNKNOWN_VALUE',            _('value unknown'))
err( 10, 'ERR_FILE_OPEN',                _('cannot open file'))
err( 11, 'ERR_INVALID_EMAIL_ADDR',       _('invalid email address'))

# gobject IO Errors
err( 12, 'ERR_SOCKET_ERROR',             _('socket error'))
err( 13, 'ERR_SOCKET_HUP',               _('connection has been broken'))
err( 14, 'ERR_IO_INVALID',               _('Invalid request. The file descriptor is not open'))

err( 15, 'ERR_USER_PERMISSION',          _('insufficient permission to modify user'))
err( 16, 'ERR_AUTHENTICATION_FAILED',    _('authentication failed'))
err( 17, 'ERR_USER_PROHIBITED',          _('user prohibited'))
err( 18, 'ERR_NOT_AUTHENTICATED',        _('not authenticated'))
err( 19, 'ERR_USER_LOOKUP',              _('user lookup failed'))
