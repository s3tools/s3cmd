# -*- coding: utf-8 -*-

# patterned on /usr/include/sysexits.h

EX_OK                = 0
EX_GENERAL           = 1
EX_PARTIAL           = 2    # some parts of the command succeeded, while others failed
EX_SERVERMOVED       = 10   # 301: Moved permanently & 307: Moved temp
EX_SERVERERROR       = 11   # 400, 405, 411, 416, 417, 501: Bad request, 504: Gateway Time-out
EX_NOTFOUND          = 12   # 404: Not found
EX_CONFLICT          = 13   # 409: Conflict (ex: bucket error)
EX_PRECONDITION      = 14   # 412: Precondition failed
EX_SERVICE           = 15   # 503: Service not available or slow down
EX_USAGE             = 64   # The command was used incorrectly (e.g. bad command line syntax)
EX_DATAERR           = 65   # Failed file transfer, upload or download
EX_SOFTWARE          = 70   # internal software error (e.g. S3 error of unknown specificity)
EX_OSERR             = 71   # system error (e.g. out of memory)
EX_OSFILE            = 72   # OS error (e.g. invalid Python version)
EX_IOERR             = 74   # An error occurred while doing I/O on some file.
EX_TEMPFAIL          = 75   # temporary failure (S3DownloadError or similar, retry later)
EX_ACCESSDENIED      = 77   # Insufficient permissions to perform the operation on S3
EX_CONFIG            = 78   # Configuration file error
EX_CONNECTIONREFUSED = 111  # TCP connection refused (e.g. connecting to a closed server port)
_EX_SIGNAL           = 128
_EX_SIGINT           = 2
EX_BREAK             = _EX_SIGNAL + _EX_SIGINT # Control-C (KeyboardInterrupt raised)

class ExitScoreboard(object):
    """Helper to return best return code"""
    def __init__(self):
        self._success = 0
        self._notfound = 0
        self._failed = 0

    def success(self):
        self._success += 1

    def notfound(self):
        self._notfound += 1

    def failed(self):
        self._failed += 1

    def rc(self):
        if self._success:
            if not self._failed and not self._notfound:
                return EX_OK
            elif self._failed:
                return EX_PARTIAL
        else:
            if self._failed:
                return EX_GENERAL
            else:
                if self._notfound:
                    return EX_NOTFOUND
        return EX_GENERAL
