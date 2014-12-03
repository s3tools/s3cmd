# patterned on /usr/include/sysexits.h

EX_OK               = 0
EX_GENERAL          = 1
EX_PARTIAL          = 2    # some parts of the command succeeded, while others failed
EX_SERVERMOVED      = 10   # 301: Moved permanantly & 307: Moved temp
EX_SERVERERROR      = 11   # 400, 405, 411, 416, 501: Bad request
EX_NOTFOUND         = 12   # 404: Not found
EX_CONFLICT         = 13   # 409: Conflict (ex: bucket error)
EX_PRECONDITION     = 14   # 412: Precondition failed
EX_SERVICE          = 15   # 503: Service not available or slow down
EX_USAGE            = 64   # The command was used incorrectly (e.g. bad command line syntax)
EX_SOFTWARE         = 70   # internal software error (e.g. S3 error of unknown specificity)
EX_OSERR            = 71   # system error (e.g. out of memory)
EX_OSFILE           = 72   # OS error (e.g. invalid Python version)
EX_IOERR            = 74   # An error occurred while doing I/O on some file.
EX_TEMPFAIL         = 75   # temporary failure (S3DownloadError or similar, retry later)
EX_ACCESSDENIED     = 77   # Insufficient permissions to perform the operation on S3
EX_CONFIG           = 78   # Configuration file error
_EX_SIGNAL          = 128
_EX_SIGINT          = 2
EX_BREAK            = _EX_SIGNAL + _EX_SIGINT # Control-C (KeyboardInterrupt raised)
