# patterned on /usr/include/sysexits.h

EX_OK         = 0
EX_GENERAL    = 1
EX_SOMEFAILED = 2    # some parts of the command succeeded, while others failed
EX_USAGE      = 64   # The command was used incorrectly (e.g. bad command line syntax)
EX_SOFTWARE   = 70   # internal software error (e.g. S3 error of unknown specificity)
EX_OSERR      = 71   # system error (e.g. out of memory)
EX_OSFILE     = 72   # OS error (e.g. invalid Python version)
EX_IOERR      = 74   # An error occurred while doing I/O on some file.
EX_TEMPFAIL   = 75   # temporary failure (S3DownloadError or similar, retry later)
EX_NOPERM     = 77   # Insufficient permissions to perform the operation on S3  
EX_CONFIG     = 78   # Configuration file error
_EX_SIGNAL    = 128
_EX_SIGINT    = 2
EX_BREAK      = _EX_SIGNAL + _EX_SIGINT # Control-C (KeyboardInterrupt raised)
