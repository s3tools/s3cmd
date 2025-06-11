Installation of s3cmd package
=============================

Copyright:
    TGRMN Software and contributors

S3tools / S3cmd project homepage:
    http://s3tools.org

!!!
!!! Please consult README file for setup, usage and examples!
!!!

Package formats
---------------
S3cmd is distributed in two formats:

1) Prebuilt RPM file - should work on most RPM-based
   distributions

2) Source .tar.gz package

Installation of Brew package
---------------------------
```
brew install s3cmd
```

Installation of RPM package
---------------------------
The s3cmd-X.Y.Z.noarch.rpm is available via the epel repository. Run the following command as the root user:
```
dnf install s3cmd
```

If the package has been downloaded locally, run the following command as the root user, where X.Y.Z is the most recent s3cmd release version:
```
rpm -ivh s3cmd-X.Y.Z.noarch.rpm
```

You may be informed about missing dependencies
on Python or some libraries. Please consult your 
distribution documentation on ways to solve the problem.

Installation from PyPA (Python Package Authority)
---------------------
S3cmd can be installed from the PyPA using PIP (the recommended tool for PyPA).

1) Confirm you have PIP installed. PIP home page is here: https://pypi.python.org/pypi/pip. Example install on a RHEL yum based machine
```
sudo yum install python-pip
```
2) Install with pip
```
sudo pip install s3cmd
```

Installation from zip file 
--------------------------
There are three options to run s3cmd from source tarball:

1) The S3cmd program, as distributed in s3cmd-X.Y.Z.tar.gz
   on [SourceForge](https://s3tools.org/download) or in master.zip on [GitHub](https://github.com/s3tools/s3cmd/archive/master.zip), can be run directly 
   from where you unzipped the package.

2) Or you may want to move "s3cmd" file and "S3" subdirectory
   to some other path. Make sure that "S3" subdirectory ends up
   in the same place where you move the "s3cmd" file. 

   For instance if you decide to move s3cmd to you $HOME/bin
   you will have $HOME/bin/s3cmd file and $HOME/bin/S3 directory 
   with a number of support files.

3) The cleanest and most recommended approach is to unzip the 
   package and then just run:
   
   `python setup.py install`

   You will however need Python "distutils" module for this to 
   work. It is often part of the core python package (e.g. in 
   OpenSuse Python 2.5 package) or it can be installed using your
   package manager, e.g. in Debian use 
   
   `apt-get install python-setuptools`

   Again, consult your distribution documentation on how to 
   find out the actual package name and how to install it then.

   Note that on Linux, if you are not "root" already, you may 
   need to run:
   
   `sudo python setup.py install`

   instead.


Note to distributions package maintainers
----------------------------------------
Define shell environment variable S3CMD_PACKAGING=yes if you
don't want setup.py to install manpages and doc files. You'll
have to install them manually in your .spec or similar package
build scripts.

On the other hand if you want setup.py to install manpages 
and docs, but to other than default path, define env 
variables $S3CMD_INSTPATH_MAN and $S3CMD_INSTPATH_DOC. Check 
out setup.py for details and default values.


Where to get help
-----------------
If in doubt, or if something doesn't work as expected, 
get back to us via mailing list:
```
s3tools-general@lists.sourceforge.net
```

or visit the S3cmd / S3tools homepage at: [http://s3tools.org](http://s3tools.org)
