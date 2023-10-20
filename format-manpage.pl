#!/usr/bin/perl

# Format s3cmd.1 manpage
# Usage:
#   s3cmd --help | format-manpage.pl > s3cmd.1

use strict;

my $commands = "";
my $cfcommands = "";
my $wscommands = "";
my $options = "";

while (<>) {
	if (/^Commands:/) {
		while (<>) {
			last if (/^\s*$/);
			my ($desc, $cmd, $cmdline);
			($desc = $_) =~ s/^\s*(.*?)\s*$/$1/;
			($cmdline = <>) =~ s/^\s*s3cmd (.*?) (.*?)\s*$/s3cmd \\fB$1\\fR \\fI$2\\fR/;
			$cmd = $1;
			$cmdline =~ s/-/\\-/g;
			if ($cmd =~ /^cf/) {
				$cfcommands .= ".TP\n$cmdline\n$desc\n";
			} elsif ($cmd =~ /^ws/) {
				$wscommands .= ".TP\n$cmdline\n$desc\n";
			} else {
				$commands .= ".TP\n$cmdline\n$desc\n";
			}
		}
	}
	if (/^Options:/) {
		my ($opt, $desc);
		while (<>) {
			last if (/^\s*$/);
			$_ =~ s/(.*?)\s*$/$1/;
			$desc = "";
			$opt = "";
			if (/^  (-.*)/) {
				$opt = $1;
				if ($opt =~ /  /) {
					($opt, $desc) = split(/\s\s+/, $opt, 2);
				}
				$opt =~ s/(-[^ ,=\.]+)/\\fB$1\\fR/g;
				# escape all single dashes
				$opt =~ s/-/\\-/g;
				$options .= ".TP\n$opt\n";
			} else {
				$_ =~ s/\s*(.*?)\s*$/$1/;
				$_ =~ s/(--[^ ,=\.]+)/\\fB$1\\fR/g;
				# escape word 'Cache-Control'
				$_ =~ s/'(\S+-\S+)'/\\&'$1'/g;
				# escape all single dashes
				$_ =~ s/-/\\-/g;
				$desc .= $_;
			}
			if ($desc) {
				$options .= "$desc\n";
			}
		}
	}
}
print "
.\\\" !!! IMPORTANT: This file is generated from s3cmd \\-\\-help output using format-manpage.pl
.\\\" !!!            Do your changes either in s3cmd file or in 'format\\-manpage.pl' otherwise
.\\\" !!!            they will be overwritten!

.TH s3cmd 1
.SH NAME
s3cmd \\- tool for managing Amazon S3 storage space and Amazon CloudFront content delivery network
.SH SYNOPSIS
.B s3cmd
[\\fIOPTIONS\\fR] \\fICOMMAND\\fR [\\fIPARAMETERS\\fR]
.SH DESCRIPTION
.PP
.B s3cmd
is a command line client for copying files to/from
Amazon S3 (Simple Storage Service) and performing other
related tasks, for instance creating and removing buckets,
listing objects, etc.

.SH COMMANDS
.PP
.B s3cmd
can do several \\fIactions\\fR specified by the following \\fIcommands\\fR.
$commands

.PP
Commands for static WebSites configuration
$wscommands

.PP
Commands for CloudFront management
$cfcommands

.SH OPTIONS
.PP
Some of the below specified options can have their default
values set in
.B s3cmd
config file (by default \$HOME/.s3cmd). As it's a simple text file
feel free to open it with your favorite text editor and do any
changes you like.
$options

.SH EXAMPLES
One of the most powerful commands of \\fIs3cmd\\fR is \\fBs3cmd sync\\fR used for
synchronising complete directory trees to or from remote S3 storage. To some extent
\\fBs3cmd put\\fR and \\fBs3cmd get\\fR share a similar behaviour with \\fBsync\\fR.
.PP
Basic usage common in backup scenarios is as simple as:
.nf
	s3cmd sync /local/path/ s3://test\\-bucket/backup/
.fi
.PP
This command will find all files under /local/path directory and copy them
to corresponding paths under s3://test\\-bucket/backup on the remote side.
For example:
.nf
	/local/path/\\fBfile1.ext\\fR         \\->  s3://bucket/backup/\\fBfile1.ext\\fR
	/local/path/\\fBdir123/file2.bin\\fR  \\->  s3://bucket/backup/\\fBdir123/file2.bin\\fR
.fi
.PP
However if the local path doesn't end with a slash the last directory's name
is used on the remote side as well. Compare these with the previous example:
.nf
	s3cmd sync /local/path s3://test\\-bucket/backup/
.fi
will sync:
.nf
	/local/\\fBpath/file1.ext\\fR         \\->  s3://bucket/backup/\\fBpath/file1.ext\\fR
	/local/\\fBpath/dir123/file2.bin\\fR  \\->  s3://bucket/backup/\\fBpath/dir123/file2.bin\\fR
.fi
.PP
To retrieve the files back from S3 use inverted syntax:
.nf
	s3cmd sync s3://test\\-bucket/backup/ ~/restore/
.fi
that will download files:
.nf
	s3://bucket/backup/\\fBfile1.ext\\fR         \\->  ~/restore/\\fBfile1.ext\\fR
	s3://bucket/backup/\\fBdir123/file2.bin\\fR  \\->  ~/restore/\\fBdir123/file2.bin\\fR
.fi
.PP
Without the trailing slash on source the behaviour is similar to
what has been demonstrated with upload:
.nf
	s3cmd sync s3://test\\-bucket/backup ~/restore/
.fi
will download the files as:
.nf
	s3://bucket/\\fBbackup/file1.ext\\fR         \\->  ~/restore/\\fBbackup/file1.ext\\fR
	s3://bucket/\\fBbackup/dir123/file2.bin\\fR  \\->  ~/restore/\\fBbackup/dir123/file2.bin\\fR
.fi
.PP
All source file names, the bold ones above, are matched against \\fBexclude\\fR
rules and those that match are then re\\-checked against \\fBinclude\\fR rules to see
whether they should be excluded or kept in the source list.
.PP
For the purpose of \\fB\\-\\-exclude\\fR and \\fB\\-\\-include\\fR matching only the
bold file names above are used. For instance only \\fBpath/file1.ext\\fR is tested
against the patterns, not \\fI/local/\\fBpath/file1.ext\\fR
.PP
Both \\fB\\-\\-exclude\\fR and \\fB\\-\\-include\\fR work with shell\\-style wildcards (a.k.a. GLOB).
For a greater flexibility s3cmd provides Regular\\-expression versions of the two exclude options
named \\fB\\-\\-rexclude\\fR and \\fB\\-\\-rinclude\\fR.
The options with ...\\fB\\-from\\fR suffix (eg \\-\\-rinclude\\-from) expect a filename as
an argument. Each line of such a file is treated as one pattern.
.PP
There is only one set of patterns built from all \\fB\\-\\-(r)exclude(\\-from)\\fR options
and similarly for include variant. Any file excluded with eg \\-\\-exclude can
be put back with a pattern found in \\-\\-rinclude\\-from list.
.PP
Run s3cmd with \\fB\\-\\-dry\\-run\\fR to verify that your rules work as expected.
Use together with \\fB\\-\\-debug\\fR get detailed information
about matching file names against exclude and include rules.
.PP
For example to exclude all files with \".jpg\" extension except those beginning with a number use:
.PP
	\\-\\-exclude '*.jpg' \\-\\-rinclude '[0\\-9].*\\.jpg'
.PP
To exclude all files except \"*.jpg\" extension, use:
.PP
	\\-\\-exclude '*' \\-\\-include '*.jpg'
.PP
To exclude local directory 'somedir', be sure to use a trailing forward slash, as such:
.PP
	\\-\\-exclude 'somedir/'
.PP

.SH SEE ALSO
For the most up to date list of options run:
.B s3cmd \\-\\-help
.br
For more info about usage, examples and other related info visit project homepage at:
.B https://s3tools.org
.SH AUTHOR
Written by Michal Ludvig, Florent Viard and contributors
.SH CONTACT, SUPPORT
Preferred way to get support is our mailing list:
.br
.I s3tools\\-general\@lists.sourceforge.net
.br
or visit the project homepage:
.br
.B https://s3tools.org
.SH REPORTING BUGS
Report bugs to
.I s3tools\\-bugs\@lists.sourceforge.net
.SH COPYRIGHT
Copyright \\(co 2007\\-2023 TGRMN Software (https://www.tgrmn.com), Sodria SAS (https://www.sodria.com) and contributors
.br
.SH LICENSE
This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
.br
";
