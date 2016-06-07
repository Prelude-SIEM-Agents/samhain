#! /usr/bin/perl

# Copyright Rainer Wichmann (2004)
#
# License Information:
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

use warnings;
use strict;

my $fno = 0;
my $file = '';
my @last2 = ();
my $line = '';

sub usage () {
    print "Usage: concat.pl <list_of_database_files>\n\n";
    print "       Will concatenate samhain file signature database files\n";
    print "       and print to stdout.\n";
    print "       Does not work on signed or otherwise modified\n";
    print "       file signature databases.\n";
}

if ($#ARGV < 0) { # must be at least one file
    usage();
    exit 1;
} elsif ($ARGV[0] =~ /^-h$/ || $ARGV[0] =~ /^--?help$/) {
    usage();
    exit 0;
}
    

for $file (@ARGV) {
    open FH, "< $file" or die "Cannot open $file: $!";
    if ($fno != 0) { # search and read past the start-of-file marker
	while (<FH>) {
	    last if ($_ =~ /^\[SOF\]$/);
	}
    } 
    @last2 = ();
    while (<FH>) {
	push @last2, $_;
	if (@last2 > 2) {
	    $line = shift @last2;
	    print $line;
	}
    }
    close FH;
    ++$fno;
}

# last two lines of last file
$line = shift @last2;
print $line;
$line = shift @last2;
print $line;
