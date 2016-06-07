#! /bin/sh

# NOTE: tested on Debian Linux
# 
# NO WARRANTY - may or may not work on your system
#

# Copyright Rainer Wichmann (2003)
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


CHROOT=$1

SYSTEM=`uname -s`

if test "x$SYSTEM" = xLinux; then
    :
else
    echo "This script will fail on systems other than Linux,"
    echo "mainly because of the mknod commands to create devices"
    echo "in the chroot jail."
    exit 1
fi

if test "x$CHROOT" = x; then
    echo "Usage: chroot.sh chroot_dir"
    echo "Purpose: prepare a chroot jail for yule"
    echo
    echo "NOTE: tested on Debian Linux"
    echo "NO WARRANTY - may or may not work on your system"
    exit 1
fi

#
#  Link configuration file
#
echo " Link configuration file:"
echo " ln -s ${CHROOT}/etc/yulerc /etc/yulerc"

ln -s -f ${CHROOT}/etc/yulerc /etc/yulerc
echo


#
#  Create passwd file
#
echo " Create passwd file"
echo " grep root   /etc/passwd >  ${CHROOT}/etc/passwd"
echo " grep daemon /etc/passwd >> ${CHROOT}/etc/passwd"
echo " grep yule   /etc/passwd >> ${CHROOT}/etc/passwd"

grep root /etc/passwd > ${CHROOT}/etc/passwd
grep daemon /etc/passwd >> ${CHROOT}/etc/passwd
grep yule /etc/passwd >> ${CHROOT}/etc/passwd
echo


#
#  Create group file
#
echo " Create group file"
echo " grep root   /etc/group >  ${CHROOT}/etc/group"
echo " grep daemon /etc/group >> ${CHROOT}/etc/group"
echo " grep yule   /etc/group >> ${CHROOT}/etc/group"

grep root   /etc/group >  ${CHROOT}/etc/group
grep daemon /etc/group >> ${CHROOT}/etc/group
grep yule   /etc/group >> ${CHROOT}/etc/group
echo

#
#  Create devices
#
echo " Create devices"
echo " mkdir ${CHROOT}/dev"
echo " mknod -m 444 ${CHROOT}/dev/urandom c 1 9"
echo " mknod -m 666 ${CHROOT}/dev/random  c 1 8"
echo " mknod -m 666 ${CHROOT}/dev/null    c 1 3"
echo " mknod -m 666 ${CHROOT}/dev/null    c 1 5"

mkdir ${CHROOT}/dev
mknod -m 444 ${CHROOT}/dev/urandom c 1 9
mknod -m 666 ${CHROOT}/dev/random  c 1 8
mknod -m 666 ${CHROOT}/dev/null    c 1 3
mknod -m 666 ${CHROOT}/dev/zero    c 1 5
echo

#
#  DNS
#
echo " Copy files for DNS"
echo " cp -p /etc/nsswitch.conf ${CHROOT}/etc/"
echo " cp -p /etc/hosts         ${CHROOT}/etc/"
echo " cp -p /etc/host.conf     ${CHROOT}/etc/"
echo " cp -p /etc/resolv.conf   ${CHROOT}/etc/"
echo " cp -p /etc/services      ${CHROOT}/etc/"
echo " cp -p /etc/protocols     ${CHROOT}/etc/"

cp -p /etc/nsswitch.conf ${CHROOT}/etc/
cp -p /etc/hosts         ${CHROOT}/etc/
cp -p /etc/host.conf     ${CHROOT}/etc/
cp -p /etc/resolv.conf   ${CHROOT}/etc/
cp -p /etc/services      ${CHROOT}/etc/
cp -p /etc/protocols     ${CHROOT}/etc/

echo "----------------------------------------------------"
echo
echo " You may want to review ${CHROOT}/etc/passwd"
echo " to replace passwords with a *, and to fix the"
echo " path to the home directory of the yule user."
echo
echo " If using a signed configuration file, you need"
echo " a working copy of GnuPG inside the chroot jail."
echo
echo "----------------------------------------------------"
 