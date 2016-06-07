#!/bin/sh
#
if test x$UID != x -a x$UID != x0; then
  TRUST="--with-trusted=0,2,$UID"
else
  TRUST="--with-trusted=0,2,1000"
fi
export TRUST
#
PW_DIR=`pwd`; export PW_DIR
RCFILE="$PW_DIR/testrc_1.dyn";  export RCFILE
LOGFILE="$PW_DIR/.samhain_log"; export LOGFILE
#
OPTIONS="\
--enable-db-reload \
--enable-suidcheck \
--enable-login-watch \
--enable-mounts-check \
--enable-logfile-monitor \
--enable-process-check \
--enable-port-check \
--enable-xml-log \
--enable-userfiles \
--disable-shellexpand \
--disable-ipv6 \
"

./configure --quiet $TRUST \
    --prefix=$PW_DIR \
    --localstatedir=$PW_DIR \
    --with-config-file=$RCFILE \
    --with-log-file=$LOGFILE \
    --with-pid-file=$PW_DIR/.samhain_lock \
    --with-data-file=$PW_DIR/.samhain_file $OPTIONS

if [ $? -ne 0 ]; 
then
    echo "Configure failed"
    exit 1
fi

make samhain

if [ $? -ne 0 ]; 
then
    echo "Make failed"
    exit 1
fi
