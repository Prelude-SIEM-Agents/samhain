#! /bin/sh


# get bits of $1

# make sure it fits in 16 bit
ORIG=`expr $1 \% 65536`

# 1 2 3 4  5  6  7   8   9  10   11   12   13   14    15    16
# 1 2 4 8 16 32 64 128 256 512 1024 2048 4096 8192 16384 32768

N=0

N=`expr $ORIG \/ 32768`
N_16=$N
if test "x$N" = "x1"; then
  echo "#define $2_16 1"
fi
ORIG=`expr $ORIG \- $N_16 \* 32768`

N=`expr $ORIG / 16384`
N_15=$N
if test "x$N" = "x1"; then
  echo "#define $2_15 1"
fi
ORIG=`expr $ORIG \- $N_15 \* 16384`

N=`expr $ORIG \/ 8192`
N_14=$N
if test "x$N" = "x1"; then
  echo "#define $2_14 1"
fi
ORIG=`expr $ORIG \- $N_14 \* 8192`

N=`expr $ORIG \/ 4096`
N_13=$N
if test "x$N" = "x1"; then
  echo "#define $2_13 1"
fi
ORIG=`expr $ORIG \- $N_13 \* 4096`

N=`expr $ORIG \/ 2048`
N_12=$N
if test "x$N" = "x1"; then
  echo "#define $2_12 1"
fi
ORIG=`expr $ORIG \- $N_12 \* 2048`

N=`expr $ORIG \/ 1024`
N_11=$N
if test "x$N" = "x1"; then
  echo "#define $2_11 1"
fi
ORIG=`expr $ORIG \- $N_11 \* 1024`

N=`expr $ORIG \/ 512`
N_10=$N
if test "x$N" = "x1"; then
  echo "#define $2_10 1"
fi
ORIG=`expr $ORIG \- $N_10 \* 512`

N=`expr $ORIG \/ 256`
N_09=$N
if test "x$N" = "x1"; then
  echo "#define $2_09 1"
fi
ORIG=`expr $ORIG \- $N_09 \* 256`

N=`expr $ORIG \/ 128`
N_08=$N
if test "x$N" = "x1"; then
  echo "#define $2_08 1"
fi
ORIG=`expr $ORIG \- $N_08 \* 128`

N=`expr $ORIG \/ 64`
N_07=$N
if test "x$N" = "x1"; then
  echo "#define $2_07 1"
fi
ORIG=`expr $ORIG \- $N_07 \* 64`

N=`expr $ORIG \/ 32`
N_06=$N
if test "x$N" = "x1"; then
  echo "#define $2_06 1"
fi
ORIG=`expr $ORIG \- $N_06 \* 32`

N=`expr $ORIG \/ 16`
N_05=$N
if test "x$N" = "x1"; then
  echo "#define $2_05 1"
fi
ORIG=`expr $ORIG \- $N_05 \* 16`

N=`expr $ORIG \/ 8`
N_04=$N
if test "x$N" = "x1"; then
  echo "#define $2_04 1"
fi
ORIG=`expr $ORIG \- $N_04 \* 8`

N=`expr $ORIG \/ 4`
N_03=$N
if test "x$N" = "x1"; then
  echo "#define $2_03 1"
fi
ORIG=`expr $ORIG \- $N_03 \* 4`

N=`expr $ORIG \/ 2`
N_02=$N
if test "x$N" = "x1"; then
  echo "#define $2_02 1"
fi
ORIG=`expr $ORIG \- $N_02 \* 2`

N=`expr $ORIG \/ 1`
N_01=$N
if test "x$N" = "x1"; then
  echo "#define $2_01 1"
fi
ORIG=`expr $ORIG \- $N_01 \* 1`

#
# obsolete
#
# echo ${N_01} ${N_02} ${N_03} ${N_04} ${N_05} ${N_06} ${N_07} ${N_08} ${N_09} ${N_10}  ${N_11} ${N_12}  ${N_13} ${N_14} ${N_15} ${N_16}

exit   0


