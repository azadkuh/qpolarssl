#!/bin/bash

WD=.


find $WD -iname '*.ncb' -print > list.del
find $WD -iname '*.pdb' -print > list.del
find $WD -iname 'vc*.idb' -print >> list.del
find $WD -iname '*vcproj*.user' -print >> list.del
find $WD -iname 'Makefile*' -print >> list.del
find $WD -iname '*fuse_hidden*' -print >> list.del

if (( $# > 0 ))  &&  (( "$1" == "clean" || "$1" == "clear" || "$1" == "all" )); then
    find $WD/xbin -iname 'lib*.*' -print >> list.del
    find $WD/xbin -iname '*.exe' -print >> list.del
    find $WD/xbin -iname '*.rcc' -print >> list.del
    find $WD/xbin -iname '*.so' -print >> list.del
    find $WD/xbin -type f -perm -u+x -print >> list.del
fi

cat list.del |xargs rm

rm list.del
rm -rf tmp/
