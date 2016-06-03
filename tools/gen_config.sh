#!/bin/sh

echo "#ifndef CONFIG_H"
echo "#define CONFIG_H 1"
for i in $1/port/*.c;do
	f=$(basename "$i" .c)
	F=$(basename "$i" .c | tr a-z A-Z)
	if [ -s "obj/test/port/$f" ];then
		echo "#define HAVE_$F 1"
	else
		echo "#undef HAVE_$F"
	fi
done
echo "#endif"
