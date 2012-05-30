#!/bin/bash
if [ -n "$1" ]
then
  smidump -k -f identifiers $1 |grep notification |awk '{ system("echo \"{[\""$4"\"],\"|tr \".\" \",\" | tr \"\\n\" \" \"");print $2 "}."}'
fi

