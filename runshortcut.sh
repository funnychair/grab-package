#!/usr/bin/env sh

if [ $# -ne 3 ]; then
  echo "No arguments: use default setting"
  ./bingrabPackage test.pcap snortalert labeldata.test.csv
else
  ./bingrabPackage $1 $2 $3
fi

