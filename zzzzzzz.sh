#/bin/bash

for ((i=0; i <= 99; i=i+1))
do
    echo "================================ $i ================================="
    sudo snort -A console -c /etc/snort/snort.conf -r ~/data/labData/test1$i >> ./snortalert.log
done
