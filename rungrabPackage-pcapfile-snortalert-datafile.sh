g++ grabPackage.cpp -std=c++11 SessionSet.cpp AlertSet.cpp -lpcap -o bingrabPackage
sudo ./bingrabPackage $1 $2 $3
rm bingrabPackage
