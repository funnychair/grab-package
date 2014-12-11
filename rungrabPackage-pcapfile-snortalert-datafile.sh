g++ grabPackage.cpp -std=c++11 SessionSet.cpp AlertSet.cpp jaychang.cpp IcmpSessionHandler.cpp UdpSessionHandler.cpp TcpSessionHandler.cpp -lpcap -o bingrabPackage
sudo ./bingrabPackage $1 $2 $3
rm bingrabPackage
