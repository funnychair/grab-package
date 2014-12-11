grabPackage.o: grabPackage.cpp SessionSet.h StructSet.h AlertSet.h
SessionSet.o: SessionSet.cpp SessionSet.h StructSet.h \
 IcmpSessionHandler.h AbstractHandler.h UdpSessionHandler.h \
 TcpSessionHandler.h jaychang.h
chehsunliu.o: chehsunliu.cpp chehsunliu.h
jaychang.o: jaychang.cpp jaychang.h StructSet.h
TcpSessionHandler.o: TcpSessionHandler.cpp TcpSessionHandler.h \
 AbstractHandler.h StructSet.h chehsunliu.h
AlertSet.o: AlertSet.cpp AlertSet.h StructSet.h
IcmpSessionHandler.o: IcmpSessionHandler.cpp IcmpSessionHandler.h \
 AbstractHandler.h StructSet.h
UdpSessionHandler.o: UdpSessionHandler.cpp UdpSessionHandler.h \
 AbstractHandler.h StructSet.h
