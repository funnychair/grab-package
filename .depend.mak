grabPackage.o: grabPackage.cpp SessionSet.h StructSet.h AlertSet.h
jaychang.o: jaychang.cpp jaychang.h StructSet.h
TcpSessionHandler.o: TcpSessionHandler.cpp TcpSessionHandler.h \
 AbstractHandler.h StructSet.h
AlertSet.o: AlertSet.cpp AlertSet.h StructSet.h
IcmpSessionHandler.o: IcmpSessionHandler.cpp IcmpSessionHandler.h \
 AbstractHandler.h StructSet.h
SessionSet.o: SessionSet.cpp SessionSet.h StructSet.h \
 IcmpSessionHandler.h AbstractHandler.h UdpSessionHandler.h \
 TcpSessionHandler.h jaychang.h
UdpSessionHandler.o: UdpSessionHandler.cpp UdpSessionHandler.h \
 AbstractHandler.h StructSet.h
