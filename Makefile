TARGET	= bingrabPackage
CSRCS	= $(wildcard *.cpp)
COBJS	= $(CSRCS:.cpp=.o)
DEPEND 	= .depend.mak

CXX		= $(CROSS_COMPILE)g++
STRIP	= $(CROSS_COMPILE)strip
CFLAGS	= -std=c++11 
LIBS	= -lpcap

%.o: %.cpp
	$(CXX) $(CFLAGS) -c $<

.PHONY: release debug all clean

release:	CFLAGS += -O2
debug:		CFLAGS += -g

release: 	$(DEPEND) $(TARGET)
debug: 		$(DEPEND) $(TARGET)

$(TARGET): $(COBJS)
	$(CXX) $(CFLAGS) -o $@ $^ $(LIBS)

$(DEPEND): $(CSRCS)
	$(CXX) -MM $^ > $@

clean:
	rm -rf *.o $(TARGET) $(DEPEND)

-include .depend.mak

