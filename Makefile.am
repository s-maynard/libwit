lib_LTLIBRARIES=libwit.la
libwit_la_CPPFLAGS= -DCLIENT_LIB_VERSION=0x$(shell cd ~/poky/libwit;git log -1 --pretty=format:%h) `pkg-config --cflags --libs libnl-3.0`
libwit_la_LDFLAGS= `pkg-config --libs libnl-3.0``pkg-config --libs libnl-genl-3.0`
libwit_la_SOURCES= \
	src/wifiscan.c
libwit_la_includedir= \
	$(includedir)
libwit_la_include_HEADERS= \
	src/libwit.h
libwit_la_DEPENDENCIES=

libwit_la_LIBADD=$(libwit_la_DEPENDENCIES) \
	../libwitutil/.libs/libwitutil.la
