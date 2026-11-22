AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)

AM_CFLAGS = \
	$(GLOBAL_CFLAGS) \
	$(libplist_CFLAGS)

check_PROGRAMS = pcapd_test
TESTS = pcapd_test

pcapd_test_SOURCES = pcapd_test.c
pcapd_test_LDADD = $(top_builddir)/src/libimobiledevice-1.0.la $(libplist_LIBS)

EXTRA_DIST = README.md device_matrix.sh
