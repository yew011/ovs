EXTRA_DIST += \
	$(COMMON_MACROS_AT) \
	$(TESTSUITE_AT) \
	$(KMOD_TESTSUITE_AT) \
	$(TESTSUITE) \
	$(KMOD_TESTSUITE) \
	tests/atlocal.in \
	$(srcdir)/package.m4 \
	$(srcdir)/tests/testsuite \
	$(srcdir)/tests/testsuite.patch

COMMON_MACROS_AT = \
	tests/ovsdb-macros.at \
	tests/ovs-macros.at \
	tests/ofproto-macros.at

TESTSUITE_AT = \
	tests/testsuite.at \
	tests/completion.at \
	tests/library.at \
	tests/heap.at \
	tests/bundle.at \
	tests/classifier.at \
	tests/check-structs.at \
	tests/daemon.at \
	tests/daemon-py.at \
	tests/ofp-actions.at \
	tests/ofp-print.at \
	tests/ofp-util.at \
	tests/ofp-errors.at \
	tests/ovs-ofctl.at \
	tests/odp.at \
	tests/mpls-xlate.at \
	tests/multipath.at \
	tests/bfd.at \
	tests/cfm.at \
	tests/lacp.at \
	tests/lib.at \
	tests/learn.at \
	tests/vconn.at \
	tests/file_name.at \
	tests/aes128.at \
	tests/unixctl-py.at \
	tests/uuid.at \
	tests/json.at \
	tests/jsonrpc.at \
	tests/jsonrpc-py.at \
	tests/tunnel.at \
	tests/tunnel-push-pop.at \
	tests/lockfile.at \
	tests/reconnect.at \
	tests/ovs-vswitchd.at \
	tests/dpif-netdev.at \
	tests/dpctl.at \
	tests/ofproto-dpif.at \
	tests/bridge.at \
	tests/vlan-splinters.at \
	tests/ofproto.at \
	tests/ovsdb.at \
	tests/ovsdb-log.at \
	tests/ovsdb-types.at \
	tests/ovsdb-data.at \
	tests/ovsdb-column.at \
	tests/ovsdb-table.at \
	tests/ovsdb-row.at \
	tests/ovsdb-schema.at \
	tests/ovsdb-condition.at \
	tests/ovsdb-mutation.at \
	tests/ovsdb-query.at \
	tests/ovsdb-transaction.at \
	tests/ovsdb-execution.at \
	tests/ovsdb-trigger.at \
	tests/ovsdb-tool.at \
	tests/ovsdb-server.at \
	tests/ovsdb-monitor.at \
	tests/ovsdb-idl.at \
	tests/ovs-vsctl.at \
	tests/ovs-monitor-ipsec.at \
	tests/ovs-xapi-sync.at \
	tests/stp.at \
	tests/rstp.at \
	tests/interface-reconfigure.at \
	tests/vlog.at \
	tests/vtep-ctl.at \
	tests/auto-attach.at

KMOD_TESTSUITE_AT = \
	tests/kmod-testsuite.at \
	tests/kmod-macros.at \
	tests/kmod-traffic.at

TESTSUITE = $(srcdir)/tests/testsuite
TESTSUITE_PATCH = $(srcdir)/tests/testsuite.patch
KMOD_TESTSUITE = $(srcdir)/tests/kmod-testsuite
DISTCLEANFILES += tests/atconfig tests/atlocal

AUTOTEST_PATH = utilities:vswitchd:ovsdb:vtep:tests

check-local: tests/atconfig tests/atlocal $(TESTSUITE)
	$(SHELL) '$(TESTSUITE)' -C tests AUTOTEST_PATH=$(AUTOTEST_PATH) $(TESTSUITEFLAGS)

# Python Coverage support.
# Requires coverage.py http://nedbatchelder.com/code/coverage/.

COVERAGE = coverage
COVERAGE_FILE='$(abs_srcdir)/.coverage'
check-pycov: all tests/atconfig tests/atlocal $(TESTSUITE) clean-pycov
	PYTHONDONTWRITEBYTECODE=yes COVERAGE_FILE=$(COVERAGE_FILE) PYTHON='$(COVERAGE) run -p' $(SHELL) '$(TESTSUITE)' -C tests AUTOTEST_PATH=$(AUTOTEST_PATH) $(TESTSUITEFLAGS)
	@cd $(srcdir) && $(COVERAGE) combine && COVERAGE_FILE=$(COVERAGE_FILE) $(COVERAGE) annotate
	@echo
	@echo '----------------------------------------------------------------------'
	@echo 'Annotated coverage source has the ",cover" extension.'
	@echo '----------------------------------------------------------------------'
	@echo
	@COVERAGE_FILE=$(COVERAGE_FILE) $(COVERAGE) report

# valgrind support

valgrind_wrappers = \
	tests/valgrind/ovs-appctl \
	tests/valgrind/ovs-ofctl \
	tests/valgrind/ovstest \
	tests/valgrind/ovs-vsctl \
	tests/valgrind/ovs-vswitchd \
	tests/valgrind/ovsdb-client \
	tests/valgrind/ovsdb-server \
	tests/valgrind/ovsdb-tool \
	tests/valgrind/test-aes128 \
	tests/valgrind/test-atomic \
	tests/valgrind/test-bundle \
	tests/valgrind/test-byte-order \
	tests/valgrind/test-classifier \
	tests/valgrind/test-cmap \
	tests/valgrind/test-csum \
	tests/valgrind/test-flows \
	tests/valgrind/test-hash \
	tests/valgrind/test-hindex \
	tests/valgrind/test-hmap \
	tests/valgrind/test-json \
	tests/valgrind/test-jsonrpc \
	tests/valgrind/test-list \
	tests/valgrind/test-lockfile \
	tests/valgrind/test-multipath \
	tests/valgrind/test-hsa-match \
	tests/valgrind/test-odp \
	tests/valgrind/test-ovsdb \
	tests/valgrind/test-packets \
	tests/valgrind/test-random \
	tests/valgrind/test-reconnect \
	tests/valgrind/test-rstp \
	tests/valgrind/test-sha1 \
	tests/valgrind/test-stp \
	tests/valgrind/test-type-props \
	tests/valgrind/test-unix-socket \
	tests/valgrind/test-uuid \
	tests/valgrind/test-vconn

$(valgrind_wrappers): tests/valgrind-wrapper.in
	@test -d tests/valgrind || mkdir tests/valgrind
	$(AM_V_GEN) sed -e 's,[@]wrap_program[@],$@,' \
		$(top_srcdir)/tests/valgrind-wrapper.in > $@.tmp && \
	chmod +x $@.tmp && \
	mv $@.tmp $@
CLEANFILES += $(valgrind_wrappers)
EXTRA_DIST += tests/valgrind-wrapper.in

VALGRIND = valgrind --log-file=valgrind.%p --leak-check=full \
	--suppressions=$(abs_top_srcdir)/tests/glibc.supp \
	--suppressions=$(abs_top_srcdir)/tests/openssl.supp --num-callers=20
EXTRA_DIST += tests/glibc.supp tests/openssl.supp
check-valgrind: all tests/atconfig tests/atlocal $(TESTSUITE) \
                $(valgrind_wrappers) $(check_DATA)
	$(SHELL) '$(TESTSUITE)' -C tests CHECK_VALGRIND=true VALGRIND='$(VALGRIND)' AUTOTEST_PATH='tests/valgrind:$(AUTOTEST_PATH)' -d $(TESTSUITEFLAGS)
	@echo
	@echo '----------------------------------------------------------------------'
	@echo 'Valgrind output can be found in tests/testsuite.dir/*/valgrind.*'
	@echo '----------------------------------------------------------------------'

# OFTest support.

check-oftest: all
	$(AM_V_at)srcdir='$(srcdir)' $(SHELL) $(srcdir)/tests/run-oftest
EXTRA_DIST += tests/run-oftest

# Ryu support.
check-ryu: all
	$(AM_V_at)srcdir='$(srcdir)' $(SHELL) $(srcdir)/tests/run-ryu
EXTRA_DIST += tests/run-ryu

# Run kmod tests. Assume kernel modules has been installed or linked into the kernel
check-kernel: all tests/atconfig tests/atlocal $(KMOD_TESTSUITE)
	$(SHELL) '$(KMOD_TESTSUITE)' -C tests  AUTOTEST_PATH='$(AUTOTEST_PATH)' -d $(TESTSUITEFLAGS)

# Testing the out of tree Kernel module
check-kmod: all tests/atconfig tests/atlocal $(KMOD_TESTSUITE)
	$(MAKE) modules_install
	modprobe -r openvswitch
	$(MAKE) check-kernel

clean-local:
	test ! -f '$(TESTSUITE)' || $(SHELL) '$(TESTSUITE)' -C tests --clean

AUTOTEST = $(AUTOM4TE) --language=autotest

if WIN32
$(TESTSUITE): package.m4 $(TESTSUITE_AT) $(COMMON_MACROS_AT) $(TESTSUITE_PATCH)
	$(AM_V_GEN)$(AUTOTEST) -I '$(srcdir)' -o testsuite.tmp $@.at
	patch -p0 testsuite.tmp $(TESTSUITE_PATCH)
	$(AM_V_at)mv testsuite.tmp $@
else
$(TESTSUITE): package.m4 $(TESTSUITE_AT) $(COMMON_MACROS_AT)
	$(AM_V_GEN)$(AUTOTEST) -I '$(srcdir)' -o $@.tmp $@.at
	$(AM_V_at)mv $@.tmp $@
endif

$(KMOD_TESTSUITE): package.m4 $(KMOD_TESTSUITE_AT) $(COMMON_MACROS_AT)
	$(AM_V_GEN)$(AUTOTEST) -I '$(srcdir)' -o $@.tmp $@.at
	$(AM_V_at)mv $@.tmp $@

# The `:;' works around a Bash 3.2 bug when the output is not writeable.
$(srcdir)/package.m4: $(top_srcdir)/configure.ac
	$(AM_V_GEN):;{ \
	  echo '# Signature of the current package.' && \
	  echo 'm4_define([AT_PACKAGE_NAME],      [$(PACKAGE_NAME)])' && \
	  echo 'm4_define([AT_PACKAGE_TARNAME],   [$(PACKAGE_TARNAME)])' && \
	  echo 'm4_define([AT_PACKAGE_VERSION],   [$(PACKAGE_VERSION)])' && \
	  echo 'm4_define([AT_PACKAGE_STRING],    [$(PACKAGE_STRING)])' && \
	  echo 'm4_define([AT_PACKAGE_BUGREPORT], [$(PACKAGE_BUGREPORT)])'; \
	} >'$(srcdir)/package.m4'

noinst_PROGRAMS += tests/test-ovsdb
tests_test_ovsdb_SOURCES = \
	tests/test-ovsdb.c \
	tests/idltest.c \
	tests/idltest.h
EXTRA_DIST += tests/uuidfilt.pl tests/ovsdb-monitor-sort.pl
tests_test_ovsdb_LDADD = ovsdb/libovsdb.la lib/libopenvswitch.la

noinst_PROGRAMS += tests/test-lib
tests_test_lib_SOURCES = \
	tests/test-lib.c
tests_test_lib_LDADD = lib/libopenvswitch.la

# idltest schema and IDL
OVSIDL_BUILT += tests/idltest.c tests/idltest.h tests/idltest.ovsidl
IDLTEST_IDL_FILES = tests/idltest.ovsschema tests/idltest.ann
EXTRA_DIST += $(IDLTEST_IDL_FILES) tests/idltest2.ovsschema
tests/idltest.ovsidl: $(IDLTEST_IDL_FILES)
	$(AM_V_GEN)$(OVSDB_IDLC) -C $(srcdir) annotate $(IDLTEST_IDL_FILES) > $@.tmp && \
	mv $@.tmp $@

tests/idltest.c: tests/idltest.h

if DPDK_NETDEV
noinst_PROGRAMS += tests/test-dpdkr
tests_test_dpdkr_SOURCES = \
	tests/dpdk/ring_client.c
tests_test_dpdkr_LDADD = lib/libopenvswitch.la $(LIBS)
endif

noinst_PROGRAMS += tests/ovstest
tests_ovstest_SOURCES = \
	tests/ovstest.c \
	tests/ovstest.h \
	tests/test-aes128.c \
	tests/test-atomic.c \
	tests/test-bundle.c \
	tests/test-byte-order.c \
	tests/test-classifier.c \
	tests/test-cmap.c \
	tests/test-csum.c \
	tests/test-flows.c \
	tests/test-hash.c \
	tests/test-heap.c \
	tests/test-hindex.c \
	tests/test-hmap.c \
	tests/test-json.c \
	tests/test-jsonrpc.c \
	tests/test-list.c \
	tests/test-lockfile.c \
	tests/test-multipath.c \
	tests/test-hsa-match.c \
	tests/test-netflow.c \
	tests/test-odp.c \
	tests/test-packets.c \
	tests/test-random.c \
	tests/test-reconnect.c \
	tests/test-rstp.c \
	tests/test-sflow.c \
	tests/test-sha1.c \
	tests/test-stp.c \
	tests/test-util.c \
	tests/test-uuid.c \
	tests/test-bitmap.c \
	tests/test-vconn.c \
	tests/test-aa.c

if !WIN32
tests_ovstest_SOURCES += \
	tests/test-unix-socket.c
endif

tests_ovstest_LDADD = lib/libopenvswitch.la
dist_check_SCRIPTS = tests/flowgen.pl

noinst_PROGRAMS += tests/test-strtok_r
tests_test_strtok_r_SOURCES = tests/test-strtok_r.c

noinst_PROGRAMS += tests/test-type-props
tests_test_type_props_SOURCES = tests/test-type-props.c

# Python tests.
CHECK_PYFILES = \
	tests/appctl.py \
	tests/test-daemon.py \
	tests/test-json.py \
	tests/test-jsonrpc.py \
	tests/test-ovsdb.py \
	tests/test-reconnect.py \
	tests/MockXenAPI.py \
	tests/test-unix-socket.py \
	tests/test-unixctl.py \
	tests/test-vlog.py
EXTRA_DIST += $(CHECK_PYFILES)
PYCOV_CLEAN_FILES += $(CHECK_PYFILES:.py=.py,cover) .coverage

if HAVE_OPENSSL
TESTPKI_FILES = \
	tests/testpki-cacert.pem \
	tests/testpki-cert.pem \
	tests/testpki-privkey.pem \
	tests/testpki-req.pem \
	tests/testpki-cert2.pem \
	tests/testpki-privkey2.pem \
	tests/testpki-req2.pem
check_DATA += $(TESTPKI_FILES)
CLEANFILES += $(TESTPKI_FILES)

tests/testpki-cacert.pem: tests/pki/stamp
	$(AM_V_GEN)cp tests/pki/switchca/cacert.pem $@
tests/testpki-cert.pem: tests/pki/stamp
	$(AM_V_GEN)cp tests/pki/test-cert.pem $@
tests/testpki-req.pem: tests/pki/stamp
	$(AM_V_GEN)cp tests/pki/test-req.pem $@
tests/testpki-privkey.pem: tests/pki/stamp
	$(AM_V_GEN)cp tests/pki/test-privkey.pem $@
tests/testpki-cert2.pem: tests/pki/stamp
	$(AM_V_GEN)cp tests/pki/test2-cert.pem $@
tests/testpki-req2.pem: tests/pki/stamp
	$(AM_V_GEN)cp tests/pki/test2-req.pem $@
tests/testpki-privkey2.pem: tests/pki/stamp
	$(AM_V_GEN)cp tests/pki/test2-privkey.pem $@

OVS_PKI = $(SHELL) $(srcdir)/utilities/ovs-pki.in --dir=tests/pki --log=tests/ovs-pki.log
tests/pki/stamp:
	$(AM_V_at)rm -f tests/pki/stamp
	$(AM_V_at)rm -rf tests/pki
	$(AM_V_GEN)$(OVS_PKI) init && \
	$(OVS_PKI) req+sign tests/pki/test && \
	$(OVS_PKI) req+sign tests/pki/test2 && \
	: > tests/pki/stamp
CLEANFILES += tests/ovs-pki.log

CLEAN_LOCAL += clean-pki
clean-pki:
	rm -f tests/pki/stamp
	rm -rf tests/pki
endif
