bin_PROGRAMS += ovn/controller-vtep/ovn-controller-vtep
ovn_controller_vtep_ovn_controller_vtep_SOURCES = \
	ovn/controller-vtep/ovn-controller-vtep.c \
	ovn/controller-vtep/ovn-controller-vtep.h
ovn_controller_vtep_ovn_controller_vtep_LDADD = ovn/lib/libovn.la lib/libopenvswitch.la vtep/libvtep.la
man_MANS += ovn/controller-vtep/ovn-controller-vtep.8
EXTRA_DIST += ovn/controller-vtep/ovn-controller-vtep.8.xml
DISTCLEANFILES += ovn/controller-vtep/ovn-controller-vtep.8
