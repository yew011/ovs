bin_PROGRAMS += ovn/controller-gw/ovn-controller-gw
ovn_controller_gw_ovn_controller_gw_SOURCES = \
	ovn/controller-gw/binding.c \
	ovn/controller-gw/binding.h \
	ovn/controller-gw/gateway.c \
	ovn/controller-gw/gateway.h \
	ovn/controller-gw/pipeline.c \
	ovn/controller-gw/pipeline.h \
	ovn/controller-gw/ovn-controller-gw.c \
	ovn/controller-gw/ovn-controller-gw.h
ovn_controller_gw_ovn_controller_gw_LDADD = ovn/lib/libovn.la lib/libopenvswitch.la vtep/libvtep.la
