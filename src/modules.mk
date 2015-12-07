mod_dbd_test.la: mod_dbd_test.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_dbd_test.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_dbd_test.la
