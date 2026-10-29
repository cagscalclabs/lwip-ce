NAME = NETSRV
DESCRIPTION = "lwIP-CE networked TLS server suite"
DEPS += lwIPSKEY.8xv lwIPSCRT.8xv
EXTRA_CLEAN = $(call RM,lwIPSKEY.pem lwIPSCRT.pem lwIPSKEY.8xv lwIPSCRT.8xv)

include ../common/suite.mk

lwIPSKEY.pem:
	openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out $@

lwIPSCRT.pem: lwIPSKEY.pem
	openssl req -new -x509 -key $< -sha256 -days 3650 \
		-subj /CN=lwip-ce-test -out $@

lwIPSKEY.8xv: lwIPSKEY.pem
	$(CONVBIN) -j bin -i $< -k 8xv -o $@ -n lwIPSKEY

lwIPSCRT.8xv: lwIPSCRT.pem
	$(CONVBIN) -j bin -i $< -k 8xv -o $@ -n lwIPSCRT
