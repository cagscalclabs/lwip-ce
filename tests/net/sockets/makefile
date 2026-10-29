NAME = NETTEST
DESCRIPTION = "lwIP-CE networked socket API suite"
DEPS += lwIPSKEY.8xv lwIPSCRT.8xv
EXTRA_CLEAN = $(call RM,lwIPSKEY.pem lwIPSCRT.pem lwIPSKEY.8xv lwIPSCRT.8xv)

include ../common/suite.mk

lwIPSKEY.pem:
	openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
		-aes-256-cbc -pass pass:lwip-ce-test-password -out $@

lwIPSCRT.pem: lwIPSKEY.pem
	openssl req -new -x509 -key $< -passin pass:lwip-ce-test-password \
		-sha256 -days 3650 \
		-subj /CN=lwip-ce-socket-test -out $@

lwIPSKEY.8xv: lwIPSKEY.pem
	$(CONVBIN) -j bin -i $< -k 8xv -o $@ -n lwIPSKEY

lwIPSCRT.8xv: lwIPSCRT.pem
	$(CONVBIN) -j bin -i $< -k 8xv -o $@ -n lwIPSCRT
