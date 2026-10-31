TESTS = test_sha2_256 test_sha2_384 test_sha2_512 \
        test_hmac_sha2_256 test_hmac_sha2_384 test_hmac_sha2_512 \
        test_aes_cbc test_aes_gcm test_aes_ccm test_pbkdf test_hkdf \
        test_rsa_sigver test_ecdsa_sigver test_detecdsa_siggen \
        test_x25519_ssc test_p256_cdh

.PHONY: all clean $(TESTS)

all: $(TESTS)

$(TESTS):
	$(MAKE) -C $@

clean:
	$(foreach test,$(TESTS),$(MAKE) -C $(test) clean &&) true
