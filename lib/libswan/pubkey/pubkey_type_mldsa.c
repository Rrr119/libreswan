/*
 * ML-DSA public key type
 *
 * FIPS 204 and draft-ietf-ipsecme-ikev2-pqc-auth.
 */

#ifdef USE_MLDSA

#include <cryptohi.h>
#include <keyhi.h>

#include "lswnss.h"
#include "lswlog.h"
#include "secrets.h"

static void MLDSA_free_pubkey_content(struct pubkey_content *pkc,
				      const struct logger *logger)
{
	SECKEY_DestroyPublicKey(pkc->public_key);
	ldbg_delref(logger, pkc->public_key);
	pkc->public_key = NULL;
}

static err_t MLDSA_extract_pubkey_content_from_SECKEYPublicKey(struct pubkey_content *pkc,
							       SECKEYPublicKey *seckey_public,
							       SECItem *cert_ckaid,
							       const struct logger *logger)
{
	PEXPECT(logger, pkc->type == &pubkey_type_mldsa);
	PEXPECT(logger, seckey_public->keyType == mldsaKey);

	pkc->public_key = SECKEY_CopyPublicKey(seckey_public);
	ldbg_newref(logger, pkc->public_key);
	pkc->ckaid = ckaid_from_secitem(cert_ckaid);
	err_t e = keyblob_to_keyid(pkc->ckaid.ptr, pkc->ckaid.len, &pkc->keyid);
	passert(e == NULL);

	if (LDBGP(DBG_BASE, logger)) {
		ckaid_buf cb;
		LDBG_log(logger, "%s keyid *%s", pkc->type->name, str_keyid(pkc->keyid));
		LDBG_log(logger, "%s ckaid *%s", pkc->type->name, str_ckaid(&pkc->ckaid, &cb));
	}

	return NULL;
}

static bool MLDSA_pubkey_same(const struct pubkey_content *lhs,
			      const struct pubkey_content *rhs,
			      const struct logger *logger)
{
	if (lhs == rhs) {
		return true;
	}

	bool same = (lhs->public_key->u.mldsa.paramSet ==
		     rhs->public_key->u.mldsa.paramSet &&
		     lhs->ckaid.len == rhs->ckaid.len &&
		     memeq(lhs->ckaid.ptr, rhs->ckaid.ptr, lhs->ckaid.len));
	if (LDBGP(DBG_CRYPT, logger)) {
		LDBG_log(logger, "ML-DSA public keys did %smatch", same ? "" : "NOT ");
	}
	return same;
}

static size_t MLDSA_strength_in_bits(const struct pubkey *pubkey)
{
	return SECKEY_PublicKeyStrengthInBits(pubkey->content.public_key);
}

const struct pubkey_type pubkey_type_mldsa = {
	.name = "MLDSA",
	.private_key_kind = SECRET_MLDSA,
	.ipseckey_algorithm = IPSECKEY_ALGORITHM_X_PUBKEY,
	.free_pubkey_content = MLDSA_free_pubkey_content,
	.extract_pubkey_content_from_SECKEYPublicKey = MLDSA_extract_pubkey_content_from_SECKEYPublicKey,
	.pubkey_same = MLDSA_pubkey_same,
	.strength_in_bits = MLDSA_strength_in_bits,
};

#endif /* USE_MLDSA */
