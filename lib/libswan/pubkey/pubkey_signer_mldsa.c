/*
 * ML-DSA IKEv2 authentication signer
 *
 * FIPS 204 and draft-ietf-ipsecme-ikev2-pqc-auth.
 */

#ifdef USE_MLDSA

#include <pk11pub.h>
#include <cryptohi.h>
#include <keyhi.h>

#include "lswnss.h"
#include "lswlog.h"
#include "secrets.h"
#include "ike_alg_hash.h"
#include "crypt_hash.h"

static size_t MLDSA_jam_auth_method(struct jambuf *buf,
				    const struct pubkey_signer *signer,
				    const struct pubkey *pubkey UNUSED,
				    const struct hash_desc *hash)
{
	return jam(buf, "%s with %s",
		   signer->name,
		   hash->common.fqn);
}

static chunk_t concat_hunks(const struct hash_hunks *hunks)
{
	chunk_t message = {0};
	for (const struct hash_hunk *hunk = hunks->hunk;
	     hunk < hunks->hunk + hunks->len; hunk++) {
		append_chunk_hunk("message", &message, *hunk);
	}
	return message;
}

static struct hash_signature MLDSA_sign_message_1(const struct pubkey_signer *signer UNUSED,
						  const struct secret_pubkey_stuff *pks,
						  chunk_t message,
						  struct logger *logger)
{
	if (!pexpect(pks->private_key != NULL)) {
		ldbg(logger, "no private key!");
		return (struct hash_signature) { .len = 0, };
	}

	int signature_len = PK11_SignatureLen(pks->private_key);
	if (signature_len <= 0 ||
	    (size_t)signature_len > sizeof(((struct hash_signature *)0)->ptr)) {
		llog(RC_LOG, logger,
		     "ML-DSA signature length %d does not fit in a %zu-byte signature buffer",
		     signature_len, sizeof(((struct hash_signature *)0)->ptr));
		return (struct hash_signature) { .len = 0, };
	}

	SECItem data_to_sign = same_hunk_as_secitem(&message, siBuffer);
	uint8_t raw_signature_data[sizeof(struct hash_signature)];
	SECItem raw_signature = {
		.type = siBuffer,
		.len = signature_len,
		.data = raw_signature_data,
	};

	ldbg(logger, "ML-DSA signature length is %d", raw_signature.len);
	if (LDBGP(DBG_BASE, logger)) {
		LDBG_log(logger, "ML-DSA message of %zu bytes:", message.len);
		LDBG_hunk(logger, &message);
	}

	SECStatus s = PK11_Sign(pks->private_key, &raw_signature, &data_to_sign);
	if (s != SECSuccess) {
		llog_nss_error(RC_LOG, logger, "ML-DSA sign function failed");
		return (struct hash_signature) { .len = 0, };
	}

	struct hash_signature signature = {
		.len = raw_signature.len,
	};
	passert(raw_signature.len <= sizeof(signature.ptr/*an-array*/));
	memcpy(signature.ptr, raw_signature.data, raw_signature.len);

	if (LDBGP(DBG_BASE, logger)) {
		LDBG_log(logger, "ML-DSA auth signature of %zu bytes:", signature.len);
		LDBG_hunk(logger, &signature);
	}

	return signature;
}

static struct hash_signature MLDSA_sign_message(const struct pubkey_signer *signer,
						const struct secret_pubkey_stuff *pks,
						const struct hash_hunks *hunks,
						struct logger *logger)
{
	chunk_t message = concat_hunks(hunks); /* must free_chunk_content() */
	struct hash_signature signature = MLDSA_sign_message_1(signer, pks, message, logger);
	free_chunk_content(&message);
	return signature;
}

static bool MLDSA_authenticate_message_signature_1(const struct pubkey_signer *signer UNUSED,
						   chunk_t message,
						   shunk_t signature,
						   struct pubkey *pubkey,
						   diag_t *fatal_diag,
						   struct logger *logger)
{
	int expected_len = SECKEY_SignatureLen(pubkey->content.public_key);
	if (expected_len > 0 && signature.len != (size_t)expected_len) {
		ldbg(logger, "ML-DSA signature is %zu bytes, expected %d",
		     signature.len, expected_len);
		*fatal_diag = NULL;
		return false;
	}

	if (LDBGP(DBG_BASE, logger)) {
		LDBG_log(logger, "ML-DSA signature of %zu bytes:", signature.len);
		LDBG_hunk(logger, &signature);
		LDBG_log(logger, "ML-DSA message of %zu bytes:", message.len);
		LDBG_hunk(logger, &message);
	}

	SECItem signature_item = {
		.type = siBuffer,
		.data = DISCARD_CONST(unsigned char *, signature.ptr),/*NSS doesn't do const*/
		.len = signature.len,
	};
	SECItem message_item = same_hunk_as_secitem(&message, siBuffer);

	if (PK11_Verify(pubkey->content.public_key, &signature_item, &message_item,
			lsw_nss_get_password_context(logger)) != SECSuccess) {
		llog_nss_error(DEBUG_STREAM, logger,
			       "ML-DSA verification using PK11_Verify() failed");
		*fatal_diag = NULL;
		return false;
	}

	*fatal_diag = NULL;
	return true;
}

static bool MLDSA_authenticate_message_signature(const struct pubkey_signer *signer,
						 const struct hash_hunks *hunks,
						 shunk_t signature,
						 struct pubkey *pubkey,
						 diag_t *fatal_diag,
						 struct logger *logger)
{
	chunk_t message = concat_hunks(hunks); /* must free_chunk_content() */
	bool ok = MLDSA_authenticate_message_signature_1(signer, message,
							 signature, pubkey,
							 fatal_diag, logger);
	free_chunk_content(&message);
	return ok;
}

static const uint8_t asn1_mldsa_44_blob[1+ASN1_MLDSA_IDENTITY_SIZE] = {
	ASN1_MLDSA_IDENTITY_SIZE,
	ASN1_MLDSA_IDENTITY_44_BLOB,
};

static const uint8_t asn1_mldsa_65_blob[1+ASN1_MLDSA_IDENTITY_SIZE] = {
	ASN1_MLDSA_IDENTITY_SIZE,
	ASN1_MLDSA_IDENTITY_65_BLOB,
};

static const uint8_t asn1_mldsa_87_blob[1+ASN1_MLDSA_IDENTITY_SIZE] = {
	ASN1_MLDSA_IDENTITY_SIZE,
	ASN1_MLDSA_IDENTITY_87_BLOB,
};

static const struct pubkey_signer_blob mldsa_44_blobs[] = {
	{
		.auth = AUTH_MLDSA_44,
		.hash = &ike_alg_hash_identity,
		HUNK_PTR(asn1_mldsa_44_blob),
	},
};

static const struct pubkey_signer_blob mldsa_65_blobs[] = {
	{
		.auth = AUTH_MLDSA_65,
		.hash = &ike_alg_hash_identity,
		HUNK_PTR(asn1_mldsa_65_blob),
	},
};

static const struct pubkey_signer_blob mldsa_87_blobs[] = {
	{
		.auth = AUTH_MLDSA_87,
		.hash = &ike_alg_hash_identity,
		HUNK_PTR(asn1_mldsa_87_blob),
	},
};

const struct pubkey_signer signer_pubkey_mldsa_44_blob = {
	.name = "ML-DSA-44",
	.type = &pubkey_type_mldsa,
	.digital_signature_blobs = { LIST_REF(mldsa_44_blobs), },
	.authby = { AUTHBY_MLDSA_44, },
	.sign_message = MLDSA_sign_message,
	.authenticate_message_signature = MLDSA_authenticate_message_signature,
	.jam_auth_method = MLDSA_jam_auth_method,
};

const struct pubkey_signer signer_pubkey_mldsa_65_blob = {
	.name = "ML-DSA-65",
	.type = &pubkey_type_mldsa,
	.digital_signature_blobs = { LIST_REF(mldsa_65_blobs), },
	.authby = { AUTHBY_MLDSA_65, },
	.sign_message = MLDSA_sign_message,
	.authenticate_message_signature = MLDSA_authenticate_message_signature,
	.jam_auth_method = MLDSA_jam_auth_method,
};

const struct pubkey_signer signer_pubkey_mldsa_87_blob = {
	.name = "ML-DSA-87",
	.type = &pubkey_type_mldsa,
	.digital_signature_blobs = { LIST_REF(mldsa_87_blobs), },
	.authby = { AUTHBY_MLDSA_87, },
	.sign_message = MLDSA_sign_message,
	.authenticate_message_signature = MLDSA_authenticate_message_signature,
	.jam_auth_method = MLDSA_jam_auth_method,
};

#endif /* USE_MLDSA */
