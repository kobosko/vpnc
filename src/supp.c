/*
   Algorithm support checks

   SPDX-FileCopyrightText: 2005 Maurice Massar
   SPDX-FileCopyrightText: 2006 Dan Villiom Podlaski Christiansen

   SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "supp.h"
#include "math_group.h"
#include "config.h"
#include "isakmp.h"

#include <gcrypt.h>
#include <stdlib.h>

const supported_algo_t supp_dh_group[] = {
    {"nopfs", 0, 0, 0, 0},
    {"dh1", OAKLEY_GRP_1, IKE_GROUP_MODP_768, IKE_GROUP_MODP_768, 0},
    {"dh2", OAKLEY_GRP_2, IKE_GROUP_MODP_1024, IKE_GROUP_MODP_1024, 0},
    {"dh5", OAKLEY_GRP_5, IKE_GROUP_MODP_1536, IKE_GROUP_MODP_1536, 0},
    {"dh14", OAKLEY_GRP_14, IKE_GROUP_MODP_2048, IKE_GROUP_MODP_2048, 0},
    {"dh15", OAKLEY_GRP_15, IKE_GROUP_MODP_3072, IKE_GROUP_MODP_3072, 0},
    {"dh16", OAKLEY_GRP_16, IKE_GROUP_MODP_4096, IKE_GROUP_MODP_4096, 0},
    {"dh17", OAKLEY_GRP_17, IKE_GROUP_MODP_6144, IKE_GROUP_MODP_6144, 0},
    {"dh18", OAKLEY_GRP_18, IKE_GROUP_MODP_8192, IKE_GROUP_MODP_8192, 0},
    /*{ "dh7", OAKLEY_GRP_7, IKE_GROUP_EC2N_163K, IKE_GROUP_EC2N_163K, 0 } note: code missing */
    {NULL, 0, 0, 0, 0}};

const supported_algo_t supp_hash[] = {
    {"md5", GCRY_MD_MD5, IKE_HASH_MD5, IPSEC_AUTH_HMAC_MD5, 0},
    {"sha1", GCRY_MD_SHA1, IKE_HASH_SHA, IPSEC_AUTH_HMAC_SHA, 0},
    {"sha256", GCRY_MD_SHA256, IKE_HASH_SHA2_256, IPSEC_AUTH_HMAC_SHA2_256, 0},
    {"sha384", GCRY_MD_SHA384, IKE_HASH_SHA2_384, IPSEC_AUTH_HMAC_SHA2_384, 0},
    {"sha512", GCRY_MD_SHA512, IKE_HASH_SHA2_512, IPSEC_AUTH_HMAC_SHA2_512, 0},
    {NULL, 0, 0, 0, 0}};

const supported_algo_t supp_crypt[] = {
    {"null", GCRY_CIPHER_NONE, IKE_ENC_NO_CBC, ISAKMP_IPSEC_ESP_NULL, 0},
    {"des", GCRY_CIPHER_DES, IKE_ENC_DES_CBC, ISAKMP_IPSEC_ESP_DES, 0},
    {"3des", GCRY_CIPHER_3DES, IKE_ENC_3DES_CBC, ISAKMP_IPSEC_ESP_3DES, 0},
    {"aes128", GCRY_CIPHER_AES128, IKE_ENC_AES_CBC, ISAKMP_IPSEC_ESP_AES, 128},
    {"aes192", GCRY_CIPHER_AES192, IKE_ENC_AES_CBC, ISAKMP_IPSEC_ESP_AES, 192},
    {"aes256", GCRY_CIPHER_AES256, IKE_ENC_AES_CBC, ISAKMP_IPSEC_ESP_AES, 256},
    /*
     * AEAD, ESP only: ike_sa_id is 0 because these are never offered for
     * phase 1, and the trailing 16 is the ICV length ESP_AES_GCM_16 asks for.
     */
    {"aes128-gcm", GCRY_CIPHER_AES128, 0, ISAKMP_IPSEC_ESP_AES_GCM_16, 128},
    {"aes192-gcm", GCRY_CIPHER_AES192, 0, ISAKMP_IPSEC_ESP_AES_GCM_16, 192},
    {"aes256-gcm", GCRY_CIPHER_AES256, 0, ISAKMP_IPSEC_ESP_AES_GCM_16, 256},
    {NULL, 0, 0, 0, 0}};

const supported_algo_t supp_auth[] = {
    {"psk", 0, IKE_AUTH_PRESHARED, 0, 0},
    {"psk+xauth", 0, IKE_AUTH_XAUTHInitPreShared, 0, 0},
#if 0
	{"cert(dsa)", 0, IKE_AUTH_RSA_SIG, 0, 0},
	{"cert(rsasig)", 0, IKE_AUTH_DSS, 0, 0},
	{"hybrid(dsa)", 0, IKE_AUTH_DSS, 0, 0},
#endif /* 0 */
    {"hybrid(rsa)", 0, IKE_AUTH_HybridInitRSA, 0, 0},
    {NULL, 0, 0, 0, 0}};

/*
 * ICV length in bytes an ESP integrity algorithm is truncated to. RFC 2403
 * and RFC 2404 cut MD5 and SHA-1 down to 96 bits; RFC 4868 cuts the SHA-2
 * family to half the digest instead, so the length is no longer a constant.
 */
int esp_icv_len(int md_algo)
{
	switch (md_algo) {
	case GCRY_MD_SHA256:
		return 16;
	case GCRY_MD_SHA384:
		return 24;
	case GCRY_MD_SHA512:
		return 32;
	default:
		return 12;
	}
}

int esp_aead_icv_len(int ipsec_sa_id)
{
	switch (ipsec_sa_id) {
	case ISAKMP_IPSEC_ESP_AES_GCM_8:
		return 8;
	case ISAKMP_IPSEC_ESP_AES_GCM_12:
		return 12;
	case ISAKMP_IPSEC_ESP_AES_GCM_16:
		return 16;
	default:
		return 0;
	}
}

const supported_algo_t *get_algo(enum algo_group what, enum supp_algo_key key, int id,
				 const char *name, int keylen)
{
	const supported_algo_t *sa = NULL;
	int i = 0, val = 0;
	const char *valname = NULL;

	switch (what) {
	case SUPP_ALGO_DH_GROUP:
		sa = supp_dh_group;
		break;
	case SUPP_ALGO_HASH:
		sa = supp_hash;
		break;
	case SUPP_ALGO_CRYPT:
		sa = supp_crypt;
		break;
	case SUPP_ALGO_AUTH:
		sa = supp_auth;
		break;
	default:
		abort();
	}

	for (i = 0; sa[i].name != NULL; i++) {
		switch (key) {
		case SUPP_ALGO_NAME:
			valname = sa[i].name;
			break;
		case SUPP_ALGO_MY_ID:
			val = sa[i].my_id;
			break;
		case SUPP_ALGO_IKE_SA:
			val = sa[i].ike_sa_id;
			break;
		case SUPP_ALGO_IPSEC_SA:
			val = sa[i].ipsec_sa_id;
			break;
		default:
			abort();
		}
		if ((key == SUPP_ALGO_NAME) ? !strcasecmp(name, valname) : (val == id))
			if (keylen == sa[i].keylen)
				return sa + i;
	}

	return NULL;
}

const supported_algo_t *get_dh_group_ike(void)
{
	return get_algo(SUPP_ALGO_DH_GROUP, SUPP_ALGO_NAME, 0, config[CONFIG_IKE_DH], 0);
}
const supported_algo_t *get_dh_group_ipsec(int server_setting)
{
	const char *pfs_setting = config[CONFIG_IPSEC_PFS];

	if (!strcmp(config[CONFIG_IPSEC_PFS], "server")) {
		/* treat server_setting == -1 (unknown) as 0 */
		pfs_setting = (server_setting == 1) ? "dh2" : "nopfs";
	}

	return get_algo(SUPP_ALGO_DH_GROUP, SUPP_ALGO_NAME, 0, pfs_setting, 0);
}
