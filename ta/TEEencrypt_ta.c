/* 2023-01 System and Network Security

   Chungnam National University Sys&NetSec Term Project
   OP-TEE File Encryption Trusted Application

   Created-By: Ji Myoung Ha <noplayer40600@gmail.com>
   Student-ID: 201802162 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <TEEencrypt_ta.h>

#define RSA_KEY_SIZE 2048
#define MAX_PLAIN_LEN_2048 214 // (2048 / 8) - 42(padding)
#define RSA_CIPHER_LEN_2048 (RSA_KEY_SIZE / 8)

const int32_t rootKey = 15;
uint32_t randomKey = 0;

struct rsa_session
{
	TEE_OperationHandle operation_handle;
	TEE_ObjectHandle key_handle;
};

TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("has been called");

	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	DMSG("has been called");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types, TEE_Param __maybe_unused params[4], void __maybe_unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
											   TEE_PARAM_TYPE_NONE,
											   TEE_PARAM_TYPE_NONE,
											   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	(void)&params;

	/* RSA session */
	struct rsa_session *session;
	session = TEE_Malloc(sizeof(*session), 0);
	if (!session)
		return TEE_ERROR_OUT_OF_MEMORY;

	session->operation_handle = TEE_HANDLE_NULL;
	session->key_handle = TEE_HANDLE_NULL;

	*sess_ctx = (void *)session;

	DMSG("RSA Session %p: newly allocated", *sess_ctx);

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	struct rsa_session *session;

	/* Release RSA session */
	DMSG("RSA Session %p: release session", sess_ctx);
	session = (struct rsa_session *)sess_ctx;

	if (session->operation_handle != TEE_HANDLE_NULL)
		TEE_FreeOperation(session->operation_handle);
	if (session->key_handle != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(session->key_handle);
	TEE_Free(session);
}

static TEE_Result caesar_enc_value(uint32_t param_types, TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
											   TEE_PARAM_TYPE_NONE,
											   TEE_PARAM_TYPE_NONE,
											   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	IMSG("Encrypt %zu bytes of data from NW", params[0].memref.size);

	char *string = params[0].memref.buffer;
	size_t index = 0;
	for (index; index < params[0].memref.size; index++)
	{
		char c = string[index];
		if ('a' <= c && c <= 'z')
		{
			c += randomKey;
			if ('z' < c)
			{
				c -= 26;
			}
			string[index] = c;
		}
		else if ('A' <= c && c <= 'Z')
		{
			c += randomKey;
			if ('Z' < c)
			{
				c -= 26;
			}
			string[index] = c;
		}
	}

	return TEE_SUCCESS;
}

static TEE_Result caesar_dec_value(uint32_t param_types, TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
											   TEE_PARAM_TYPE_VALUE_INPUT,
											   TEE_PARAM_TYPE_NONE,
											   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	IMSG("Got %u bytes of data from NW", params[0].memref.size);

	int32_t key = params[1].value.a;
	key -= rootKey;
	if (key < 0)
	{
		key += 26;
	}

	IMSG("Key is %d", key);

	// IMSG("Before: %s", params[0].memref.buffer);

	char *string = params[0].memref.buffer;
	size_t index = 0;
	for (index; index < params[0].memref.size; index++)
	{
		char c = string[index];
		if ('a' <= c && c <= 'z')
		{
			c -= key;
			if (c < 'a')
			{
				c += 26;
			}
			string[index] = c;
		}
		else if ('A' <= c && c <= 'Z')
		{
			c -= key;
			if (c < 'A')
			{
				c += 26;
			}
			string[index] = c;
		}
	}

	// IMSG("After: %s", params[0].memref.buffer);

	return TEE_SUCCESS;
}

static TEE_Result caesar_gen_key()
{
	DMSG("has been called");

	do
	{
		TEE_GenerateRandom(&randomKey, sizeof(randomKey));
		randomKey %= 26;
	} while (randomKey == 0);

	DMSG("Created new random key: %u", randomKey);

	return TEE_SUCCESS;
}

static TEE_Result caesar_enc_key(uint32_t param_types, TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
											   TEE_PARAM_TYPE_NONE,
											   TEE_PARAM_TYPE_NONE,
											   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	params[0].value.a = (randomKey + rootKey) % 26;

	IMSG("Set encrypted random key: %u", params[0].value.a);

	return TEE_SUCCESS;
}

static TEE_Result rsa_prepare(TEE_OperationHandle *handle, uint32_t alg, TEE_OperationMode mode, TEE_ObjectHandle key)
{
	DMSG("has been called");

	TEE_Result result = TEE_SUCCESS;
	TEE_ObjectInfo key_info;
	result = TEE_GetObjectInfo1(key, &key_info);
	if (result != TEE_SUCCESS)
	{
		EMSG("\nTEE_GetObjectInfo1: %#\n" PRIx32, result);
		return result;
	}

	result = TEE_AllocateOperation(handle, alg, mode, key_info.objectSize);
	if (result != TEE_SUCCESS)
	{
		EMSG("\nFailed to alloc operation handle : 0x%x\n", result);
		return result;
	}
	DMSG("\n========== Operation allocated successfully. ==========\n");

	result = TEE_SetOperationKey(*handle, key);
	if (result != TEE_SUCCESS)
	{
		EMSG("\nFailed to set key : 0x%x\n", result);
		return result;
	}
	DMSG("\n========== Operation key already set. ==========\n");

	return result;
}

static TEE_Result rsa_enc_value(void *sess_ctx, uint32_t param_types, TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
											   TEE_PARAM_TYPE_MEMREF_OUTPUT,
											   TEE_PARAM_TYPE_NONE,
											   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* from RSA_encrypt of optee_rsa_example */
	TEE_Result result;
	uint32_t rsa_alg = TEE_ALG_RSAES_PKCS1_V1_5;
	struct rsa_session *sess = (struct rsa_session *)sess_ctx;

	void *plain_txt = params[0].memref.buffer;
	size_t plain_len = params[0].memref.size;
	void *cipher = params[1].memref.buffer;
	size_t cipher_len = params[1].memref.size;

	DMSG("\n========== Preparing encryption operation ==========\n");
	result = rsa_prepare(&sess->operation_handle, rsa_alg, TEE_MODE_ENCRYPT, sess->key_handle);
	if (result != TEE_SUCCESS)
	{
		EMSG("\nFailed to prepare RSA operation: 0x%x\n", result);
		TEE_FreeOperation(sess->operation_handle);
		TEE_FreeOperation(sess->key_handle);
		return result;
	}

	DMSG("\nData to encrypt: %s\n", (char *)plain_txt);
	result = TEE_AsymmetricEncrypt(sess->operation_handle, (TEE_Attribute *)NULL, 0,
								   plain_txt, plain_len, cipher, &cipher_len);
	if (result != TEE_SUCCESS)
	{
		EMSG("\nFailed to encrypt the passed buffer: 0x%x\n", result);
		TEE_FreeOperation(sess->operation_handle);
		TEE_FreeOperation(sess->key_handle);
		return result;
	}
	DMSG("\nEncrypted data: %s\n", (char *)cipher);
	DMSG("\n========== Encryption successfully ==========\n");

	return result;
}

static TEE_Result rsa_gen_key(void *sess_ctx)
{
	TEE_Result ret;
	size_t key_size = RSA_KEY_SIZE;
	struct rsa_session *session = (struct rsa_session *)sess_ctx;

	ret = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, key_size, &session->key_handle);
	if (ret != TEE_SUCCESS)
	{
		EMSG("\nFailed to alloc transient object handle: 0x%x\n", ret);
		return ret;
	}
	DMSG("\n========== Transient object allocated. ==========\n");

	ret = TEE_GenerateKey(session->key_handle, key_size, (TEE_Attribute *)NULL, 0);
	if (ret != TEE_SUCCESS)
	{
		EMSG("\nGenerate key failure: 0x%x\n", ret);
		return ret;
	}
	DMSG("\n========== Keys generated. ==========\n");
	return ret;
}

/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id, uint32_t param_types, TEE_Param params[4])
{
	switch (cmd_id)
	{
	case TA_TEEencrypt_CMD_CAESAR_ENC_VALUE:
		return caesar_enc_value(param_types, params);
	case TA_TEEencrypt_CMD_CAESAR_DEC_VALUE:
		return caesar_dec_value(param_types, params);
	case TA_TEEencrypt_CMD_CAESAR_GEN_KEY:
		return caesar_gen_key();
	case TA_TEEencrypt_CMD_CAESAR_ENC_KEY:
		return caesar_enc_key(param_types, params);
	case TA_TEEencrypt_CMD_RSA_ENC_VALUE:
		return rsa_enc_value(sess_ctx, param_types, params);
	case TA_TEEencrypt_CMD_RSA_GEN_KEY:
		return rsa_gen_key(sess_ctx);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
