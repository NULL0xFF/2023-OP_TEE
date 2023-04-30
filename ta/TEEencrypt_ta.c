/* 2023-01 System and Network Security

   Chungnam National University Sys&NetSec Term Project
   OP-TEE File Encryption Trusted Application

   Created-By: Ji Myoung Ha <noplayer40600@gmail.com>
   Student-ID: 201802162 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <TEEencrypt_ta.h>

const int rootKey = 15;
unsigned int randomKey = 0;

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
	(void)&sess_ctx;

	IMSG("Hello World!\n");

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	(void)&sess_ctx;

	IMSG("Goodbye!\n");
}

static TEE_Result enc_value(uint32_t param_types, TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
											   TEE_PARAM_TYPE_VALUE_OUTPUT,
											   TEE_PARAM_TYPE_NONE,
											   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	IMSG("Got %zu bytes of data from NW", params[0].memref.size);

	// IMSG("Before: %s", params[0].memref.buffer);

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

	// IMSG("After: %s", params[0].memref.buffer);

	return TEE_SUCCESS;
}

static TEE_Result dec_value(uint32_t param_types, TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
											   TEE_PARAM_TYPE_VALUE_INPUT,
											   TEE_PARAM_TYPE_NONE,
											   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	IMSG("Got %zu bytes of data from NW", params[0].memref.size);

	int key = params[1].value.a;
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

static TEE_Result randomkey_get(uint32_t param_types, TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
											   TEE_PARAM_TYPE_VALUE_OUTPUT,
											   TEE_PARAM_TYPE_NONE,
											   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	do
	{
		TEE_GenerateRandom(&randomKey, sizeof(randomKey));
		randomKey %= 26;
	} while (randomKey == 0);

	IMSG("Created new random key: %u", randomKey);

	return TEE_SUCCESS;
}

static TEE_Result randomkey_enc(uint32_t param_types, TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
											   TEE_PARAM_TYPE_VALUE_OUTPUT,
											   TEE_PARAM_TYPE_NONE,
											   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	params[1].value.a = (randomKey + rootKey) % 26;

	IMSG("Set encrypted random key: %u", params[1].value.a);

	return TEE_SUCCESS;
}
/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx, uint32_t cmd_id, uint32_t param_types, TEE_Param params[4])
{
	(void)&sess_ctx; /* Unused parameter */

	switch (cmd_id)
	{
	case TA_TEEencrypt_CMD_ENC_VALUE:
		return enc_value(param_types, params);
	case TA_TEEencrypt_CMD_DEC_VALUE:
		return dec_value(param_types, params);
	case TA_TEEencrypt_CMD_RANDOMKEY_GET:
		return randomkey_get(param_types, params);
	case TA_TEEencrypt_CMD_RANDOMKEY_ENC:
		return randomkey_enc(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
