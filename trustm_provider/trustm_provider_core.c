#include <stdarg.h>

#include "trustm_provider_common.h"
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/bio.h>

static OSSL_FUNC_core_gettable_params_fn *c_gettable_params = NULL;
static OSSL_FUNC_core_get_params_fn *c_get_params = NULL;

static OSSL_FUNC_core_new_error_fn *c_new_error = NULL;
static OSSL_FUNC_core_set_error_debug_fn *c_set_error_debug = NULL;
static OSSL_FUNC_core_vset_error_fn *c_vset_error = NULL;


int init_core_func_from_dispatch(const OSSL_DISPATCH *fns) 
{
	for (; fns->function_id != 0; fns++) 
	{
		switch( fns->function_id ) {
			case OSSL_FUNC_CORE_GETTABLE_PARAMS:
				if (c_gettable_params == NULL)
					c_gettable_params = OSSL_FUNC_core_gettable_params(fns);
				break;
			case OSSL_FUNC_CORE_GET_PARAMS:
				if (c_get_params == NULL)
					c_get_params = OSSL_FUNC_core_get_params(fns);
				break;
			case OSSL_FUNC_CORE_NEW_ERROR:
				if (c_new_error == NULL)
					c_new_error = OSSL_FUNC_core_new_error(fns);
				break;
			
			case OSSL_FUNC_CORE_SET_ERROR_DEBUG:
				if (c_set_error_debug == NULL)
					c_set_error_debug = OSSL_FUNC_core_set_error_debug(fns);
				break;
			
			case OSSL_FUNC_CORE_VSET_ERROR:
				if (c_vset_error == NULL)
					c_vset_error = OSSL_FUNC_core_vset_error(fns);
				break;
		}
	}
	
	return 1;
}

void trustm_new_error(const OSSL_CORE_HANDLE *handle, uint32_t reason, const char *fmt, ...) 
{
	if (c_new_error != NULL && c_vset_error != NULL) 
	{
		va_list args;
		
		va_start(args, fmt);
		c_new_error(handle);
		c_vset_error(handle, reason, fmt, args);
		va_end(args);
	}
}

void trustm_set_error_debug(const OSSL_CORE_HANDLE *handle, const char *file, int line, const char *func) 
{
	if (c_set_error_debug != NULL)
		c_set_error_debug(handle, file, line, func);
}

void trustm_list_params(const char *text, const OSSL_PARAM params[])
{
    fprintf(stderr, "%s [", text);

    while (params->key != NULL) {
        fprintf(stderr, " %s", params->key);
        params++;
    }

    fprintf(stderr, " ]\n");
}
