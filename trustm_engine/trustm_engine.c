/**
* MIT License
*
* Copyright (c) 2019 Infineon Technologies AG
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE

*/
#include "trustm_engine_common.h"

#include <string.h>
#include <openssl/engine.h>
#include "trustm_engine.h"

static const char *engine_id   = "trustm_engine";
static const char *engine_name = "Infineon OPTIGA TrustM Engine";

static int engine_init(ENGINE *e);
static int engine_finish(ENGINE *e);
static int engine_destroy(ENGINE *e);

static int engine_init(ENGINE *e)
{
	int ret = TRUSTM_ENGINE_SUCCESS;
	TRUSTM_ENGINE_DBGFN("> Engine 0x%x init", (unsigned int) e);
/*
	if (trustmEngine_init() != 1)
	{
		TRUSTM_ENGINE_ERRFN("Engine context init failed");
		TRUSTM_ENGINE_DBGFN("<");
		ret = TRUSTM_ENGINE_FAIL;
	}
*/
	TRUSTM_ENGINE_DBGFN("<");
	return ret;
}

static int engine_destroy(ENGINE *e)
{
	TRUSTM_ENGINE_DBGFN("> Engine 0x%x destroy", (unsigned int) e);
	//trustmEngine_close();
	TRUSTM_ENGINE_DBGFN("<");
	return TRUSTM_ENGINE_SUCCESS;
}

static int engine_finish(ENGINE *e)
{
	TRUSTM_ENGINE_DBGFN("> Engine 0x%x finish (releasing functional reference)", (unsigned int) e);
	TRUSTM_ENGINE_DBGFN("<");
	return TRUSTM_ENGINE_SUCCESS;
}

/**************************************************************** 
 engine_loadkey()
 This function implements loading trustx key.
 e        : The engine for this callback (unused).
 key_id   : The name of the file with the TPM key data.
 ui The ui: functions for querying the user.
 cb_data  : Callback data.
*****************************************************************/
static EVP_PKEY * engine_loadkey(ENGINE *e, const char *key_id, UI_METHOD *ui, void *cb_data)
{
    return NULL;
}


static int engine_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f) ())
{
    return 0;
}

static int bind(ENGINE *e, const char *id)
{
	int ret = TRUSTM_ENGINE_FAIL;
	
    TRUSTM_ENGINE_DBGFN(">");

	do {
		if (!ENGINE_set_id(e, engine_id)) {
			TRUSTM_ENGINE_DBGFN("ENGINE_set_id failed\n");
			break;
		}
		if (!ENGINE_set_name(e, engine_name)) {
			TRUSTM_ENGINE_DBGFN("ENGINE_set_name failed\n");
			break;
		}

		/* The init function is not allways called so we initialize crypto methods
		   directly from bind. */
		if (!engine_init(e)) {
			TRUSTM_ENGINE_DBGFN("TrustM enigne initialization failed\n");
			break;
		}

		if (!ENGINE_set_load_privkey_function(e, engine_loadkey)) {
			TRUSTM_ENGINE_DBGFN("ENGINE_set_load_privkey_function failed\n");
			break;
		}
		
		if (!ENGINE_set_finish_function(e, engine_finish)) {
			TRUSTM_ENGINE_DBGFN("ENGINE_set_finish_function failed\n");
			break;
		}

		if (!ENGINE_set_destroy_function(e, engine_destroy)) {
			TRUSTM_ENGINE_DBGFN("ENGINE_set_destroy_function failed\n");
			break;
		}

		if (!ENGINE_set_ctrl_function(e, engine_ctrl)) {
			TRUSTM_ENGINE_DBGFN("ENGINE_set_ctrl_function failed\n");
			break;
		}

/*
		if (!ENGINE_set_cmd_defns(e, engine_cmd_defns)) {
			TRUSTM_ENGINE_DBGFN("ENGINE_set_cmd_defns failed\n");
			break;
		}
*/
		ret = TRUSTM_ENGINE_SUCCESS;
	}while(FALSE);

    TRUSTM_ENGINE_DBGFN("<");
    return ret;
  }

IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()

