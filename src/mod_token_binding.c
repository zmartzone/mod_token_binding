/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

/***************************************************************************
 * Copyright (C) 2017 ZmartZone IAM
 * All rights reserved.
 *
 *      ZmartZone IAM
 *      info@zmartzone.eu
 *      http://www.zmartzone.eu
 *
 * THE SOFTWARE PROVIDED HEREUNDER IS PROVIDED ON AN "AS IS" BASIS, WITHOUT
 * ANY WARRANTIES OR REPRESENTATIONS EXPRESS, IMPLIED OR STATUTORY; INCLUDING,
 * WITHOUT LIMITATION, WARRANTIES OF QUALITY, PERFORMANCE, NONINFRINGEMENT,
 * MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.  NOR ARE THERE ANY
 * WARRANTIES CREATED BY A COURSE OR DEALING, COURSE OF PERFORMANCE OR TRADE
 * USAGE.  FURTHERMORE, THERE ARE NO WARRANTIES THAT THE SOFTWARE WILL MEET
 * YOUR NEEDS OR BE FREE FROM ERRORS, OR THAT THE OPERATION OF THE SOFTWARE
 * WILL BE UNINTERRUPTED.  IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * @Author: Hans Zandbelt - hans.zandbelt@zmartzone.eu
 *
 **************************************************************************/

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_request.h"

#include "apr_hooks.h"
#include "apr_optional.h"

#include "openssl/rand.h"

#include "mod_token_binding.h"

#include "token_bind_common.h"
#include "token_bind_server.h"
#include "base64.h"

module AP_MODULE_DECLARE_DATA token_binding_module;

typedef struct {
	int enabled;
	tbCache *cache;
} tb_server_config;

APR_DECLARE_OPTIONAL_FN(int, tb_add_ext, (server_rec *s, SSL_CTX *ctx));

// called dynamically from mod_ssl
static int tb_add_ext(server_rec *s, SSL_CTX *ctx) {

	ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
			"tb_add_ext: ### s=%pp, ctx=%pp ###", s, ctx);

	if (!tbEnableTLSTokenBindingNegotiation(ctx)) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
				"tb_add_ext: tbEnableTLSTokenBindingNegotiation() failed");
		return -1;
	}
	ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
			"tb_add_ext: tbEnableTLSTokenBindingNegotiation() succeeded");

	return 1;
}

static int tb_fixup_handler(request_rec *r) {
	ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "tb_fixup_handler: enter");
	return OK;
}

static apr_status_t tb_cleanup_handler(void *data) {
	ap_log_error(APLOG_MARK, APLOG_INFO, 0, (server_rec * ) data,
			"%s - shutdown", NAMEVERSION);
	return APR_SUCCESS;
}

static int tb_post_config_handler(apr_pool_t *pool, apr_pool_t *p1,
		apr_pool_t *p2, server_rec *s) {
	ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "%s - init", NAMEVERSION);

	if (!tbTLSLibInit()) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
				"tb_post_config_handler: tbTLSLibInit() failed");
	}
	ap_log_error(APLOG_MARK, APLOG_INFO, 0, s,
			"tb_post_config_handler: tbTLSLibInit() succeeded");

	apr_pool_cleanup_register(pool, s, tb_cleanup_handler,
			apr_pool_cleanup_null);
	return OK;
}

static const char TB_SEC_TOKEN_BINDING_HDR_NAME[] = "Sec-Token-Binding";
static const char TB_SEC_TOKEN_BINDING_ENV_NAME[] = "Token-Binding-ID";

APR_DECLARE_OPTIONAL_FN(SSL *, ssl_get_ssl_from_request, (request_rec *));

APR_DECLARE_OPTIONAL_FN(int, ssl_is_https, (conn_rec *));

static int tb_auth(request_rec *r) {

	tb_server_config *cfg = (tb_server_config*) ap_get_module_config(
			r->server->module_config, &token_binding_module);

	ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, "tb_auth: enter: %pp, %pp, %d",
			cfg, cfg->cache, cfg->enabled);

	if (cfg->enabled == 0)
		return DECLINED;

	tbKeyType tls_key_type;

	APR_OPTIONAL_FN_TYPE(ssl_is_https) *ssl_is_https_fn =
			APR_RETRIEVE_OPTIONAL_FN(ssl_is_https);

	if (ssl_is_https_fn == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
				"tb_auth: no ssl_is_https_fn function found: perhaps mod_ssl is not loaded?");
		return DECLINED;
	}

	ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
			"tb_auth: ssl_is_https_fn found");

	APR_OPTIONAL_FN_TYPE(ssl_get_ssl_from_request) *get_ssl_from_request_fn =
			APR_RETRIEVE_OPTIONAL_FN(ssl_get_ssl_from_request);

	if (get_ssl_from_request_fn == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
				"tb_auth: no ssl_get_ssl_from_request function found: perhaps mod_ssl is not loaded?");
		return DECLINED;
	}

	ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
			"tb_auth: ssl_get_ssl_from_request found");

	if (!tbTokenBindingEnabled(get_ssl_from_request_fn(r), &tls_key_type)) {
		ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
				"tb_auth: Token Binding is not enabled");
		return DECLINED;
	}

	ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
			"tb_auth: Token Binding is enabled!!");

	const char *tb_header = apr_table_get(r->headers_in,
			TB_SEC_TOKEN_BINDING_HDR_NAME);
	if (tb_header == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"tb_auth: no \"%s\" header found in request",
				TB_SEC_TOKEN_BINDING_HDR_NAME);
		return HTTP_UNAUTHORIZED;
	}

	ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
			"tb_auth: Token Binding header found: %s=%s",
			TB_SEC_TOKEN_BINDING_HDR_NAME, tb_header);

	uint8_t* out_tokbind_id;
	size_t out_tokbind_id_len;
	uint8_t* referred_tokbind_id;
	size_t referred_tokbind_id_len;

	size_t maxlen = strlen(tb_header);
	char* message = apr_pcalloc(r->pool, maxlen);
	size_t message_len = WebSafeBase64Unescape(tb_header, message, maxlen);
	if (message_len == 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"tb_auth: could not base64urlecode Token Binding header");
		return HTTP_UNAUTHORIZED;
	}

	ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
			"tb_auth: call tbCacheMessageAlreadyVerified");

	if (tbCacheMessageAlreadyVerified(cfg->cache, (uint8_t*) message,
			message_len, &out_tokbind_id, &out_tokbind_id_len,
			&referred_tokbind_id, &referred_tokbind_id_len)) {
		if (referred_tokbind_id != NULL) {
			ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
					"tb_auth: Token Binding header with referred TokenBindingID was found in the cache");
		} else {
			ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
					"tb_auth: Token Binding header was found in the cache");
		}
		return DECLINED;
	}

	ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
			"tb_auth: call tbCacheMessageAlreadyVerified returned false; call tbGetEKM");

	uint8_t ekm[TB_HASH_LEN];
	if (!tbGetEKM(get_ssl_from_request_fn(r), ekm)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"tb_auth: unable to get EKM from TLS connection\n");
		return DECLINED;
	}

	ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
			"tb_auth: call tbGetEKM returned; call tbCacheVerifyTokenBindingMessage");

	if (!tbCacheVerifyTokenBindingMessage(cfg->cache, (uint8_t*) message,
			message_len, tls_key_type, ekm, &out_tokbind_id,
			&out_tokbind_id_len, &referred_tokbind_id,
			&referred_tokbind_id_len)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"tb_auth: bad Token Binding header\n");
		return DECLINED;
	}

	ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
			"tb_auth: verified Token Binding header!");

	size_t env_var_len = CalculateBase64EscapedLen(out_tokbind_id_len, false);
	char* env_var_str = apr_pcalloc(r->pool, env_var_len + 1);
	WebSafeBase64Escape((const char *) out_tokbind_id, out_tokbind_id_len,
			env_var_str, env_var_len, false);
	ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r,
			"tb_auth: set Token Binding ID environment variable: %s=%s",
			TB_SEC_TOKEN_BINDING_ENV_NAME, env_var_str);

	apr_table_set(r->subprocess_env, TB_SEC_TOKEN_BINDING_ENV_NAME,
			env_var_str);

	return DECLINED;
}

void *tb_create_server_config(apr_pool_t *pool, server_rec *svr) {
	tb_server_config *c = apr_pcalloc(pool, sizeof(tb_server_config));
	c->enabled = 1;
	uint64_t rand_seed = 0;
	RAND_seed(&rand_seed, sizeof(uint64_t));
	tbCacheLibInit(rand_seed);
	c->cache = tbCacheCreate();
	return c;
}

void *tb_merge_server_config(apr_pool_t *pool, void *BASE, void *ADD) {
	tb_server_config *c = apr_pcalloc(pool, sizeof(tb_server_config));
	tb_server_config *base = BASE;
	tb_server_config *add = ADD;
	c->enabled = add->enabled;
	c->cache = add->cache;
	return c;
}

static void tb_register_hooks(apr_pool_t *p) {
	static const char * const aszSucc[] = { "mod_rewrite.c", NULL };
	ap_hook_post_config(tb_post_config_handler, NULL, NULL, APR_HOOK_LAST);
	ap_hook_post_read_request(tb_auth, NULL, NULL, APR_HOOK_LAST);
	/*
	 #if MODULE_MAGIC_NUMBER_MAJOR >= 20100714
	 ap_hook_check_authn(tb_auth, NULL, NULL, APR_HOOK_MIDDLE, AP_AUTH_INTERNAL_PER_CONF);
	 #else
	 static const char * const authzSucc[] = { "mod_authz_user.c", NULL };
	 ap_hook_check_user_id(tb_auth, NULL, NULL, APR_HOOK_MIDDLE);
	 #endif
	 */
	ap_hook_fixups(tb_fixup_handler, NULL, aszSucc, APR_HOOK_FIRST);
	APR_REGISTER_OPTIONAL_FN(tb_add_ext);
}

static const char *tb_set_enabled(cmd_parms *cmd, void *struct_ptr,
		const char *arg) {
	tb_server_config *cfg = (tb_server_config *) ap_get_module_config(
			cmd->server->module_config, &token_binding_module);
	if (strcmp(arg, "Off") == 0)
		cfg->enabled = 0;
	if (strcmp(arg, "On") == 0)
		cfg->enabled = 1;
	return "Invalid value: must be \"On\" or \"Off\"";
}

static const command_rec tb_cmds[] = {
		AP_INIT_TAKE1("TokenBindingEnabled", tb_set_enabled, NULL, RSRC_CONF, "Enable or disable mod_token_binding"),
		{ NULL }
};

module AP_MODULE_DECLARE_DATA token_binding_module = {
		STANDARD20_MODULE_STUFF,
		NULL,
		NULL,
		tb_create_server_config,
		tb_merge_server_config,
		tb_cmds,
		tb_register_hooks,
};
