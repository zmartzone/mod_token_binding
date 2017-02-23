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

#include <httpd.h>
#include <http_config.h>
#include <http_request.h>
#include <http_protocol.h>

#include <apr_strings.h>
#include <apr_hooks.h>
#include <apr_optional.h>

#include "openssl/rand.h"
#include <openssl/ssl.h>

#include "mod_token_binding.h"

#include "token_bind_common.h"
#include "token_bind_server.h"
#include "base64.h"

module AP_MODULE_DECLARE_DATA token_binding_module;

#define tb_log(r, level, fmt, ...) ap_log_rerror(APLOG_MARK, level, 0, r,"# %s: %s", __FUNCTION__, apr_psprintf(r->pool, fmt, ##__VA_ARGS__))
#define tb_slog(s, level, fmt, ...) ap_log_error(APLOG_MARK, level, 0, s, "## %s: %s", __FUNCTION__, apr_psprintf(s->process->pool, fmt, ##__VA_ARGS__))

#define tb_debug(r, fmt, ...) tb_log(r, APLOG_DEBUG, fmt, ##__VA_ARGS__)
#define tb_info(r, fmt, ...)  tb_log(r, APLOG_INFO, fmt, ##__VA_ARGS__)
#define tb_warn(r, fmt, ...)  tb_log(r, APLOG_WARNING, fmt, ##__VA_ARGS__)
#define tb_error(r, fmt, ...) tb_log(r, APLOG_ERR, fmt, ##__VA_ARGS__)

#define tb_sdebug(s, fmt, ...) tb_slog(s, APLOG_DEBUG, fmt, ##__VA_ARGS__)
#define tb_sinfo(r, fmt, ...)  tb_slog(r, APLOG_INFO, fmt, ##__VA_ARGS__)
#define tb_swarn(s, fmt, ...) tb_slog(s, APLOG_WARNING, fmt, ##__VA_ARGS__)
#define tb_serror(s, fmt, ...) tb_slog(s, APLOG_ERR, fmt, ##__VA_ARGS__)

typedef struct {
	int enabled;
	tbCache *cache;
} tb_server_config;

APR_DECLARE_OPTIONAL_FN(int, tb_add_ext, (server_rec *s, SSL_CTX *ctx));

APR_DECLARE_OPTIONAL_FN(int, ssl_is_https, (conn_rec *));
APR_DECLARE_OPTIONAL_FN(SSL *, ssl_get_ssl_from_request, (request_rec *));

static APR_OPTIONAL_FN_TYPE(ssl_is_https) *ssl_is_https_fn = NULL;
static APR_OPTIONAL_FN_TYPE(ssl_get_ssl_from_request) *get_ssl_from_request_fn =
		NULL;

// called dynamically from mod_ssl
static int tb_add_ext(server_rec *s, SSL_CTX *ctx) {

	tb_sdebug(s, "enter");

	if (!tbTLSLibInit()) {
		tb_serror(s, "tbTLSLibInit() failed");
		return -1;
	}

	tb_sdebug(s, "tbTLSLibInit() succeeded");

	if (!tbEnableTLSTokenBindingNegotiation(ctx)) {
		tb_serror(s, "tbEnableTLSTokenBindingNegotiation() failed");
		return -1;
	}

	tb_sdebug(s, "tbEnableTLSTokenBindingNegotiation() succeeded");

	return 1;
}

static int tb_fixup_handler(request_rec *r) {
	tb_debug(r, "enter");
	return OK;
}

static apr_status_t tb_cleanup_handler(void *data) {
	server_rec *s = (server_rec *) data;
	tb_sinfo(s, "%s - shutdown", NAMEVERSION);
	return APR_SUCCESS;
}

static int tb_post_config_handler(apr_pool_t *pool, apr_pool_t *p1,
		apr_pool_t *p2, server_rec *s) {
	tb_sinfo(s, "%s - init", NAMEVERSION);
	apr_pool_cleanup_register(pool, s, tb_cleanup_handler,
			apr_pool_cleanup_null);
	return OK;
}

static const char TB_SEC_TOKEN_BINDING_HDR_NAME[] = "Sec-Token-Binding";
static const char TB_SEC_TOKEN_BINDING_ENV_NAME[] = "Token-Binding-ID";

static void tb_set_env_var(request_rec *r, uint8_t* out_tokbind_id,
		size_t out_tokbind_id_len) {

	tb_debug(r, "enter");

	if ((out_tokbind_id == NULL) || (out_tokbind_id_len <= 0))
		return;

	size_t env_var_len = CalculateBase64EscapedLen(out_tokbind_id_len, false);
	char* env_var_str = apr_pcalloc(r->pool, env_var_len + 1);
	WebSafeBase64Escape((const char *) out_tokbind_id, out_tokbind_id_len,
			env_var_str, env_var_len, false);

	tb_debug(r, "set Token Binding ID environment variable: %s=%s",
			TB_SEC_TOKEN_BINDING_ENV_NAME, env_var_str);

	apr_table_set(r->subprocess_env, TB_SEC_TOKEN_BINDING_ENV_NAME,
			env_var_str);

}

static int tb_is_enabled(request_rec *r, tb_server_config *c,
		tbKeyType *tls_key_type) {

	tb_debug(r, "enter: enabled=%d, ssl_is_https_fn=%pp, get_ssl_from_request_fn=%pp", c->enabled, ssl_is_https_fn, get_ssl_from_request_fn);

	if (c->enabled == 0)
		return 0;

	if (ssl_is_https_fn == NULL) {
		tb_error(r,
				"no ssl_is_https_fn function found: perhaps mod_ssl is not loaded?");
		return 0;
	}

	if (ssl_is_https_fn(r->connection) != 1) {
		tb_debug(r,
				"no ssl_is_https_fn returned != 1: looks like this is not an SSL connection");
		return 0;
	}

	if (get_ssl_from_request_fn == NULL) {
		tb_warn(r,
				"no ssl_get_ssl_from_request function found: perhaps a version of mod_ssl is loaded that is not patched for token binding?");
		return 0;
	}

	if (!tbTokenBindingEnabled(get_ssl_from_request_fn(r), tls_key_type)) {
		tb_warn(r, "Token Binding is not enabled");
		return 0;
	}

	tb_debug(r, "Token Binding is enabled: key_type=%d!", *tls_key_type);

	tb_debug(r, "ssl_is_https_fn returned 1: this is an SSL connection");

	return 1;
}

static int tb_get_decoded_header(request_rec *r, char **message,
		size_t *message_len) {
	const char *header = apr_table_get(r->headers_in,
			TB_SEC_TOKEN_BINDING_HDR_NAME);
	if (header == NULL) {
		tb_warn(r, "no \"%s\" header found in request",
				TB_SEC_TOKEN_BINDING_HDR_NAME);
		return 0;
	}

	tb_debug(r, "Token Binding header found: %s=%s",
			TB_SEC_TOKEN_BINDING_HDR_NAME, header);

	size_t maxlen = strlen(header);
	*message = apr_pcalloc(r->pool, maxlen);
	*message_len = WebSafeBase64Unescape(header, *message, maxlen);
	if (*message_len == 0) {
		tb_error(r, "could not base64url decode Token Binding header");
		return 0;
	}

	return 1;
}

static int tb_post_read_request(request_rec *r) {

	tb_server_config *cfg = (tb_server_config*) ap_get_module_config(
			r->server->module_config, &token_binding_module);
	tbKeyType tls_key_type;
	char *message = NULL;
	size_t message_len;

	tb_debug(r, "enter: enabled=%d", cfg->enabled);

	if (tb_is_enabled(r, cfg, &tls_key_type) == 0)
		return DECLINED;

	if (tb_get_decoded_header(r, &message, &message_len) == 0)
		return HTTP_UNAUTHORIZED;

	uint8_t* out_tokbind_id;
	size_t out_tokbind_id_len;
	uint8_t* referred_tokbind_id;
	size_t referred_tokbind_id_len;

	if (tbCacheMessageAlreadyVerified(cfg->cache, (uint8_t*) message,
			message_len, &out_tokbind_id, &out_tokbind_id_len,
			&referred_tokbind_id, &referred_tokbind_id_len)) {
		if (referred_tokbind_id != NULL) {
			tb_debug(r,
					"Token Binding header with referred TokenBindingID was found in the cache");
		} else {
			tb_debug(r, "Token Binding header was found in the cache");
		}
		tb_set_env_var(r, out_tokbind_id, out_tokbind_id_len);
		return DECLINED;
	}

	tb_debug(r,
			"call tbCacheMessageAlreadyVerified returned false; call tbGetEKM");

	uint8_t ekm[TB_HASH_LEN];
	if (!tbGetEKM(get_ssl_from_request_fn(r), ekm)) {
		tb_warn(r, "unable to get EKM from TLS connection\n");
		return DECLINED;
	}

	tb_debug(r,
			"call tbGetEKM returned; call tbCacheVerifyTokenBindingMessage");

	if (!tbCacheVerifyTokenBindingMessage(cfg->cache, (uint8_t*) message,
			message_len, tls_key_type, ekm, &out_tokbind_id,
			&out_tokbind_id_len, &referred_tokbind_id,
			&referred_tokbind_id_len)) {
		tb_error(r, "bad Token Binding header\n");
		return DECLINED;
	}

	tb_debug(r, "verified Token Binding header!");

	tb_set_env_var(r, out_tokbind_id, out_tokbind_id_len);

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
	tb_server_config *add = ADD;
	c->enabled = add->enabled;
	c->cache = add->cache;
	return c;
}

#define TB_FIXUP_HEADERS_ERR "TB_FIXUP_HEADERS_ERR"
#define TB_FIXUP_HEADERS_OUT "TB_FIXUP_HEADERS_OUT"

static void tb_insert_output_filter(request_rec *r) {
	tb_server_config *cfg = (tb_server_config*) ap_get_module_config(
			r->server->module_config, &token_binding_module);

	tb_debug(r, "enter: enabled=%d", cfg->enabled);

	if (cfg->enabled == 1)
		ap_add_output_filter(TB_FIXUP_HEADERS_OUT, NULL, r, r->connection);
}

static void tb_insert_error_filter(request_rec *r) {
	tb_server_config *cfg = (tb_server_config*) ap_get_module_config(
			r->server->module_config, &token_binding_module);

	tb_debug(r, "enter: enabled=%d", cfg->enabled);

	if (cfg->enabled == 1)
		ap_add_output_filter(TB_FIXUP_HEADERS_ERR, NULL, r, r->connection);
}

static apr_status_t tb_output_filter(ap_filter_t *f, apr_bucket_brigade *in) {
	request_rec *r = f->r;
	tb_server_config *cfg = (tb_server_config*) ap_get_module_config(
			r->server->module_config, &token_binding_module);

	tb_debug(r, "enter: enabled=%d", cfg->enabled);

	//do_headers_fixup(f->r, f->r->err_headers_out, dirconf->fixup_err, 0);
	//do_headers_fixup(f->r, f->r->headers_out, dirconf->fixup_out, 0);

	ap_remove_output_filter(f);

	return ap_pass_brigade(f->next, in);
}

static apr_status_t tb_error_filter(ap_filter_t *f, apr_bucket_brigade *in) {
	request_rec *r = f->r;
	tb_server_config *cfg = (tb_server_config*) ap_get_module_config(
			r->server->module_config, &token_binding_module);

	tb_debug(r, "enter: enabled=%d", cfg->enabled);

	/*
	 * Add any header fields defined by "Header always" to r->err_headers_out.
	 * Server-wide first, then per-directory to allow overriding.
	 */
	//do_headers_fixup(f->r, f->r->err_headers_out, dirconf->fixup_err, 0);
	ap_remove_output_filter(f);

	return ap_pass_brigade(f->next, in);
}

static void tb_retrieve_optional_fn() {
	ssl_is_https_fn = APR_RETRIEVE_OPTIONAL_FN(ssl_is_https);
	get_ssl_from_request_fn = APR_RETRIEVE_OPTIONAL_FN(
			ssl_get_ssl_from_request);
}

static void tb_register_hooks(apr_pool_t *p) {
	static const char * const aszSucc[] = { "mod_rewrite.c", NULL };
	ap_hook_post_config(tb_post_config_handler, NULL, NULL, APR_HOOK_LAST);
	ap_hook_post_read_request(tb_post_read_request, NULL, NULL, APR_HOOK_LAST);
	ap_hook_fixups(tb_fixup_handler, NULL, aszSucc, APR_HOOK_FIRST);
	ap_register_output_filter(TB_FIXUP_HEADERS_OUT, tb_output_filter,
			NULL, AP_FTYPE_CONTENT_SET);
	ap_register_output_filter(TB_FIXUP_HEADERS_ERR, tb_error_filter,
			NULL, AP_FTYPE_CONTENT_SET);
	ap_hook_insert_filter(tb_insert_output_filter, NULL, NULL, APR_HOOK_LAST);
	ap_hook_insert_error_filter(tb_insert_error_filter, NULL, NULL,
			APR_HOOK_LAST);
	ap_hook_optional_fn_retrieve(tb_retrieve_optional_fn, NULL, NULL,
			APR_HOOK_MIDDLE);
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
		AP_INIT_TAKE1(
				"TokenBindingEnabled",
				tb_set_enabled,
				NULL,
				RSRC_CONF,
				"Enable or disable mod_token_binding"),
		{ NULL }
};

module AP_MODULE_DECLARE_DATA token_binding_module = {
		STANDARD20_MODULE_STUFF,
		NULL,
		NULL,
		tb_create_server_config,
		tb_merge_server_config,
		tb_cmds,
		tb_register_hooks
};
