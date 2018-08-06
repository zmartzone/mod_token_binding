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
 * Copyright (C) 2017-2018 ZmartZone IAM
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
#include <apr_lib.h>

#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <mod_ssl_openssl.h>

#include "mod_token_binding.h"

#include "token_bind_common.h"
#include "token_bind_server.h"
#include "base64.h"

module AP_MODULE_DECLARE_DATA token_binding_module;

#define tb_log(r, level, fmt, ...) ap_log_rerror(APLOG_MARK, level, 0, r,"# %s: %s", __FUNCTION__, apr_psprintf(r->pool, fmt, ##__VA_ARGS__))
#define tb_slog(s, level, fmt, ...) ap_log_error(APLOG_MARK, level, 0, s, "# %s: %s", __FUNCTION__, apr_psprintf(s->process->pool, fmt, ##__VA_ARGS__))

#define tb_debug(r, fmt, ...) tb_log(r, APLOG_DEBUG, fmt, ##__VA_ARGS__)
#define tb_info(r, fmt, ...)  tb_log(r, APLOG_INFO, fmt, ##__VA_ARGS__)
#define tb_warn(r, fmt, ...)  tb_log(r, APLOG_WARNING, fmt, ##__VA_ARGS__)
#define tb_error(r, fmt, ...) tb_log(r, APLOG_ERR, fmt, ##__VA_ARGS__)

#define tb_sdebug(s, fmt, ...) tb_slog(s, APLOG_DEBUG, fmt, ##__VA_ARGS__)
#define tb_sinfo(r, fmt, ...)  tb_slog(r, APLOG_INFO, fmt, ##__VA_ARGS__)
#define tb_swarn(s, fmt, ...) tb_slog(s, APLOG_WARNING, fmt, ##__VA_ARGS__)
#define tb_serror(s, fmt, ...) tb_slog(s, APLOG_ERR, fmt, ##__VA_ARGS__)

#define TB_CFG_POS_INT_UNSET                  -1

#define TB_CFG_SEC_TB_HDR_NAME                "Sec-Token-Binding"
#define TB_CFG_PROVIDED_TBID_HDR_NAME         "Sec-Provided-Token-Binding-ID"
#define TB_CFG_REFERRED_TBID_HDR_NAME         "Sec-Referred-Token-Binding-ID"
#define TB_CFG_TB_CONTEXT_HDR_NAME            "Sec-Token-Binding-Context"

#define TB_CFG_ENABLED_DEFAULT                TRUE
#define TB_CFG_PROVIDED_ENV_VAR_DEFAULT       TB_CFG_PROVIDED_TBID_HDR_NAME
#define TB_CFG_REFERRED_ENV_VAR_DEFAULT       TB_CFG_REFERRED_TBID_HDR_NAME
#define TB_CFG_CONTEXT_ENV_VAR_DEFAULT        TB_CFG_TB_CONTEXT_HDR_NAME

#define TB_CFG_PASS_VAR_PROVIDED_STR          "provided"
#define TB_CFG_PASS_VAR_REFERRED_STR          "referred"
#define TB_CFG_PASS_VAR_CONTEXT_STR           "context"

#define TB_CFG_PASS_VAR_PROVIDED               1
#define TB_CFG_PASS_VAR_REFERRED               2
#define TB_CFG_PASS_VAR_CONTEXT                4
#define TB_CFG_PASS_VAR_DEFAULT                TB_CFG_PASS_VAR_PROVIDED | TB_CFG_PASS_VAR_REFERRED | TB_CFG_PASS_VAR_CONTEXT

typedef struct {
	int enabled;
	tbCache *cache;
	const char *provided_env_var;
	const char *referred_env_var;
	const char *context_env_var;
} tb_server_config;

typedef struct {
	int pass_var;
} tb_dir_config;

typedef struct tb_conn_config {
	SSL *ssl;
	tbKeyType tls_key_type;
	int is_proxy;
} tb_conn_config;

static tb_conn_config *tb_get_conn_config(conn_rec *c) {
	tb_conn_config *conn_cfg = ap_get_module_config(c->conn_config,
			&token_binding_module);

	if (!conn_cfg) {
		conn_cfg = apr_pcalloc(c->pool, sizeof *conn_cfg);
		ap_set_module_config(c->conn_config, &token_binding_module, conn_cfg);
	}

	return conn_cfg;
}

APR_DECLARE_OPTIONAL_FN(int, ssl_is_https, (conn_rec *));
static APR_OPTIONAL_FN_TYPE(ssl_is_https) *ssl_is_https_fn = NULL;

static const char *tb_cfg_set_enabled(cmd_parms *cmd, void *struct_ptr,
		const char *arg) {
	tb_server_config *cfg = (tb_server_config *) ap_get_module_config(
			cmd->server->module_config, &token_binding_module);
	if (strcmp(arg, "Off") == 0) {
		cfg->enabled = 0;
		return NULL;
	}
	if (strcmp(arg, "On") == 0) {
		cfg->enabled = 1;
		return NULL;
	}
	return "Invalid value: must be \"On\" or \"Off\"";
}

static apr_byte_t tb_cfg_get_enabled(tb_server_config *cfg) {
	return (cfg->enabled != TB_CFG_POS_INT_UNSET) ?
			(cfg->enabled > 0) : TB_CFG_ENABLED_DEFAULT;
}

static const char *tb_cfg_set_provided_env_var(cmd_parms *cmd, void *struct_ptr,
		const char *arg) {
	tb_server_config *cfg = (tb_server_config *) ap_get_module_config(
			cmd->server->module_config, &token_binding_module);
	cfg->provided_env_var = arg;
	return NULL;
}

static const char * tb_cfg_get_provided_env_var(tb_server_config *cfg) {
	return cfg->provided_env_var ?
			cfg->provided_env_var : TB_CFG_PROVIDED_ENV_VAR_DEFAULT;
}

static const char *tb_cfg_set_referred_env_var(cmd_parms *cmd, void *struct_ptr,
		const char *arg) {
	tb_server_config *cfg = (tb_server_config *) ap_get_module_config(
			cmd->server->module_config, &token_binding_module);
	cfg->referred_env_var = arg;
	return NULL;
}

static const char * tb_cfg_get_referred_env_var(tb_server_config *cfg) {
	return cfg->referred_env_var ?
			cfg->referred_env_var : TB_CFG_REFERRED_ENV_VAR_DEFAULT;
}

static const char *tb_cfg_set_context_env_var(cmd_parms *cmd, void *struct_ptr,
		const char *arg) {
	tb_server_config *cfg = (tb_server_config *) ap_get_module_config(
			cmd->server->module_config, &token_binding_module);
	cfg->context_env_var = arg;
	return NULL;
}

static const char * tb_cfg_get_context_env_var(tb_server_config *cfg) {
	return cfg->context_env_var ?
			cfg->context_env_var : TB_CFG_CONTEXT_ENV_VAR_DEFAULT;
}

static int tb_ssl_init_server(server_rec *s, apr_pool_t *p, int is_proxy,
		SSL_CTX *ctx) {
	tb_sdebug(s, "enter");

	if (!tbTLSLibInit()) {
		tb_serror(s, "tbTLSLibInit() failed");
		return -1;
	}

	if (!tbEnableTLSTokenBindingNegotiation(ctx)) {
		tb_serror(s, "tbEnableTLSTokenBindingNegotiation() failed");
		return -1;
	}

	return 0;
}

static int tb_ssl_pre_handshake(conn_rec *c, SSL * ssl, int is_proxy) {

	tb_sdebug(c->base_server, "enter");

	tb_conn_config *conn_config = tb_get_conn_config(c);
	conn_config->ssl = ssl;
	conn_config->is_proxy = is_proxy;

	return 0;
}

static void tb_set_var(request_rec *r, const char *env_var_name,
		const char *header_name, uint8_t* tokbind_id, size_t tokbind_id_len) {

	size_t len = CalculateBase64EscapedLen(tokbind_id_len, false);
	char* val = apr_pcalloc(r->pool, len + 1);
	WebSafeBase64Escape((const char *) tokbind_id, tokbind_id_len, val, len,
			false);

	if (env_var_name) {
		tb_debug(r, "set Token Binding ID environment variable: %s=%s",
				env_var_name, val);
		apr_table_set(r->subprocess_env, env_var_name, val);
	}

	if (header_name) {
		tb_debug(r, "set Token Binding ID header: %s=%s", header_name, val);
		apr_table_set(r->headers_in, header_name, val);
	}
}

static int tb_is_enabled(request_rec *r, tb_server_config *c,
		tb_conn_config *conn_cfg) {

	if (tb_cfg_get_enabled(c) == FALSE) {
		tb_debug(r, "token binding is not enabled in the configuration");
		return 0;
	}

	if (ssl_is_https_fn == NULL) {
		tb_warn(r,
				"no ssl_is_https_fn function found: perhaps mod_ssl is not loaded?");
		return 0;
	}

	if (ssl_is_https_fn(r->connection) != 1) {
		tb_debug(r,
				"no ssl_is_https_fn returned != 1: looks like this is not an SSL connection");
		return 0;
	}

	if (!tbTokenBindingEnabled(conn_cfg->ssl, &conn_cfg->tls_key_type)) {
		tb_debug(r, "Token Binding is not enabled by the peer");
		return 0;
	}

	tb_debug(r, "Token Binding is enabled on this connection: key_type=%s",
			tbGetKeyTypeName(conn_cfg->tls_key_type));

	return 1;
}

static const char * tb_cfg_set_pass_var(cmd_parms *cmd, void *m,
		const char *arg) {
	tb_dir_config *c = (tb_dir_config *) m;
	int n = TB_CFG_POS_INT_UNSET;
	if (strcmp(arg, TB_CFG_PASS_VAR_PROVIDED_STR) == 0) {
		n = TB_CFG_PASS_VAR_PROVIDED;
	} else if (strcmp(arg, TB_CFG_PASS_VAR_REFERRED_STR) == 0) {
		n = TB_CFG_PASS_VAR_REFERRED;
	} else if (strcmp(arg, TB_CFG_PASS_VAR_CONTEXT_STR) == 0) {
		n = TB_CFG_PASS_VAR_CONTEXT;
	}
	if (n != TB_CFG_POS_INT_UNSET) {
		if (c->pass_var == TB_CFG_POS_INT_UNSET)
			c->pass_var = n;
		else
			c->pass_var |= n;
		return NULL;
	}
	return "Invalid value: must be \"" TB_CFG_PASS_VAR_PROVIDED_STR "\",\"" TB_CFG_PASS_VAR_REFERRED_STR "\" or \"" TB_CFG_PASS_VAR_CONTEXT_STR "\"";
}

static int tb_cfg_dir_get_pass_var(request_rec *r) {
	tb_dir_config *c = ap_get_module_config(r->per_dir_config,
			&token_binding_module);
	if (c->pass_var == TB_CFG_POS_INT_UNSET)
		return TB_CFG_PASS_VAR_DEFAULT;
	return c->pass_var;
}

static int tb_char_to_env(int c) {
	return apr_isalnum(c) ? apr_toupper(c) : '_';
}

static int tb_strnenvcmp(const char *a, const char *b) {
	int d, i = 0;
	while (1) {
		if (!*a && !*b)
			return 0;
		if (*a && !*b)
			return 1;
		if (!*a && *b)
			return -1;
		d = tb_char_to_env(*a) - tb_char_to_env(*b);
		if (d)
			return d;
		a++;
		b++;
		i++;
	}
	return 0;
}

static void tb_clean_header(request_rec *r, const char *name) {
	const apr_array_header_t * const h = apr_table_elts(r->headers_in);
	apr_table_t *clean_headers = apr_table_make(r->pool, h->nelts);
	const apr_table_entry_t * const e = (const apr_table_entry_t *) h->elts;
	int i = 0;
	while (i < h->nelts) {
		if (e[i].key != NULL) {
			if (tb_strnenvcmp(e[i].key, name) != 0)
				apr_table_addn(clean_headers, e[i].key, e[i].val);
			else
				tb_warn(r, "removing incoming request header (%s: %s)",
						e[i].key, e[i].val);
		}
		i++;
	}
	r->headers_in = clean_headers;
}

static int tb_get_decoded_header(request_rec *r, tb_server_config *cfg,
		char **message, size_t *message_len) {

	const char *header = apr_table_get(r->headers_in, TB_CFG_SEC_TB_HDR_NAME);
	if (header == NULL) {
		tb_warn(r, "no \"%s\" header found in request", TB_CFG_SEC_TB_HDR_NAME);
		return 0;
	}

	tb_debug(r, "Token Binding header found: %s=%s", TB_CFG_SEC_TB_HDR_NAME,
			header);

	size_t maxlen = strlen(header);
	*message = apr_pcalloc(r->pool, maxlen);
	*message_len = WebSafeBase64Unescape(header, *message, maxlen);

	tb_clean_header(r, TB_CFG_SEC_TB_HDR_NAME);

	if (*message_len == 0) {
		tb_error(r, "could not base64url decode Token Binding header");
		return 0;
	}

	return 1;
}

static void tb_draft_campbell_tokbind_tls_term(request_rec *r,
		tb_server_config *cfg, SSL* ssl, tbKeyType key_type, uint8_t *ekm,
		size_t ekm_len) {
	static const size_t kHeaderSize = 2;
	uint8_t* buf;
	size_t buf_len;

	int pass_var = tb_cfg_dir_get_pass_var(r);
	if (!(pass_var & TB_CFG_PASS_VAR_CONTEXT))
		return;

	if (key_type >= TB_INVALID_KEY_TYPE) {
		tb_error(r, "key_type is invalid");
		return;
	}

	buf_len = kHeaderSize + ekm_len + 1;
	buf = apr_pcalloc(r->pool, buf_len * sizeof(uint8_t));
	if (buf == NULL) {
		tb_error(r, "could not allocate memory for buf");
		return;
	}

	getNegotiatedVersion(ssl, buf);
	buf[kHeaderSize] = key_type;
	memcpy(buf + kHeaderSize + 1, ekm, ekm_len);

	tb_set_var(r, tb_cfg_get_context_env_var(cfg), TB_CFG_TB_CONTEXT_HDR_NAME,
			buf, buf_len);
}

static void tb_draft_ietf_tokbind_ttrp(request_rec *r, tb_server_config *cfg,
		uint8_t* out_tokbind_id, size_t out_tokbind_id_len,
		uint8_t* referred_tokbind_id, size_t referred_tokbind_id_len) {

	int pass_var = tb_cfg_dir_get_pass_var(r);

	if ((out_tokbind_id != NULL) && (out_tokbind_id_len > 0)) {
		if (pass_var & TB_CFG_PASS_VAR_PROVIDED)
			tb_set_var(r, tb_cfg_get_provided_env_var(cfg),
					TB_CFG_PROVIDED_TBID_HDR_NAME, out_tokbind_id, out_tokbind_id_len);
	} else
		tb_debug(r, "no provided token binding ID found");

	if ((referred_tokbind_id != NULL) && (referred_tokbind_id_len > 0)) {
		if (pass_var & TB_CFG_PASS_VAR_REFERRED)
			tb_set_var(r, tb_cfg_get_referred_env_var(cfg),
					TB_CFG_REFERRED_TBID_HDR_NAME, referred_tokbind_id,
					referred_tokbind_id_len);
	} else
		tb_debug(r, "no referred token binding ID found");
}

static int tb_post_read_request(request_rec *r) {

	tb_server_config *cfg = (tb_server_config*) ap_get_module_config(
			r->server->module_config, &token_binding_module);
	tb_conn_config *conn_cfg = tb_get_conn_config(r->connection);
	char *message = NULL;
	size_t message_len;

	tb_debug(r, "enter");

	tb_clean_header(r, TB_CFG_TB_CONTEXT_HDR_NAME);
	tb_clean_header(r, TB_CFG_PROVIDED_TBID_HDR_NAME);
	tb_clean_header(r, TB_CFG_REFERRED_TBID_HDR_NAME);

	if (tb_is_enabled(r, cfg, conn_cfg) == 0) {
		tb_clean_header(r, TB_CFG_SEC_TB_HDR_NAME);
		return DECLINED;
	}

	if (tb_get_decoded_header(r, cfg, &message, &message_len) == 0)
		return HTTP_UNAUTHORIZED;

	uint8_t* out_tokbind_id = NULL;
	size_t out_tokbind_id_len = -1;
	uint8_t* referred_tokbind_id = NULL;
	size_t referred_tokbind_id_len = -1;

	if (tbCacheMessageAlreadyVerified(cfg->cache, (uint8_t*) message,
			message_len, &out_tokbind_id, &out_tokbind_id_len,
			&referred_tokbind_id, &referred_tokbind_id_len)) {
		tb_debug(r, "tbCacheMessageAlreadyVerified returned true");
		tb_draft_ietf_tokbind_ttrp(r, cfg, out_tokbind_id, out_tokbind_id_len,
				referred_tokbind_id, referred_tokbind_id_len);
		return DECLINED;
	}

	uint8_t ekm[TB_HASH_LEN];
	if (!tbGetEKM(conn_cfg->ssl, ekm)) {
		tb_warn(r, "unable to get EKM from TLS connection");
		return DECLINED;
	}

	if (!tbCacheVerifyTokenBindingMessage(cfg->cache, (uint8_t*) message,
			message_len, conn_cfg->tls_key_type, ekm, &out_tokbind_id,
			&out_tokbind_id_len, &referred_tokbind_id,
			&referred_tokbind_id_len)) {
		tb_error(r,
				"tbCacheVerifyTokenBindingMessage returned false: bad Token Binding header");
		return DECLINED;
	}

	u_int8_t buf[2] = { 0, 0 };
	getNegotiatedVersion(conn_cfg->ssl, buf);
	tb_debug(r,
			"verified Token Binding header (negotiated Token Binding version: %d.%d)",
			buf[0], buf[1]);

	tb_draft_ietf_tokbind_ttrp(r, cfg, out_tokbind_id, out_tokbind_id_len,
			referred_tokbind_id, referred_tokbind_id_len);
	tb_draft_campbell_tokbind_tls_term(r, cfg, conn_cfg->ssl,
			conn_cfg->tls_key_type, ekm,
			TB_HASH_LEN);

	return DECLINED;
}

void *tb_create_dir_config(apr_pool_t *pool, char *path) {
	tb_dir_config *c = apr_pcalloc(pool, sizeof(tb_dir_config));
	c->pass_var = TB_CFG_POS_INT_UNSET;
	return c;
}

void *tb_merge_dir_config(apr_pool_t *pool, void *BASE, void *ADD) {
	tb_dir_config *c = apr_pcalloc(pool, sizeof(tb_dir_config));
	tb_dir_config *base = BASE;
	tb_dir_config *add = ADD;
	c->pass_var =
			add->pass_var != TB_CFG_POS_INT_UNSET ?
					add->pass_var : base->pass_var;
	return c;
}

void *tb_create_server_config(apr_pool_t *pool, server_rec *svr) {
	tb_server_config *c = apr_pcalloc(pool, sizeof(tb_server_config));
	c->enabled = TB_CFG_POS_INT_UNSET;

	uint64_t rand_seed = 0;
	RAND_seed(&rand_seed, sizeof(uint64_t));
	tbCacheLibInit(rand_seed);

	c->cache = tbCacheCreate();
	c->provided_env_var = NULL;
	c->referred_env_var = NULL;
	c->context_env_var = NULL;
	return c;
}

void *tb_merge_server_config(apr_pool_t *pool, void *BASE, void *ADD) {
	tb_server_config *c = apr_pcalloc(pool, sizeof(tb_server_config));
	tb_server_config *base = BASE;
	tb_server_config *add = ADD;
	c->enabled =
			add->enabled != TB_CFG_POS_INT_UNSET ? add->enabled : base->enabled;
	c->cache = add->cache;
	c->provided_env_var =
			add->provided_env_var != NULL ?
					add->provided_env_var : base->provided_env_var;
	c->referred_env_var =
			add->referred_env_var != NULL ?
					add->referred_env_var : base->referred_env_var;
	c->context_env_var =
			add->context_env_var != NULL ?
					add->context_env_var : base->context_env_var;
	return c;
}

static apr_status_t tb_cleanup_handler(void *data) {
	server_rec *s = (server_rec *) data;
	tb_sinfo(s, "%s - shutdown", NAMEVERSION);
	return APR_SUCCESS;
}

static int tb_post_config_handler(apr_pool_t *pool, apr_pool_t *p1,
		apr_pool_t *p2, server_rec *s) {
	tb_sinfo(s, "%s - init - token_bind %d.%d (>=%d.%d)", NAMEVERSION,
			TB_MAJOR_VERSION, TB_MINOR_VERSION, TB_MIN_SUPPORTED_MAJOR_VERSION,
			TB_MIN_SUPPORTED_MINOR_VERSION);
	apr_pool_cleanup_register(pool, s, tb_cleanup_handler,
			apr_pool_cleanup_null);
	return OK;
}

static void tb_retrieve_optional_fn() {
	ssl_is_https_fn = APR_RETRIEVE_OPTIONAL_FN(ssl_is_https);
}

static void tb_register_hooks(apr_pool_t *p) {
	ap_hook_post_config(tb_post_config_handler, NULL, NULL, APR_HOOK_LAST);
	ap_hook_post_read_request(tb_post_read_request, NULL, NULL, APR_HOOK_LAST);
	ap_hook_optional_fn_retrieve(tb_retrieve_optional_fn, NULL, NULL,
			APR_HOOK_MIDDLE);
	APR_OPTIONAL_HOOK(ssl, init_server, tb_ssl_init_server, NULL, NULL,
			APR_HOOK_MIDDLE);
	APR_OPTIONAL_HOOK(ssl, pre_handshake, tb_ssl_pre_handshake, NULL, NULL,
			APR_HOOK_MIDDLE);
}

static const command_rec tb_cmds[] = {
		AP_INIT_TAKE1(
			"TokenBindingEnabled",
			tb_cfg_set_enabled,
			NULL,
			RSRC_CONF,
			"enable or disable mod_token_binding. (default: On)"),
		AP_INIT_TAKE1(
			"TokenBindingProvidedEnvVar",
			tb_cfg_set_provided_env_var,
			NULL,
			RSRC_CONF,
			"set the environment variable name in which the Provided Token Binding ID will be passed. (default: " TB_CFG_PROVIDED_ENV_VAR_DEFAULT ")"),
		AP_INIT_TAKE1(
			"TokenBindingReferredEnvVar",
			tb_cfg_set_referred_env_var,
			NULL,
			RSRC_CONF,
			"set the environment variable name in which the Referred Token Binding ID will be passed. (default: " TB_CFG_REFERRED_ENV_VAR_DEFAULT ")"),
		AP_INIT_TAKE1(
			"TokenBindingContextEnvVar",
			tb_cfg_set_context_env_var,
			NULL,
			RSRC_CONF,
			"set the environment variable name in which the Token Binding Context re. draft_campbell_tokbind_tls_term will be passed. (default: " TB_CFG_CONTEXT_ENV_VAR_DEFAULT ")"),
		AP_INIT_ITERATE(
			"TokenBindingPassVar",
			tb_cfg_set_pass_var,
			NULL,
			RSRC_CONF|ACCESS_CONF|OR_AUTHCFG,
			"The variables that will be passed as headers/environment-vars; must be one or more of: provided | referred | context]. (default is all)"),
		{ NULL }
};

module AP_MODULE_DECLARE_DATA token_binding_module = {
		STANDARD20_MODULE_STUFF,
		tb_create_dir_config,
		tb_merge_dir_config,
		tb_create_server_config,
		tb_merge_server_config,
		tb_cmds,
		tb_register_hooks
};
