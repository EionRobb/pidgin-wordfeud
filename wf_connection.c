/*
 * pidgin-wordfeud
 *
 * pidgin-wordfeud is the property of its developers.  See the COPYRIGHT file
 * for more details.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "wf_connection.h"

#if !GLIB_CHECK_VERSION (2, 22, 0)
#define g_hostname_is_ip_address(hostname) (g_ascii_isdigit(hostname[0]) && g_strstr_len(hostname, 4, "."))
#endif

static void wf_attempt_connection(WordfeudConnection *);
static void wf_next_connection(WordfeudAccount *wfa);

static gchar *wf_gunzip(const guchar *gzip_data, ssize_t *len_ptr)
{
	gsize gzip_data_len	= *len_ptr;
	z_stream zstr;
	int gzip_err = 0;
	gchar *data_buffer;
	gulong gzip_len = G_MAXUINT16;
	GString *output_string = NULL;

	data_buffer = g_new0(gchar, gzip_len);

	zstr.next_in = NULL;
	zstr.avail_in = 0;
	zstr.zalloc = Z_NULL;
	zstr.zfree = Z_NULL;
	zstr.opaque = 0;
	gzip_err = inflateInit2(&zstr, MAX_WBITS+32);
	if (gzip_err != Z_OK)
	{
		g_free(data_buffer);
		purple_debug_error("wordfeud", "no built-in gzip support in zlib\n");
		return NULL;
	}
	
	zstr.next_in = (Bytef *)gzip_data;
	zstr.avail_in = gzip_data_len;
	
	zstr.next_out = (Bytef *)data_buffer;
	zstr.avail_out = gzip_len;
	
	gzip_err = inflate(&zstr, Z_SYNC_FLUSH);

	if (gzip_err == Z_DATA_ERROR)
	{
		inflateEnd(&zstr);
		inflateInit2(&zstr, -MAX_WBITS);
		if (gzip_err != Z_OK)
		{
			g_free(data_buffer);
			purple_debug_error("wordfeud", "Cannot decode gzip header\n");
			return NULL;
		}
		zstr.next_in = (Bytef *)gzip_data;
		zstr.avail_in = gzip_data_len;
		zstr.next_out = (Bytef *)data_buffer;
		zstr.avail_out = gzip_len;
		gzip_err = inflate(&zstr, Z_SYNC_FLUSH);
	}
	output_string = g_string_new("");
	while (gzip_err == Z_OK)
	{
		//append data to buffer
		output_string = g_string_append_len(output_string, data_buffer, gzip_len - zstr.avail_out);
		//reset buffer pointer
		zstr.next_out = (Bytef *)data_buffer;
		zstr.avail_out = gzip_len;
		gzip_err = inflate(&zstr, Z_SYNC_FLUSH);
	}
	if (gzip_err == Z_STREAM_END)
	{
		output_string = g_string_append_len(output_string, data_buffer, gzip_len - zstr.avail_out);
	} else {
		purple_debug_error("wordfeud", "gzip inflate error\n");
	}
	inflateEnd(&zstr);

	g_free(data_buffer);	

	gchar *output_data = g_strdup(output_string->str);
	*len_ptr = output_string->len;

	g_string_free(output_string, TRUE);

	return output_data;
}

void wf_connection_destroy(WordfeudConnection *wfconn)
{
	wfconn->wfa->conns = g_slist_remove(wfconn->wfa->conns, wfconn);

	if (wfconn->request != NULL)
		g_string_free(wfconn->request, TRUE);

	g_free(wfconn->rx_buf);

	if (wfconn->connect_data != NULL)
		purple_proxy_connect_cancel(wfconn->connect_data);

	if (wfconn->ssl_conn != NULL)
		purple_ssl_close(wfconn->ssl_conn);

	if (wfconn->fd >= 0) {
		close(wfconn->fd);
	}

	if (wfconn->input_watcher > 0)
		purple_input_remove(wfconn->input_watcher);

	g_free(wfconn->hostname);
	g_free(wfconn);
}

static void wf_update_cookies(WordfeudAccount *wfa, const gchar *headers)
{
	const gchar *cookie_start;
	const gchar *cookie_end;
	gchar *cookie_name;
	gchar *cookie_value;
	int header_len;

	g_return_if_fail(headers != NULL);

	header_len = strlen(headers);

	/* look for the next "Set-Cookie: " */
	/* grab the data up until ';' */
	cookie_start = headers;
	while ((cookie_start = strstr(cookie_start, "\r\nSet-Cookie: ")) &&
			(headers-cookie_start) < header_len)
	{
		cookie_start += 14;
		cookie_end = strchr(cookie_start, '=');
		cookie_name = g_strndup(cookie_start, cookie_end-cookie_start);
		cookie_start = cookie_end + 1;
		cookie_end = strchr(cookie_start, ';');
		cookie_value= g_strndup(cookie_start, cookie_end-cookie_start);
		cookie_start = cookie_end;

		purple_debug_info("wordfeud", "got cookie %s=%s\n",
				cookie_name, cookie_value);

		g_hash_table_replace(wfa->cookie_table, cookie_name,
				cookie_value);
	}
}

static void wf_connection_process_data(WordfeudConnection *wfconn)
{
	ssize_t len;
	gchar *tmp;

	len = wfconn->rx_len;
	tmp = g_strstr_len(wfconn->rx_buf, len, "\r\n\r\n");
	if (tmp == NULL) {
		/* This is a corner case that occurs when the connection is
		 * prematurely closed either on the client or the server.
		 * This can either be no data at all or a partial set of
		 * headers.  We pass along the data to be good, but don't
		 * do any fancy massaging.  In all likelihood the result will
		 * be tossed by the connection callback func anyways
		 */
		tmp = g_strndup(wfconn->rx_buf, len);
	} else {
		tmp += 4;
		len -= g_strstr_len(wfconn->rx_buf, len, "\r\n\r\n") -
				wfconn->rx_buf + 4;
		tmp = g_memdup(tmp, len + 1);
		tmp[len] = '\0';
		wfconn->rx_buf[wfconn->rx_len - len] = '\0';
		//purple_debug_misc("wordfeud", "response headers\n%s\n",
		//		wfconn->rx_buf);
		wf_update_cookies(wfconn->wfa, wfconn->rx_buf);
		
		if (strstr(wfconn->rx_buf, "Content-Encoding: gzip"))
		{
			/* we've received compressed gzip data, decompress */
			gchar *gunzipped;
			gunzipped = wf_gunzip((const guchar *)tmp, &len);
			g_free(tmp);
			tmp = gunzipped;
		}
	}

	g_free(wfconn->rx_buf);
	wfconn->rx_buf = NULL;

	if (wfconn->callback != NULL)
	{
		if (!len)
		{
			purple_debug_error("wordfeud", "No data in response\n");
		} else {
			JsonParser *parser = json_parser_new();
			if (!json_parser_load_from_data(parser, tmp, len, NULL))
			{
				purple_debug_error("wordfeud", "Error parsing response: %s\n", tmp);
			} else {
				JsonNode *root = json_parser_get_root(parser);
				JsonObject *jsonobj = json_node_get_object(root);
				const gchar *status = json_object_get_string_member(jsonobj, "status");
				JsonObject *content = json_object_get_object_member(jsonobj, "content");
				
				purple_debug_info("wordfeud", "Got response: %s\n", tmp);
				wfconn->callback(wfconn->wfa, status, content, wfconn->user_data);
				//json_node_free(root);
			}
			//g_object_unref(parser);
		}
	}

	g_free(tmp);
}

static void wf_fatal_connection_cb(WordfeudConnection *wfconn)
{
	PurpleConnection *pc = wfconn->wfa->pc;

	purple_debug_error("wordfeud", "fatal connection error\n");

	wf_connection_destroy(wfconn);

	/* We died.  Do not pass Go.  Do not collect $200 */
	/* In all seriousness, don't attempt to call the normal callback here.
	 * That may lead to the wrong error message being displayed */
	purple_connection_error_reason(pc,
				PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
				_("Server closed the connection."));

}

static void wf_post_or_get_readdata_cb(gpointer data, gint source,
		PurpleInputCondition cond)
{
	WordfeudAccount *wfa;
	WordfeudConnection *wfconn;
	gchar buf[4096];
	ssize_t len;

	wfconn = data;
	wfa = wfconn->wfa;

	if (wfconn->method & WF_METHOD_SSL) {
		len = purple_ssl_read(wfconn->ssl_conn,
				buf, sizeof(buf) - 1);
	} else {
		len = recv(wfconn->fd, buf, sizeof(buf) - 1, 0);
	}

	if (len < 0)
	{
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
			/* Try again later */
			return;
		}

		if (wfconn->method & WF_METHOD_SSL && wfconn->rx_len > 0) {
			/*
			 * This is a slightly hacky workaround for a bug in either
			 * GNU TLS or in the SSL implementation on Facebook's web
			 * servers.  The sequence of events is:
			 * 1. We attempt to read the first time and successfully read
			 *    the server's response.
			 * 2. We attempt to read a second time and libpurple's call
			 *    to gnutls_record_recv() returns the error
			 *    GNUTLS_E_UNEXPECTED_PACKET_LENGTH, or
			 *    "A TLS packet with unexpected length was received."
			 *
			 * Normally the server would have closed the connection
			 * cleanly and this second read() request would have returned
			 * 0.  Or maybe it's normal for SSL connections to be severed
			 * in this manner?  In any case, this differs from the behavior
			 * of the standard recv() system call.
			 */
			purple_debug_warning("wordfeud",
				"ssl error, but data received.  attempting to continue\n");
		} else {
			/* TODO: Is this a regular occurrence?  If so then maybe resend the request? */
			wf_fatal_connection_cb(wfconn);
			return;
		}
	}

	if (len > 0)
	{
		buf[len] = '\0';

		wfconn->rx_buf = g_realloc(wfconn->rx_buf,
				wfconn->rx_len + len + 1);
		memcpy(wfconn->rx_buf + wfconn->rx_len, buf, len + 1);
		wfconn->rx_len += len;

		/* Wait for more data before processing */
		return;
	}

	/* The server closed the connection, let's parse the data */
	wf_connection_process_data(wfconn);
	
	wf_connection_destroy(wfconn);

	wf_next_connection(wfa);
}

static void wf_post_or_get_ssl_readdata_cb (gpointer data,
		PurpleSslConnection *ssl, PurpleInputCondition cond)
{
	wf_post_or_get_readdata_cb(data, -1, cond);
}

static void wf_post_or_get_connect_cb(gpointer data, gint source,
		const gchar *error_message)
{
	WordfeudConnection *wfconn;
	ssize_t len;

	wfconn = data;
	wfconn->connect_data = NULL;

	if (error_message)
	{
		purple_debug_error("wordfeud", "post_or_get_connect_cb %s\n",
				error_message);
		wf_fatal_connection_cb(wfconn);
		return;
	}

	purple_debug_info("wordfeud", "post_or_get_connect_cb\n");
	wfconn->fd = source;

	/* TODO: Check the return value of write() */
	len = write(wfconn->fd, wfconn->request->str,
			wfconn->request->len);
	wfconn->input_watcher = purple_input_add(wfconn->fd,
			PURPLE_INPUT_READ,
			wf_post_or_get_readdata_cb, wfconn);
}

static void wf_post_or_get_ssl_connect_cb(gpointer data,
		PurpleSslConnection *ssl, PurpleInputCondition cond)
{
	WordfeudConnection *wfconn;
	ssize_t len;

	wfconn = data;

	purple_debug_info("wordfeud", "post_or_get_ssl_connect_cb\n");

	/* TODO: Check the return value of write() */
	len = purple_ssl_write(wfconn->ssl_conn,
			wfconn->request->str, wfconn->request->len);
	purple_ssl_input_add(wfconn->ssl_conn,
			wf_post_or_get_ssl_readdata_cb, wfconn);
}

static void wf_host_lookup_cb(GSList *hosts, gpointer data,
		const char *error_message)
{
	GSList *host_lookup_list;
	struct sockaddr_in *addr;
	gchar *hostname;
	gchar *ip_address;
	WordfeudAccount *wfa;
	PurpleDnsQueryData *query;

	purple_debug_info("wordfeud", "updating cache of dns addresses\n");

	/* Extract variables */
	host_lookup_list = data;

	wfa = host_lookup_list->data;
	host_lookup_list =
			g_slist_delete_link(host_lookup_list, host_lookup_list);
	hostname = host_lookup_list->data;
	host_lookup_list =
			g_slist_delete_link(host_lookup_list, host_lookup_list);
	query = host_lookup_list->data;
	host_lookup_list =
			g_slist_delete_link(host_lookup_list, host_lookup_list);

	/* The callback has executed, so we no longer need to keep track of
	 * the original query.  This always needs to run when the cb is 
	 * executed. */
	wfa->dns_queries = g_slist_remove(wfa->dns_queries, query);

	/* Any problems, capt'n? */
	if (error_message != NULL)
	{
		purple_debug_warning("wordfeud",
				"Error doing host lookup: %s\n", error_message);
		return;
	}

	if (hosts == NULL)
	{
		purple_debug_warning("wordfeud",
				"Could not resolve host name\n");
		return;
	}

	/* Discard the length... */
	hosts = g_slist_delete_link(hosts, hosts);
	/* Copy the address then free it... */
	addr = hosts->data;
	ip_address = g_strdup(inet_ntoa(addr->sin_addr));
	g_free(addr);
	hosts = g_slist_delete_link(hosts, hosts);

	/*
	 * DNS lookups can return a list of IP addresses, but we only cache
	 * the first one.  So free the rest.
	 */
	while (hosts != NULL)
	{
		/* Discard the length... */
		hosts = g_slist_delete_link(hosts, hosts);
		/* Free the address... */
		g_free(hosts->data);
		hosts = g_slist_delete_link(hosts, hosts);
	}

	purple_debug_info("wordfeud", "Host %s has IP %s\n",
			hostname, ip_address);

	g_hash_table_insert(wfa->hostname_ip_cache, hostname, ip_address);
}

static void wf_cookie_foreach_cb(gchar *cookie_name,
		gchar *cookie_value, GString *str)
{
	/* TODO: Need to escape name and value? */
	g_string_append_printf(str, "%s=%s;", cookie_name, cookie_value);
}

static gchar *wf_cookies_to_string(WordfeudAccount *wfa)
{
	GString *str;

	str = g_string_new(NULL);

	g_hash_table_foreach(wfa->cookie_table,
			(GHFunc)wf_cookie_foreach_cb, str);

	return g_string_free(str, FALSE);
}

static void wf_ssl_connection_error(PurpleSslConnection *ssl,
		PurpleSslErrorType errortype, gpointer data)
{
	WordfeudConnection *wfconn = data;
	PurpleConnection *pc = wfconn->wfa->pc;

	wfconn->ssl_conn = NULL;
	wf_connection_destroy(wfconn);
	purple_connection_ssl_error(pc, errortype);
}

void wf_post_or_get(WordfeudAccount *wfa, WordfeudMethod method,
		const gchar *host, const gchar *url, JsonObject *postdata,
		WordfeudProxyCallbackFunc callback_func, gpointer user_data,
		gboolean keepalive)
{
	GString *request;
	gchar *cookies;
	WordfeudConnection *wfconn;
	gchar *real_url;
	gboolean is_proxy = FALSE;
	const gchar* const *languages;
	gchar *language_names;
	PurpleProxyInfo *proxy_info = NULL;
	gchar *proxy_auth;
	gchar *proxy_auth_base64;
	gchar *postdata_str;

	/* TODO: Fix keepalive and use it as much as possible */
	keepalive = FALSE;

	if (host == NULL && wfa && wfa->account)
		host = purple_account_get_string(wfa->account, "host", "game00.wordfeud.com");
	if (host == NULL)
		host = "game00.wordfeud.com";

	if (wfa && wfa->account && !(method & WF_METHOD_SSL))
	{
		proxy_info = purple_proxy_get_setup(wfa->account);
		if (purple_proxy_info_get_type(proxy_info) == PURPLE_PROXY_USE_GLOBAL)
			proxy_info = purple_global_proxy_get_info();
		if (purple_proxy_info_get_type(proxy_info) == PURPLE_PROXY_HTTP)
		{
			is_proxy = TRUE;
		}	
	}
	if (is_proxy == TRUE)
	{
		real_url = g_strdup_printf("http://%s%s", host, url);
	} else {
		real_url = g_strdup(url);
	}
	
	cookies = wf_cookies_to_string(wfa);
	
	if (method & WF_METHOD_POST)
	{
		if (!postdata)
			postdata_str = "";
		else
		{
			JsonNode *root = json_node_new(JSON_NODE_OBJECT);
			json_node_set_object(root, postdata);
			
			JsonGenerator *generator = json_generator_new();
			json_generator_set_root(generator, root);
			postdata_str = json_generator_to_data(generator, NULL);
			json_node_free(root);
			g_object_unref(generator);
		}
	}
	
	/* Build the request */
	request = g_string_new(NULL);
	g_string_append_printf(request, "%s %s HTTP/1.0\r\n",
			(method & WF_METHOD_POST) ? "POST" : "GET",
			real_url);
	
	if (is_proxy == FALSE)
		g_string_append_printf(request, "Host: %s\r\n", host);
	g_string_append_printf(request, "User-Agent: WebFeudClient/ (Pidgin)\r\n");
	g_string_append_printf(request, "Connection: %s\r\n",
			(keepalive ? "Keep-Alive" : "close"));
	if (method & WF_METHOD_POST) {
		g_string_append_printf(request,
				"Content-Type: application/json\r\n");
		g_string_append_printf(request,
				"Content-length: %zu\r\n", strlen(postdata_str));
	}
	g_string_append_printf(request, "Accept: */*\r\n");
	g_string_append_printf(request, "Cookie: %s\r\n", cookies);
	//g_string_append_printf(request, "Accept-Encoding: gzip\r\n");
	
	if (is_proxy == TRUE)
	{
		if (purple_proxy_info_get_username(proxy_info) &&
			purple_proxy_info_get_password(proxy_info))
		{
			proxy_auth = g_strdup_printf("%s:%s", purple_proxy_info_get_username(proxy_info), purple_proxy_info_get_password(proxy_info));
			proxy_auth_base64 = purple_base64_encode((guchar *)proxy_auth, strlen(proxy_auth));
			g_string_append_printf(request, "Proxy-Authorization: Basic %s\r\n", proxy_auth_base64);
			g_free(proxy_auth_base64);
			g_free(proxy_auth);
		}
	}
	/* Tell the server what language we accept, so that we get error messages in our language (rather than our IP's) */
	languages = g_get_language_names();
	language_names = g_strjoinv(", ", (gchar **)languages);
	purple_util_chrreplace(language_names, '_', '-');
	g_string_append_printf(request, "Accept-Language: %s\r\n", language_names);
	g_free(language_names);

	purple_debug_misc("wordfeud", "requesting url %s\n", url);

	g_string_append_printf(request, "\r\n");
	if (method & WF_METHOD_POST)
		g_string_append_printf(request, "%s", postdata_str);

	/* If it needs to go over a SSL connection, we probably shouldn't print
	 * it in the debug log.  Without this condition a user's password is
	 * printed in the debug log */
	if (method == WF_METHOD_POST)
	{
		purple_debug_misc("wordfeud", "sending request data:\n%s\n",
			postdata_str);
		g_free(postdata_str);
	}
	
	g_free(cookies);
	g_free(real_url);
	/*
	 * Do a separate DNS lookup for the given host name and cache it
	 * for next time.
	 *
	 * TODO: It would be better if we did this before we call
	 *       purple_proxy_connect(), so we could re-use the result.
	 *       Or even better: Use persistent HTTP connections for servers
	 *       that we access continually.
	 *
	 * TODO: This cache of the hostname<-->IP address does not respect
	 *       the TTL returned by the DNS server.  We should expire things
	 *       from the cache after some amount of time.
	 */
	if (!is_proxy && !g_hostname_is_ip_address(host) && !(method & WF_METHOD_SSL))
	{
		/* Don't do this for proxy connections, since proxies do the DNS lookup */
		gchar *host_ip;

		host_ip = g_hash_table_lookup(wfa->hostname_ip_cache, host);
		if (host_ip != NULL) {
			purple_debug_info("wordfeud",
					"swapping original host %s with cached value of %s\n",
					host, host_ip);
			host = host_ip;
		} else if (wfa->account && !wfa->account->disconnecting) {
			GSList *host_lookup_list = NULL;
			PurpleDnsQueryData *query;

			host_lookup_list = g_slist_prepend(
					host_lookup_list, g_strdup(host));
			host_lookup_list = g_slist_prepend(
					host_lookup_list, wfa);

			query = purple_dnsquery_a(host, 80,
					wf_host_lookup_cb, host_lookup_list);
			wfa->dns_queries = g_slist_prepend(wfa->dns_queries, query);
			host_lookup_list = g_slist_append(host_lookup_list, query);
		}
	}

	wfconn = g_new0(WordfeudConnection, 1);
	wfconn->wfa = wfa;
	wfconn->method = method;
	wfconn->hostname = g_strdup(host);
	wfconn->request = request;
	wfconn->callback = callback_func;
	wfconn->user_data = user_data;
	wfconn->fd = -1;
	wfconn->connection_keepalive = keepalive;
	wfconn->request_time = time(NULL);

	g_queue_push_head(wfa->waiting_conns, wfconn);
	wf_next_connection(wfa);
}

static void wf_next_connection(WordfeudAccount *wfa)
{
	WordfeudConnection *wfconn;

	g_return_if_fail(wfa != NULL);	

	if (!g_queue_is_empty(wfa->waiting_conns))
	{
		if(g_slist_length(wfa->conns) < WF_MAX_CONNECTIONS)
		{
			wfconn = g_queue_pop_tail(wfa->waiting_conns);
			wf_attempt_connection(wfconn);
		}
	}
}

static void wf_attempt_connection(WordfeudConnection *wfconn)
{
	WordfeudAccount *wfa = wfconn->wfa;

	wfa->conns = g_slist_prepend(wfa->conns, wfconn);

	if (wfconn->method & WF_METHOD_SSL) {
		wfconn->ssl_conn = purple_ssl_connect(wfa->account, wfconn->hostname,
				443, wf_post_or_get_ssl_connect_cb,
				wf_ssl_connection_error, wfconn);
	} else {
		wfconn->connect_data = purple_proxy_connect(NULL, wfa->account,
				wfconn->hostname, 80, wf_post_or_get_connect_cb, wfconn);
	}

	return;
}

