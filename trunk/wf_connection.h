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

#ifndef WF_CONNECTION_H
#define WF_CONNECTION_H

#include "pidgin-wordfeud.h"
#include <core.h>
#include <zlib.h>

/*
 * This is a bitmask.
 */
typedef enum
{
	WF_METHOD_GET  = 0x0001,
	WF_METHOD_POST = 0x0002,
	WF_METHOD_SSL  = 0x0004
} WordfeudMethod;

typedef void (*WordfeudProxyCallbackFunc)(WordfeudAccount *wfa, const gchar *status, JsonObject *content, gpointer user_data);

typedef struct _WordfeudConnection WordfeudConnection;
struct _WordfeudConnection {
	WordfeudAccount *wfa;
	WordfeudMethod method;
	gchar *hostname;
	GString *request;
	WordfeudProxyCallbackFunc callback;
	gpointer user_data;
	char *rx_buf;
	size_t rx_len;
	PurpleProxyConnectData *connect_data;
	PurpleSslConnection *ssl_conn;
	int fd;
	guint input_watcher;
	gboolean connection_keepalive;
	time_t request_time;
};

void wf_connection_destroy(WordfeudConnection *wfcconn);
void wf_post_or_get(WordfeudAccount *wfa, WordfeudMethod method,
		const gchar *host, const gchar *url, JsonObject *postdata,
		WordfeudProxyCallbackFunc callback_func, gpointer user_data,
		gboolean keepalive);

#endif /* WF_CONNECTION_H */
