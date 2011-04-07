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
 
#include "pidgin-wordfeud.h"
#include "wf_connection.h"

static void wf_chat_history_cb(WordfeudAccount *wfa, const gchar *status, JsonObject *content, gpointer user_data)
{
	gint game_id = GPOINTER_TO_INT(user_data);
	JsonArray *messages = json_object_get_array_member(content, "messages");
	guint messages_length = json_array_get_length(messages);
	guint i;
	for(i = 0; i < messages_length; i++)
	{
		JsonObject *message = json_array_get_object_element(messages, i);
		const gchar *message_str = json_object_get_string_member(message, "message");
		gint sender = (gint) json_object_get_int_member(message, "sender");
		gchar *sender_str = g_strdup_printf("%d", sender);
		gdouble sent = json_object_get_double_member(message, "sent");
		time_t senttime = (time_t) sent;
		
		serv_got_chat_in(wfa->pc, game_id, sender_str, PURPLE_MESSAGE_RECV, message_str, senttime);
		
		g_free(sender_str);
	}
}

static void wf_get_chat_history(WordfeudAccount *wfa, gint game_id)
{
	gchar *url = g_strdup_printf("/wf/game/%d/chat/", game_id);
	wf_post_or_get(wfa, WF_METHOD_POST, NULL, url, NULL, wf_chat_history_cb, GINT_TO_POINTER(game_id), FALSE);
	g_free(url);
}

/******************************************************************************/
/* PRPL functions */
/******************************************************************************/

static const char *wf_list_icon(PurpleAccount *account, PurpleBuddy *buddy)
{
	return "wordfeud";
}

static GList *wf_statuses(PurpleAccount *account)
{
	GList *types = NULL;
	PurpleStatusType *status;
	
	status = purple_status_type_new_full(PURPLE_STATUS_AVAILABLE, NULL, NULL, TRUE, TRUE, FALSE);
	types = g_list_append(types, status);

	status = purple_status_type_new_full(PURPLE_STATUS_OFFLINE, NULL, NULL, TRUE, TRUE, FALSE);
	types = g_list_append(types, status);

	return types;
}

static void wf_games_cb(WordfeudAccount *wfa, const gchar *status, JsonObject *content, gpointer user_data)
{
	purple_debug_info("wordfeud", "games_cb\n");
	
	JsonArray *games = json_object_get_array_member(content, "games");
	guint games_length = json_array_get_length(games);
	guint i;
	for(i = 0; i < games_length; i++)
	{
		JsonObject *game = json_array_get_object_element(games, i);
		gint game_id = (gint) json_object_get_int_member(game, "id");
		
		const gchar *other_player = " ";
		JsonArray *players = json_object_get_array_member(game, "players");
		guint players_length = json_array_get_length(players);
		guint j;
		for(j = 0; j < players_length; j++)
		{
			JsonObject *player = json_array_get_object_element(players, j);
			gint player_id = (gint) json_object_get_int_member(player, "id");
			purple_debug_info("wordfeud", "Found user %d\n", player_id);
			if(player_id != purple_account_get_int(wfa->account, "wordfeudid", 0))
			{
				other_player = json_object_get_string_member(player, "username");
				purple_debug_info("wordfeud", "Other user %s\n", other_player);
				break;
			}
		}
		
		purple_debug_info("wordfeud", "New game: %d %s\n", game_id, other_player);
		
		gchar *game_id_str = g_strdup_printf("%d", game_id);
		/*GHashTable *components = g_hash_table_new(g_str_hash, g_str_equal);
		g_hash_table_insert(components, "game_id", game_id_str);
		PurpleChat *chat = purple_chat_new(wfa->account, other_player, components);
		g_free(game_id_str);
		
		purple_blist_add_chat(chat, purple_find_group("Wordfeud"), NULL);*/
		
		serv_got_joined_chat(wfa->pc, game_id, game_id_str);
	}
}

static void wf_friends_cb(WordfeudAccount *wfa, const gchar *status, JsonObject *content, gpointer user_data)
{
	purple_debug_info("wordfeud", "friends_cb\n");
	
	JsonArray *relationships = json_object_get_array_member(content, "relationships");
	guint rel_length = json_array_get_length(relationships);
	guint i;
	for(i = 0; i < rel_length; i++)
	{
		JsonObject *friend = json_array_get_object_element(relationships, i);
		gint user_id = (gint) json_object_get_int_member(friend, "user_id");
		const gchar *username = json_object_get_string_member(friend, "username");
		purple_debug_info("wordfeud", "New friend: %d %s\n", user_id, username);
		
		gchar *user_id_str = g_strdup_printf("%d", user_id);
		PurpleBuddy *buddy = purple_buddy_new(wfa->account, user_id_str, username);
		g_free(user_id_str);
		purple_blist_add_buddy(buddy, NULL, purple_find_group("Wordfeud"), NULL);
	}
}

static void wf_notifications_cb(WordfeudAccount *wfa, const gchar *status, JsonObject *content, gpointer user_data)
{
	JsonArray *entries = json_object_get_array_member(content, "entries");
	guint entries_length = json_array_get_length(entries);
	guint i;
	for(i = 0; i < entries_length; i++)
	{
		JsonObject *entry = json_array_get_object_element(entries, i);
		const gchar *entry_type = json_object_get_string_member(entry, "type");
		if (g_str_equal(entry_type, "chat"))
		{
			const gchar *username = json_object_get_string_member(entry, "username");
			const gchar *game_id_str = json_object_get_string_member(entry, "game_id");
			guint game_id = atoi(game_id_str);
			const gchar *message = json_object_get_string_member(entry, "message");
	
			serv_got_chat_in(wfa->pc, game_id, username, PURPLE_MESSAGE_RECV, message, time(NULL));
		} else {
			purple_debug_warning("wordfeud", "Unknown notification type '%s'\n", entry_type);
		}
	}
}

static gboolean wf_notifications_timer(WordfeudAccount *wfa)
{
	wf_post_or_get(wfa, WF_METHOD_POST, NULL, "/wf/user/notifications/", NULL, wf_notifications_cb, NULL, FALSE);
	
	return TRUE; //repeat ad nauseum
}

static void wf_login_cb(WordfeudAccount *wfa, const gchar *status, JsonObject *content, gpointer user_data)
{
	purple_debug_info("wordfeud", "login_cb\n");

	purple_connection_update_progress(wfa->pc, _("Authenticating"), 2, 3);
	
	if (g_str_equal(status, "error"))
	{
		if (g_str_equal(json_object_get_string_member(content, "type"), "wrong_password"))
			purple_connection_error_reason(wfa->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED, "Bad password");
		else
			purple_connection_error_reason(wfa->pc, PURPLE_CONNECTION_ERROR_INVALID_USERNAME, "Bad username or password");
	} else {
		gint wordfeudid = (gint) json_object_get_int_member(content, "id");
		if (wordfeudid)
		{
			purple_debug_info("wordfeud", "New wordfeud user id: %d\n", wordfeudid);
			purple_account_set_int(wfa->account, "wordfeudid", wordfeudid);
		}
		const gchar *username = json_object_get_string_member(content, "username");
		if (username && *username)
			purple_account_set_username(wfa->account, username);
		
		if (!purple_find_group("Wordfeud"))
			purple_blist_add_group(purple_group_new("Wordfeud"), NULL);
		
		wf_post_or_get(wfa, WF_METHOD_POST, NULL, "/wf/user/games/", NULL, wf_games_cb, NULL, FALSE);
		wf_post_or_get(wfa, WF_METHOD_POST, NULL, "/wf/user/relationships/", NULL, wf_friends_cb, NULL, FALSE);
		
		
		wfa->notifications_timer = purple_timeout_add_seconds(20, (GSourceFunc)wf_notifications_timer, wfa);
		
		purple_connection_set_state(wfa->pc, PURPLE_CONNECTED);
	}
}

static void wf_login(PurpleAccount *account)
{
	WordfeudAccount *wfa;
	const gchar *url;
	gchar password[41];

	purple_debug_info("wordfeud", "login\n");

	/* Create account and initialize state */
	wfa = g_new0(WordfeudAccount, 1);
	wfa->account = account;
	wfa->pc = purple_account_get_connection(account);
	
	wfa->cookie_table = g_hash_table_new_full(g_str_hash, g_str_equal,
			g_free, g_free);
	wfa->hostname_ip_cache = g_hash_table_new_full(g_str_hash, g_str_equal,
			g_free, g_free);
	wfa->waiting_conns = g_queue_new();

	account->gc->proto_data = wfa;

	purple_connection_set_state(wfa->pc, PURPLE_CONNECTING);
	purple_connection_update_progress(wfa->pc, _("Connecting"), 1, 3);

	gint32 rand_host_num = g_random_int_range(0, 7);
	gchar *rand_host = g_strdup_printf("game0%d.wordfeud.com", rand_host_num);
	purple_account_set_string(account, "host", rand_host);
	g_free(rand_host);
	
	JsonObject *jsonobj = json_object_new();
	
	if (purple_account_get_int(account, "wordfeudid", 0))
	{
		url = "/wf/user/login/id/";
		json_object_set_int_member(jsonobj, "id", purple_account_get_int(account, "wordfeudid", 0));
	}
	else if (purple_email_is_valid(purple_account_get_username(account)))
	{
		url = "/wf/user/login/email/";
		json_object_set_string_member(jsonobj, "email", purple_account_get_username(account));
	}
	else
	{
		url = "/wf/user/login/";
		json_object_set_string_member(jsonobj, "username", purple_account_get_username(account));
	}
	
	PurpleCipher *cipher = purple_ciphers_find_cipher("sha1");
	PurpleCipherContext *context = purple_cipher_context_new(cipher, NULL);
	purple_cipher_context_append(context, (guchar *)purple_account_get_password(account), strlen(purple_account_get_password(account)));
	purple_cipher_context_append(context, (guchar *)"JarJarBinks9", 12);
	purple_cipher_context_digest_to_str(context, sizeof(password), password, NULL);
	purple_cipher_context_destroy(context);
	
	json_object_set_string_member(jsonobj, "password", password);
	
	wf_post_or_get(wfa, WF_METHOD_POST, NULL, url, jsonobj, wf_login_cb, NULL, FALSE);
	
	json_object_unref(jsonobj);
}

static void wf_close(PurpleConnection *pc)
{
	WordfeudAccount *wfa;

	purple_debug_info("wordfeud", "disconnecting account\n");

	wfa = pc->proto_data;

	if (wfa->notifications_timer)
		purple_timeout_remove(wfa->notifications_timer);

	purple_debug_info("wordfeud", "destroying %d waiting connections\n",
			g_queue_get_length(wfa->waiting_conns));

	while (!g_queue_is_empty(wfa->waiting_conns))
		wf_connection_destroy(g_queue_pop_tail(wfa->waiting_conns));
	g_queue_free(wfa->waiting_conns);

	purple_debug_info("wordfeud", "destroying %d incomplete connections\n",
			g_slist_length(wfa->conns));

	while (wfa->conns != NULL)
		wf_connection_destroy(wfa->conns->data);

	while (wfa->dns_queries != NULL) {
		PurpleDnsQueryData *dns_query = wfa->dns_queries->data;
		purple_debug_info("wordfeud", "canceling dns query for %s\n",
					purple_dnsquery_get_host(dns_query));
		wfa->dns_queries = g_slist_remove(wfa->dns_queries, dns_query);
		purple_dnsquery_destroy(dns_query);
	}

	g_hash_table_destroy(wfa->cookie_table);
	g_hash_table_destroy(wfa->hostname_ip_cache);
	
	g_free(wfa);
}

static void wf_add_buddy_cb(WordfeudAccount *wfa, const gchar *status, JsonObject *content, gpointer user_data)
{
	if (g_str_equal(status, "error"))
	{
		purple_blist_remove_buddy((PurpleBuddy *) user_data);
	}
}

void wf_add_buddy(PurpleConnection *pc, PurpleBuddy *buddy, PurpleGroup *group)
{
	WordfeudAccount *wfa;
	wfa = pc->proto_data;
	
	JsonObject *jsonobj = json_object_new();
	
	json_object_set_string_member(jsonobj, "username_or_email", buddy->name);
	json_object_set_int_member(jsonobj, "type", 0);
	
	wf_post_or_get(wfa, WF_METHOD_POST, NULL, "/wf/relationship/create/", jsonobj, wf_add_buddy_cb, buddy, FALSE);
	
	json_object_unref(jsonobj);
}

void wf_fake_group_buddy(PurpleConnection *pc, const char *who, const char *old_group, const char *new_group)
{
	/* Do nuffink, so that buddies aren't deleted! */
}

gchar *wf_get_chat_name(GHashTable *components)
{
	return g_hash_table_lookup(components, "game_id");
}

int wf_chat_send(PurpleConnection *pc, int id, const char *message, PurpleMessageFlags flags)
{
	WordfeudAccount *wfa;
	wfa = pc->proto_data;
	gchar *url = g_strdup_printf("/wf/game/%d/chat/send/", id);
	
	JsonObject *jsonobj = json_object_new();
	
	json_object_set_string_member(jsonobj, "message", message);
	
	wf_post_or_get(wfa, WF_METHOD_POST, NULL, url, jsonobj, NULL, NULL, FALSE);
	
	g_free(url);
	json_object_unref(jsonobj);
	
	serv_got_chat_in(wfa->pc, id, purple_account_get_username(wfa->account), PURPLE_MESSAGE_SEND,
					message, time(NULL));
	return 1;
}

GList *
wf_chat_info(PurpleConnection *gc)
{
	GList *m = NULL;
	struct proto_chat_entry *pce;

	pce = g_new0(struct proto_chat_entry, 1);
	pce->label = _("Game ID");
	pce->identifier = "game_id";
	pce->required = TRUE;
	m = g_list_append(m, pce);
	
	return m;
}

void
wf_join_chat(PurpleConnection *pc, GHashTable *data)
{
	gchar *game_id_str = g_hash_table_lookup(data, "game_id");
	gint game_id = atoi(game_id_str);
	serv_got_joined_chat(pc, game_id, game_id_str);
}

/******************************************************************************/
/* Plugin functions */
/******************************************************************************/

static gboolean plugin_load(PurplePlugin *plugin)
{
	return TRUE;
}

static gboolean plugin_unload(PurplePlugin *plugin)
{
	return TRUE;
}

static void plugin_init(PurplePlugin *plugin)
{
	PurpleAccountOption *option;
	PurplePluginInfo *info = plugin->info;
	PurplePluginProtocolInfo *prpl_info = info->extra_info;
}

static PurplePluginProtocolInfo prpl_info = {
	/* options */
	OPT_PROTO_MAIL_CHECK,

	NULL,                   /* user_splits */
	NULL,                   /* protocol_options */
	{"jpg", 0, 0, 60, 60, -1, PURPLE_ICON_SCALE_SEND}, /* icon_spec */
	wf_list_icon,           /* list_icon */
	NULL,                   /* list_emblems */
	NULL,                   /* status_text */
	NULL,                   /* tooltip_text */
	wf_statuses,            /* status_types */
	NULL,                   /* blist_node_menu */
	NULL,                   /* chat_info */
	NULL,                   /* chat_info_defaults */
	wf_login,               /* login */
	wf_close,               /* close */
	NULL,                   /* send_im */
	NULL,                   /* set_info */
	NULL,                   /* send_typing */
	NULL,                   /* get_info */
	NULL,                   /* set_status */
	NULL,                   /* set_idle */
	NULL,                   /* change_passwd */
	wf_add_buddy,           /* add_buddy */
	NULL,                   /* add_buddies */
	NULL,                   /* remove_buddy */
	NULL,                   /* remove_buddies */
	NULL,                   /* add_permit */
	NULL,                   /* add_deny */
	NULL,                   /* rem_permit */
	NULL,                   /* rem_deny */
	NULL,                   /* set_permit_deny */
	wf_join_chat,           /* join_chat */
	NULL,                   /* reject chat invite */
	wf_get_chat_name,       /* get_chat_name */
	NULL,                   /* chat_invite */
	NULL,                   /* chat_leave */
	NULL,                   /* chat_whisper */
	wf_chat_send,           /* chat_send */
	NULL,                   /* keepalive */
	NULL,                   /* register_user */
	NULL,                   /* get_cb_info */
	NULL,                   /* get_cb_away */
	NULL,                   /* alias_buddy */
	wf_fake_group_buddy,    /* group_buddy */
	NULL,                   /* rename_group */
	NULL,                   /* buddy_free */
	NULL,                   /* convo_closed */
	purple_normalize_nocase,/* normalize */
	NULL,                   /* set_buddy_icon */
	NULL,                   /* remove_group */
	NULL,                   /* get_cb_real_name */
	NULL,                   /* set_chat_topic */
	NULL,                   /* find_blist_chat */
	NULL,                   /* roomlist_get_list */
	NULL,                   /* roomlist_cancel */
	NULL,                   /* roomlist_expand_category */
	NULL,                   /* can_receive_file */
	NULL,                   /* send_file */
	NULL,                   /* new_xfer */
	NULL,                   /* offline_message */
	NULL,                   /* whiteboard_prpl_ops */
	NULL,                   /* send_raw */
	NULL,                   /* roomlist_room_serialize */
	NULL,                   /* unregister_user */
	NULL,                   /* send_attention */
	NULL,                   /* attention_types */
	sizeof(PurplePluginProtocolInfo), /* struct_size */
	NULL,                   /* get_account_text_table */
};

static PurplePluginInfo info = {
	PURPLE_PLUGIN_MAGIC,
	2, /* major_version */
	3, /* minor version */
	PURPLE_PLUGIN_PROTOCOL, /* type */
	NULL, /* ui_requirement */
	0, /* flags */
	NULL, /* dependencies */
	PURPLE_PRIORITY_DEFAULT, /* priority */
	"prpl-bigbrownchunx-wordfeud", /* id */
	"Wordfeud", /* name */
	"0.1", /* version */
	N_("Wordfeud Protocol Plugin"), /* summary */
	N_("Wordfeud Protocol Plugin"), /* description */
	"Eion Robb <eionrobb@gmail.com>", /* author */
	"", /* homepage */
	plugin_load, /* load */
	plugin_unload, /* unload */
	NULL, /* destroy */
	NULL, /* ui_info */
	&prpl_info, /* extra_info */
	NULL, /* prefs_info */
	NULL, /* actions */

	/* padding */
	NULL,
	NULL,
	NULL,
	NULL
};

PURPLE_INIT_PLUGIN(wordfeud, plugin_init, info);
