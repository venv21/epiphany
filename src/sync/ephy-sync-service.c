/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 *  Copyright © 2016 Gabriel Ivascu <ivascu.gabriel59@gmail.com>
 *
 *  This file is part of Epiphany.
 *
 *  Epiphany is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Epiphany is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Epiphany.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "config.h"
#include "ephy-sync-service.h"

#include "ephy-bookmark.h"
#include "ephy-bookmarks-manager.h"
#include "ephy-debug.h"
#include "ephy-embed-prefs.h"
#include "ephy-notification.h"
#include "ephy-settings.h"
#include "ephy-shell.h"
#include "ephy-sync-crypto.h"
#include "ephy-sync-secret.h"

#include <glib/gi18n.h>
#include <json-glib/json-glib.h>
#include <string.h>

#define MOZILLA_TOKEN_SERVER_URL  "https://token.services.mozilla.com/1.0/sync/1.5"
#define MOZILLA_FXA_SERVER_URL    "https://api.accounts.firefox.com/v1/"
#define EPHY_BOOKMARKS_COLLECTION "ephy-bookmarks"
#define SYNC_FREQUENCY            (15 * 60)        /* seconds */
#define CERTIFICATE_DURATION      (60 * 60 * 1000) /* milliseconds, limited to 24 hours */
#define ASSERTION_DURATION        (5 * 60)         /* seconds */

struct _EphySyncService {
  GObject      parent_instance;

  SoupSession *session;
  guint        source_id;

  char        *uid;
  char        *sessionToken;
  char        *keyFetchToken;
  char        *unwrapBKey;
  char        *kA;
  char        *kB;

  char        *user_email;
  double       sync_time;
  gint64       auth_at;

  gboolean     locked;
  char        *storage_endpoint;
  char        *storage_credentials_id;
  char        *storage_credentials_key;
  gint64       storage_credentials_expiry_time;
  GQueue      *storage_queue;

  char                     *certificate;
  EphySyncCryptoRSAKeyPair *keypair;
};

G_DEFINE_TYPE (EphySyncService, ephy_sync_service, G_TYPE_OBJECT);

enum {
  STORE_FINISHED,
  LOAD_FINISHED,
  LAST_SIGNAL
};

static guint signals[LAST_SIGNAL];

typedef struct {
  EphySyncService     *service;
  char                *endpoint;
  const char          *method;
  char                *request_body;
  double               modified_since;
  double               unmodified_since;
  SoupSessionCallback  callback;
  gpointer             user_data;
} StorageRequestAsyncData;

static void ephy_sync_service_send_next_storage_request (EphySyncService *self);

static StorageRequestAsyncData *
storage_server_request_async_data_new (EphySyncService     *service,
                                       char                *endpoint,
                                       const char          *method,
                                       char                *request_body,
                                       double               modified_since,
                                       double               unmodified_since,
                                       SoupSessionCallback  callback,
                                       gpointer             user_data)
{
  StorageRequestAsyncData *data;

  data = g_slice_new (StorageRequestAsyncData);
  data->service = g_object_ref (service);
  data->endpoint = g_strdup (endpoint);
  data->method = method;
  data->request_body = g_strdup (request_body);
  data->modified_since = modified_since;
  data->unmodified_since = unmodified_since;
  data->callback = callback;
  data->user_data = user_data;

  return data;
}

static void
storage_server_request_async_data_free (StorageRequestAsyncData *data)
{
  g_assert (data != NULL);

  g_object_unref (data->service);
  g_free (data->endpoint);
  g_free (data->request_body);
  g_slice_free (StorageRequestAsyncData, data);
}

static gboolean
ephy_sync_service_storage_credentials_is_expired (EphySyncService *self)
{
  g_return_val_if_fail (EPHY_IS_SYNC_SERVICE (self), TRUE);

  if (self->storage_credentials_id == NULL || self->storage_credentials_key == NULL)
    return TRUE;

  if (self->storage_credentials_expiry_time == 0)
    return TRUE;

  /* Consider a 60 seconds safety interval. */
  return self->storage_credentials_expiry_time < ephy_sync_utils_current_time_seconds () - 60;
}

static void
ephy_sync_service_fxa_hawk_post_async (EphySyncService     *self,
                                       const char          *endpoint,
                                       const char          *id,
                                       guint8              *key,
                                       gsize                key_length,
                                       char                *request_body,
                                       SoupSessionCallback  callback,
                                       gpointer             user_data)
{
  EphySyncCryptoHawkOptions *hoptions;
  EphySyncCryptoHawkHeader *hheader;
  SoupMessage *msg;
  char *url;
  const char *content_type = "application/json";

  g_return_if_fail (EPHY_IS_SYNC_SERVICE (self));
  g_return_if_fail (endpoint != NULL);
  g_return_if_fail (id != NULL);
  g_return_if_fail (key != NULL);
  g_return_if_fail (request_body != NULL);

  url = g_strdup_printf ("%s%s", MOZILLA_FXA_SERVER_URL, endpoint);
  msg = soup_message_new (SOUP_METHOD_POST, url);
  soup_message_set_request (msg, content_type, SOUP_MEMORY_COPY,
                            request_body, strlen (request_body));

  hoptions = ephy_sync_crypto_hawk_options_new (NULL, NULL, NULL, content_type,
                                                NULL, NULL, NULL, request_body, NULL);
  hheader = ephy_sync_crypto_compute_hawk_header (url, "POST", id, key, key_length, hoptions);
  soup_message_headers_append (msg->request_headers, "authorization", hheader->header);
  soup_message_headers_append (msg->request_headers, "content-type", content_type);
  soup_session_queue_message (self->session, msg, callback, user_data);

  g_free (url);
  ephy_sync_crypto_hawk_options_free (hoptions);
  ephy_sync_crypto_hawk_header_free (hheader);
}

static guint
ephy_sync_service_fxa_hawk_get_sync (EphySyncService  *self,
                                     const char       *endpoint,
                                     const char       *id,
                                     guint8           *key,
                                     gsize             key_length,
                                     JsonNode        **node)
{
  EphySyncCryptoHawkHeader *hheader;
  SoupMessage *msg;
  JsonParser *parser;
  char *url;
  guint retval;

  g_return_val_if_fail (EPHY_IS_SYNC_SERVICE (self), 0);
  g_return_val_if_fail (endpoint != NULL, 0);
  g_return_val_if_fail (id != NULL, 0);
  g_return_val_if_fail (key != NULL, 0);

  url = g_strdup_printf ("%s%s", MOZILLA_FXA_SERVER_URL, endpoint);
  msg = soup_message_new (SOUP_METHOD_GET, url);
  hheader = ephy_sync_crypto_compute_hawk_header (url, "GET", id, key, key_length, NULL);
  soup_message_headers_append (msg->request_headers, "authorization", hheader->header);
  soup_session_send_message (self->session, msg);

  if (node != NULL) {
    parser = json_parser_new ();
    json_parser_load_from_data (parser, msg->response_body->data, -1, NULL);
    *node = json_node_copy (json_parser_get_root (parser));
    g_object_unref (parser);
  }

  retval = msg->status_code;

  g_free (url);
  g_object_unref (msg);
  ephy_sync_crypto_hawk_header_free (hheader);

  return retval;
}

static gboolean
ephy_sync_service_certificate_is_valid (EphySyncService *self,
                                        const char      *certificate)
{
  JsonParser *parser;
  JsonObject *json;
  JsonObject *principal;
  SoupURI *uri;
  char **pieces;
  char *header;
  char *payload;
  char *uid_email = NULL;
  const char *alg;
  const char *email;
  gsize len;
  gboolean retval = FALSE;

  g_return_val_if_fail (EPHY_IS_SYNC_SERVICE (self), FALSE);
  g_return_val_if_fail (certificate != NULL, FALSE);

  /* Check if the certificate is something that we were expecting, i.e.
   * if the algorithm and email fields match the expected values. */

  uri = soup_uri_new (MOZILLA_FXA_SERVER_URL);
  pieces = g_strsplit (certificate, ".", 0);
  header = (char *)ephy_sync_crypto_base64_urlsafe_decode (pieces[0], &len, TRUE);
  payload = (char *)ephy_sync_crypto_base64_urlsafe_decode (pieces[1], &len, TRUE);

  parser = json_parser_new ();
  json_parser_load_from_data (parser, header, -1, NULL);
  json = json_node_get_object (json_parser_get_root (parser));
  alg = json_object_get_string_member (json, "alg");

  if (g_strcmp0 (alg, "RS256") != 0) {
    g_warning ("Expected algorithm RS256, found %s. Giving up.", alg);
    goto out;
  }

  json_parser_load_from_data (parser, payload, -1, NULL);
  json = json_node_get_object (json_parser_get_root (parser));
  principal = json_object_get_object_member (json, "principal");
  email = json_object_get_string_member (principal, "email");
  uid_email = g_strdup_printf ("%s@%s", self->uid, soup_uri_get_host (uri));

  if (g_strcmp0 (uid_email, email) != 0) {
    g_warning ("Expected email %s, found %s. Giving up.", uid_email, email);
    goto out;
  }

  self->auth_at = json_object_get_int_member (json, "fxa-lastAuthAt");
  retval = TRUE;

out:
  g_free (header);
  g_free (payload);
  g_free (uid_email);
  g_strfreev (pieces);
  g_object_unref (parser);
  soup_uri_free (uri);

  return retval;
}

static void
obtain_storage_credentials_response_cb (SoupSession *session,
                                        SoupMessage *msg,
                                        gpointer     user_data)
{
  EphySyncService *service;
  JsonParser *parser;
  JsonObject *json;

  service = EPHY_SYNC_SERVICE (user_data);

  if (msg->status_code != 200) {
    g_warning ("Failed to talk to the Token Server, status code %u. "
               "See https://docs.services.mozilla.com/token/apis.html#error-responses",
               msg->status_code);
    service->locked = FALSE;
    return;
  }

  parser = json_parser_new ();
  json_parser_load_from_data (parser, msg->response_body->data, -1, NULL);
  json = json_node_get_object (json_parser_get_root (parser));

  service->storage_endpoint = g_strdup (json_object_get_string_member (json, "api_endpoint"));
  service->storage_credentials_id = g_strdup (json_object_get_string_member (json, "id"));
  service->storage_credentials_key = g_strdup (json_object_get_string_member (json, "key"));
  service->storage_credentials_expiry_time = json_object_get_int_member (json, "duration") +
                                             ephy_sync_utils_current_time_seconds ();
  service->locked = FALSE;
  ephy_sync_service_send_next_storage_request (service);

  g_object_unref (parser);
}

static void
ephy_sync_service_obtain_storage_credentials (EphySyncService *self)
{
  SoupMessage *msg;
  guint8 *kB;
  char *hashed_kB;
  char *client_state;
  char *audience;
  char *assertion;
  char *authorization;

  g_return_if_fail (EPHY_IS_SYNC_SERVICE (self));
  g_return_if_fail (self->certificate != NULL);
  g_return_if_fail (self->keypair != NULL);

  audience = ephy_sync_utils_make_audience (MOZILLA_TOKEN_SERVER_URL);
  assertion = ephy_sync_crypto_create_assertion (self->certificate, audience,
                                                 ASSERTION_DURATION, self->keypair);
  g_return_if_fail (assertion != NULL);

  kB = ephy_sync_crypto_decode_hex (self->kB);
  hashed_kB = g_compute_checksum_for_data (G_CHECKSUM_SHA256, kB, EPHY_SYNC_TOKEN_LENGTH);
  client_state = g_strndup (hashed_kB, EPHY_SYNC_TOKEN_LENGTH);
  authorization = g_strdup_printf ("BrowserID %s", assertion);

  msg = soup_message_new (SOUP_METHOD_GET, MOZILLA_TOKEN_SERVER_URL);
  /* We need to add the X-Client-State header so that the Token Server will
   * recognize accounts that were previously used to sync Firefox data too. */
  soup_message_headers_append (msg->request_headers, "X-Client-State", client_state);
  soup_message_headers_append (msg->request_headers, "authorization", authorization);
  soup_session_queue_message (self->session, msg, obtain_storage_credentials_response_cb, self);

  g_free (kB);
  g_free (hashed_kB);
  g_free (client_state);
  g_free (audience);
  g_free (assertion);
  g_free (authorization);
}

static void
obtain_signed_certificate_response_cb (SoupSession *session,
                                       SoupMessage *msg,
                                       gpointer     user_data)
{
  EphySyncService *service;
  JsonParser *parser;
  JsonObject *json;
  const char *certificate;

  service = EPHY_SYNC_SERVICE (user_data);

  parser = json_parser_new ();
  json_parser_load_from_data (parser, msg->response_body->data, -1, NULL);
  json = json_node_get_object (json_parser_get_root (parser));

  /* Since a new Firefox Account password implies new tokens, this will fail
   * with an error code 110 (Invalid authentication token in request signature)
   * if the user has changed his password since the last time he signed in.
   * When this happens, notify the user to sign in with the new password. */
  if (msg->status_code == 401 && json_object_get_int_member (json, "errno") == 110) {
    char *error = g_strdup_printf (_("The password of your Firefox account %s "
                                     "seems to have been changed."),
                                   ephy_sync_service_get_user_email (service));
    const char *suggestion = _("Please visit Preferences and sign in with "
                               "the new password to continue the sync process.");

    ephy_notification_show (ephy_notification_new (error, suggestion));

    g_free (error);
    service->locked = FALSE;
    goto out;
  }

  if (msg->status_code != 200) {
    g_warning ("FxA server errno: %ld, errmsg: %s",
               json_object_get_int_member (json, "errno"),
               json_object_get_string_member (json, "message"));
    service->locked = FALSE;
    goto out;
  }

  certificate = json_object_get_string_member (json, "cert");

  if (ephy_sync_service_certificate_is_valid (service, certificate) == FALSE) {
    ephy_sync_crypto_rsa_key_pair_free (service->keypair);
    service->locked = FALSE;
    goto out;
  }

  service->certificate = g_strdup (certificate);
  ephy_sync_service_obtain_storage_credentials (service);

out:
  g_object_unref (parser);
}

static void
ephy_sync_service_obtain_signed_certificate (EphySyncService *self)
{
  guint8 *tokenID;
  guint8 *reqHMACkey;
  guint8 *requestKey;
  char *tokenID_hex;
  char *public_key_json;
  char *request_body;
  char *n;
  char *e;

  g_return_if_fail (EPHY_IS_SYNC_SERVICE (self));
  g_return_if_fail (self->sessionToken != NULL);

  /* Generate a new RSA key pair that is going to be used to sign the new certificate. */
  if (self->keypair != NULL)
    ephy_sync_crypto_rsa_key_pair_free (self->keypair);

  self->keypair = ephy_sync_crypto_generate_rsa_key_pair ();
  g_return_if_fail (self->keypair != NULL);

  /* Derive tokenID, reqHMACkey and requestKey from the sessionToken. */
  ephy_sync_crypto_process_session_token (self->sessionToken, &tokenID, &reqHMACkey, &requestKey);
  tokenID_hex = ephy_sync_crypto_encode_hex (tokenID, 0);

  n = mpz_get_str (NULL, 10, self->keypair->public.n);
  e = mpz_get_str (NULL, 10, self->keypair->public.e);
  public_key_json = ephy_sync_utils_build_json_string ("algorithm", "RS", "n", n, "e", e, NULL);
  request_body = g_strdup_printf ("{\"publicKey\": %s, \"duration\": %d}",
                                  public_key_json, CERTIFICATE_DURATION);
  ephy_sync_service_fxa_hawk_post_async (self, "certificate/sign", tokenID_hex,
                                         reqHMACkey, EPHY_SYNC_TOKEN_LENGTH, request_body,
                                         obtain_signed_certificate_response_cb, self);

  g_free (tokenID);
  g_free (reqHMACkey);
  g_free (requestKey);
  g_free (tokenID_hex);
  g_free (public_key_json);
  g_free (request_body);
  g_free (n);
  g_free (e);
}

static void
ephy_sync_service_send_storage_request (EphySyncService         *self,
                                        StorageRequestAsyncData *data)
{
  EphySyncCryptoHawkOptions *hoptions = NULL;
  EphySyncCryptoHawkHeader *hheader;
  SoupMessage *msg;
  char *url;
  char *if_modified_since = NULL;
  char *if_unmodified_since = NULL;
  const char *content_type = "application/json";

  g_assert (EPHY_IS_SYNC_SERVICE (self));
  g_assert (data);

  url = g_strdup_printf ("%s/%s", self->storage_endpoint, data->endpoint);
  msg = soup_message_new (data->method, url);

  if (data->request_body != NULL) {
    hoptions = ephy_sync_crypto_hawk_options_new (NULL, NULL, NULL, content_type,
                                                  NULL, NULL, NULL, data->request_body, NULL);
    soup_message_set_request (msg, content_type, SOUP_MEMORY_COPY,
                              data->request_body, strlen (data->request_body));
  }

  if (g_strcmp0 (data->method, SOUP_METHOD_POST) == 0)
    soup_message_headers_append (msg->request_headers, "content-type", content_type);

  if (data->modified_since >= 0) {
    if_modified_since = g_strdup_printf ("%.2lf", data->modified_since);
    soup_message_headers_append (msg->request_headers, "X-If-Modified-Since", if_modified_since);
  }

  if (data->unmodified_since >= 0) {
    if_unmodified_since = g_strdup_printf ("%.2lf", data->unmodified_since);
    soup_message_headers_append (msg->request_headers, "X-If-Unmodified-Since", if_unmodified_since);
  }

  hheader = ephy_sync_crypto_compute_hawk_header (url, data->method, self->storage_credentials_id,
                                                 (guint8 *)self->storage_credentials_key,
                                                 strlen (self->storage_credentials_key),
                                                 hoptions);
  soup_message_headers_append (msg->request_headers, "authorization", hheader->header);
  soup_session_queue_message (self->session, msg, data->callback, data->user_data);

  if (hoptions != NULL)
    ephy_sync_crypto_hawk_options_free (hoptions);

  g_free (url);
  g_free (if_modified_since);
  g_free (if_unmodified_since);
  ephy_sync_crypto_hawk_header_free (hheader);
  storage_server_request_async_data_free (data);
}

static void
ephy_sync_service_send_next_storage_request (EphySyncService *self)
{
  g_assert (EPHY_IS_SYNC_SERVICE (self));

  if (self->locked || g_queue_is_empty (self->storage_queue))
    return;

  /* If the storage credentials are valid, then directly send the request.
   * Otherwise, the request will remain queued and scheduled to be sent when
   * the new credentials are obtained. */
  if (!ephy_sync_service_storage_credentials_is_expired (self)) {
    ephy_sync_service_send_storage_request (self, g_queue_pop_head (self->storage_queue));
  } else {
    /* Mark as locked so other requests won't lead to conflicts while obtaining
     * new storage credentials. */
    self->locked = TRUE;
    ephy_sync_service_clear_storage_credentials (self);
    ephy_sync_service_obtain_signed_certificate (self);
  }
}

static void
ephy_sync_service_queue_storage_request (EphySyncService     *self,
                                         char                *endpoint,
                                         const char          *method,
                                         char                *request_body,
                                         double               modified_since,
                                         double               unmodified_since,
                                         SoupSessionCallback  callback,
                                         gpointer             user_data)
{
  g_assert (EPHY_IS_SYNC_SERVICE (self));
  g_assert (endpoint);
  g_assert (method);

  g_queue_push_tail (self->storage_queue,
                     storage_server_request_async_data_new (self, endpoint,
                                                            method, request_body,
                                                            modified_since, unmodified_since,
                                                            callback, user_data));

  ephy_sync_service_send_next_storage_request (self);
}

static void
ephy_sync_service_finalize (GObject *object)
{
  EphySyncService *self = EPHY_SYNC_SERVICE (object);

  if (self->keypair != NULL)
    ephy_sync_crypto_rsa_key_pair_free (self->keypair);

  g_queue_free_full (self->storage_queue, (GDestroyNotify) storage_server_request_async_data_free);

  G_OBJECT_CLASS (ephy_sync_service_parent_class)->finalize (object);
}

static void
ephy_sync_service_dispose (GObject *object)
{
  EphySyncService *self = EPHY_SYNC_SERVICE (object);

  if (ephy_sync_service_is_signed_in (self))
    ephy_sync_service_stop_periodical_sync (self);

  ephy_sync_service_clear_storage_credentials (self);
  ephy_sync_service_clear_tokens (self);
  g_clear_pointer (&self->user_email, g_free);
  g_clear_object (&self->session);

  G_OBJECT_CLASS (ephy_sync_service_parent_class)->dispose (object);
}

static void
ephy_sync_service_class_init (EphySyncServiceClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);

  object_class->finalize = ephy_sync_service_finalize;
  object_class->dispose = ephy_sync_service_dispose;

  signals[STORE_FINISHED] =
    g_signal_new ("sync-tokens-store-finished",
                  EPHY_TYPE_SYNC_SERVICE,
                  G_SIGNAL_RUN_LAST,
                  0, NULL, NULL, NULL,
                  G_TYPE_NONE, 1,
                  G_TYPE_ERROR);

  signals[LOAD_FINISHED] =
    g_signal_new ("sync-tokens-load-finished",
                  EPHY_TYPE_SYNC_SERVICE,
                  G_SIGNAL_RUN_LAST,
                  0, NULL, NULL, NULL,
                  G_TYPE_NONE, 1,
                  G_TYPE_ERROR);
}

static void
ephy_sync_service_init (EphySyncService *self)
{
  char *email;
  const char *user_agent;
  WebKitSettings *settings;

  self->session = soup_session_new ();
  self->storage_queue = g_queue_new ();

  settings = ephy_embed_prefs_get_settings ();
  user_agent = webkit_settings_get_user_agent (settings);
  g_object_set (self->session, "user-agent", user_agent, NULL);

  email = g_settings_get_string (EPHY_SETTINGS_MAIN, EPHY_PREFS_SYNC_USER);

  if (g_strcmp0 (email, "") != 0) {
    ephy_sync_service_set_user_email (self, email);
    ephy_sync_secret_load_tokens (self);
  }

  g_free (email);
}

EphySyncService *
ephy_sync_service_new (void)
{
  return EPHY_SYNC_SERVICE (g_object_new (EPHY_TYPE_SYNC_SERVICE, NULL));
}

gboolean
ephy_sync_service_is_signed_in (EphySyncService *self)
{
  g_return_val_if_fail (EPHY_IS_SYNC_SERVICE (self), FALSE);

  return self->user_email != NULL;
}

char *
ephy_sync_service_get_user_email (EphySyncService *self)
{
  g_return_val_if_fail (EPHY_IS_SYNC_SERVICE (self), NULL);

  return self->user_email;
}

void
ephy_sync_service_set_user_email (EphySyncService *self,
                                  const char      *email)
{
  g_return_if_fail (EPHY_IS_SYNC_SERVICE (self));

  g_free (self->user_email);
  self->user_email = g_strdup (email);
}

double
ephy_sync_service_get_sync_time (EphySyncService *self)
{
  g_return_val_if_fail (EPHY_IS_SYNC_SERVICE (self), 0);

  if (self->sync_time != 0)
    return self->sync_time;

  self->sync_time = g_settings_get_double (EPHY_SETTINGS_MAIN, EPHY_PREFS_SYNC_TIME);
  return self->sync_time;
}


void
ephy_sync_service_set_sync_time (EphySyncService *self,
                                 double           time)
{
  g_return_if_fail (EPHY_IS_SYNC_SERVICE (self));

  self->sync_time = time;
  g_settings_set_double (EPHY_SETTINGS_MAIN, EPHY_PREFS_SYNC_TIME, time);
}

char *
ephy_sync_service_get_token (EphySyncService   *self,
                             EphySyncTokenType  type)
{
  g_return_val_if_fail (EPHY_IS_SYNC_SERVICE (self), NULL);

  switch (type) {
    case TOKEN_UID:
      return self->uid;
    case TOKEN_SESSIONTOKEN:
      return self->sessionToken;
    case TOKEN_KEYFETCHTOKEN:
      return self->keyFetchToken;
    case TOKEN_UNWRAPBKEY:
      return self->unwrapBKey;
    case TOKEN_KA:
      return self->kA;
    case TOKEN_KB:
      return self->kB;
    default:
      g_assert_not_reached ();
  }
}

void
ephy_sync_service_set_token (EphySyncService   *self,
                             const char        *value,
                             EphySyncTokenType  type)
{
  g_return_if_fail (EPHY_IS_SYNC_SERVICE (self));
  g_return_if_fail (value != NULL);

  switch (type) {
    case TOKEN_UID:
      g_free (self->uid);
      self->uid = g_strdup (value);
      break;
    case TOKEN_SESSIONTOKEN:
      g_free (self->sessionToken);
      self->sessionToken = g_strdup (value);
      break;
    case TOKEN_KEYFETCHTOKEN:
      g_free (self->keyFetchToken);
      self->keyFetchToken = g_strdup (value);
      break;
    case TOKEN_UNWRAPBKEY:
      g_free (self->unwrapBKey);
      self->unwrapBKey = g_strdup (value);
      break;
    case TOKEN_KA:
      g_free (self->kA);
      self->kA = g_strdup (value);
      break;
    case TOKEN_KB:
      g_free (self->kB);
      self->kB = g_strdup (value);
      break;
    default:
      g_assert_not_reached ();
  }
}

void
ephy_sync_service_clear_storage_credentials (EphySyncService *self)
{
  g_return_if_fail (EPHY_IS_SYNC_SERVICE (self));

  g_clear_pointer (&self->certificate, g_free);
  g_clear_pointer (&self->storage_endpoint, g_free);
  g_clear_pointer (&self->storage_credentials_id, g_free);
  g_clear_pointer (&self->storage_credentials_key, g_free);
  self->storage_credentials_expiry_time = 0;
}

void
ephy_sync_service_clear_tokens (EphySyncService *self)
{
  g_return_if_fail (EPHY_IS_SYNC_SERVICE (self));

  g_clear_pointer (&self->uid, g_free);
  g_clear_pointer (&self->sessionToken, g_free);
  g_clear_pointer (&self->keyFetchToken, g_free);
  g_clear_pointer (&self->unwrapBKey, g_free);
  g_clear_pointer (&self->kA, g_free);
  g_clear_pointer (&self->kB, g_free);
}

static void
destroy_session_response_cb (SoupSession *session,
                             SoupMessage *msg,
                             gpointer     user_data)
{
  JsonParser *parser;
  JsonObject *json;

  if (msg->status_code == 200) {
    LOG ("Session destroyed");
    return;
  }

  parser = json_parser_new ();
  json_parser_load_from_data (parser, msg->response_body->data, -1, NULL);
  json = json_node_get_object (json_parser_get_root (parser));

  g_warning ("Failed to destroy session: errno: %ld, errmsg: %s",
             json_object_get_int_member (json, "errno"),
             json_object_get_string_member (json, "message"));

  g_object_unref (parser);
}

void
ephy_sync_service_destroy_session (EphySyncService *self,
                                   const char      *sessionToken)
{
  EphySyncCryptoHawkOptions *hoptions;
  EphySyncCryptoHawkHeader *hheader;
  SoupMessage *msg;
  guint8 *tokenID;
  guint8 *reqHMACkey;
  guint8 *requestKey;
  char *tokenID_hex;
  char *url;
  const char *content_type = "application/json";
  const char *endpoint = "session/destroy";
  const char *request_body = "{}";

  g_return_if_fail (EPHY_IS_SYNC_SERVICE (self));

  if (sessionToken == NULL)
    sessionToken = ephy_sync_service_get_token (self, TOKEN_SESSIONTOKEN);
  g_return_if_fail (sessionToken != NULL);

  url = g_strdup_printf ("%s%s", MOZILLA_FXA_SERVER_URL, endpoint);
  ephy_sync_crypto_process_session_token (sessionToken, &tokenID, &reqHMACkey, &requestKey);
  tokenID_hex = ephy_sync_crypto_encode_hex (tokenID, 0);

  msg = soup_message_new (SOUP_METHOD_POST, url);
  soup_message_set_request (msg, content_type, SOUP_MEMORY_STATIC,
                            request_body, strlen (request_body));
  hoptions = ephy_sync_crypto_hawk_options_new (NULL, NULL, NULL, content_type,
                                                NULL, NULL, NULL, request_body, NULL);
  hheader = ephy_sync_crypto_compute_hawk_header (url, "POST", tokenID_hex,
                                                  reqHMACkey, EPHY_SYNC_TOKEN_LENGTH,
                                                  hoptions);
  soup_message_headers_append (msg->request_headers, "authorization", hheader->header);
  soup_message_headers_append (msg->request_headers, "content-type", content_type);
  soup_session_queue_message (self->session, msg, destroy_session_response_cb, NULL);

  ephy_sync_crypto_hawk_options_free (hoptions);
  ephy_sync_crypto_hawk_header_free (hheader);
  g_free (tokenID_hex);
  g_free (tokenID);
  g_free (reqHMACkey);
  g_free (requestKey);
  g_free (url);
}

char *
ephy_sync_service_start_sign_in (EphySyncService  *self,
                                 guint8           *tokenID,
                                 guint8           *reqHMACkey)
{
  JsonNode *node;
  JsonObject *json;
  char *tokenID_hex;
  char *bundle = NULL;
  guint status_code;

  /* Retrieve the sync keys bundle from the /account/keys endpoint. */
  tokenID_hex = ephy_sync_crypto_encode_hex (tokenID, 0);
  status_code = ephy_sync_service_fxa_hawk_get_sync (self, "account/keys", tokenID_hex,
                                                     reqHMACkey, EPHY_SYNC_TOKEN_LENGTH,
                                                     &node);
  json = json_node_get_object (node);

  if (status_code == 200) {
    bundle = g_strdup (json_object_get_string_member (json, "bundle"));
  } else {
    LOG ("Failed to retrieve sync keys bundle: code: %ld, errno: %ld, error: '%s', message: '%s'",
         json_object_get_int_member (json, "code"),
         json_object_get_int_member (json, "errno"),
         json_object_get_string_member (json, "error"),
         json_object_get_string_member (json, "message"));
  }

  g_free (tokenID_hex);
  json_node_free (node);

  return bundle;
}

void
ephy_sync_service_finish_sign_in (EphySyncService *self,
                                  const char      *email,
                                  const char      *uid,
                                  const char      *sessionToken,
                                  const char      *keyFetchToken,
                                  const char      *unwrapBKey,
                                  char            *bundle,
                                  guint8          *respHMACkey,
                                  guint8          *respXORkey)
{
  guint8 *unwrapKB;
  guint8 *kA;
  guint8 *kB;
  char *kA_hex;
  char *kB_hex;

  g_return_if_fail (EPHY_IS_SYNC_SERVICE (self));
  g_return_if_fail (email != NULL);
  g_return_if_fail (uid != NULL);
  g_return_if_fail (sessionToken != NULL);
  g_return_if_fail (keyFetchToken != NULL);
  g_return_if_fail (unwrapBKey != NULL);
  g_return_if_fail (bundle != NULL);
  g_return_if_fail (respHMACkey != NULL);
  g_return_if_fail (respXORkey != NULL);

  /* Derive the sync keys form the received key bundle. */
  unwrapKB = ephy_sync_crypto_decode_hex (unwrapBKey);
  ephy_sync_crypto_compute_sync_keys (bundle,
                                      respHMACkey, respXORkey, unwrapKB,
                                      &kA, &kB);
  kA_hex = ephy_sync_crypto_encode_hex (kA, 0);
  kB_hex = ephy_sync_crypto_encode_hex (kB, 0);

  /* Save the email and the tokens. */
  g_settings_set_string (EPHY_SETTINGS_MAIN, EPHY_PREFS_SYNC_USER, email);
  ephy_sync_service_set_user_email (self, email);
  ephy_sync_service_set_token (self, uid, TOKEN_UID);
  ephy_sync_service_set_token (self, sessionToken, TOKEN_SESSIONTOKEN);
  ephy_sync_service_set_token (self, keyFetchToken, TOKEN_KEYFETCHTOKEN);
  ephy_sync_service_set_token (self, unwrapBKey, TOKEN_UNWRAPBKEY);
  ephy_sync_service_set_token (self, kA_hex, TOKEN_KA);
  ephy_sync_service_set_token (self, kB_hex, TOKEN_KB);

  /* Store the tokens in the secret schema. */
  ephy_sync_secret_store_tokens (self, email, uid, sessionToken,
                                 keyFetchToken, unwrapBKey, kA_hex, kB_hex);

  g_free (kA);
  g_free (kB);
  g_free (kA_hex);
  g_free (kB_hex);
  g_free (unwrapKB);
}

static void
upload_bookmark_response_cb (SoupSession *session,
                             SoupMessage *msg,
                             gpointer     user_data)
{
  EphySyncService *service;
  EphyBookmarksManager *manager;
  EphyBookmark *bookmark;
  double last_modified;

  service = ephy_shell_get_sync_service (ephy_shell_get_default ());
  manager = ephy_shell_get_bookmarks_manager (ephy_shell_get_default ());
  bookmark = EPHY_BOOKMARK (user_data);

  if (msg->status_code == 200) {
    last_modified = g_ascii_strtod (msg->response_body->data, NULL);
    ephy_bookmark_set_modification_time (bookmark, last_modified);
    ephy_bookmark_set_is_uploaded (bookmark, TRUE);
    ephy_bookmarks_manager_save_to_file_async (manager, NULL, NULL, NULL);

    LOG ("Successfully uploaded to server");
  } else if (msg->status_code == 412) {
    ephy_sync_service_download_bookmark (service, bookmark);
  } else {
    LOG ("Failed to upload to server. Status code: %u, response: %s",
         msg->status_code, msg->response_body->data);
  }

  ephy_sync_service_send_next_storage_request (service);
}

void
ephy_sync_service_upload_bookmark (EphySyncService *self,
                                   EphyBookmark    *bookmark,
                                   gboolean         force)
{
  char *endpoint;
  char *bso;
  double modified;

  g_return_if_fail (EPHY_IS_SYNC_SERVICE (self));
  g_return_if_fail (ephy_sync_service_is_signed_in (self));
  g_return_if_fail (EPHY_IS_BOOKMARK (bookmark));

  endpoint = g_strdup_printf ("storage/%s/%s",
                              EPHY_BOOKMARKS_COLLECTION,
                              ephy_bookmark_get_id (bookmark));
  bso = ephy_bookmark_to_bso (bookmark);
  modified = ephy_bookmark_get_modification_time (bookmark);
  ephy_sync_service_queue_storage_request (self, endpoint,
                                           SOUP_METHOD_PUT, bso, -1,
                                           force ? -1 : modified,
                                           upload_bookmark_response_cb,
                                           bookmark);

  g_free (endpoint);
  g_free (bso);
}

static void
download_bookmark_response_cb (SoupSession *session,
                               SoupMessage *msg,
                               gpointer     user_data)
{
  EphySyncService *service;
  EphyBookmarksManager *manager;
  EphyBookmark *bookmark;
  GSequenceIter *iter;
  JsonParser *parser;
  JsonObject *bso;
  const char *id;

  if (msg->status_code != 200) {
    LOG ("Failed to download from server. Status code: %u, response: %s",
         msg->status_code, msg->response_body->data);
    goto out;
  }

  parser = json_parser_new ();
  json_parser_load_from_data (parser, msg->response_body->data, -1, NULL);
  bso = json_node_get_object (json_parser_get_root (parser));
  bookmark = ephy_bookmark_from_bso (bso);
  id = ephy_bookmark_get_id (bookmark);

  /* Overwrite any local bookmark. */
  manager = ephy_shell_get_bookmarks_manager (ephy_shell_get_default ());
  ephy_bookmarks_manager_remove_bookmark (manager,
                                          ephy_bookmarks_manager_get_bookmark_by_id (manager, id));
  ephy_bookmarks_manager_add_bookmark (manager, bookmark);

  /* We have to manually add the tags to the bookmarks manager. */
  for (iter = g_sequence_get_begin_iter (ephy_bookmark_get_tags (bookmark));
       !g_sequence_iter_is_end (iter); iter = g_sequence_iter_next (iter))
    ephy_bookmarks_manager_create_tag (manager, g_sequence_get (iter));

  g_object_unref (bookmark);
  g_object_unref (parser);

out:
  service = ephy_shell_get_sync_service (ephy_shell_get_default ());
  ephy_sync_service_send_next_storage_request (service);
}

void
ephy_sync_service_download_bookmark (EphySyncService *self,
                                     EphyBookmark    *bookmark)
{
  char *endpoint;

  g_return_if_fail (EPHY_IS_SYNC_SERVICE (self));
  g_return_if_fail (ephy_sync_service_is_signed_in (self));
  g_return_if_fail (EPHY_IS_BOOKMARK (bookmark));

  endpoint = g_strdup_printf ("storage/%s/%s",
                              EPHY_BOOKMARKS_COLLECTION,
                              ephy_bookmark_get_id (bookmark));
  ephy_sync_service_queue_storage_request (self, endpoint,
                                           SOUP_METHOD_GET, NULL, -1, -1,
                                           download_bookmark_response_cb, NULL);

  g_free (endpoint);
}

static void
delete_bookmark_conditional_response_cb (SoupSession *session,
                                         SoupMessage *msg,
                                         gpointer     user_data)
{
  EphySyncService *service;
  EphyBookmark *bookmark;
  EphyBookmarksManager *manager;

  bookmark = EPHY_BOOKMARK (user_data);
  manager = ephy_shell_get_bookmarks_manager (ephy_shell_get_default ());

  if (msg->status_code == 404) {
    ephy_bookmarks_manager_remove_bookmark (manager, bookmark);
  } else if (msg->status_code == 200) {
    LOG ("The bookmark still exists on the server, don't delete it");
  } else {
    LOG ("Failed to delete conditionally. Status code: %u, response: %s",
         msg->status_code, msg->response_body->data);
  }

  service = ephy_shell_get_sync_service (ephy_shell_get_default ());
  ephy_sync_service_send_next_storage_request (service);
}

static void
delete_bookmark_response_cb (SoupSession *session,
                             SoupMessage *msg,
                             gpointer     user_data)
{
  EphySyncService *service;

  if (msg->status_code == 200)
    LOG ("Successfully deleted the bookmark from the server");
  else
    LOG ("Failed to delete. Status code: %u, response: %s",
         msg->status_code, msg->response_body->data);

  service = ephy_shell_get_sync_service (ephy_shell_get_default ());
  ephy_sync_service_send_next_storage_request (service);
}

void
ephy_sync_service_delete_bookmark (EphySyncService *self,
                                   EphyBookmark    *bookmark,
                                   gboolean         conditional)
{
  char *endpoint;

  g_return_if_fail (EPHY_IS_SYNC_SERVICE (self));
  g_return_if_fail (ephy_sync_service_is_signed_in (self));
  g_return_if_fail (EPHY_IS_BOOKMARK (bookmark));

  endpoint = g_strdup_printf ("storage/%s/%s",
                              EPHY_BOOKMARKS_COLLECTION,
                              ephy_bookmark_get_id (bookmark));

  /* If the bookmark does not exist on the server, delete it from the local
   * instance too. */
  if (conditional == TRUE) {
    ephy_sync_service_queue_storage_request (self, endpoint,
                                             SOUP_METHOD_GET, NULL, -1, -1,
                                             delete_bookmark_conditional_response_cb,
                                             bookmark);
  } else {
    ephy_sync_service_queue_storage_request (self, endpoint,
                                             SOUP_METHOD_DELETE, NULL, -1, -1,
                                             delete_bookmark_response_cb, NULL);
  }

  g_free (endpoint);
}

static void
sync_bookmarks_first_time_response_cb (SoupSession *session,
                                       SoupMessage *msg,
                                       gpointer     user_data)
{
  EphySyncService *service;
  EphyBookmarksManager *manager;
  GSequence *bookmarks;
  GSequenceIter *iter;
  GHashTable *marked;
  JsonParser *parser;
  JsonArray *array;
  const char *timestamp;
  double server_time;

  service = ephy_shell_get_sync_service (ephy_shell_get_default ());
  manager = ephy_shell_get_bookmarks_manager (ephy_shell_get_default ());
  bookmarks = ephy_bookmarks_manager_get_bookmarks (manager);
  marked = g_hash_table_new_full (g_direct_hash, g_direct_equal, g_object_unref, NULL);
  parser = json_parser_new ();
  json_parser_load_from_data (parser, msg->response_body->data, -1, NULL);

  if (msg->status_code != 200) {
    LOG ("Failed to do a first time sync. Status code: %u, response: %s",
         msg->status_code, msg->response_body->data);
    goto out;
  }

  array = json_node_get_array (json_parser_get_root (parser));
  for (gsize i = 0; i < json_array_get_length (array); i++) {
    JsonObject *bso = json_array_get_object_element (array, i);
    EphyBookmark *remote = ephy_bookmark_from_bso (bso);
    EphyBookmark *local;

    if (remote == NULL)
      continue;

    local = ephy_bookmarks_manager_get_bookmark_by_id (manager, ephy_bookmark_get_id (remote));

    if (local == NULL) {
      local = ephy_bookmarks_manager_get_bookmark_by_url (manager, ephy_bookmark_get_url (remote));

      /* If there is no local equivalent of the remote bookmark, then add it to
       * the local instance together with its tags. */
      if (local == NULL) {
        ephy_bookmarks_manager_add_bookmark (manager, remote);

        /* We have to manually add the tags to the bookmarks manager. */
        for (iter = g_sequence_get_begin_iter (ephy_bookmark_get_tags (remote));
             !g_sequence_iter_is_end (iter); iter = g_sequence_iter_next (iter))
          ephy_bookmarks_manager_create_tag (manager, g_sequence_get (iter));

        g_hash_table_add (marked, g_object_ref (remote));
      }
      /* If there is a local bookmark with the same url as the remote one, then
       * merge tags into the local one, keep the remote id and upload it to the
       * server. */
      else {
        for (iter = g_sequence_get_begin_iter (ephy_bookmark_get_tags (remote));
             !g_sequence_iter_is_end (iter); iter = g_sequence_iter_next (iter)) {
          ephy_bookmark_add_tag (local, g_sequence_get (iter));
          ephy_bookmarks_manager_create_tag (manager, g_sequence_get (iter));
        }

        ephy_bookmark_set_id (local, ephy_bookmark_get_id (remote));
        ephy_sync_service_upload_bookmark (service, local, TRUE);
        g_hash_table_add (marked, g_object_ref (local));
      }
    }
    /* Having a local bookmark with the same id as the remote one means that the
     * bookmark has been synced before in the past. Keep the one with the most
     * recent modified timestamp. */
    else {
      if (ephy_bookmark_get_modification_time (remote) > ephy_bookmark_get_modification_time (local)) {
        ephy_bookmarks_manager_remove_bookmark (manager, local);
        ephy_bookmarks_manager_add_bookmark (manager, remote);

        /* We have to manually add the tags to the bookmarks manager. */
        for (iter = g_sequence_get_begin_iter (ephy_bookmark_get_tags (remote));
             !g_sequence_iter_is_end (iter); iter = g_sequence_iter_next (iter))
          ephy_bookmarks_manager_create_tag (manager, g_sequence_get (iter));

        g_hash_table_add (marked, g_object_ref (remote));
      } else {
        if (ephy_bookmark_get_modification_time (local) > ephy_bookmark_get_modification_time (remote))
          ephy_sync_service_upload_bookmark (service, local, TRUE);

        g_hash_table_add (marked, g_object_ref (local));
      }
    }

    g_object_unref (remote);
  }

  /* Upload the remaining local bookmarks to the server. */
  for (iter = g_sequence_get_begin_iter (bookmarks);
       !g_sequence_iter_is_end (iter); iter = g_sequence_iter_next (iter)) {
    EphyBookmark *bookmark = g_sequence_get (iter);

    if (g_hash_table_contains (marked, bookmark) == FALSE)
      ephy_sync_service_upload_bookmark (service, bookmark, TRUE);
  }

  /* Save changes to file. */
  ephy_bookmarks_manager_save_to_file_async (manager, NULL, NULL, NULL);

  /* Set the sync time. */
  timestamp = soup_message_headers_get_one (msg->response_headers, "X-Weave-Timestamp");
  server_time = g_ascii_strtod (timestamp, NULL);
  ephy_sync_service_set_sync_time (service, server_time);

out:
  g_object_unref (parser);
  g_hash_table_unref (marked);

  ephy_sync_service_send_next_storage_request (service);
}

static void
sync_bookmarks_response_cb (SoupSession *session,
                            SoupMessage *msg,
                            gpointer     user_data)
{
  EphySyncService *service;
  EphyBookmarksManager *manager;
  GSequence *bookmarks;
  GSequenceIter *iter;
  JsonParser *parser;
  JsonArray *array;
  const char *timestamp;
  double server_time;

  service = ephy_shell_get_sync_service (ephy_shell_get_default ());
  manager = ephy_shell_get_bookmarks_manager (ephy_shell_get_default ());
  bookmarks = ephy_bookmarks_manager_get_bookmarks (manager);
  parser = json_parser_new ();
  json_parser_load_from_data (parser, msg->response_body->data, -1, NULL);

  /* Code 304 indicates that the resource has not been modified. Therefore,
   * only upload the local bookmarks that were not uploaded. */
  if (msg->status_code == 304)
    goto handle_local_bookmarks;

  if (msg->status_code != 200) {
    LOG ("Failed to sync bookmarks. Status code: %u, response: %s",
         msg->status_code, msg->response_body->data);
    goto out;
  }

  array = json_node_get_array (json_parser_get_root (parser));
  for (gsize i = 0; i < json_array_get_length (array); i++) {
    JsonObject *bso = json_array_get_object_element (array, i);
    EphyBookmark *remote = ephy_bookmark_from_bso (bso);
    EphyBookmark *local;

    if (remote == NULL)
      continue;

    local = ephy_bookmarks_manager_get_bookmark_by_id (manager, ephy_bookmark_get_id (remote));

    if (local == NULL) {
      ephy_bookmarks_manager_add_bookmark (manager, remote);

      /* We have to manually add the tags to the bookmarks manager. */
      for (iter = g_sequence_get_begin_iter (ephy_bookmark_get_tags (remote));
           !g_sequence_iter_is_end (iter); iter = g_sequence_iter_next (iter))
        ephy_bookmarks_manager_create_tag (manager, g_sequence_get (iter));
    } else {
      if (ephy_bookmark_get_modification_time (remote) > ephy_bookmark_get_modification_time (local)) {
        ephy_bookmarks_manager_remove_bookmark (manager, local);
        ephy_bookmarks_manager_add_bookmark (manager, remote);

        /* We have to manually add the tags to the bookmarks manager. */
        for (iter = g_sequence_get_begin_iter (ephy_bookmark_get_tags (remote));
             !g_sequence_iter_is_end (iter); iter = g_sequence_iter_next (iter))
          ephy_bookmarks_manager_create_tag (manager, g_sequence_get (iter));
      } else {
        if (ephy_bookmark_get_modification_time (local) > ephy_bookmark_get_modification_time (remote))
          ephy_sync_service_upload_bookmark (service, local, TRUE);

        g_object_unref (remote);
      }
    }
  }

handle_local_bookmarks:
  for (iter = g_sequence_get_begin_iter (bookmarks);
       !g_sequence_iter_is_end (iter); iter = g_sequence_iter_next (iter)) {
    EphyBookmark *bookmark = EPHY_BOOKMARK (g_sequence_get (iter));

    if (ephy_bookmark_is_uploaded (bookmark) == TRUE)
      ephy_sync_service_delete_bookmark (service, bookmark, TRUE);
    else
      ephy_sync_service_upload_bookmark (service, bookmark, FALSE);
  }

  /* Save changes to file. */
  ephy_bookmarks_manager_save_to_file_async (manager, NULL, NULL, NULL);

  /* Set the sync time. */
  timestamp = soup_message_headers_get_one (msg->response_headers, "X-Weave-Timestamp");
  server_time = g_ascii_strtod (timestamp, NULL);
  ephy_sync_service_set_sync_time (service, server_time);

out:
  g_object_unref (parser);

  ephy_sync_service_send_next_storage_request (service);
}

void
ephy_sync_service_sync_bookmarks (EphySyncService *self,
                                  gboolean         first)
{
  char *endpoint;

  g_return_if_fail (EPHY_IS_SYNC_SERVICE (self));
  g_return_if_fail (ephy_sync_service_is_signed_in (self));

  endpoint = g_strdup_printf ("storage/%s?full=true", EPHY_BOOKMARKS_COLLECTION);

  if (first == TRUE) {
    ephy_sync_service_queue_storage_request (self, endpoint,
                                             SOUP_METHOD_GET, NULL, -1, -1,
                                             sync_bookmarks_first_time_response_cb, NULL);
  } else {
    ephy_sync_service_queue_storage_request (self, endpoint,
                                             SOUP_METHOD_GET, NULL,
                                             ephy_sync_service_get_sync_time (self), -1,
                                             sync_bookmarks_response_cb, NULL);
  }

  g_free (endpoint);
}

static gboolean
do_periodical_sync (gpointer user_data)
{
  EphySyncService *service = EPHY_SYNC_SERVICE (user_data);

  ephy_sync_service_sync_bookmarks (service, FALSE);

  return G_SOURCE_CONTINUE;
}

void
ephy_sync_service_start_periodical_sync (EphySyncService *self,
                                         gboolean         now)
{
  g_return_if_fail (EPHY_IS_SYNC_SERVICE (self));
  g_return_if_fail (ephy_sync_service_is_signed_in (self));

  if (now == TRUE)
    do_periodical_sync (self);

  self->source_id = g_timeout_add_seconds (SYNC_FREQUENCY, do_periodical_sync, self);
}

void
ephy_sync_service_stop_periodical_sync (EphySyncService *self)
{
  g_return_if_fail (EPHY_IS_SYNC_SERVICE (self));
  g_return_if_fail (ephy_sync_service_is_signed_in (self));

  if (self->source_id != 0) {
    g_source_remove (self->source_id);
    self->source_id = 0;
  }
}
