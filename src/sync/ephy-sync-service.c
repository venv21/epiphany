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
#define CERTIFICATE_DURATION      (60 * 60 * 1000) /* milliseconds, limited to 24 hours */
#define ASSERTION_DURATION        (5 * 60)         /* seconds */
#define STORAGE_VERSION           5

struct _EphySyncService {
  GObject      parent_instance;

  SoupSession *session;
  guint        source_id;

  char        *uid;
  char        *sessionToken;
  char        *kB;
  GHashTable  *key_bundles;

  char        *user_email;
  double       sync_time;
  gint64       auth_at;

  gboolean     locked;
  char        *storage_endpoint;
  char        *storage_credentials_id;
  char        *storage_credentials_key;
  gint64       storage_credentials_expiry_time;
  GQueue      *storage_queue;

  char                 *certificate;
  SyncCryptoRSAKeyPair *keypair;
};

G_DEFINE_TYPE (EphySyncService, ephy_sync_service, G_TYPE_OBJECT);

enum {
  STORE_FINISHED,
  LOAD_FINISHED,
  SIGN_IN_ERROR,
  SYNC_FREQUENCY_CHANGED,
  SYNC_FINISHED,
  LAST_SIGNAL
};

static guint signals[LAST_SIGNAL];

typedef struct {
  char                *endpoint;
  char                *method;
  char                *request_body;
  double               modified_since;
  double               unmodified_since;
  SoupSessionCallback  callback;
  gpointer             user_data;
} StorageRequestAsyncData;

typedef struct {
  char   *email;
  char   *uid;
  char   *sessionToken;
  char   *unwrapBKey;
  char   *tokenID_hex;
  guint8 *reqHMACkey;
  guint8 *respHMACkey;
  guint8 *respXORkey;
} SignInAsyncData;

typedef struct {
  EphySynchronizableManager *manager;
  gboolean                   is_initial;
  guint                      collection_index;
  guint                      num_collections;
} SyncCollectionAsyncData;

typedef struct {
  EphySynchronizableManager *manager;
  EphySynchronizable        *synchronizable;
} SyncAsyncData;

static void ephy_sync_service_send_next_storage_request (EphySyncService *self);
static void ephy_sync_service_obtain_sync_key_bundles (EphySyncService *self);

static StorageRequestAsyncData *
storage_request_async_data_new (const char          *endpoint,
                                const char          *method,
                                const char          *request_body,
                                double               modified_since,
                                double               unmodified_since,
                                SoupSessionCallback  callback,
                                gpointer             user_data)
{
  StorageRequestAsyncData *data;

  data = g_slice_new (StorageRequestAsyncData);
  data->endpoint = g_strdup (endpoint);
  data->method = g_strdup (method);
  data->request_body = g_strdup (request_body);
  data->modified_since = modified_since;
  data->unmodified_since = unmodified_since;
  data->callback = callback;
  data->user_data = user_data;

  return data;
}

static void
storage_request_async_data_free (StorageRequestAsyncData *data)
{
  g_assert (data);

  g_free (data->endpoint);
  g_free (data->method);
  g_free (data->request_body);
  g_slice_free (StorageRequestAsyncData, data);
}

static SignInAsyncData *
sign_in_async_data_new (const char   *email,
                        const char   *uid,
                        const char   *sessionToken,
                        const char   *unwrapBKey,
                        const char   *tokenID_hex,
                        const guint8 *reqHMACkey,
                        const guint8 *respHMACkey,
                        const guint8 *respXORkey)
{
  SignInAsyncData *data;

  data = g_slice_new (SignInAsyncData);
  data->email = g_strdup (email);
  data->uid = g_strdup (uid);
  data->sessionToken = g_strdup (sessionToken);
  data->unwrapBKey = g_strdup (unwrapBKey);
  data->tokenID_hex = g_strdup (tokenID_hex);
  data->reqHMACkey = g_malloc (EPHY_SYNC_TOKEN_LENGTH);
  memcpy (data->reqHMACkey, reqHMACkey, EPHY_SYNC_TOKEN_LENGTH);
  data->respHMACkey = g_malloc (EPHY_SYNC_TOKEN_LENGTH);
  memcpy (data->respHMACkey, respHMACkey, EPHY_SYNC_TOKEN_LENGTH);
  data->respXORkey = g_malloc (2 * EPHY_SYNC_TOKEN_LENGTH);
  memcpy (data->respXORkey, respXORkey, 2 * EPHY_SYNC_TOKEN_LENGTH);

  return data;
}

static void
sign_in_async_data_free (SignInAsyncData *data)
{
  g_assert (data != NULL);

  g_free (data->email);
  g_free (data->uid);
  g_free (data->sessionToken);
  g_free (data->unwrapBKey);
  g_free (data->tokenID_hex);
  g_free (data->reqHMACkey);
  g_free (data->respHMACkey);
  g_free (data->respXORkey);

  g_slice_free (SignInAsyncData, data);
}

static SyncCollectionAsyncData *
sync_collection_async_data_new (EphySynchronizableManager *manager,
                                gboolean                   is_initial,
                                guint                      collection_index,
                                guint                      num_collections)
{
  SyncCollectionAsyncData *data;

  data = g_slice_new (SyncCollectionAsyncData);
  data->manager = g_object_ref (manager);
  data->is_initial = is_initial;
  data->collection_index = collection_index;
  data->num_collections = num_collections;

  return data;
}

static void
sync_collection_async_data_free (SyncCollectionAsyncData *data)
{
  g_assert (data);

  g_object_unref (data->manager);
  g_slice_free (SyncCollectionAsyncData, data);
}

static SyncAsyncData *
sync_async_data_new (EphySynchronizableManager *manager,
                     EphySynchronizable        *synchronizable)
{
  SyncAsyncData *data;

  data = g_slice_new (SyncAsyncData);
  data->manager = g_object_ref (manager);
  data->synchronizable = g_object_ref (synchronizable);

  return data;
}

static void
sync_async_data_free (SyncAsyncData *data)
{
  g_assert (data);

  g_object_unref (data->manager);
  g_object_unref (data->synchronizable);
  g_slice_free (SyncAsyncData, data);
}

static gboolean
ephy_sync_service_storage_credentials_is_expired (EphySyncService *self)
{
  g_assert (EPHY_IS_SYNC_SERVICE (self));

  if (!self->storage_credentials_id || !self->storage_credentials_key)
    return TRUE;

  if (self->storage_credentials_expiry_time == 0)
    return TRUE;

  /* Consider a 60 seconds safety interval. */
  return self->storage_credentials_expiry_time < ephy_sync_utils_current_time_seconds () - 60;
}

static void
ephy_sync_service_stop_periodical_sync (EphySyncService *self)
{
  g_assert (EPHY_IS_SYNC_SERVICE (self));

  if (self->source_id != 0) {
    g_source_remove (self->source_id);
    self->source_id = 0;
  }
}

static gboolean
ephy_sync_service_sync (gpointer user_data)
{
  EphySyncService *service = EPHY_SYNC_SERVICE (user_data);
  GList *managers = NULL;

  managers = ephy_shell_get_synchronizable_managers (ephy_shell_get_default ());
  if (managers) {
    ephy_sync_service_obtain_sync_key_bundles (service);
    g_list_free (managers);
  } else {
    g_signal_emit (service, signals[SYNC_FINISHED], 0);
  }

  return G_SOURCE_CONTINUE;
}

static void
ephy_sync_service_schedule_periodical_sync (EphySyncService *self)
{
  g_assert (EPHY_IS_SYNC_SERVICE (self));

  self->source_id = g_timeout_add_seconds (g_settings_get_uint (EPHY_SETTINGS_SYNC,
                                                                EPHY_PREFS_SYNC_FREQUENCY) * 60,
                                           ephy_sync_service_sync,
                                           self);
  LOG ("Scheduled new sync with frequency %u mins",
       g_settings_get_uint (EPHY_SETTINGS_SYNC, EPHY_PREFS_SYNC_FREQUENCY));
}

static void
ephy_sync_service_sync_frequency_changed_cb (EphySyncService *self)
{
  g_assert (EPHY_IS_SYNC_SERVICE (self));

  ephy_sync_service_stop_periodical_sync (self);
  ephy_sync_service_schedule_periodical_sync (self);
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
  SyncCryptoHawkOptions *hoptions;
  SyncCryptoHawkHeader *hheader;
  SoupMessage *msg;
  char *url;
  const char *content_type = "application/json";

  g_assert (EPHY_IS_SYNC_SERVICE (self));
  g_assert (endpoint);
  g_assert (id);
  g_assert (key);
  g_assert (request_body);

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

static void
ephy_sync_service_fxa_hawk_get_async (EphySyncService     *self,
                                      const char          *endpoint,
                                      const char          *id,
                                      guint8              *key,
                                      gsize                key_length,
                                      SoupSessionCallback  callback,
                                      gpointer             user_data)
{
  SyncCryptoHawkHeader *hheader;
  SoupMessage *msg;
  char *url;

  g_assert (EPHY_IS_SYNC_SERVICE (self));
  g_assert (endpoint);
  g_assert (id);
  g_assert (key);

  url = g_strdup_printf ("%s%s", MOZILLA_FXA_SERVER_URL, endpoint);
  msg = soup_message_new (SOUP_METHOD_GET, url);
  hheader = ephy_sync_crypto_compute_hawk_header (url, "GET", id, key, key_length, NULL);
  soup_message_headers_append (msg->request_headers, "authorization", hheader->header);
  soup_session_queue_message (self->session, msg, callback, user_data);

  g_free (url);
  ephy_sync_crypto_hawk_header_free (hheader);
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

  g_assert (EPHY_IS_SYNC_SERVICE (self));
  g_assert (certificate);

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

  if (g_strcmp0 (alg, "RS256")) {
    g_warning ("Expected algorithm RS256, found %s. Giving up.", alg);
    goto out;
  }

  json_parser_load_from_data (parser, payload, -1, NULL);
  json = json_node_get_object (json_parser_get_root (parser));
  principal = json_object_get_object_member (json, "principal");
  email = json_object_get_string_member (principal, "email");
  uid_email = g_strdup_printf ("%s@%s",
                               ephy_sync_service_get_token (self, TOKEN_UID),
                               soup_uri_get_host (uri));

  if (g_strcmp0 (uid_email, email)) {
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
obtain_storage_credentials_cb (SoupSession *session,
                               SoupMessage *msg,
                               gpointer     user_data)
{
  EphySyncService *service;
  JsonParser *parser;
  JsonObject *json;

  service = ephy_shell_get_sync_service (ephy_shell_get_default ());

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

  g_assert (EPHY_IS_SYNC_SERVICE (self));
  g_assert (self->certificate);
  g_assert (self->keypair);

  audience = ephy_sync_utils_make_audience (MOZILLA_TOKEN_SERVER_URL);
  assertion = ephy_sync_crypto_create_assertion (self->certificate, audience,
                                                 ASSERTION_DURATION, self->keypair);
  g_assert (assertion);

  kB = ephy_sync_crypto_decode_hex (ephy_sync_service_get_token (self, TOKEN_KB));
  hashed_kB = g_compute_checksum_for_data (G_CHECKSUM_SHA256, kB, EPHY_SYNC_TOKEN_LENGTH);
  client_state = g_strndup (hashed_kB, EPHY_SYNC_TOKEN_LENGTH);
  authorization = g_strdup_printf ("BrowserID %s", assertion);

  msg = soup_message_new (SOUP_METHOD_GET, MOZILLA_TOKEN_SERVER_URL);
  /* We need to add the X-Client-State header so that the Token Server will
   * recognize accounts that were previously used to sync Firefox data too. */
  soup_message_headers_append (msg->request_headers, "X-Client-State", client_state);
  soup_message_headers_append (msg->request_headers, "authorization", authorization);
  soup_session_queue_message (self->session, msg, obtain_storage_credentials_cb, NULL);

  g_free (kB);
  g_free (hashed_kB);
  g_free (client_state);
  g_free (audience);
  g_free (assertion);
  g_free (authorization);
}

static void
obtain_signed_certificate_cb (SoupSession *session,
                              SoupMessage *msg,
                              gpointer     user_data)
{
  EphySyncService *service;
  JsonParser *parser;
  JsonObject *json;
  const char *certificate;

  service = ephy_shell_get_sync_service (ephy_shell_get_default ());

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

  if (!ephy_sync_service_certificate_is_valid (service, certificate)) {
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

  g_assert (EPHY_IS_SYNC_SERVICE (self));

  /* Generate a new RSA key pair that is going to be used to sign the new certificate. */
  if (self->keypair)
    ephy_sync_crypto_rsa_key_pair_free (self->keypair);

  self->keypair = ephy_sync_crypto_generate_rsa_key_pair ();
  g_assert (self->keypair);

  /* Derive tokenID, reqHMACkey and requestKey from the sessionToken. */
  ephy_sync_crypto_process_session_token (ephy_sync_service_get_token (self, TOKEN_SESSIONTOKEN),
                                          &tokenID, &reqHMACkey, &requestKey);
  tokenID_hex = ephy_sync_crypto_encode_hex (tokenID, 0);

  n = mpz_get_str (NULL, 10, self->keypair->public.n);
  e = mpz_get_str (NULL, 10, self->keypair->public.e);
  public_key_json = ephy_sync_utils_build_json_string (FALSE, "algorithm", "RS", "n", n, "e", e, NULL);
  request_body = g_strdup_printf ("{\"publicKey\": %s, \"duration\": %d}",
                                  public_key_json, CERTIFICATE_DURATION);
  ephy_sync_service_fxa_hawk_post_async (self, "certificate/sign", tokenID_hex,
                                         reqHMACkey, EPHY_SYNC_TOKEN_LENGTH, request_body,
                                         obtain_signed_certificate_cb, NULL);

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
  SyncCryptoHawkOptions *hoptions = NULL;
  SyncCryptoHawkHeader *hheader;
  SoupMessage *msg;
  char *url;
  char *if_modified_since = NULL;
  char *if_unmodified_since = NULL;
  const char *content_type = "application/json";

  g_assert (EPHY_IS_SYNC_SERVICE (self));
  g_assert (data);

  url = g_strdup_printf ("%s/%s", self->storage_endpoint, data->endpoint);
  msg = soup_message_new (data->method, url);

  if (data->request_body) {
    hoptions = ephy_sync_crypto_hawk_options_new (NULL, NULL, NULL, content_type,
                                                  NULL, NULL, NULL, data->request_body, NULL);
    soup_message_set_request (msg, content_type, SOUP_MEMORY_COPY,
                              data->request_body, strlen (data->request_body));
  }

  if (!g_strcmp0 (data->method, SOUP_METHOD_POST))
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

  if (hoptions)
    ephy_sync_crypto_hawk_options_free (hoptions);

  g_free (url);
  g_free (if_modified_since);
  g_free (if_unmodified_since);
  ephy_sync_crypto_hawk_header_free (hheader);
  storage_request_async_data_free (data);
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
                                         const char          *endpoint,
                                         const char          *method,
                                         const char          *request_body,
                                         double               modified_since,
                                         double               unmodified_since,
                                         SoupSessionCallback  callback,
                                         gpointer             user_data)
{
  g_assert (EPHY_IS_SYNC_SERVICE (self));
  g_assert (endpoint);
  g_assert (method);

  g_queue_push_tail (self->storage_queue,
                     storage_request_async_data_new (endpoint, method, request_body,
                                                     modified_since, unmodified_since,
                                                     callback, user_data));

  ephy_sync_service_send_next_storage_request (self);
}

static void
ephy_sync_service_finalize (GObject *object)
{
  EphySyncService *self = EPHY_SYNC_SERVICE (object);

  if (self->keypair)
    ephy_sync_crypto_rsa_key_pair_free (self->keypair);

  g_queue_free_full (self->storage_queue, (GDestroyNotify) storage_request_async_data_free);
  g_hash_table_destroy (self->key_bundles);

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

  signals[SIGN_IN_ERROR] =
    g_signal_new ("sync-sign-in-error",
                  EPHY_TYPE_SYNC_SERVICE,
                  G_SIGNAL_RUN_LAST,
                  0, NULL, NULL, NULL,
                  G_TYPE_NONE, 1,
                  G_TYPE_STRING);

  signals[SYNC_FREQUENCY_CHANGED] =
    g_signal_new ("sync-frequency-changed",
                  EPHY_TYPE_SYNC_SERVICE,
                  G_SIGNAL_RUN_LAST,
                  0, NULL, NULL, NULL,
                  G_TYPE_NONE, 0);

  signals[SYNC_FINISHED] =
    g_signal_new ("sync-finished",
                  EPHY_TYPE_SYNC_SERVICE,
                  G_SIGNAL_RUN_LAST,
                  0, NULL, NULL, NULL,
                  G_TYPE_NONE, 0);
}

static void
ephy_sync_service_init (EphySyncService *self)
{
  char *email;
  const char *user_agent;
  WebKitSettings *settings;

  self->session = soup_session_new ();
  self->storage_queue = g_queue_new ();
  self->key_bundles = g_hash_table_new_full (g_str_hash, g_str_equal,
                                             NULL, (GDestroyNotify)ephy_sync_crypto_key_bundle_free);

  settings = ephy_embed_prefs_get_settings ();
  user_agent = webkit_settings_get_user_agent (settings);
  g_object_set (self->session, "user-agent", user_agent, NULL);

  email = g_settings_get_string (EPHY_SETTINGS_SYNC, EPHY_PREFS_SYNC_USER);

  if (g_strcmp0 (email, "")) {
    ephy_sync_service_set_user_email (self, email);
    ephy_sync_secret_load_tokens (self);
  }

  g_signal_connect (self, "sync-frequency-changed",
                    G_CALLBACK (ephy_sync_service_sync_frequency_changed_cb),
                    NULL);

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

const char *
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

const char *
ephy_sync_service_get_token (EphySyncService   *self,
                             EphySyncTokenType  type)
{
  g_return_val_if_fail (EPHY_IS_SYNC_SERVICE (self), NULL);

  switch (type) {
    case TOKEN_UID:
      return self->uid;
    case TOKEN_SESSIONTOKEN:
      return self->sessionToken;
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
  g_return_if_fail (value);

  switch (type) {
    case TOKEN_UID:
      g_free (self->uid);
      self->uid = g_strdup (value);
      break;
    case TOKEN_SESSIONTOKEN:
      g_free (self->sessionToken);
      self->sessionToken = g_strdup (value);
      break;
    case TOKEN_KB:
      g_free (self->kB);
      self->kB = g_strdup (value);
      break;
    default:
      g_assert_not_reached ();
  }
}

SyncCryptoKeyBundle *
ephy_sync_service_get_key_bundle (EphySyncService *self,
                                  const char      *collection)
{
  SyncCryptoKeyBundle *bundle;

  g_return_val_if_fail (EPHY_IS_SYNC_SERVICE (self), NULL);
  g_return_val_if_fail (collection, NULL);

  bundle = g_hash_table_lookup (self->key_bundles, collection);
  if (!bundle)
    bundle = g_hash_table_lookup (self->key_bundles, "default");

  return bundle;
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
  g_clear_pointer (&self->kB, g_free);
}

static void
destroy_session_cb (SoupSession *session,
                    SoupMessage *msg,
                    gpointer     user_data)
{
  if (msg->status_code != 200)
    g_warning ("Failed to destroy session. Status code: %u, response: %s",
               msg->status_code, msg->response_body->data);
  else
    LOG ("Successfully destroyed session");
}

void
ephy_sync_service_destroy_session (EphySyncService *self,
                                   const char      *sessionToken)
{
  SyncCryptoHawkOptions *hoptions;
  SyncCryptoHawkHeader *hheader;
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

  if (!sessionToken) {
    sessionToken = ephy_sync_service_get_token (self, TOKEN_SESSIONTOKEN);
    if (!sessionToken) {
      g_warning ("Cannot destroy session: missing sessionToken");
      return;
    }
  }

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
  soup_session_queue_message (self->session, msg, destroy_session_cb, NULL);

  ephy_sync_crypto_hawk_options_free (hoptions);
  ephy_sync_crypto_hawk_header_free (hheader);
  g_free (tokenID_hex);
  g_free (tokenID);
  g_free (reqHMACkey);
  g_free (requestKey);
  g_free (url);
}

static void
ephy_sync_service_report_sign_in_error (EphySyncService *self,
                                        const char      *message,
                                        gboolean         clear_tokens)
{
  g_assert (EPHY_IS_SYNC_SERVICE (self));
  g_assert (message);

  g_signal_emit (self, signals[SIGN_IN_ERROR], 0, message);
  ephy_sync_service_destroy_session (self, NULL);

  if (clear_tokens) {
    ephy_sync_service_set_user_email (self, NULL);
    ephy_sync_service_clear_tokens (self);
  }
}

static void
check_storage_version_cb (SoupSession *session,
                          SoupMessage *msg,
                          gpointer     user_data)
{
  EphySyncService *service;
  JsonParser *parser;
  JsonObject *json;
  char *payload;
  char *message;
  int storage_version;

  service = ephy_shell_get_sync_service (ephy_shell_get_default ());

  if (msg->status_code != 200) {
    g_warning ("Failed to check storage version. Status code: %u, response: %s",
               msg->status_code, msg->response_body->data);
    ephy_sync_service_report_sign_in_error (service,
                                            _("Something went wrong, please try again."),
                                            TRUE);
    goto out;
  }

  parser = json_parser_new ();
  json_parser_load_from_data (parser, msg->response_body->data, -1, NULL);
  json = json_node_get_object (json_parser_get_root (parser));
  payload = g_strdup (json_object_get_string_member (json, "payload"));
  json_parser_load_from_data (parser, payload, -1, NULL);
  json = json_node_get_object (json_parser_get_root (parser));
  storage_version = json_object_get_int_member (json, "storageVersion");

  /* If the storage version is correct, proceed to store the tokens.
   * Otherwise, signal the error to the user. */
  if (storage_version == STORAGE_VERSION) {
    ephy_sync_secret_store_tokens (service);
  } else {
    LOG ("Unsupported storage version: %d", storage_version);
    /* Translators: the %d is the storage version, the \n is a newline character. */
    message = g_strdup_printf (_("Your Firefox Account uses a storage version "
                                       "that Epiphany does not support, namely v%d.\n"
                                       "Create a new account to use the latest storage version."),
                                     storage_version);
    ephy_sync_service_report_sign_in_error (service, message, TRUE);
    g_free (message);
  }

  g_free (payload);
  g_object_unref (parser);

out:
  ephy_sync_service_send_next_storage_request (service);
}

static void
ephy_sync_service_check_storage_version (EphySyncService *self)
{
  g_assert (EPHY_IS_SYNC_SERVICE (self));

  ephy_sync_service_queue_storage_request (self, "storage/meta/global",
                                           SOUP_METHOD_GET, NULL, -1, -1,
                                           check_storage_version_cb, NULL);
}

static void
ephy_sync_service_conclude_sign_in (EphySyncService *self,
                                    SignInAsyncData *data,
                                    const char      *bundle)
{
  guint8 *unwrapKB;
  guint8 *kA;
  guint8 *kB;
  char *kB_hex;

  g_assert (EPHY_IS_SYNC_SERVICE (self));
  g_assert (data);
  g_assert (bundle);

  /* Derive the master sync keys form the key bundle. */
  unwrapKB = ephy_sync_crypto_decode_hex (data->unwrapBKey);
  ephy_sync_crypto_compute_sync_keys (bundle, data->respHMACkey,
                                      data->respXORkey, unwrapKB,
                                      &kA, &kB);
  kB_hex = ephy_sync_crypto_encode_hex (kB, 0);

  /* Save the email and the tokens. */
  ephy_sync_service_set_user_email (self, data->email);
  ephy_sync_service_set_token (self, data->uid, TOKEN_UID);
  ephy_sync_service_set_token (self, data->sessionToken, TOKEN_SESSIONTOKEN);
  ephy_sync_service_set_token (self, kB_hex, TOKEN_KB);

  ephy_sync_service_check_storage_version (self);

  g_free (kA);
  g_free (kB);
  g_free (kB_hex);
  g_free (unwrapKB);
  sign_in_async_data_free (data);
}

static void
get_account_keys_cb (SoupSession *session,
                     SoupMessage *msg,
                     gpointer     user_data)
{
  EphySyncService *service;
  SignInAsyncData *data;
  JsonParser *parser;
  JsonObject *json;

  service = ephy_shell_get_sync_service (ephy_shell_get_default ());
  data = (SignInAsyncData *)user_data;
  parser = json_parser_new ();
  json_parser_load_from_data (parser, msg->response_body->data, -1, NULL);
  json = json_node_get_object (json_parser_get_root (parser));

  if (msg->status_code == 200) {
    /* Extract the master sync keys from the bundle and save tokens. */
    ephy_sync_service_conclude_sign_in (service, data,
                                        json_object_get_string_member (json, "bundle"));
  } else if (msg->status_code == 400 && json_object_get_int_member (json, "errno") == 104) {
    /* Poll the Firefox Accounts Server until the user verifies the account. */
    LOG ("Account not verified, retrying...");
    ephy_sync_service_fxa_hawk_get_async (service, "account/keys", data->tokenID_hex,
                                          data->reqHMACkey, EPHY_SYNC_TOKEN_LENGTH,
                                          get_account_keys_cb, data);
  } else {
    g_warning ("Failed to GET /account/keys. Status code: %u, response: %s",
               msg->status_code, msg->response_body->data);
    ephy_sync_service_report_sign_in_error (service,
                                            _("Failed to retrieve the Sync Key"),
                                            FALSE);
    sign_in_async_data_free (data);
  }

  g_object_unref (parser);
}

void
ephy_sync_service_do_sign_in (EphySyncService *self,
                              const char      *email,
                              const char      *uid,
                              const char      *sessionToken,
                              const char      *keyFetchToken,
                              const char      *unwrapBKey)
{
  SignInAsyncData *data;
  guint8 *tokenID;
  guint8 *reqHMACkey;
  guint8 *respHMACkey;
  guint8 *respXORkey;
  char *tokenID_hex;

  g_return_if_fail (EPHY_IS_SYNC_SERVICE (self));
  g_return_if_fail (email);
  g_return_if_fail (uid);
  g_return_if_fail (sessionToken);
  g_return_if_fail (keyFetchToken);
  g_return_if_fail (unwrapBKey);

  /* Derive tokenID, reqHMACkey, respHMACkey and respXORkey from keyFetchToken.
   * tokenID and reqHMACkey are used to sign a HAWK GET requests to the /account/keys
   * endpoint. The server looks up the stored table entry with tokenID, checks
   * the request HMAC for validity, then returns the pre-encrypted response.
   * See https://github.com/mozilla/fxa-auth-server/wiki/onepw-protocol#fetching-sync-keys */
  ephy_sync_crypto_process_key_fetch_token (keyFetchToken,
                                            &tokenID, &reqHMACkey,
                                            &respHMACkey, &respXORkey);
  tokenID_hex = ephy_sync_crypto_encode_hex (tokenID, 0);

  /* Get the master sync key bundle from the /account/keys endpoint. */
  data = sign_in_async_data_new (email, uid, sessionToken,
                                 unwrapBKey, tokenID_hex,
                                 reqHMACkey, respHMACkey, respXORkey);
  ephy_sync_service_fxa_hawk_get_async (self, "account/keys", tokenID_hex,
                                        reqHMACkey, EPHY_SYNC_TOKEN_LENGTH,
                                        get_account_keys_cb, data);

  g_free (tokenID_hex);
}

void
ephy_sync_service_do_sign_out (EphySyncService *self)
{
  g_return_if_fail (EPHY_IS_SYNC_SERVICE (self));

  /* Destroy session and delete tokens. */
  ephy_sync_service_stop_periodical_sync (self);
  ephy_sync_service_destroy_session (self, NULL);
  ephy_sync_service_clear_storage_credentials (self);
  ephy_sync_service_clear_tokens (self);
  ephy_sync_secret_forget_tokens ();
  ephy_sync_service_set_user_email (self, NULL);

  g_settings_set_string (EPHY_SETTINGS_SYNC, EPHY_PREFS_SYNC_USER, "");
}

static void
delete_synchronizable_cb (SoupSession *session,
                          SoupMessage *msg,
                          gpointer     user_data)
{
  EphySyncService *service;

  if (msg->status_code == 200) {
    LOG ("Successfully deleted from server");
  } else {
    g_warning ("Failed to delete object. Status code: %u, response: %s",
               msg->status_code, msg->response_body->data);
  }

  service = ephy_shell_get_sync_service (ephy_shell_get_default ());
  ephy_sync_service_send_next_storage_request (service);
}

void
ephy_sync_service_delete_synchronizable (EphySyncService           *self,
                                         EphySynchronizableManager *manager,
                                         EphySynchronizable        *synchronizable)
{
  char *endpoint;
  const char *collection;
  const char *id;

  g_assert (EPHY_IS_SYNC_SERVICE (self));
  g_assert (EPHY_IS_SYNCHRONIZABLE_MANAGER (manager));
  g_assert (EPHY_IS_SYNCHRONIZABLE (synchronizable));

  id = ephy_synchronizable_get_id (synchronizable);
  collection = ephy_synchronizable_manager_get_collection_name (manager);
  endpoint = g_strdup_printf ("storage/%s/%s", collection, id);

  LOG ("Deleting object with id %s...", id);
  ephy_sync_service_queue_storage_request (self, endpoint,
                                           SOUP_METHOD_DELETE, NULL, -1, -1,
                                           delete_synchronizable_cb, NULL);

  g_free (endpoint);
}

static void
download_synchronizable_cb (SoupSession *session,
                            SoupMessage *msg,
                            gpointer     user_data)
{
  EphySyncService *service;
  EphySynchronizable *synchronizable;
  SyncCryptoKeyBundle *bundle;
  SyncAsyncData *data;
  JsonParser *parser;
  JsonObject *bso;
  GError *error = NULL;
  GType type;
  const char *collection;
  gboolean is_deleted;

  data = (SyncAsyncData *)user_data;
  service = ephy_shell_get_sync_service (ephy_shell_get_default ());

  if (msg->status_code != 200) {
    g_warning ("Failed to download object. Status code: %u, response: %s",
               msg->status_code, msg->response_body->data);
    goto out;
  }

  parser = json_parser_new ();
  json_parser_load_from_data (parser, msg->response_body->data, -1, &error);
  if (error) {
    g_warning ("Response is not a valid JSON");
    g_error_free (error);
    goto free_parser;
  }
  if (!JSON_NODE_HOLDS_OBJECT (json_parser_get_root (parser))) {
    g_warning ("JSON root does not hold a JSON object");
    goto free_parser;
  }

  bso = json_node_get_object (json_parser_get_root (parser));
  type = ephy_synchronizable_manager_get_synchronizable_type (data->manager);
  collection = ephy_synchronizable_manager_get_collection_name (data->manager);
  bundle = ephy_sync_service_get_key_bundle (service, collection);
  synchronizable = EPHY_SYNCHRONIZABLE (ephy_synchronizable_from_bso (bso, type, bundle, &is_deleted));
  if (!synchronizable) {
    g_warning ("Failed to create synchronizable object from BSO");
    goto free_parser;
  }

  /* Delete the local object and add the remote one if it is not marked as deleted. */
  ephy_synchronizable_manager_remove (data->manager, data->synchronizable);
  if (!is_deleted) {
    ephy_synchronizable_manager_add (data->manager, synchronizable);
    LOG ("Successfully downloaded from server");
  } else {
    g_object_unref (synchronizable);
  }

  g_object_unref (synchronizable);
free_parser:
  g_object_unref (parser);
out:
  sync_async_data_free (data);
  ephy_sync_service_send_next_storage_request (service);
}

static void
ephy_sync_service_download_synchronizable (EphySyncService           *self,
                                           EphySynchronizableManager *manager,
                                           EphySynchronizable        *synchronizable)
{
  SyncAsyncData *data;
  char *endpoint;
  const char *collection;
  const char *id;

  g_assert (EPHY_IS_SYNC_SERVICE (self));
  g_assert (EPHY_IS_SYNCHRONIZABLE_MANAGER (manager));
  g_assert (EPHY_IS_SYNCHRONIZABLE (synchronizable));

  id = ephy_synchronizable_get_id (synchronizable);
  collection = ephy_synchronizable_manager_get_collection_name (manager);
  endpoint = g_strdup_printf ("storage/%s/%s", collection, id);
  data = sync_async_data_new (manager, synchronizable);

  LOG ("Downloading object with id %s...", id);
  ephy_sync_service_queue_storage_request (self, endpoint,
                                           SOUP_METHOD_GET, NULL, -1, -1,
                                           download_synchronizable_cb, data);

  g_free (endpoint);
}

static void
upload_synchronizable_cb (SoupSession *session,
                          SoupMessage *msg,
                          gpointer     user_data)
{
  EphySyncService *service;
  SyncAsyncData *data;
  double modified;

  data = (SyncAsyncData *)user_data;
  service = ephy_shell_get_sync_service (ephy_shell_get_default ());

  /* Code 412 means that there is a more recent version of the object
   * on the server. Download it. */
  if (msg->status_code == 412) {
    LOG ("Found a newer version of the object on the server, downloading it...");
    ephy_sync_service_download_synchronizable (service, data->manager, data->synchronizable);
  } else if (msg->status_code == 200) {
    LOG ("Successfully uploaded to server");
    modified = g_ascii_strtod (msg->response_body->data, NULL);
    /* FIXME: Make sure the synchronizable manager commits this change to file/database. */
    ephy_synchronizable_set_modification_time (data->synchronizable, modified);
  } else {
    g_warning ("Failed to upload object. Status code: %u, response: %s",
               msg->status_code, msg->response_body->data);
  }

  sync_async_data_free (data);
  ephy_sync_service_send_next_storage_request (service);
}

static void
ephy_sync_service_upload_synchronizable (EphySyncService           *self,
                                         EphySynchronizableManager *manager,
                                         EphySynchronizable        *synchronizable)
{
  SyncAsyncData *data;
  char *bso;
  char *endpoint;
  const char *collection;
  const char *id;

  g_assert (EPHY_IS_SYNC_SERVICE (self));
  g_assert (EPHY_IS_SYNCHRONIZABLE_MANAGER (manager));
  g_assert (EPHY_IS_SYNCHRONIZABLE (synchronizable));

  collection = ephy_synchronizable_manager_get_collection_name (manager);
  bso = ephy_synchronizable_to_bso (synchronizable,
                                    ephy_sync_service_get_key_bundle (self, collection));
  if (!bso) {
    g_warning ("Failed to convert synchronizable to BSO");
    return;
  }

  id = ephy_synchronizable_get_id (synchronizable);
  endpoint = g_strdup_printf ("storage/%s/%s", collection, id);
  data = sync_async_data_new (manager, synchronizable);

  LOG ("Uploading object with id %s...", id);
  ephy_sync_service_queue_storage_request (self, endpoint, SOUP_METHOD_PUT, bso, -1,
                                           ephy_synchronizable_get_modification_time (synchronizable),
                                           upload_synchronizable_cb, data);

  g_free (endpoint);
  g_free (bso);
}

static void
sync_collection_cb (SoupSession *session,
                    SoupMessage *msg,
                    gpointer     user_data)
{
  EphySyncService *service;
  SyncCollectionAsyncData *data;
  EphySynchronizable *remote;
  SyncCryptoKeyBundle *bundle;
  JsonParser *parser = NULL;
  JsonArray *array;
  JsonNode *node;
  JsonObject *object;
  GError *error = NULL;
  GList *remotes_updated = NULL;
  GList *remotes_deleted = NULL;
  GList *to_upload;
  GType type;
  const char *collection;
  const char *timestamp;
  gboolean is_deleted;

  service = ephy_shell_get_sync_service (ephy_shell_get_default ());
  data = (SyncCollectionAsyncData *)user_data;
  collection = ephy_synchronizable_manager_get_collection_name (data->manager);

  /* Code 304 means that the collection has not been modified. */
  if (msg->status_code == 304) {
    LOG ("There are no new remote objects");
    goto merge_remotes;
  }

  if (msg->status_code != 200) {
    g_warning ("Failed to get records in collection %s. Status code: %u, response: %s",
               collection, msg->status_code, msg->response_body->data);
    goto out;
  }

  parser = json_parser_new ();
  json_parser_load_from_data (parser, msg->response_body->data, -1, &error);
  if (error) {
    g_warning ("Response is not a valid JSON: %s", error->message);
    g_error_free (error);
    goto free_parser;
  }
  if (!JSON_NODE_HOLDS_ARRAY (json_parser_get_root (parser))) {
    g_warning ("JSON root does not hold an array");
    goto free_parser;
  }

  type = ephy_synchronizable_manager_get_synchronizable_type (data->manager);
  bundle = ephy_sync_service_get_key_bundle (service, collection);
  array = json_node_get_array (json_parser_get_root (parser));

  for (guint i = 0; i < json_array_get_length (array); i++) {
    node = json_array_get_element (array, i);
    if (!JSON_NODE_HOLDS_OBJECT (node)) {
      g_warning ("Array member does not hold a JSON object, skipping...");
      continue;
    }
    object = json_node_get_object (node);
    remote = EPHY_SYNCHRONIZABLE (ephy_synchronizable_from_bso (object, type, bundle, &is_deleted));
    if (!remote) {
      g_warning ("Failed to create synchronizable object from BSO, skipping...");
      continue;
    }
    if (is_deleted)
      remotes_deleted = g_list_prepend (remotes_deleted, remote);
    else
      remotes_updated = g_list_prepend (remotes_updated, remote);
  }

merge_remotes:
  to_upload = ephy_synchronizable_manager_merge_remotes (data->manager, data->is_initial,
                                                         remotes_deleted, remotes_updated);

  if (to_upload) {
    LOG ("Uploading local objects to server...");
    for (GList *l = to_upload; l && l->data; l = l->next) {
      ephy_sync_service_upload_synchronizable (service, data->manager,
                                               EPHY_SYNCHRONIZABLE (l->data));
    }
  }

  ephy_synchronizable_manager_set_is_initial_sync (data->manager, FALSE);
  /* Update sync time. */
  timestamp = soup_message_headers_get_one (msg->response_headers, "X-Weave-Timestamp");
  ephy_synchronizable_manager_set_sync_time (data->manager, g_ascii_strtod (timestamp, NULL));

  g_list_free_full (to_upload, g_object_unref);
  g_list_free_full (remotes_updated, g_object_unref);
  g_list_free_full (remotes_deleted, g_object_unref);
free_parser:
  if (parser)
    g_object_unref (parser);
out:
  if (data->collection_index == data->num_collections)
    g_signal_emit (service, signals[SYNC_FINISHED], 0);

  sync_collection_async_data_free (data);
  ephy_sync_service_send_next_storage_request (service);
}

static void
ephy_sync_service_sync_collection (EphySyncService           *self,
                                   EphySynchronizableManager *manager,
                                   guint                      collection_index,
                                   guint                      num_collections)
{
  SyncCollectionAsyncData *data;
  const char *collection;
  char *endpoint;
  gboolean is_initial;

  g_assert (EPHY_IS_SYNC_SERVICE (self));
  g_assert (EPHY_IS_SYNCHRONIZABLE_MANAGER (manager));

  collection = ephy_synchronizable_manager_get_collection_name (manager);
  endpoint = g_strdup_printf ("storage/%s?full=true", collection);
  is_initial = ephy_synchronizable_manager_is_initial_sync (manager);
  data = sync_collection_async_data_new (manager, is_initial, collection_index, num_collections);

  LOG ("Syncing %s collection...", collection);
  ephy_sync_service_queue_storage_request (self, endpoint, SOUP_METHOD_GET, NULL,
                                           is_initial ? -1 : ephy_synchronizable_manager_get_sync_time (manager),
                                           -1, sync_collection_cb, data);

  g_free (endpoint);
}

static void
obtain_sync_key_bundles_cb (SoupSession *session,
                            SoupMessage *msg,
                            gpointer     user_data)
{
  EphySyncService *service;
  SyncCryptoKeyBundle *bundle;
  JsonParser *parser;
  JsonObject *json;
  JsonObject *collections;
  JsonNode *node;
  JsonArray *array;
  JsonObjectIter iter;
  GError *error = NULL;
  GList *managers = NULL;
  const char *member;
  const char *payload;
  char *record;
  guint8 *kB;
  gboolean sync_finished = TRUE;

  service = ephy_shell_get_sync_service (ephy_shell_get_default ());

  if (msg->status_code != 200) {
    /* TODO: Generate and upload new sync key bundles. */
    g_warning ("Failed to get crypto/keys record. Status code: %u, response: %s",
               msg->status_code, msg->response_body->data);
    goto out;
  }

  parser = json_parser_new ();
  json_parser_load_from_data (parser, msg->response_body->data, -1, &error);
  if (error) {
    g_warning ("Response is not a valid JSON: %s", error->message);
    g_error_free (error);
    goto free_parser;
  }
  if (!JSON_NODE_HOLDS_OBJECT (json_parser_get_root (parser))) {
    g_warning ("JSON root does not hold an array");
    goto free_parser;
  }
  json = json_node_get_object (json_parser_get_root (parser));
  if (!json_object_has_member (json, "payload")) {
    g_warning ("JSON object is missing 'payload' member");
    goto free_parser;
  }
  payload = json_object_get_string_member (json, "payload");

  /* Derive the Sync Key bundle from kB. The bundle consists of two 32 bytes keys:
   * the first one used as a symmetric encryption key (AES) and the second one
   * used as a HMAC key. */
  kB = ephy_sync_crypto_decode_hex (ephy_sync_service_get_token (service, TOKEN_KB));
  bundle = ephy_sync_crypto_derive_key_bundle (kB, EPHY_SYNC_TOKEN_LENGTH);

  record = ephy_sync_crypto_decrypt_record (payload, bundle);
  if (!record) {
    /* TODO: Notify user to sign in again. */
    g_warning ("Failed to decrypt crypto keys record");
    goto free_bundle;
  }

  json_parser_load_from_data (parser, record, -1, &error);
  if (error) {
    g_warning ("Failed to parse JSON from record: %s", error->message);
    g_error_free (error);
    goto free_record;
  }
  if (!JSON_NODE_HOLDS_OBJECT (json_parser_get_root (parser))) {
    g_warning ("JSON root does not hold a JSON object");
    goto free_record;
  }
  json = json_node_get_object (json_parser_get_root (parser));

  /* Get the default key bundle. This must be always present. */
  if (!json_object_has_member (json, "default")) {
    g_warning ("Record is missing default keys");
    goto free_record;
  }
  if (!JSON_NODE_HOLDS_ARRAY (json_object_get_member (json, "default"))) {
    g_warning ("Default keys are not a JSON array");
    goto free_record;
  }
  array = json_object_get_array_member (json, "default");
  if (json_array_get_length (array) != 2) {
    g_warning ("Expected 2 default keys, found %u", json_array_get_length (array));
    goto free_record;
  }

  g_hash_table_insert (service->key_bundles,
                       (char *)"default",
                       ephy_sync_crypto_key_bundle_from_array (array));

  /* Get the per-collection key bundles, if any. */
  if (json_object_has_member (json, "collections")) {
    if (JSON_NODE_HOLDS_OBJECT (json_object_get_member (json, "collections"))) {
      collections = json_object_get_object_member (json, "collections");
      json_object_iter_init (&iter, collections);
      while (json_object_iter_next (&iter, &member, &node)) {
        if (!JSON_NODE_HOLDS_ARRAY (node))
          continue;

        array = json_node_get_array (node);
        if (json_array_get_length (array) == 2) {
          g_hash_table_insert (service->key_bundles,
                               (char *)member,
                               ephy_sync_crypto_key_bundle_from_array (array));
        }
      }
    }
  }

  /* Successfully retrieved key bundles, sync collections. */
  managers = ephy_shell_get_synchronizable_managers (ephy_shell_get_default ());
  if (managers) {
    guint num_managers = g_list_length (managers);
    guint index = 1;

    for (GList *l = managers; l && l->data; l = l->next, index++)
      ephy_sync_service_sync_collection (service,
                                         EPHY_SYNCHRONIZABLE_MANAGER (l->data),
                                         index, num_managers);

    g_list_free (managers);
    sync_finished = FALSE;
  }

free_record:
  g_free (record);
free_bundle:
  ephy_sync_crypto_key_bundle_free (bundle);
  g_free (kB);
free_parser:
  g_object_unref (parser);
out:
  if (sync_finished)
    g_signal_emit (service, signals[SYNC_FINISHED], 0);

  ephy_sync_service_send_next_storage_request (service);
}

static void
ephy_sync_service_obtain_sync_key_bundles (EphySyncService *self)
{
  g_assert (EPHY_IS_SYNC_SERVICE (self));

  g_hash_table_remove_all (self->key_bundles);
  ephy_sync_service_queue_storage_request (self, "storage/crypto/keys",
                                           SOUP_METHOD_GET, NULL, -1, -1,
                                           obtain_sync_key_bundles_cb, NULL);
}

void
ephy_sync_service_do_sync (EphySyncService *self)
{
  g_return_if_fail (EPHY_IS_SYNC_SERVICE (self));
  g_return_if_fail (ephy_sync_service_is_signed_in (self));

  ephy_sync_service_sync (self);
}

void
ephy_sync_service_start_periodical_sync (EphySyncService *self)
{
  g_return_if_fail (EPHY_IS_SYNC_SERVICE (self));
  g_return_if_fail (ephy_sync_service_is_signed_in (self));

  ephy_sync_service_sync (self);
  ephy_sync_service_schedule_periodical_sync (self);
}
