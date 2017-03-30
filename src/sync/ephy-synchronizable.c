/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/*
 *  Copyright © 2017 Gabriel Ivascu <ivascu.gabriel59@gmail.com>
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
#include "ephy-synchronizable.h"

G_DEFINE_INTERFACE (EphySynchronizable, ephy_synchronizable, JSON_TYPE_SERIALIZABLE);

static void
ephy_synchronizable_default_init (EphySynchronizableInterface *iface)
{
  iface->get_id = ephy_synchronizable_get_id;
  iface->get_modification_time = ephy_synchronizable_get_modification_time;
  iface->set_modification_time = ephy_synchronizable_set_modification_time;
  iface->is_uploaded = ephy_synchronizable_is_uploaded;
  iface->set_is_uploaded = ephy_synchronizable_set_is_uploaded;
  iface->to_bso = ephy_synchronizable_to_bso;

  g_object_interface_install_property (iface,
                                       g_param_spec_string ("id",
                                                            "ID",
                                                            "The record's id",
                                                            "112233445566",
                                                            G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
}

/**
 * ephy_synchronizable_get_id:
 * @synchronizable: an #EphySynchronizable
 *
 * Returns @synchronizable's id.
 *
 * Return value: (transfer none): @synchronizable's id
 **/
const char *
ephy_synchronizable_get_id (EphySynchronizable *synchronizable)
{
  EphySynchronizableInterface *iface;

  g_return_val_if_fail (EPHY_IS_SYNCHRONIZABLE (synchronizable), NULL);

  iface = EPHY_SYNCHRONIZABLE_GET_IFACE (synchronizable);
  return iface->get_id (synchronizable);
}

/**
 * ephy_synchronizable_set_id:
 * @synchronizable: an #EphySynchronizable
 * @id: @synchronizable's new id
 *
 * Sets @id as @synchronizable's id.
 **/
void
ephy_synchronizable_set_id (EphySynchronizable *synchronizable,
                            const char         *id)
{
  EphySynchronizableInterface *iface;

  g_return_if_fail (EPHY_IS_SYNCHRONIZABLE (synchronizable));

  iface = EPHY_SYNCHRONIZABLE_GET_IFACE (synchronizable);
  iface->set_id (synchronizable, id);
}

/**
 * ephy_synchronizable_get_modification_time:
 * @synchronizable: an #EphySynchronizable
 *
 * Returns @synchronizable's last modification time.
 *
 * Return value: @synchronizable's last modification time
 **/
double
ephy_synchronizable_get_modification_time (EphySynchronizable *synchronizable)
{
  EphySynchronizableInterface *iface;

  g_return_val_if_fail (EPHY_IS_SYNCHRONIZABLE (synchronizable), 0);

  iface = EPHY_SYNCHRONIZABLE_GET_IFACE (synchronizable);
  return iface->get_modification_time (synchronizable);
}

/**
 * ephy_synchronizable_set_modification_time:
 * @synchronizable: an #EphySynchronizable
 * @modified: the last modification time
 *
 * Sets @modified as @synchronizable's last modification time.
 **/
void
ephy_synchronizable_set_modification_time (EphySynchronizable *synchronizable,
                                           double              modified)
{
  EphySynchronizableInterface *iface;

  g_return_if_fail (EPHY_IS_SYNCHRONIZABLE (synchronizable));

  iface = EPHY_SYNCHRONIZABLE_GET_IFACE (synchronizable);
  iface->set_modification_time (synchronizable, modified);
}

/**
 * ephy_synchronizable_is_uploaded:
 * @synchronizable: an #EphySynchronizable
 *
 * Returns TRUE is @synchronizable is uploaded to server, FALSE otherwise.
 *
 * Return value: TRUE if @synchronizable is uploaded, FALSE otherwise
 **/
gboolean
ephy_synchronizable_is_uploaded (EphySynchronizable *synchronizable)
{
  EphySynchronizableInterface *iface;

  g_return_val_if_fail (EPHY_IS_SYNCHRONIZABLE (synchronizable), FALSE);

  iface = EPHY_SYNCHRONIZABLE_GET_IFACE (synchronizable);
  return iface->is_uploaded (synchronizable);
}

/**
 * ephy_synchronizable_set_is_uploaded:
 * @synchronizable: an #EphySynchronizable
 * @uploaded: TRUE if @synchronizable is uploaded to server, FALSE otherwise
 *
 * Sets @synchronizable's uploaded flag.
 **/
void
ephy_synchronizable_set_is_uploaded (EphySynchronizable *synchronizable,
                                     gboolean            uploaded)
{
  EphySynchronizableInterface *iface;

  g_return_if_fail (EPHY_IS_SYNCHRONIZABLE (synchronizable));

  iface = EPHY_SYNCHRONIZABLE_GET_IFACE (synchronizable);
  iface->set_is_uploaded (synchronizable, uploaded);
}

/**
 * ephy_synchronizable_to_bso:
 * @synchronizable: an #EphySynchronizable
 * @bundle: a %SyncCryptoKeyBundle holding the encryption key and the HMAC key
 *          used to validate and encrypt the Basic Storage Object
 *
 * Converts an #EphySynchronizable into its JSON string representation
 * of a Basic Storage Object from the client's point of view
 * (i.e. the %modified field is missing). Check the BSO format documentation
 * (https://docs.services.mozilla.com/storage/apis-1.5.html#basic-storage-object)
 * for more details.
 *
 * Return value: (transfer full): @synchronizable's BSO's JSON string representation
 **/
char *
ephy_synchronizable_to_bso (EphySynchronizable  *synchronizable,
                            SyncCryptoKeyBundle *bundle)
{
  EphySynchronizableInterface *iface;

  g_return_val_if_fail (EPHY_IS_SYNCHRONIZABLE (synchronizable), NULL);
  g_return_val_if_fail (bundle, NULL);

  iface = EPHY_SYNCHRONIZABLE_GET_IFACE (synchronizable);
  return iface->to_bso (synchronizable, bundle);
}

/**
 * ephy_synchronizable_from_bso:
 * @bso: a JSON object representing the Basic Storage Object
 * @gtype: the #GType of object to construct
 * @bundle: a %SyncCryptoKeyBundle holding the encryption key and the HMAC key
 *          used to validate and decrypt the Basic Storage Object
 * @is_deleted: return value for a flag that shows whether the object is marked as deleted
 *
 * Converts a JSON object representing the Basic Storage Object
 * from the server's point of view (i.e. the %modified field is present)
 * into an object of type @gtype. See the BSO format documentation
 * (https://docs.services.mozilla.com/storage/apis-1.5.html#basic-storage-object)
 * for more details.
 *
 * Note: The @gtype must be a sub-type of #EphySynchronizable (i.e. must
 * implement the #EphySynchronizable interface). It is up to the caller to cast
 * the returned #GObject to the type of @gtype.
 *
 *  Return value: (transfer full): a #GObject or %NULL
 **/
GObject *
ephy_synchronizable_from_bso (JsonObject          *bso,
                              GType                gtype,
                              SyncCryptoKeyBundle *bundle,
                              gboolean            *is_deleted)
{
  GObject *object = NULL;
  GError *error = NULL;
  JsonParser *parser;
  JsonObject *json;
  char *serialized;
  const char *payload;
  double modified;

  g_return_val_if_fail (bso, NULL);
  g_return_val_if_fail (bundle, NULL);
  g_return_val_if_fail (is_deleted, NULL);

  if (!json_object_has_member (bso, "id") ||
      !json_object_has_member (bso, "payload") ||
      !json_object_has_member (bso, "modified")) {
    g_warning ("BSO has missing members");
    goto out;
  }

  payload = json_object_get_string_member (bso, "payload");
  modified = json_object_get_double_member (bso, "modified");
  serialized = ephy_sync_crypto_decrypt_record (payload, bundle);
  if (!serialized) {
    g_warning ("Failed to decrypt the BSO payload");
    goto out;
  }

  parser = json_parser_new ();
  json_parser_load_from_data (parser, serialized, -1, &error);
  if (error) {
    g_warning ("Decrypted text is not a valid JSON: %s", error->message);
    g_error_free (error);
    goto free_parser;
  }
  if (!JSON_NODE_HOLDS_OBJECT (json_parser_get_root (parser))) {
    g_warning ("JSON root does not hold a JSON object");
    goto free_parser;
  }
  json = json_node_get_object (json_parser_get_root (parser));
  if (json_object_has_member (json, "deleted")) {
    if (JSON_NODE_HOLDS_VALUE (json_object_get_member (json, "deleted")))
      *is_deleted = json_object_get_boolean_member (json, "deleted");
  } else {
    *is_deleted = FALSE;
  }

  object = json_gobject_from_data (gtype, serialized, -1, &error);
  if (error) {
    g_warning ("Failed to create GObject from BSO: %s", error->message);
    g_error_free (error);
    goto free_parser;
  }

  ephy_synchronizable_set_modification_time (EPHY_SYNCHRONIZABLE (object), modified);
  ephy_synchronizable_set_is_uploaded (EPHY_SYNCHRONIZABLE (object), TRUE);

free_parser:
  g_object_unref (parser);
  g_free (serialized);
out:
  return object;
}
