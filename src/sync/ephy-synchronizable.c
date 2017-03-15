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

enum {
  PROP_0,
  PROP_ID,
  LAST_PROP
};

static void
ephy_synchronizable_default_init (EphySynchronizableInterface *iface)
{
  iface->get_id = ephy_synchronizable_get_id;
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
 * ephy_synchronizable_to_bso:
 * @synchronizable: an #EphySynchronizable
 * @error: return location for a #GError, or %NULL
 *
 * Converts an #EphySynchronizable into its string representation
 * of a Basic Storage Object from the client's point of view
 * (i.e. the %modified field is missing). Check the BSO format documentation
 * (https://docs.services.mozilla.com/storage/apis-1.5.html#basic-storage-object)
 * for more details.
 *
 * Return value: (transfer full): @synchronizable's BSO's string representation
 **/
char *
ephy_synchronizable_to_bso (EphySynchronizable  *synchronizable,
                            GError             **error)
{
  EphySynchronizableInterface *iface;

  g_return_val_if_fail (EPHY_IS_SYNCHRONIZABLE (synchronizable), NULL);

  iface = EPHY_SYNCHRONIZABLE_GET_IFACE (synchronizable);
  return iface->to_bso (synchronizable, error);
}

/**
 * ephy_synchronizable_from_bso:
 * @bso: an #JsonObject holding the JSON representation of a Basic Storage Object
 * @gtype: the #GType of object to construct
 * @error: return location for a #GError, or %NULL
 *
 * Converts a JSON representation of a Basic Storage Object
 * from the server's point of view (i.e. the %modified field is present)
 * into an object of type @gtype. Check the BSO format documentation
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
ephy_synchronizable_from_bso (JsonObject  *bso,
                              GType        gtype,
                              GError     **error)
{
  g_return_val_if_fail (bso, NULL);

  /* TODO: Implement this. */

  return NULL;
}
