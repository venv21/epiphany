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

#pragma once

#include "ephy-sync-crypto.h"

#include <glib-object.h>
#include <json-glib/json-glib.h>

G_BEGIN_DECLS

#define EPHY_TYPE_SYNCHRONIZABLE (ephy_synchronizable_get_type ())

/* FIXME: This needs to be defined manually for json-glib < 1.2.4
 * G_DEFINE_AUTOPTR_CLEANUP_FUNC (JsonSerializable, g_object_unref)
 */

G_DECLARE_INTERFACE (EphySynchronizable, ephy_synchronizable, EPHY, SYNCHRONIZABLE, JsonSerializable)

struct _EphySynchronizableInterface {
  GTypeInterface parent_iface;

  const char * (*get_id)                  (EphySynchronizable  *synchronizable);
  void         (*set_id)                  (EphySynchronizable  *synchronizable,
                                           const char          *id);

  double       (*get_modification_time)   (EphySynchronizable  *synchronizable);
  void         (*set_modification_time)   (EphySynchronizable  *synchronizable,
                                           double               modified);

  gboolean     (*is_uploaded)             (EphySynchronizable  *synchronizable);
  void         (*set_is_uploaded)         (EphySynchronizable  *synchronizable,
                                           gboolean             uploaded);

  char *       (*to_bso)                  (EphySynchronizable  *synchronizable,
                                           SyncCryptoKeyBundle *bundle);
};

const char          *ephy_synchronizable_get_id                 (EphySynchronizable  *synchronizable);
void                 ephy_synchronizable_set_id                 (EphySynchronizable  *synchronizable,
                                                                 const char          *id);
double               ephy_synchronizable_get_modification_time  (EphySynchronizable  *synchronizable);
void                 ephy_synchronizable_set_modification_time  (EphySynchronizable  *synchronizable,
                                                                 double               modified);
gboolean             ephy_synchronizable_is_uploaded            (EphySynchronizable  *synchronizable);
void                 ephy_synchronizable_set_is_uploaded        (EphySynchronizable  *synchronizable,
                                                                 gboolean             uploaded);
char                *ephy_synchronizable_to_bso                 (EphySynchronizable  *synchronizable,
                                                                 SyncCryptoKeyBundle *bundle);
/* This can't be an interface method because we lack the EphySynchronizable object.
 * Think of it as more of an utility function. */
GObject             *ephy_synchronizable_from_bso               (JsonObject          *bso,
                                                                 GType                gtype,
                                                                 SyncCryptoKeyBundle *bundle);

G_END_DECLS
