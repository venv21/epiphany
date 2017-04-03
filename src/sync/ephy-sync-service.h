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

#pragma once

#include "ephy-bookmark.h"
#include "ephy-sync-utils.h"

#include <glib-object.h>
#include <libsoup/soup.h>

G_BEGIN_DECLS

#define EPHY_TYPE_SYNC_SERVICE (ephy_sync_service_get_type ())

G_DECLARE_FINAL_TYPE (EphySyncService, ephy_sync_service, EPHY, SYNC_SERVICE, GObject)

EphySyncService *ephy_sync_service_new                          (void);
gboolean         ephy_sync_service_is_signed_in                 (EphySyncService *self);
char            *ephy_sync_service_get_user_email               (EphySyncService *self);
void             ephy_sync_service_set_user_email               (EphySyncService *self,
                                                                 const char      *email);
double           ephy_sync_service_get_sync_time                (EphySyncService *self);
void             ephy_sync_service_set_sync_time                (EphySyncService *self,
                                                                 double           time);
char            *ephy_sync_service_get_token                    (EphySyncService   *self,
                                                                 EphySyncTokenType  type);
void             ephy_sync_service_set_token                    (EphySyncService   *self,
                                                                 const char        *value,
                                                                 EphySyncTokenType  type);
void             ephy_sync_service_clear_storage_credentials    (EphySyncService *self);
void             ephy_sync_service_clear_tokens                 (EphySyncService *self);
void             ephy_sync_service_destroy_session              (EphySyncService *self,
                                                                 const char      *sessionToken);
void             ephy_sync_service_do_sign_in                   (EphySyncService *self,
                                                                 const char      *email,
                                                                 const char      *uid,
                                                                 const char      *sessionToken,
                                                                 const char      *keyFetchToken,
                                                                 const char      *unwrapBKey);
void             ephy_sync_service_upload_bookmark              (EphySyncService *self,
                                                                 EphyBookmark    *bookmark,
                                                                 gboolean         force);
void             ephy_sync_service_download_bookmark            (EphySyncService *self,
                                                                 EphyBookmark    *bookmark);
void             ephy_sync_service_delete_bookmark              (EphySyncService *self,
                                                                 EphyBookmark    *bookmark,
                                                                 gboolean         conditional);
void             ephy_sync_service_sync_bookmarks               (EphySyncService *self,
                                                                 gboolean         first);
void             ephy_sync_service_start_periodical_sync        (EphySyncService *self,
                                                                 gboolean         now);
void             ephy_sync_service_stop_periodical_sync         (EphySyncService *self);

G_END_DECLS
