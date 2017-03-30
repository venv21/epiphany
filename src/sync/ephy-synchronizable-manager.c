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
#include "ephy-synchronizable-manager.h"

G_DEFINE_INTERFACE (EphySynchronizableManager, ephy_synchronizable_manager, G_TYPE_OBJECT);

static void
ephy_synchronizable_manager_default_init (EphySynchronizableManagerInterface *iface)
{
  iface->get_collection_name = ephy_synchronizable_manager_get_collection_name;
  iface->get_synchronizable_type = ephy_synchronizable_manager_get_synchronizable_type;
  iface->is_initial_sync = ephy_synchronizable_manager_is_initial_sync;
  iface->set_is_initial_sync = ephy_synchronizable_manager_set_is_initial_sync;
  iface->get_sync_time = ephy_synchronizable_manager_get_sync_time;
  iface->set_sync_time = ephy_synchronizable_manager_set_sync_time;
  iface->add = ephy_synchronizable_manager_add;
  iface->remove = ephy_synchronizable_manager_remove;
  iface->merge_remotes = ephy_synchronizable_manager_merge_remotes;
}

const char *
ephy_synchronizable_manager_get_collection_name (EphySynchronizableManager *manager)
{
  EphySynchronizableManagerInterface *iface;

  g_return_val_if_fail (EPHY_IS_SYNCHRONIZABLE_MANAGER (manager), NULL);

  iface = EPHY_SYNCHRONIZABLE_MANAGER_GET_IFACE (manager);
  return iface->get_collection_name (manager);
}

GType
ephy_synchronizable_manager_get_synchronizable_type (EphySynchronizableManager *manager)
{
  EphySynchronizableManagerInterface *iface;

  g_return_val_if_fail (EPHY_IS_SYNCHRONIZABLE_MANAGER (manager), 0);

  iface = EPHY_SYNCHRONIZABLE_MANAGER_GET_IFACE (manager);
  return iface->get_synchronizable_type (manager);
}

gboolean
ephy_synchronizable_manager_is_initial_sync (EphySynchronizableManager *manager)
{
  EphySynchronizableManagerInterface *iface;

  g_return_val_if_fail (EPHY_IS_SYNCHRONIZABLE_MANAGER (manager), FALSE);

  iface = EPHY_SYNCHRONIZABLE_MANAGER_GET_IFACE (manager);
  return iface->is_initial_sync (manager);
}

void
ephy_synchronizable_manager_set_is_initial_sync (EphySynchronizableManager *manager,
                                                 gboolean                   is_initial)
{
  EphySynchronizableManagerInterface *iface;

  g_return_if_fail (EPHY_IS_SYNCHRONIZABLE_MANAGER (manager));

  iface = EPHY_SYNCHRONIZABLE_MANAGER_GET_IFACE (manager);
  iface->set_is_initial_sync (manager, is_initial);
}

double
ephy_synchronizable_manager_get_sync_time (EphySynchronizableManager *manager)
{
  EphySynchronizableManagerInterface *iface;

  g_return_val_if_fail (EPHY_IS_SYNCHRONIZABLE_MANAGER (manager), 0);

  iface = EPHY_SYNCHRONIZABLE_MANAGER_GET_IFACE (manager);
  return iface->get_sync_time (manager);
}

void
ephy_synchronizable_manager_set_sync_time (EphySynchronizableManager *manager,
                                           double                     sync_time)
{
  EphySynchronizableManagerInterface *iface;

  g_return_if_fail (EPHY_IS_SYNCHRONIZABLE_MANAGER (manager));

  iface = EPHY_SYNCHRONIZABLE_MANAGER_GET_IFACE (manager);
  iface->set_sync_time (manager, sync_time);
}

void
ephy_synchronizable_manager_add (EphySynchronizableManager *manager,
                                 EphySynchronizable        *synchronizable)
{
  EphySynchronizableManagerInterface *iface;

  g_return_if_fail (EPHY_IS_SYNCHRONIZABLE_MANAGER (manager));
  g_return_if_fail (EPHY_IS_SYNCHRONIZABLE (synchronizable));

  iface = EPHY_SYNCHRONIZABLE_MANAGER_GET_IFACE (manager);
  iface->add (manager, synchronizable);
}

void
ephy_synchronizable_manager_remove (EphySynchronizableManager *manager,
                                    EphySynchronizable        *synchronizable)
{
  EphySynchronizableManagerInterface *iface;

  g_return_if_fail (EPHY_IS_SYNCHRONIZABLE_MANAGER (manager));
  g_return_if_fail (EPHY_IS_SYNCHRONIZABLE (synchronizable));

  iface = EPHY_SYNCHRONIZABLE_MANAGER_GET_IFACE (manager);
  iface->remove (manager, synchronizable);
}

void
ephy_synchronizable_manager_merge_remotes (EphySynchronizableManager  *manager,
                                           gboolean                    is_initial,
                                           GList                      *remotes_deleted,
                                           GList                      *remtoes_updated,
                                           GList                     **to_updload)
{
  EphySynchronizableManagerInterface *iface;

  g_return_if_fail (EPHY_IS_SYNCHRONIZABLE_MANAGER (manager));
  g_return_if_fail (to_updload);

  iface = EPHY_SYNCHRONIZABLE_MANAGER_GET_IFACE (manager);
  iface->merge_remotes (manager, is_initial, remotes_deleted, remtoes_updated, to_updload);
}
