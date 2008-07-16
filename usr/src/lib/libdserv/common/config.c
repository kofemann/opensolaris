/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "libdserv_impl.h"

static scf_propertygroup_t *
dserv_handle_pg(dserv_handle_t *handle, const char *pgname)
{
	scf_propertygroup_t *rc =
	    scf_pg_create(handle->dsh_scf_handle);

	if (rc == NULL)
		goto scferr;

	if (handle->dsh_scf_instance == NULL) {
		handle->dsh_error = DSERV_ERR_NOINSTANCE;
		scf_pg_destroy(rc);
		return (NULL);
	}
	if (scf_instance_get_pg(handle->dsh_scf_instance,
	    pgname, rc) == 0)
		return (rc);
	handle->dsh_scf_error = scf_error();
	if (handle->dsh_scf_error != SCF_ERROR_NOT_FOUND) {
		handle->dsh_error = DSERV_ERR_SCF;
		scf_pg_destroy(rc);
		return (NULL);
	}
	if (scf_instance_add_pg(handle->dsh_scf_instance, pgname, "application",
	    0, rc) == 0)
		return (rc);

scferr:
	handle->dsh_error = DSERV_ERR_SCF;
	handle->dsh_scf_error = scf_error();
	if (rc != NULL)
		scf_pg_destroy(rc);

	return (NULL);
}

static scf_iter_t *
dserv_pg_property_iter(dserv_handle_t *handle,
    scf_propertygroup_t *pg, const char *propname, scf_iter_t *iter)
{
	scf_property_t *prop = NULL;
	int result;

	if (iter != NULL)
		scf_iter_reset(iter);
	else if ((iter = scf_iter_create(handle->dsh_scf_handle)) == NULL)
		goto scferr;

	if ((prop = scf_property_create(handle->dsh_scf_handle)) == NULL)
		goto scferr;

	result = scf_pg_get_property(pg, propname, prop);
	handle->dsh_scf_error = scf_error();

	if ((result == -1) && (handle->dsh_scf_error == SCF_ERROR_NOT_FOUND)) {
		scf_property_destroy(prop);
		scf_iter_destroy(iter);
		return (NULL);
	} else if (result != 0) {
		goto scferr;
	}

	if (scf_iter_property_values(iter, prop) == -1)
		goto scferr;

	scf_property_destroy(prop);

	return (iter);

scferr:
	handle->dsh_scf_error = scf_error();
	handle->dsh_error = DSERV_ERR_SCF;
	if (prop != NULL)
		scf_property_destroy(prop);
	if (iter != NULL)
		scf_iter_destroy(iter);
	return (NULL);
}

/*
 * The mds property values is just a single Metadata Server's universal
 * address.  The data server can only know of one Metadata Server at a time.
 * therefore, his function enforces the rule that there can only be one
 * Metadata Server address existing at a time.
 */
static int
dserv_addmds_enforce_rule(dserv_handle_t *handle,
    scf_transaction_entry_t *newprop, const char *propval)
{
	scf_iter_t *oldmds = NULL;
	scf_value_t *value = NULL;
	int result;

	/*
	 * If dserv_pg_property_iter returns NULL and no error it means
	 * that there is no "mds" property in existence yet.
	 */
	oldmds = dserv_pg_property_iter(handle, handle->dsh_pg_storage,
	    DSERV_PROP_MDS, NULL);
	if ((oldmds == NULL)) {
		if (handle->dsh_error != DSERV_ERR_NONE)
			goto scferr;
		else
			return (0);
	} else if (oldmds != NULL) {
		/*
		 * A property can exist, but not have any values associated
		 * with it.  Therefore, make sure to check if there are
		 * values even if oldmds is not equal to NULL.
		 */
		value = scf_value_create(handle->dsh_scf_handle);
		if (value == NULL)
			goto scferr;

		result = scf_iter_next_value(oldmds, value);
		if (result == -1)
			goto scferr;
		else if (result == 1) {
			/*
			 * There can only be one MDS property entry at a time.
			 * So, if one already exists, return an error.
			 */
			scf_value_destroy(value);
			scf_iter_destroy(oldmds);
			handle->dsh_error = DSERV_ERR_MDS_EXISTS;
			return (-1);
		} else if (result == 0) {
			scf_iter_destroy(oldmds);
			oldmds = NULL;
			return (0);
		}
	}

scferr:
	handle->dsh_scf_error = scf_error();
	handle->dsh_error = DSERV_ERR_SCF;
	if (oldmds != NULL)
		scf_iter_destroy(oldmds);
	if (value != NULL)
		scf_value_destroy(value);
	return (-1);

}

static int
dserv_addpool_enforce_rule(dserv_handle_t *handle,
    scf_transaction_entry_t *newprop, const char *propval)
{
	scf_iter_t *oldzpools = NULL;
	scf_value_t *value = NULL;
	int result;

	oldzpools = dserv_pg_property_iter(handle,
	    handle->dsh_pg_storage, DSERV_PROP_ZPOOLS, NULL);
	if (oldzpools == NULL) {
		if (handle->dsh_error != DSERV_ERR_NONE)
			goto scferr;
		else
			return (0);
	} else if (oldzpools != NULL) {
		value = scf_value_create(handle->dsh_scf_handle);
		if (value == NULL)
			goto scferr;

		for (result = scf_iter_next_value(oldzpools, value);
		    result == 1;
		    result = scf_iter_next_value(oldzpools, value)) {
			char buffy[MAXNAMELEN]; /* XXX */
			if (scf_value_get_astring(value,
			    buffy, sizeof (buffy)) == -1)
				goto scferr;
			if (strcmp(propval, buffy) == 0) {
				scf_value_destroy(value);
				scf_iter_destroy(oldzpools);
				handle->dsh_error = DSERV_ERR_DUPLICATE_DATASET;
				return (-1);
			}

			if (scf_entry_add_value(newprop, value) == -1)
				goto scferr;
			/*
			 * value successfully added to entry.  It will
			 * be destroyed with either its entry or with the
			 * transaction.  We need a new value for the next
			 * thing to be added.
			 */
			value = scf_value_create(handle->dsh_scf_handle);
			if (value == NULL)
				goto scferr;
		}
		scf_iter_destroy(oldzpools);
		oldzpools = NULL;
	}

	if (result == -1)
		goto scferr;
	else
		return (0);

scferr:
	handle->dsh_scf_error = scf_error();
	handle->dsh_error = DSERV_ERR_SCF;
	if (oldzpools != NULL)
		scf_iter_destroy(oldzpools);
	if (value != NULL)
		scf_value_destroy(value);
	return (-1);
}

/*
 * propname will be either DSERV_PROP_ZPOOLS or DSERV_PROP_MDS.
 *
 * propval will be a zpool name if propname is DSERV_PROP_ZPOOLS, propval
 * will be a universal address identifying the metadata server if
 * propname is DSERV_PROP_MDS.
 */
int
dserv_addprop(dserv_handle_t *handle, const char *propname,
    const char *propval)
{
	scf_transaction_t *tx = NULL;
	scf_transaction_entry_t *newprop = NULL;
	scf_value_t *value = NULL;
	int result;

	if ((strcmp(propname, DSERV_PROP_ZPOOLS) != 0) &&
	    (strcmp(propname, DSERV_PROP_MDS) != 0)) {
		handle->dsh_error = DSERV_ERR_INVALID_PROP;
		return (-1);
	}

	if (handle->dsh_pg_storage == NULL)
		handle->dsh_pg_storage = dserv_handle_pg(handle, "storage");
	if (handle->dsh_pg_storage == NULL)
		return (-1);

	tx = scf_transaction_create(handle->dsh_scf_handle);
	if (tx == NULL)
		goto scferr;

retry:
	newprop = scf_entry_create(handle->dsh_scf_handle);
	if (newprop == NULL)
		goto scferr;

	if (scf_pg_update(handle->dsh_pg_storage) == -1)
		goto scferr;

	if (scf_transaction_start(tx, handle->dsh_pg_storage) == -1)
		goto scferr;

	if (scf_transaction_property_change_type(tx, newprop,
	    propname, SCF_TYPE_ASTRING) == -1) {
		handle->dsh_scf_error = scf_error();
		if (handle->dsh_scf_error != SCF_ERROR_NOT_FOUND) {
			handle->dsh_error = DSERV_ERR_SCF;
			scf_transaction_destroy(tx);
			scf_entry_destroy(newprop);
			return (-1);
		}
		if (scf_transaction_property_new(tx, newprop,
		    propname, SCF_TYPE_ASTRING) == -1)
			goto scferr;
	}

	/*
	 * Each data server property may have a different set of rules
	 * to enforce (i.e. there can only be one property entry, etc.).
	 * Enforce those property rules here.
	 */
	if (strcmp(propname, DSERV_PROP_ZPOOLS) == 0) {
		result = dserv_addpool_enforce_rule(handle, newprop, propval);
	} else if (strcmp(propname, DSERV_PROP_MDS) == 0) {
		result = dserv_addmds_enforce_rule(handle, newprop, propval);
	}

	if (result == -1) {
		scf_entry_destroy_children(newprop);
		scf_transaction_destroy(tx);
		return (-1);
	}

	if (value == NULL)
		value = scf_value_create(handle->dsh_scf_handle);
	if (value == NULL)
		goto scferr;
	if (scf_value_set_astring(value, propval) == -1)
		goto scferr;
	if (scf_entry_add_value(newprop, value) == -1)
		goto scferr;
	/*
	 * value will be destroyed with its entry or transaction.
	 * prevent double-destroying it.
	 */
	value = NULL;

	result = scf_transaction_commit(tx);

	if (result == -1)
		goto scferr;

	if (result == 0) {
		scf_transaction_destroy_children(tx);
		scf_transaction_reset(tx);
		goto retry;
	}

	scf_transaction_destroy_children(tx);
	scf_transaction_destroy(tx);

	return (0);

scferr:
	handle->dsh_scf_error = scf_error();
	handle->dsh_error = DSERV_ERR_SCF;
	if (newprop != NULL) {
		scf_entry_destroy_children(newprop);
		scf_entry_destroy(newprop);
	}
	if (value != NULL)
		scf_value_destroy(value);
	if (tx != NULL)
		scf_transaction_destroy(tx);
	return (-1);
}

int
dserv_dropprop(dserv_handle_t *handle, const char *propname,
    const char *propval)
{
	scf_transaction_t *tx = NULL;
	scf_transaction_entry_t *newprop = NULL;
	scf_value_t *value = NULL;
	scf_iter_t *oldprops = NULL;
	int found = 0;
	int result;

	if ((strcmp(propname, DSERV_PROP_ZPOOLS) != 0) &&
	    (strcmp(propname, DSERV_PROP_MDS) != 0)) {
		handle->dsh_error = DSERV_ERR_INVALID_PROP;
		return (-1);
	}

	if (handle->dsh_pg_storage == NULL)
		handle->dsh_pg_storage = dserv_handle_pg(handle, "storage");
	if (handle->dsh_pg_storage == NULL)
		return (-1);
	tx = scf_transaction_create(handle->dsh_scf_handle);
	if (tx == NULL)
		goto scferr;
retry:
	if (scf_pg_update(handle->dsh_pg_storage) == -1)
		goto scferr;
	oldprops = dserv_pg_property_iter(handle, handle->dsh_pg_storage,
	    propname, NULL);
	if ((oldprops == NULL) && (handle->dsh_error != DSERV_ERR_NONE))
		return (-1);
	if (oldprops == NULL) {
		if (strcmp(propname, DSERV_PROP_ZPOOLS) == 0)
			handle->dsh_error = DSERV_ERR_DATASET_NOT_FOUND;
		else {
			handle->dsh_error = DSERV_ERR_MDS_NOT_FOUND;
		}
		scf_transaction_destroy(tx);
		return (-1);
	}

	newprop = scf_entry_create(handle->dsh_scf_handle);
	if (newprop == NULL)
		goto scferr;

	if (scf_transaction_start(tx, handle->dsh_pg_storage) == -1)
		goto scferr;
	if (scf_transaction_property_change_type(tx,
	    newprop, propname, SCF_TYPE_ASTRING) == -1)
		goto scferr;

	value = scf_value_create(handle->dsh_scf_handle);
	if (value == NULL)
		goto scferr;

	if (strcmp(propname, DSERV_PROP_ZPOOLS) == 0) {
		for (result = scf_iter_next_value(oldprops, value);
		    result == 1;
		    result = scf_iter_next_value(oldprops, value)) {
			char buffy[MAXNAMELEN];

			if (scf_value_get_astring(value, buffy,
			    sizeof (buffy)) == -1)
				goto scferr;
			if (strcmp(buffy, propval) == 0)
				found = 1;
			else if (scf_entry_add_value(newprop, value) == -1)
				goto scferr;
			value = scf_value_create(handle->dsh_scf_handle);
			if (value == NULL)
				goto scferr;
		}
	} else {
		result = scf_iter_next_value(oldprops, value);
		/*
		 * If result is:
		 * -1: We have run into an error
		 *  1: We have found a MDS in the list.
		 *	This will be the one we will remove.
		 *  0: We have not found a MDS in the list.
		 *	Therefore, there is no MDS to remove.
		 */
		if (result == 1)
			found = 1;
	}

	if (result == -1)
		goto scferr;
	scf_iter_destroy(oldprops);
	oldprops = NULL;
	scf_value_destroy(value);
	value = NULL;

	if (! found) {
		scf_transaction_destroy_children(tx);
		scf_transaction_destroy(tx);
		if (strcmp(propname, DSERV_PROP_ZPOOLS) == 0)
			handle->dsh_error = DSERV_ERR_DATASET_NOT_FOUND;
		else
			handle->dsh_error = DSERV_ERR_MDS_NOT_FOUND;

		return (-1);
	}

	result = scf_transaction_commit(tx);
	if (result == -1)
		goto scferr;
	if (result == 0) {
		scf_transaction_destroy_children(tx);
		newprop = NULL;
		scf_transaction_reset(tx);
		goto retry;
	}

	scf_transaction_destroy_children(tx);
	scf_transaction_destroy(tx);

	return (0);

scferr:
	handle->dsh_scf_error = scf_error();
	handle->dsh_error = DSERV_ERR_SCF;
	if (oldprops != NULL)
		scf_iter_destroy(oldprops);
	if (newprop != NULL) {
		scf_entry_destroy_children(newprop);
		scf_entry_destroy(newprop);
	}
	if (value != NULL)
		scf_value_destroy(value);
	if (tx != NULL)
		scf_transaction_destroy(tx);
	return (-1);
}

char *
dserv_firstpool(dserv_handle_t *handle)
{
	if (handle->dsh_pg_storage == NULL)
		handle->dsh_pg_storage = dserv_handle_pg(handle, "storage");
	if (handle->dsh_pg_storage == NULL)
		return (NULL);
	if (scf_pg_update(handle->dsh_pg_storage) == -1)
		goto scferr;

	handle->dsh_iter_zpools = dserv_pg_property_iter(handle,
	    handle->dsh_pg_storage, DSERV_PROP_ZPOOLS, handle->dsh_iter_zpools);
	if (handle->dsh_iter_zpools == NULL)
		return (NULL);

	return (dserv_nextpool(handle));

scferr:
	handle->dsh_scf_error = scf_error();
	handle->dsh_error = DSERV_ERR_SCF;
	return (NULL);
}

char *
dserv_nextpool(dserv_handle_t *handle)
{
	scf_value_t *zpool = scf_value_create(handle->dsh_scf_handle);
	int state;

	if (zpool == NULL)
		goto scferr;
	state = scf_iter_next_value(handle->dsh_iter_zpools, zpool);
	if (state == -1)
		goto scferr;
	if (state == 0) {
		scf_value_destroy(zpool);
		return (NULL);
	}

	if (scf_value_get_astring(zpool, handle->dsh_astring,
	    sizeof (handle->dsh_astring)) == -1)
		goto scferr;

	return (handle->dsh_astring);

scferr:
	handle->dsh_scf_error = scf_error();
	handle->dsh_error = DSERV_ERR_SCF;
	if (zpool != NULL)
		scf_value_destroy(zpool);
	return (NULL);
}

char *
dserv_getmds(dserv_handle_t *handle)
{
	scf_value_t *mds;
	scf_iter_t *mds_iter = NULL;
	int state;

	if (handle->dsh_pg_storage == NULL)
		handle->dsh_pg_storage = dserv_handle_pg(handle, "storage");
	if (handle->dsh_pg_storage == NULL)
		return (NULL);
	if (scf_pg_update(handle->dsh_pg_storage) == -1)
		goto scferr;

	mds_iter = dserv_pg_property_iter(handle, handle->dsh_pg_storage,
	    DSERV_PROP_MDS, mds_iter);
	if (mds_iter == NULL)
		return (NULL);

	mds = scf_value_create(handle->dsh_scf_handle);
	if (mds == NULL)
		goto scferr;

	state = scf_iter_next_value(mds_iter, mds);
	if (state == -1)
		goto scferr;
	if (state == 0) {
		scf_value_destroy(mds);
		return (NULL);
	}

	if (scf_value_get_astring(mds, handle->dsh_astring,
	    sizeof (handle->dsh_astring)) == -1)
		goto scferr;

	return (handle->dsh_astring);

scferr:
	handle->dsh_scf_error = scf_error();
	handle->dsh_error = DSERV_ERR_SCF;
	if (mds != NULL)
		scf_value_destroy(mds);
	return (NULL);
}
