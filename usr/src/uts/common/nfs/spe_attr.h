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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SPE_ATTR_H
#define	_SPE_ATTR_H

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct attribute_table {
	char		*at_name;
	int		at_len;
	spe_attributes	at_attr;
} attribute_table;

/*
 * XXX: While these are global, they do not need
 * to go into server instances.
 */
attribute_table spe_attribute_table[] = {
	{ "base", 5, SPE_ATTR_BASE },
	{ "day", 4, SPE_ATTR_DAY },
	{ "domain", 7, SPE_ATTR_DOMAIN },
	{ "ext", 4, SPE_ATTR_EXTENSION },
	{ "file", 5, SPE_ATTR_FILE },
	{ "fqdn", 5, SPE_ATTR_FQDN },
	{ "gid", 4, SPE_ATTR_GID },
	{ "group", 6, SPE_ATTR_GROUP },
	{ "hour", 5, SPE_ATTR_HOUR },
	{ "host", 5, SPE_ATTR_HOST },
	{ "ip", 3, SPE_ATTR_IP },
	{ "path", 5, SPE_ATTR_PATH },
	{ "subnet", 7, SPE_ATTR_SUBNET },
	{ "uid", 4, SPE_ATTR_UID },
	{ "user", 5, SPE_ATTR_USER },
	{ "weekday", 8, SPE_ATTR_WEEKDAY },
};

int Attribute_count = sizeof (spe_attribute_table) / sizeof (attribute_table);

char *Spe_ops_list[] = {
	"&&",
	"||",
	"!",
	"==",
	"!=",
	NULL
};

char *Spe_weekdays[] = {
	"sun",
	"mon",
	"tue",
	"wed",
	"thu",
	"fri",
	"sat",
	NULL
};

#define	SPE_WEEKDAY_LEN		3

#define	SPE_HOSTNAME_BUF	256

#ifdef	__cplusplus
}
#endif

#endif /* _SPE_ATTR_H */
