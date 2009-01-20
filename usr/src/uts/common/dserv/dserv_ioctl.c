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

#include <sys/dserv_impl.h>

#include <sys/sdt.h>
#include <sys/list.h>
#include <nfs/nfs4.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/model.h>
#include <nfs/ds.h>

static dev_info_t	*dserv_dip;
extern int dserv_debug;

static int
dserv_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	/*
	 * Do we really need the DDI_RESUME?  zfs_attach doesn't have it.
	 */
	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	if (ddi_create_minor_node(dip, "dserv", S_IFCHR, 0,
	    DDI_PSEUDO, 0) == DDI_FAILURE)
		return (DDI_FAILURE);

	dserv_server_setup();
	dserv_mds_setup();

	dserv_dip = dip;
	return (DDI_SUCCESS);
}

static int
dserv_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	/*
	 * Do we really need DDI_SUSPEND?  zfs_detach doesn't have it.
	 */
	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	dserv_mds_teardown();
	dserv_server_teardown();

	/* Is the following required? */
	dserv_dip = NULL;

	ddi_remove_minor_node(dip, NULL);
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
dserv_open(dev_t *devp, int flag, int otyp, cred_t *cred_p)
{
	return (0);
}

/*ARGSUSED*/
static int
dserv_info(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	int error;

	switch (infocmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = (void *)dserv_dip;
		error = DDI_SUCCESS;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)0;
		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;
	}
	return (error);
}

/*
 * The set of ioctls supported are:
 * DSERV_IOC_DATASET_INFO - accepts a dataset which will be for use by the
 *	data server (Will be going away in lieu of DSERV_IOC_DATASET_PROPS.)
 * DSERV_IOC_DATASET_PROPS - accepts a dataset for use by the data server
 * DSERV_IOC_INSTANCE_SHUTDOWN - tells the data server that an instance
 *	is going down (i.e. the administrator has shut down the service).
 * DSERV_IOC_REPORTAVAIL - tells the data server to call DS_REPORTAVAIL
 * DSERV_IOC_SVC - starts up the dserv server
 * DSERV_IOC_SETMDS - Tells the data server what MDS to use (Will be going
 *	away in lieu of DSERV_IOC_DATASET_PROPS.)
 * DSERV_IOC_SETPORT - tells the data server that its listening at the
 *      given port
 */
/* ARGSUSED */
static int
dserv_ioctl(dev_t dev, int cmd, intptr_t arg, int flag, cred_t *cr, int *rvalp)
{
	int error = 0;

	switch (cmd) {

	case DSERV_IOC_DATASET_INFO: {
		dserv_dataset_info_t dinfo;

		error = ddi_copyin((void *)arg, &dinfo,
		    sizeof (dserv_dataset_info_t), flag);
		if (error)
			return (EFAULT);

		error = dserv_mds_addobjset(dinfo.dataset_name);
		break;
	}

	case DSERV_IOC_DATASET_PROPS: {
		dserv_dataset_props_t dprops;

		error = ddi_copyin((void *)arg, &dprops,
		    sizeof (dserv_dataset_props_t), flag);
		if (error)
			return (EFAULT);
		DTRACE_PROBE3(dserv__i__dataset_props,
		    char *, dprops.ddp_name,
		    char *, dprops.ddp_mds_netid,
		    char *, dprops.ddp_mds_uaddr);
		break;
	}

	case DSERV_IOC_INSTANCE_SHUTDOWN: {
		error = dserv_mds_instance_teardown();
		break;
	}

	case DSERV_IOC_REPORTAVAIL: {
		error = dserv_mds_reportavail();
		break;
	}

	case DSERV_IOC_SVC: {
		dserv_svc_args_t svcargs;

		error = ddi_copyin((void *)arg, &svcargs,
		    sizeof (dserv_svc_args_t), flag);
		if (error)
			return (EFAULT);

		error =	dserv_svc(&svcargs);
		break;
	}

	case DSERV_IOC_SETMDS: {
		dserv_setmds_args_t smargs;

		error = ddi_copyin((void *)arg, &smargs,
		    sizeof (dserv_setmds_args_t), flag);
		if (error)
			return (EFAULT);

		DTRACE_PROBE2(dserv__i__ioc_setmds,
		    char *, smargs.dsm_mds_uaddr, char *, smargs.dsm_mds_netid);

		error = dserv_mds_setmds(smargs.dsm_mds_netid,
		    smargs.dsm_mds_uaddr);
		break;
	}

	case DSERV_IOC_SETPORT: {
		dserv_setport_args_t spargs;

		error = ddi_copyin((void *)arg, &spargs,
		    sizeof (dserv_setport_args_t), flag);
		if (error)
			return (EFAULT);

		DTRACE_PROBE2(dserv__i__ioc_setport, char *, spargs.dsa_uaddr,
		    char *, spargs.dsa_proto);

		error = dserv_mds_addport(spargs.dsa_uaddr, spargs.dsa_proto,
		    spargs.dsa_name);
		break;
	}

	default:
		return (ENOTTY);
	}

	return (error);
}

static struct cb_ops dserv_cb_ops = {
	dserv_open,		/* open */
	nodev,			/* close */
	nulldev,		/* strategy */
	nulldev,		/* print */
	nodev,			/* dump */
	nodev,			/* read */
	nodev,			/* write */
	dserv_ioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	nochpoll,		/* poll */
	ddi_prop_op,		/* cb_prop_op */
	0,			/* streamtab  */
	D_NEW | D_MP		/* Driver compatibility flag */
};

static struct dev_ops dserv_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* refcnt */
	dserv_info,		/* get_dev_info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	dserv_attach,		/* attach */
	dserv_detach,		/* detach */
	nodev,			/* reset */
	&dserv_cb_ops,		/* driver operations */
	NULL,			/* bus operations */
	nodev			/* dev power */
};

/*
 * Module linkage information for the kernel.
 */
static struct modldrv modldrv = {
	&mod_driverops,		/* module type (this is a pseudo driver) */
	"Parallel NFS Data Server",	/* name of module */
	&dserv_ops		/* driver ops */
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}
