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

/*
 * AUDIO CONTROL Driver:
 * This driver is derived from the legacy SADA streams-based usb_ac driver
 * and serves as an intermediate measure before the full conversion to the
 * to the Boomer framework in a follow-on phase of the Boomer project, which
 * will utilize more comprehensive USB audio features as well.  Multiplexor
 * plumbing functionality that used to be in the usb_ac_dacf DACF module is
 * now located here.
 *
 * usb_ac is a multiplexor that sits on top of usb_as and hid and is
 * responsible for (1) providing the entry points to audio mixer framework,
 * (2) passing control commands to and from usb_as and hid and (3) processing
 * control messages from hid/usb_ah that it can handle.
 *
 * 1. Mixer entry points are: usb_ac_setup(), usb_ac_teardown(),
 *	usb_ac_set_config(), usb_ac_set_format(), usb_ac_start_play(),
 *	usb_ac_pause_play(), usb_ac_stop_play, usb_ac_start_record(),
 *	usb_ac_stop_record().
 * 2. usb_ac is a streams driver that passes streams messages down to
 *	usb_as that selects the correct alternate with passed format
 *	parameters, sets sample frequency, starts play/record, stops
 *	play/record, pause play/record, open/close isoc pipe.
 * 3. usb_ac handles the set_config command through the default pipe
 *	of sound control interface of the audio device in a synchronous
 *	manner.
 *
 * Serialization: A competing thread can't be allowed to interfere with
 * (1) pipe, (2) streams state.
 * So we need some kind of serialization among the asynchronous
 * threads that can run in the driver. The serialization is mostly
 * needed to avoid races among open/close/events/power entry points
 * etc. Once a routine takes control, it checks if the resource (pipe or
 * stream or dev state) is still accessible. If so, it proceeds with
 * its job and until it completes, no other thread requiring the same
 * resource can run.
 *
 * PM model in usb_ac: Raise power during attach. If a device is not at full
 * power, raise power in the entry points. After the command is over,
 * pm_idle_component() is called. The power is lowered in detach().
 */
#include <sys/usb/usba/usbai_version.h>
#include <sys/usb/usba.h>
#include <sys/stropts.h>
#include <sys/sunndi.h>
#include <sys/ndi_impldefs.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunldi.h>

#include <sys/audio.h>
#include <sys/audio/audio_support.h>
#include <sys/mixer.h>
#include <sys/audio/audio_mixer.h>

#include <sys/usb/clients/audio/usb_audio.h>
#include <sys/usb/clients/audio/usb_mixer.h>
#include <sys/usb/clients/audio/usb_ac/usb_ac.h>

/* for getting the minor node info from hid */
#include <sys/usb/clients/hid/hidminor.h>
#include <sys/usb/clients/audio/usb_as/usb_as.h>

#include "audio_shim.h"

/* debug support */
uint_t	usb_ac_errlevel 	= USB_LOG_L4;
uint_t	usb_ac_errmask		= (uint_t)-1;
uint_t	usb_ac_instance_debug	= (uint_t)-1;

/*
 * wait period in seconds for the HID message processing thread
 * used primarily to check when the stream has closed
 */
uint_t usb_ac_wait_hid = 1;

/*
 * table for converting term types of input and output terminals
 * to SADA port types (pretty rough mapping)
 */
static struct {
	ushort_t	term_type;
	ushort_t	port_type;
} usb_ac_term_type_map[] = {
{ USB_AUDIO_TERM_TYPE_STREAMING,	AUDIO_LINE_IN|AUDIO_LINE_OUT },
{ USB_AUDIO_TERM_TYPE_MICROPHONE,		AUDIO_MICROPHONE },
{ USB_AUDIO_TERM_TYPE_DT_MICROPHONE,		AUDIO_MICROPHONE },
{ USB_AUDIO_TERM_TYPE_PERS_MICROPHONE,		AUDIO_MICROPHONE },
{ USB_AUDIO_TERM_TYPE_OMNI_DIR_MICROPHONE,	AUDIO_MICROPHONE },
{ USB_AUDIO_TERM_TYPE_MICROPHONE_ARRAY,		AUDIO_MICROPHONE },
{ USB_AUDIO_TERM_TYPE_PROCESSING_MIC_ARRAY,	AUDIO_MICROPHONE },
{ USB_AUDIO_TERM_TYPE_SPEAKER,			AUDIO_SPEAKER },
{ USB_AUDIO_TERM_TYPE_HEADPHONES,		AUDIO_HEADPHONE },
{ USB_AUDIO_TERM_TYPE_DISPLAY_AUDIO,		AUDIO_LINE_OUT },
{ USB_AUDIO_TERM_TYPE_DT_SPEAKER,		AUDIO_SPEAKER },
{ USB_AUDIO_TERM_TYPE_ROOM_SPEAKER,		AUDIO_SPEAKER },
{ USB_AUDIO_TERM_TYPE_COMM_SPEAKER,		AUDIO_SPEAKER },
{ USB_AUDIO_TERM_TYPE_LF_EFFECTS_SPEAKER,	AUDIO_SPEAKER },
{ USB_AUDIO_TERM_TYPE_HANDSET,		AUDIO_LINE_IN|AUDIO_LINE_OUT },
{ USB_AUDIO_TERM_TYPE_HEADSET,		AUDIO_LINE_IN|AUDIO_LINE_OUT },
{ USB_AUDIO_TERM_TYPE_SPEAKERPHONE,	AUDIO_LINE_IN|AUDIO_LINE_OUT },
{ USB_AUDIO_TERM_TYPE_ECHO_SUPP_SPEAKERPHONE,
					AUDIO_LINE_IN|AUDIO_LINE_OUT },
{ USB_AUDIO_TERM_TYPE_ECHO_CANCEL_SPEAKERPHONE,
					AUDIO_LINE_IN|AUDIO_LINE_OUT },
{ USB_AUDIO_TERM_TYPE_PHONE_LINE,	AUDIO_LINE_IN|AUDIO_LINE_OUT },
{ USB_AUDIO_TERM_TYPE_TELEPHONE,	AUDIO_LINE_IN|AUDIO_LINE_OUT },
{ USB_AUDIO_TERM_TYPE_DOWN_LINE_PHONE,	AUDIO_LINE_IN|AUDIO_LINE_OUT },
{ USB_AUDIO_TERM_TYPE_ANALOG_CONNECTOR,	AUDIO_LINE_IN|AUDIO_LINE_OUT },
{ USB_AUDIO_TERM_TYPE_DIGITAL_AUDIO_IF,	AUDIO_LINE_IN|AUDIO_LINE_OUT },
{ USB_AUDIO_TERM_TYPE_LINE_CONNECTOR,	AUDIO_LINE_IN|AUDIO_LINE_OUT },
{ USB_AUDIO_TERM_TYPE_LEGACY_AUDIO_CONNECTOR,
					AUDIO_LINE_IN|AUDIO_LINE_OUT },
{ USB_AUDIO_TERM_TYPE_SPDIF_IF,		AUDIO_SPDIF_IN },
{ USB_AUDIO_TERM_TYPE_1394_DA_STREAM,
					AUDIO_LINE_IN|AUDIO_LINE_OUT },
{ USB_AUDIO_TERM_TYPE_1394_DV_STREAM_SNDTRCK,
					AUDIO_LINE_IN|AUDIO_LINE_OUT },
{ 0, 0 }
};


/*
 * Module linkage routines for the kernel
 */
static int	usb_ac_attach(dev_info_t *, ddi_attach_cmd_t);
static int	usb_ac_detach(dev_info_t *, ddi_detach_cmd_t);
static int	usb_ac_power(dev_info_t *, int, int);

/* plumbing */
static usb_ac_plumbed_t *usb_ac_get_plumb_info(usb_ac_state_t *, char *,
				uchar_t);
static uint_t	usb_ac_get_featureID(usb_ac_state_t *, uchar_t, uint_t,
				uint_t);

/* module entry points */
int		usb_ac_open(dev_info_t *);
void		usb_ac_close(dev_info_t *);

/* registration */
static int	usb_ac_get_curr_n_channels(usb_ac_state_t *, int);
static usb_audio_formats_t *usb_ac_get_curr_format(usb_ac_state_t *, int);

/* descriptor handling */
static int	usb_ac_handle_descriptors(usb_ac_state_t *);
static void	usb_ac_add_unit_descriptor(usb_ac_state_t *, uchar_t *, size_t);
static void	usb_ac_alloc_unit(usb_ac_state_t *, uint_t);
static void	usb_ac_free_all_units(usb_ac_state_t *);
static void	usb_ac_setup_connections(usb_ac_state_t *);
static void	usb_ac_map_termtype_to_port(usb_ac_state_t *, uint_t);

/* power management */
static int	usb_ac_pwrlvl0(usb_ac_state_t *);
static int	usb_ac_pwrlvl1(usb_ac_state_t *);
static int	usb_ac_pwrlvl2(usb_ac_state_t *);
static int	usb_ac_pwrlvl3(usb_ac_state_t *);
static void	usb_ac_create_pm_components(dev_info_t *, usb_ac_state_t *);
static void	usb_ac_pm_busy_component(usb_ac_state_t *);
static void	usb_ac_pm_idle_component(usb_ac_state_t *);

/* event handling */
static int	usb_ac_disconnect_event_cb(dev_info_t *);
static int	usb_ac_reconnect_event_cb(dev_info_t *);
static int	usb_ac_cpr_suspend(dev_info_t *);
static void	usb_ac_cpr_resume(dev_info_t *);

static usb_event_t usb_ac_events = {
	usb_ac_disconnect_event_cb,
	usb_ac_reconnect_event_cb,
	NULL, NULL
};

/* misc. support */
static void	usb_ac_restore_device_state(dev_info_t *, usb_ac_state_t *);
static int	usb_ac_cleanup(dev_info_t *, usb_ac_state_t *);
static void	usb_ac_serialize_access(usb_ac_state_t *);
static void	usb_ac_release_access(usb_ac_state_t *);

static void	usb_ac_push_unit_id(usb_ac_state_t *, uint_t);
static void	usb_ac_pop_unit_id(usb_ac_state_t *, uint_t);
static void	usb_ac_show_traverse_path(usb_ac_state_t *);
static int	usb_ac_check_path(usb_ac_state_t *, uint_t);

static uint_t	usb_ac_traverse_connections(usb_ac_state_t *, uint_t, uint_t,
				uint_t, uint_t, uint_t, uint_t,
				uint_t *, uint_t, uint_t *,
				int (*func)(usb_ac_state_t *, uint_t, uint_t,
				uint_t, uint_t, uint_t, uint_t *));
static uint_t	usb_ac_set_port(usb_ac_state_t *, uint_t, uint_t);
static uint_t	usb_ac_set_control(usb_ac_state_t *, uint_t, uint_t,
				uint_t, uint_t, uint_t,
				uint_t *, uint_t,
				int (*func)(usb_ac_state_t *, uint_t, uint_t,
				uint_t, uint_t, uint_t, uint_t *));
static uint_t	usb_ac_set_monitor_gain_control(usb_ac_state_t *, uint_t,
				uint_t, uint_t, uint_t, uint_t,
				uint_t *, uint_t,
				int (*func)(usb_ac_state_t *, uint_t, uint_t,
				uint_t, uint_t, uint_t, uint_t *));
static uint_t	usb_ac_traverse_all_units(usb_ac_state_t *, uint_t, uint_t,
				uint_t, uint_t, uint_t, uint_t *,
				uint_t, uint_t *,
				int (*func)(usb_ac_state_t *, uint_t, uint_t,
				uint_t, uint_t, uint_t, uint_t *));
static int	usb_ac_update_port(usb_ac_state_t *, uint_t,
				uint_t, uint_t, uint_t, uint_t, uint_t *);
static int	usb_ac_set_selector(usb_ac_state_t *, uint_t,
				uint_t, uint_t, uint_t, uint_t, uint_t *);
static int	usb_ac_feature_unit_check(usb_ac_state_t *, uint_t,
				uint_t, uint_t, uint_t, uint_t, uint_t *);
static int	usb_ac_set_gain(usb_ac_state_t *, uint_t,
				uint_t, uint_t, uint_t, uint_t, uint_t *);
static int	usb_ac_set_monitor_gain(usb_ac_state_t *, uint_t,
				uint_t, uint_t, uint_t, uint_t, uint_t *);
static int	usb_ac_set_mute(usb_ac_state_t *, uint_t, uint_t,
				uint_t, uint_t, uint_t, uint_t *);
static int	usb_ac_set_volume(usb_ac_state_t *, uint_t, short, int dir,
				int);
static int	usb_ac_get_maxmin_volume(usb_ac_state_t *, uint_t, int, int,
				int, short *);
static int	usb_ac_send_as_cmd(usb_ac_state_t *, usb_ac_plumbed_t *,
				int, void *);
static int	usb_ac_send_format_cmd(audiohdl_t, int, int, int, int, int);
static int	usb_ac_do_setup(audiohdl_t, int);
static void	usb_ac_do_teardown(audiohdl_t, int);
static void	usb_ac_do_stop_play(audiohdl_t);
static void	usb_ac_do_stop_record(audiohdl_t);

/*  Mixer entry points */
static int	usb_ac_setup(audiohdl_t, int);
static void	usb_ac_teardown(audiohdl_t, int);
static int	usb_ac_set_config(audiohdl_t, int, int, int, int);
static int	usb_ac_set_format(audiohdl_t, int, int, int, int, int);
static int	usb_ac_start_play(audiohdl_t);
static void	usb_ac_stop_play(audiohdl_t);
static int	usb_ac_start_record(audiohdl_t);
static void	usb_ac_stop_record(audiohdl_t);
static int	usb_ac_restore_audio_state(usb_ac_state_t *, int);

/*
 * Mux
 */
static int	usb_ac_mux_walk_siblings(usb_ac_state_t *);
static void	usb_ac_print_reg_data(usb_ac_state_t *,
				usb_as_registration_t *);
static int	usb_ac_get_reg_data(usb_ac_state_t *, ldi_handle_t, int);
static int	usb_ac_setup_plumbed(usb_ac_state_t *, int, int, int);
static int	usb_ac_mixer_registration(usb_ac_state_t *);
static void	usb_ac_hold_siblings(usb_ac_state_t *);
static int	usb_ac_online_siblings(usb_ac_state_t *);
static void	usb_ac_rele_siblings(usb_ac_state_t *);
static int	usb_ac_mux_plumbing(usb_ac_state_t *);
static void	usb_ac_mux_plumbing_tq(void *);
static int	usb_ac_mux_unplumbing(usb_ac_state_t *);
static void	usb_ac_mux_unplumbing_tq(void *);
static int	usb_ac_plumb(usb_ac_plumbed_t *);
static void	usb_ac_unplumb(usb_ac_plumbed_t *);
static void	usb_ac_reader(void *);
static int	usb_ac_read_msg(usb_ac_plumbed_t *, mblk_t *);
static int	usb_ac_do_plumbing(usb_ac_state_t *);
static int	usb_ac_do_unplumbing(usb_ac_state_t *);

/* just generic, USB Audio, 1.0 spec-compliant */
static audio_device_t usb_dev_info =
	{ {"USB Audio"}, {"1.0"}, {"external"} };


/*
 * mixer registration data
 */
static am_ad_entry_t usb_ac_entry = {
	usb_ac_setup,		/* ad_setup() */
	usb_ac_teardown,	/* ad_teardown() */
	usb_ac_set_config,	/* ad_set_config() */
	usb_ac_set_format,	/* ad_set_format() */
	usb_ac_start_play,	/* ad_start_play() */
	usb_ac_stop_play,	/* ad_stop_play() */
	usb_ac_start_record,	/* ad_start_record() */
	usb_ac_stop_record,	/* ad_stop_record() */
};

/* anchor for soft state structures */
void	*usb_ac_statep;


/*
 * DDI Structures
 */

/* Device operations structure */
static struct dev_ops usb_ac_dev_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	NULL,			/* devo_getinfo */
	nulldev,		/* devo_identify - obsolete */
	nulldev,		/* devo_probe - not needed */
	usb_ac_attach,		/* devo_attach */
	usb_ac_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	NULL,			/* devi_cb_ops */
	NULL,			/* devo_busb_ac_ops */
	usb_ac_power,		/* devo_power */
	ddi_quiesce_not_needed,	/* devo_quiesce */
};

/* Linkage structure for loadable drivers */
static struct modldrv usb_ac_modldrv = {
	&mod_driverops,				/* drv_modops */
	"USB Audio Control Driver",		/* drv_linkinfo */
	&usb_ac_dev_ops				/* drv_dev_ops */
};

/* Module linkage structure */
static struct modlinkage usb_ac_modlinkage = {
	MODREV_1,			/* ml_rev */
	(void *)&usb_ac_modldrv,	/* ml_linkage */
	NULL				/* NULL terminates the list */
};


/* standard entry points */
int
_init(void)
{
	int rval;

	/* initialize the soft state */
	if ((rval = ddi_soft_state_init(&usb_ac_statep,
	    sizeof (usb_ac_state_t), 1)) != DDI_SUCCESS) {
		return (rval);
	}

	audio_init_ops(&usb_ac_dev_ops, "usb_ac");

	if ((rval = mod_install(&usb_ac_modlinkage)) != 0) {
		ddi_soft_state_fini(&usb_ac_statep);
		audio_fini_ops(&usb_ac_dev_ops);
	}

	return (rval);
}


int
_fini(void)
{
	int rval;

	if ((rval = mod_remove(&usb_ac_modlinkage)) == 0) {
		/* Free the soft state internal structures */
		ddi_soft_state_fini(&usb_ac_statep);
		audio_fini_ops(&usb_ac_dev_ops);
	}

	return (rval);
}


int
_info(struct modinfo *modinfop)
{
	return (mod_info(&usb_ac_modlinkage, modinfop));
}


extern	uint_t		nproc;
#define	INIT_PROCESS_CNT 3

static int
usb_ac_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	usb_ac_state_t		*uacp = NULL;
	int			instance = ddi_get_instance(dip);

	switch (cmd) {
		case DDI_ATTACH:
			break;
		case DDI_RESUME:
			usb_ac_cpr_resume(dip);

			return (DDI_SUCCESS);
		default:
			return (DDI_FAILURE);
	}

	/*
	 * wait  until all processes are started from main.
	 * USB enumerates early in boot (ie. consconfig time).
	 * If the plumbing takes place early, the file descriptors
	 * are owned by the init process and can never be closed anymore
	 * Consequently, hot removal is not possible and the dips
	 * never go away. By waiting some time, e.g. INIT_PROCESS_CNT,
	 * the problem is avoided.
	 */
	if (nproc < INIT_PROCESS_CNT) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, NULL,
		    "usb_ac%d attach too early", instance);

		return (DDI_FAILURE);
	}

	/*
	 * Allocate soft state information.
	 */
	if (ddi_soft_state_zalloc(usb_ac_statep, instance) != DDI_SUCCESS) {

		goto fail;
	}

	/*
	 * get soft state space and initialize
	 */
	uacp = (usb_ac_state_t *)ddi_get_soft_state(usb_ac_statep, instance);
	if (uacp == NULL) {

		goto fail;
	}


	/* get log handle */
	uacp->usb_ac_log_handle = usb_alloc_log_hdl(dip, "ac",
	    &usb_ac_errlevel,
	    &usb_ac_errmask, &usb_ac_instance_debug,
	    0);

	uacp->usb_ac_instance = instance;
	uacp->usb_ac_dip = dip;

	(void) snprintf(uacp->dstr, sizeof (uacp->dstr), "%s#%d",
	    ddi_driver_name(dip), instance);

	if (usb_client_attach(dip, USBDRV_VERSION, 0) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, uacp->usb_ac_log_handle,
		    "usb_client_attach failed");

		usb_free_log_hdl(uacp->usb_ac_log_handle);
		ddi_soft_state_free(usb_ac_statep, uacp->usb_ac_instance);

		return (DDI_FAILURE);
	}

	if (usb_get_dev_data(dip, &uacp->usb_ac_dev_data,
	    USB_PARSE_LVL_IF, 0) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, uacp->usb_ac_log_handle,
		    "usb_get_dev_data failed");

		usb_client_detach(dip, NULL);
		usb_free_log_hdl(uacp->usb_ac_log_handle);
		ddi_soft_state_free(usb_ac_statep, uacp->usb_ac_instance);

		return (DDI_FAILURE);
	}

	/* initialize mutex & cv */
	mutex_init(&uacp->usb_ac_mutex, NULL, MUTEX_DRIVER,
	    uacp->usb_ac_dev_data->dev_iblock_cookie);

	uacp->usb_ac_default_ph = uacp->usb_ac_dev_data->dev_default_ph;

	uacp->usb_ac_audiohdl = audio_sup_register(dip);

	if (uacp->usb_ac_audiohdl == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, uacp->usb_ac_log_handle,
		    "audio_sup_register failed");

		goto fail;
	}

	/* save softstate pointer in audio handle */
	audio_sup_set_private(uacp->usb_ac_audiohdl, (void *)uacp);

	/* parse all class specific descriptors */
	if (usb_ac_handle_descriptors(uacp) != USB_SUCCESS) {

		goto fail;
	}

	/* we no longer need the descr tree */
	usb_free_descr_tree(dip, uacp->usb_ac_dev_data);

	uacp->usb_ac_ser_acc = usb_init_serialization(dip,
	    USB_INIT_SER_CHECK_SAME_THREAD);

	mutex_enter(&uacp->usb_ac_mutex);

	/* we are online */
	uacp->usb_ac_dev_state = USB_DEV_ONLINE;

	/*
	 * safe guard the postattach to be executed
	 * only two states arepossible: plumbed / unplumbed
	 */
	uacp->usb_ac_plumbing_state = USB_AC_STATE_UNPLUMBED;
	uacp->usb_ac_current_plumbed_index = -1;

	mutex_exit(&uacp->usb_ac_mutex);

	/* create components to power manage this device */
	usb_ac_create_pm_components(dip, uacp);

	/* Register for events */
	if (usb_register_event_cbs(dip, &usb_ac_events, 0) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, uacp->usb_ac_log_handle,
		    "usb_ac_attach: couldn't register for events");

		goto fail;
	}

	USB_DPRINTF_L4(PRINT_MASK_ATTA, uacp->usb_ac_log_handle,
	    "usb_ac_attach: End");

	/* report device */
	ddi_report_dev(dip);

	if (usb_ac_do_plumbing(uacp) != USB_SUCCESS)
		goto fail;

	return (DDI_SUCCESS);

fail:
	if (uacp) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, uacp->usb_ac_log_handle,
		    "attach failed");

		/* wait for plumbing thread to finish */
		if (uacp->tqp != NULL) {
			ddi_taskq_wait(uacp->tqp);
			ddi_taskq_destroy(uacp->tqp);
			uacp->tqp = NULL;
		}
		(void) usb_ac_cleanup(dip, uacp);
	}

	return (DDI_FAILURE);
}


static int
usb_ac_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int instance = ddi_get_instance(dip);
	usb_ac_state_t	*uacp;
	int rval = USB_FAILURE;
	char *nm = "usb_ac_detach";

	uacp = ddi_get_soft_state(usb_ac_statep, instance);

	switch (cmd) {
	case DDI_DETACH:
		dinfo("%s: %s - detaching\n", uacp->dstr, nm);

		/* wait for plumbing thread to finish */
		if (uacp->tqp != NULL)
			ddi_taskq_wait(uacp->tqp);

		mutex_enter(&uacp->usb_ac_mutex);

		/* do not allow detach if still busy */
		if (uacp->usb_ac_busy_count) {
			dinfo("%s: %s - still busy: %d\n", uacp->dstr, nm,
			    uacp->usb_ac_busy_count);

			mutex_exit(&uacp->usb_ac_mutex);
			return (USB_FAILURE);
		}

		/*
		 * call am_unregister() to stop calls into our driver from
		 * the framework; can fail if the framework is still busy
		 */
		if (uacp->usb_ac_audiohdl != NULL) {
			mutex_exit(&uacp->usb_ac_mutex);

			if (am_unregister(uacp->usb_ac_audiohdl) !=
			    AUDIO_SUCCESS) {
				dinfo("%s: %s - am_unregister failed, "
				    "framework still busy\n",
				    uacp->dstr, nm);

				return (USB_FAILURE);
			}
			mutex_enter(&uacp->usb_ac_mutex);
		}

		mutex_exit(&uacp->usb_ac_mutex);

		/*
		 * unplumb to stop activity from other modules, then
		 * cleanup, which will also teardown audio framework state
		 */
		if (usb_ac_do_unplumbing(uacp) == USB_SUCCESS)
			rval = usb_ac_cleanup(dip, uacp);

		if (rval != USB_SUCCESS) {
			USB_DPRINTF_L2(PRINT_MASK_ATTA,
			    uacp->usb_ac_log_handle, "detach failed: %s%d",
			    ddi_driver_name(dip), instance);
		}

		return ((rval == USB_SUCCESS) ? DDI_SUCCESS : DDI_FAILURE);
	case DDI_SUSPEND:
		dinfo("%s: %s - suspending\n", uacp->dstr, nm);

		rval = usb_ac_cpr_suspend(dip);

		return ((rval == USB_SUCCESS) ? DDI_SUCCESS : DDI_FAILURE);
	default:

		return (DDI_FAILURE);
	}
}


/*
 * usb_ac_cleanup:
 *	cleanup on attach failure and detach
 */
static int
usb_ac_cleanup(dev_info_t *dip, usb_ac_state_t *uacp)
{
	usb_ac_power_t	*uacpm;
	int	rval = USB_FAILURE;

	ASSERT(uacp);

	mutex_enter(&uacp->usb_ac_mutex);
	uacpm = uacp->usb_ac_pm;

	dinfo("%s: usb_ac_cleanup: uacpm=0x%p\n", uacp->dstr, (void *)uacpm);

	ASSERT(uacp->usb_ac_busy_count == 0);

	ASSERT(uacp->usb_ac_plumbing_state == USB_AC_STATE_UNPLUMBED);

	/*
	 * deregister with audio framework, if it fails we are hosed
	 * and we probably don't want to plumb again
	 */
	if (uacp->usb_ac_audiohdl) {
		if (uacp->usb_ac_registered_with_mixer) {
			mutex_exit(&uacp->usb_ac_mutex);
			if (am_detach(uacp->usb_ac_audiohdl, DDI_DETACH) !=
			    AUDIO_SUCCESS) {

				return (rval);
			}
		} else {
			mutex_exit(&uacp->usb_ac_mutex);
		}
		if (audio_sup_unregister(uacp->usb_ac_audiohdl) !=
		    AUDIO_SUCCESS) {

			return (rval);
		}
	} else {
		mutex_exit(&uacp->usb_ac_mutex);
	}

	/*
	 * Disable the event callbacks, after this point, event
	 * callbacks will never get called. Note we shouldn't hold
	 * the mutex while unregistering events because there may be a
	 * competing event callback thread. Event callbacks are done
	 * with ndi mutex held and this can cause a potential deadlock.
	 */
	usb_unregister_event_cbs(dip, &usb_ac_events);

	mutex_enter(&uacp->usb_ac_mutex);

	if (uacpm && (uacp->usb_ac_dev_state != USB_DEV_DISCONNECTED)) {
		if (uacpm->acpm_wakeup_enabled) {
			mutex_exit(&uacp->usb_ac_mutex);
			usb_ac_pm_busy_component(uacp);
			(void) pm_raise_power(dip, 0, USB_DEV_OS_FULL_PWR);

			rval = usb_handle_remote_wakeup(dip,
			    USB_REMOTE_WAKEUP_DISABLE);
			if (rval != USB_SUCCESS) {
				USB_DPRINTF_L2(PRINT_MASK_PM,
				    uacp->usb_ac_log_handle,
				    "usb_ac_cleanup: disable remote "
				    "wakeup failed, rval=%d", rval);
			}
			usb_ac_pm_idle_component(uacp);
		} else {
			mutex_exit(&uacp->usb_ac_mutex);
		}

		(void) pm_lower_power(dip, 0, USB_DEV_OS_PWR_OFF);

		mutex_enter(&uacp->usb_ac_mutex);
	}

	if (uacpm) {
		kmem_free(uacpm,  sizeof (usb_ac_power_t));
		uacp->usb_ac_pm = NULL;
	}

	usb_client_detach(dip, uacp->usb_ac_dev_data);

	/* free descriptors */
	usb_ac_free_all_units(uacp);

	mutex_exit(&uacp->usb_ac_mutex);

	mutex_destroy(&uacp->usb_ac_mutex);

	usb_fini_serialization(uacp->usb_ac_ser_acc);

	USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
	    "usb_ac_cleanup: Ending");

	usb_free_log_hdl(uacp->usb_ac_log_handle);
	kmem_free(uacp->usb_ac_connections, uacp->usb_ac_connections_len);
	kmem_free(uacp->usb_ac_connections_a, uacp->usb_ac_connections_a_len);
	kmem_free(uacp->usb_ac_unit_type, uacp->usb_ac_max_unit);
	kmem_free(uacp->usb_ac_traverse_path, uacp->usb_ac_max_unit);

	ddi_soft_state_free(usb_ac_statep, uacp->usb_ac_instance);

	ddi_prop_remove_all(dip);

	return (USB_SUCCESS);
}


int
usb_ac_open(dev_info_t *dip)
{
	int inst = ddi_get_instance(dip);
	usb_ac_state_t *uacp = ddi_get_soft_state(usb_ac_statep, inst);

	mutex_enter(&uacp->usb_ac_mutex);

	uacp->usb_ac_busy_count++;

	mutex_exit(&uacp->usb_ac_mutex);

	usb_ac_pm_busy_component(uacp);
	(void) pm_raise_power(uacp->usb_ac_dip, 0, USB_DEV_OS_FULL_PWR);

	return (0);
}


void
usb_ac_close(dev_info_t *dip)
{
	int inst = ddi_get_instance(dip);
	usb_ac_state_t *uacp = ddi_get_soft_state(usb_ac_statep, inst);

	mutex_enter(&uacp->usb_ac_mutex);

	if (uacp->usb_ac_busy_count > 0)
		uacp->usb_ac_busy_count--;

	mutex_exit(&uacp->usb_ac_mutex);

	usb_ac_pm_idle_component(uacp);
}


/*
 * usb_ac_read_msg:
 *	Handle asynchronous response from opened streams
 */
static int
usb_ac_read_msg(usb_ac_plumbed_t *plumb_infop, mblk_t *mp)
{
	usb_ac_state_t	*uacp = plumb_infop->acp_uacp;
	int error = DDI_SUCCESS;
	int	val;
	char	val1;
	struct iocblk *iocp;

	USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
	    "usb_ac_read_msg: mp=0x%p, instance=%d", (void *)mp,
	    ddi_get_instance(uacp->usb_ac_dip));

	ASSERT(mp != NULL);
	ASSERT(mutex_owned(&uacp->usb_ac_mutex));

	/*
	 * typically an M_CTL is used between modules but in order to pass
	 * through the streamhead, an M_PROTO type must be used instead
	 */
	switch (mp->b_datap->db_type) {
	case M_PROTO:
	case M_ERROR:
		USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "M_CTL/M_ERROR");

		switch (plumb_infop->acp_driver) {
		case USB_AH_PLUMBED:
			USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
			    "message from hid, instance=%d",
			    ddi_get_instance(plumb_infop->acp_dip));

			iocp = (struct iocblk *)(void *)mp->b_rptr;
			ASSERT(mp->b_cont != NULL);

			if (uacp->usb_ac_registered_with_mixer) {

				val1 = *((char *)mp->b_cont->b_rptr);
				val = (int)val1;

				USB_DPRINTF_L4(PRINT_MASK_ALL,
				    uacp->usb_ac_log_handle, "val1=0x%x(%d),"
				    "val=0x%x(%d)", val1, val1, val, val);

				switch (iocp->ioc_cmd) {
				/* Handle relative volume change */
				case USB_AUDIO_VOL_CHANGE:
					/* prevent unplumbing */
					uacp->usb_ac_busy_count++;
					if (uacp->usb_ac_plumbing_state ==
					    USB_AC_STATE_PLUMBED) {
						mutex_exit(&uacp->usb_ac_mutex);
						(void) am_hw_state_change(
						    uacp->usb_ac_audiohdl,
						    AM_HWSC_SET_GAIN_DELTA,
						    AUDIO_PLAY, val,
						    AUDIO_NO_SLEEP);
						mutex_enter(&uacp->
						    usb_ac_mutex);
					}
					uacp->usb_ac_busy_count--;
					/* FALLTHRU */
				case USB_AUDIO_MUTE:
				default:
					freemsg(mp);
					break;
				}
			} else {
				freemsg(mp);
			}

			break;
		default:
			USB_DPRINTF_L2(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
			    "message from unknown module(%s)",
			    ddi_driver_name(plumb_infop->acp_dip));
			freemsg(mp);
		}

		break;
	default:
		USB_DPRINTF_L2(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "Unknown type=%d", mp->b_datap->db_type);
		freemsg(mp);
	}

	USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
	    "usb_ac_read_msg: done");

	return (error);
}


/*
 * Power Management
 * usb_ac_power:
 *	power entry point
 */
static int
usb_ac_power(dev_info_t *dip, int comp, int level)
{
	int		instance = ddi_get_instance(dip);
	usb_ac_state_t	*uacp;
	usb_ac_power_t	*uacpm;
	int		rval = DDI_FAILURE;

	uacp = ddi_get_soft_state(usb_ac_statep, instance);

	USB_DPRINTF_L4(PRINT_MASK_PM, uacp->usb_ac_log_handle,
	    "usb_ac_power: comp=%d level=%d", comp, level);

	mutex_enter(&uacp->usb_ac_mutex);
	uacpm = uacp->usb_ac_pm;

	if (USB_DEV_PWRSTATE_OK(uacpm->acpm_pwr_states, level)) {
		USB_DPRINTF_L2(PRINT_MASK_PM, uacp->usb_ac_log_handle,
		    "usb_ac_power: illegal level=%d pwr_states=%d",
		    level, uacpm->acpm_pwr_states);

		goto done;
	}

	switch (level) {
	case USB_DEV_OS_PWR_OFF:
		rval = usb_ac_pwrlvl0(uacp);
		break;
	case USB_DEV_OS_PWR_1:
		rval = usb_ac_pwrlvl1(uacp);
		break;
	case USB_DEV_OS_PWR_2:
		rval = usb_ac_pwrlvl2(uacp);
		break;
	case USB_DEV_OS_FULL_PWR:
		rval = usb_ac_pwrlvl3(uacp);
		break;
	}

done:
	mutex_exit(&uacp->usb_ac_mutex);

	return ((rval == USB_SUCCESS) ? DDI_SUCCESS : DDI_FAILURE);
}


/*
 * functions to handle power transition for various levels
 * These functions act as place holders to issue USB commands
 * to the devices to change their power levels
 * Level 0 = Device is powered off
 * Level 3 = Device if full powered
 * Level 1,2 = Intermediate power level of the device as implemented
 *	by the hardware.
 * Note that Level 0 is OS power-off and Level 3 is OS full-power.
 */
static int
usb_ac_pwrlvl0(usb_ac_state_t *uacp)
{
	usb_ac_power_t	*uacpm;
	int		rval;

	uacpm = uacp->usb_ac_pm;

	switch (uacp->usb_ac_dev_state) {
	case USB_DEV_ONLINE:
		/* Deny the powerdown request if the device is busy */
		if (uacpm->acpm_pm_busy != 0) {

			return (USB_FAILURE);
		}

		/* Issue USB D3 command to the device here */
		rval = usb_set_device_pwrlvl3(uacp->usb_ac_dip);
		ASSERT(rval == USB_SUCCESS);

		uacp->usb_ac_dev_state = USB_DEV_PWRED_DOWN;
		uacpm->acpm_current_power = USB_DEV_OS_PWR_OFF;

		/* FALLTHRU */
	case USB_DEV_DISCONNECTED:
	case USB_DEV_SUSPENDED:
	case USB_DEV_PWRED_DOWN:
	default:
		return (USB_SUCCESS);
	}
}


/* ARGSUSED */
static int
usb_ac_pwrlvl1(usb_ac_state_t *uacp)
{
	int		rval;

	/* Issue USB D2 command to the device here */
	rval = usb_set_device_pwrlvl2(uacp->usb_ac_dip);
	ASSERT(rval == USB_SUCCESS);

	return (USB_FAILURE);
}


/* ARGSUSED */
static int
usb_ac_pwrlvl2(usb_ac_state_t *uacp)
{
	int		rval;

	rval = usb_set_device_pwrlvl1(uacp->usb_ac_dip);
	ASSERT(rval == USB_SUCCESS);

	return (USB_FAILURE);
}


static int
usb_ac_pwrlvl3(usb_ac_state_t *uacp)
{
	usb_ac_power_t	*uacpm;
	int		rval;

	uacpm = uacp->usb_ac_pm;

	switch (uacp->usb_ac_dev_state) {
	case USB_DEV_PWRED_DOWN:
		/* Issue USB D0 command to the device here */
		rval = usb_set_device_pwrlvl0(uacp->usb_ac_dip);
		ASSERT(rval == USB_SUCCESS);

		uacp->usb_ac_dev_state = USB_DEV_ONLINE;
		uacpm->acpm_current_power = USB_DEV_OS_FULL_PWR;
		/* FALLTHRU */
	case USB_DEV_ONLINE:
		/* we are already in full power */

		/* FALLTHRU */
	case USB_DEV_DISCONNECTED:
	case USB_DEV_SUSPENDED:

		return (USB_SUCCESS);
	default:
		USB_DPRINTF_L2(PRINT_MASK_PM, uacp->usb_ac_log_handle,
		    "usb_ac_pwerlvl3: Illegal dev_state");

		return (USB_FAILURE);
	}
}


static void
usb_ac_create_pm_components(dev_info_t *dip, usb_ac_state_t *uacp)
{
	usb_ac_power_t	*uacpm;
	uint_t		pwr_states;

	USB_DPRINTF_L4(PRINT_MASK_PM, uacp->usb_ac_log_handle,
	    "usb_ac_create_pm_components: begin");

	/* Allocate the state structure */
	uacpm = kmem_zalloc(sizeof (usb_ac_power_t), KM_SLEEP);
	uacp->usb_ac_pm = uacpm;
	uacpm->acpm_state = uacp;
	uacpm->acpm_capabilities = 0;
	uacpm->acpm_current_power = USB_DEV_OS_FULL_PWR;

	if (usb_create_pm_components(dip, &pwr_states) ==
	    USB_SUCCESS) {
		if (usb_handle_remote_wakeup(dip,
		    USB_REMOTE_WAKEUP_ENABLE) == USB_SUCCESS) {
			uacpm->acpm_wakeup_enabled = 1;

			USB_DPRINTF_L4(PRINT_MASK_PM,
			    uacp->usb_ac_log_handle,
			    "remote Wakeup enabled");
		}
		uacpm->acpm_pwr_states = (uint8_t)pwr_states;
		(void) pm_raise_power(dip, 0, USB_DEV_OS_FULL_PWR);
	} else {
		if (uacpm) {
			kmem_free(uacpm,  sizeof (usb_ac_power_t));
			uacp->usb_ac_pm = NULL;
		}
		USB_DPRINTF_L2(PRINT_MASK_PM, uacp->usb_ac_log_handle,
		    "pm not enabled");
	}

	USB_DPRINTF_L4(PRINT_MASK_PM, uacp->usb_ac_log_handle,
	    "usb_ac_create_pm_components: end");
}


/*
 * usb_ac_get_plumb_info:
 *	Get plumb_info pointer that matches module "name"
 *	If name = "usb_as", match the direction also (record or play)
 */
static usb_ac_plumbed_t *
usb_ac_get_plumb_info(usb_ac_state_t *uacp, char *name, uchar_t reg_play_type)
{
	int			n;
	usb_ac_plumbed_t	*plumb_infop = NULL;
	usb_as_registration_t	*asreg;
	usb_ac_streams_info_t	*asinfo;

	for (n = 0; n < USB_AC_MAX_PLUMBED; n++) {
		if (uacp->usb_ac_plumbed[n].acp_dip == NULL) {
			continue;
		}
		if (strcmp(ddi_driver_name(uacp->
		    usb_ac_plumbed[n].acp_dip), name) != 0) {
			continue;
		}
		if (uacp->usb_ac_plumbed[n].acp_driver == USB_AS_PLUMBED) {
			asinfo = uacp->usb_ac_plumbed[n].acp_data;
			asreg = asinfo->acs_streams_reg;
			/* Match direction */
			if (asreg->reg_mode & reg_play_type) {
				break;
			}
		} else if (uacp->usb_ac_plumbed[n].acp_driver ==
		    USB_AH_PLUMBED) {
			break;
		}
	}

	if (n < USB_AC_MAX_PLUMBED) {
		plumb_infop = &uacp->usb_ac_plumbed[n];
	}

	return (plumb_infop);
}


/*
 * usb_ac_get_featureID:
 *	find out if there is at least one feature unit that supports
 *	the request controls.
 *	Return featureID or USB_AC_ID_NONE.
 */
static uint_t
usb_ac_get_featureID(usb_ac_state_t *uacp, uchar_t dir,
    uint_t channel, uint_t control)
{
	uint_t count = 0;

	return (usb_ac_set_control(uacp, dir, USB_AUDIO_FEATURE_UNIT,
	    channel, control, USB_AC_FIND_ONE, &count, 0,
	    usb_ac_feature_unit_check));
}


/*
 * usb_ac_feature_unit_check:
 *	check if a feature unit can support the required channel
 *	and control combination. Return USB_SUCCESS or USB_FAILURE.
 *	Called for each matching unit from usb_ac_traverse_connections.
 */
/*ARGSUSED*/
static int
usb_ac_feature_unit_check(usb_ac_state_t *uacp, uint_t featureID,
    uint_t dir, uint_t channel, uint_t control, uint_t arg1, uint_t *depth)
{
	usb_audio_feature_unit_descr1_t *feature_descrp;
	int				n_channel_controls;

	USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
	    "usb_ac_feature_unit_check: ID=%d ch=%d cntrl=%d",
	    featureID, channel, control);

	ASSERT(featureID < uacp->usb_ac_max_unit);

	/*
	 * check if this control is supported on this channel
	 */
	feature_descrp = (usb_audio_feature_unit_descr1_t *)
	    uacp->usb_ac_units[featureID].acu_descriptor;
	ASSERT(feature_descrp->bUnitID == featureID);

	USB_DPRINTF_L3(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
	    "bControlSize=%d", feature_descrp->bControlSize);

	if (feature_descrp->bControlSize == 0) {
		featureID = USB_AC_ID_NONE;
	} else {
		uint_t index;

		n_channel_controls = (feature_descrp->bLength -
		    offsetof(usb_audio_feature_unit_descr1_t,
		    bmaControls))/feature_descrp->bControlSize;

		USB_DPRINTF_L3(PRINT_MASK_ALL,
		    uacp->usb_ac_log_handle,
		    "#controls: %d index=%d", n_channel_controls,
		    feature_descrp->bControlSize * channel);

		if (channel > n_channel_controls) {
			featureID = USB_AC_ID_NONE;
		} else {
			/*
			 * we only support MUTE and VOLUME
			 * which are in the first byte
			 */
			index = feature_descrp->bControlSize *
			    channel;

			USB_DPRINTF_L3(PRINT_MASK_ALL,
			    uacp->usb_ac_log_handle,
			    "control: 0x%x",
			    feature_descrp->bmaControls[index]);

			if ((feature_descrp->bmaControls[index] &
			    control) == 0) {
				featureID = USB_AC_ID_NONE;
			}
		}
	}

	USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
	    "usb_ac_feature_unit_check: dir=%d featureID=0x%x",
	    dir, featureID);

	return ((featureID != USB_AC_ID_NONE) ?
	    USB_SUCCESS : USB_FAILURE);
}


/*
 * Descriptor Management
 *
 * usb_ac_handle_descriptors:
 *	extract interesting descriptors from the config cloud
 */
static int
usb_ac_handle_descriptors(usb_ac_state_t *uacp)
{
	int			len, index;
	int			rval = USB_FAILURE;
	usb_audio_cs_if_descr_t descr;
	usb_client_dev_data_t	*dev_data = uacp->usb_ac_dev_data;
	usb_alt_if_data_t	*altif_data;
	usb_cvs_data_t		*cvs;

	USB_DPRINTF_L3(PRINT_MASK_ATTA, uacp->usb_ac_log_handle,
	    "config=%ld, interface=%d",
	    (long)(dev_data->dev_curr_cfg - &dev_data->dev_cfg[0]),
	    dev_data->dev_curr_if);

	altif_data = &dev_data->dev_curr_cfg->
	    cfg_if[dev_data->dev_curr_if].if_alt[0];

	uacp->usb_ac_ifno	= dev_data->dev_curr_if;
	uacp->usb_ac_if_descr	= altif_data->altif_descr;

	/* find USB_AUDIO_CS_INTERFACE type descriptor */
	for (index = 0; index < altif_data->altif_n_cvs; index++) {
		cvs = &altif_data->altif_cvs[index];
		if (cvs->cvs_buf == NULL) {
			continue;
		}
		if (cvs->cvs_buf[1] == USB_AUDIO_CS_INTERFACE) {
			break;
		}
	}

	if (index == altif_data->altif_n_cvs) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, uacp->usb_ac_log_handle,
		    "cannot find descriptor type %d", USB_AUDIO_CS_INTERFACE);

		return (rval);
	}

	len = usb_parse_data(
	    CS_AC_IF_HEADER_FORMAT,
	    cvs->cvs_buf, cvs->cvs_buf_len,
	    (void *)&descr, sizeof (usb_audio_cs_if_descr_t));

	/* is this a sane header descriptor */
	if (!((len >= CS_AC_IF_HEADER_SIZE) &&
	    (descr.bDescriptorType == USB_AUDIO_CS_INTERFACE) &&
	    (descr.bDescriptorSubType == USB_AUDIO_HEADER))) {
		USB_DPRINTF_L2(PRINT_MASK_ATTA, uacp->usb_ac_log_handle,
		    "invalid header");

		return (rval);
	}

	USB_DPRINTF_L3(PRINT_MASK_ATTA, uacp->usb_ac_log_handle,
	    "header: type=0x%x subtype=0x%x bcdADC=0x%x\n\t"
	    "total=0x%x InCol=0x%x",
	    descr.bDescriptorType,
	    descr.bDescriptorSubType,
	    descr.bcdADC,
	    descr.wTotalLength,
	    descr.blnCollection);

	/*
	 * we read descriptors by index and store them in ID array.
	 * the actual parsing is done in usb_ac_add_unit_descriptor()
	 */
	for (index++; index < altif_data->altif_n_cvs; index++) {
		USB_DPRINTF_L3(PRINT_MASK_ATTA, uacp->usb_ac_log_handle,
		    "index=%d", index);

		cvs = &altif_data->altif_cvs[index];
		if (cvs->cvs_buf == NULL) {
			continue;
		}

		/* add to ID array */
		usb_ac_add_unit_descriptor(uacp, cvs->cvs_buf,
		    cvs->cvs_buf_len);
	}
	rval = USB_SUCCESS;

	usb_ac_setup_connections(uacp);

	/* determine port types */
	usb_ac_map_termtype_to_port(uacp, AUDIO_PLAY);
	usb_ac_map_termtype_to_port(uacp, AUDIO_RECORD);

	USB_DPRINTF_L3(PRINT_MASK_ATTA, uacp->usb_ac_log_handle,
	    "input port types=0x%x output port types =0x%x",
	    uacp->usb_ac_input_ports, uacp->usb_ac_output_ports);


	return (rval);
}


/*
 * usb_ac_setup_connections:
 *	build a matrix reflecting all connections
 */
static void
usb_ac_setup_connections(usb_ac_state_t *uacp)
{
	usb_ac_unit_list_t	*units = uacp->usb_ac_units;
	uchar_t			*a, **p, i, unit;
	size_t			a_len, p_len;

	/* allocate array for unit types for quick reference */
	uacp->usb_ac_unit_type = kmem_zalloc(uacp->usb_ac_max_unit,
	    KM_SLEEP);
	/* allocate array for traversal path */
	uacp->usb_ac_traverse_path = kmem_zalloc(uacp->usb_ac_max_unit,
	    KM_SLEEP);


	/* allocate the connection matrix and set it up */
	a_len = uacp->usb_ac_max_unit * uacp->usb_ac_max_unit;
	p_len = uacp->usb_ac_max_unit * sizeof (uchar_t *);

	/* trick to create a 2 dimensional array */
	a = kmem_zalloc(a_len, KM_SLEEP);
	p = kmem_zalloc(p_len, KM_SLEEP);
	for (i = 0; i < uacp->usb_ac_max_unit; i++) {
		p[i] = a + i * uacp->usb_ac_max_unit;
	}
	uacp->usb_ac_connections = p;
	uacp->usb_ac_connections_len = p_len;
	uacp->usb_ac_connections_a = a;
	uacp->usb_ac_connections_a_len = a_len;

	/* traverse all units and set connections */
	for (unit = 0; unit < uacp->usb_ac_max_unit; unit++) {

		USB_DPRINTF_L3(PRINT_MASK_ATTA, uacp->usb_ac_log_handle,
		    "traversing unit=0x%x type=0x%x",
		    unit, units[unit].acu_type);

		/* store type in the first unused column */
		uacp->usb_ac_unit_type[unit] = units[unit].acu_type;

		/* save the Unit ID in the unit it points to */
		switch (units[unit].acu_type) {
		case USB_AUDIO_FEATURE_UNIT:
		{
			usb_audio_feature_unit_descr1_t *d =
			    units[unit].acu_descriptor;

			USB_DPRINTF_L3(PRINT_MASK_ATTA, uacp->usb_ac_log_handle,
			    "sourceID=0x%x type=0x%x", d->bSourceID,
			    units[d->bSourceID].acu_type);

			if (d->bSourceID != 0) {
				ASSERT(p[unit][d->bSourceID] == B_FALSE);
				p[unit][d->bSourceID] = B_TRUE;
			}

			break;
		}
		case USB_AUDIO_OUTPUT_TERMINAL:
		{
			usb_audio_output_term_descr_t *d =
			    units[unit].acu_descriptor;

			USB_DPRINTF_L3(PRINT_MASK_ATTA, uacp->usb_ac_log_handle,
			    "sourceID=0x%x type=0x%x", d->bSourceID,
			    units[d->bSourceID].acu_type);

			if (d->bSourceID != 0) {
				ASSERT(p[unit][d->bSourceID] == B_FALSE);
				p[unit][d->bSourceID] = B_TRUE;
			}

			break;
		}
		case USB_AUDIO_MIXER_UNIT:
		{
			usb_audio_mixer_unit_descr1_t *d =
			    units[unit].acu_descriptor;
			int n_sourceID = d->bNrInPins;
			int id;

			for (id = 0; id < n_sourceID; id++) {
				USB_DPRINTF_L3(PRINT_MASK_ATTA,
				    uacp->usb_ac_log_handle,
				    "sourceID=0x%x type=0x%x c=%d",
				    d->baSourceID[id],
				    units[d->baSourceID[id]].acu_type,
				    p[unit][d->baSourceID[id]]);

				if (d->baSourceID[id] != 0) {
					ASSERT(p[unit][d->baSourceID[id]] ==
					    B_FALSE);
					p[unit][d->baSourceID[id]] = B_TRUE;
				}
			}

			break;
		}
		case USB_AUDIO_SELECTOR_UNIT:
		{
			usb_audio_selector_unit_descr1_t *d =
			    units[unit].acu_descriptor;
			int n_sourceID = d->bNrInPins;
			int id;

			for (id = 0; id < n_sourceID; id++) {
				USB_DPRINTF_L3(PRINT_MASK_ATTA,
				    uacp->usb_ac_log_handle,
				    "sourceID=0x%x type=0x%x",
				    d->baSourceID[id],
				    units[d->baSourceID[id]].acu_type);

				if (d->baSourceID[id] != 0) {
					ASSERT(p[unit][d->baSourceID[id]] ==
					    B_FALSE);
					p[unit][d->baSourceID[id]] = B_TRUE;
				}
			}

			break;
		}
		case USB_AUDIO_PROCESSING_UNIT:
		{
			usb_audio_mixer_unit_descr1_t *d =
			    units[unit].acu_descriptor;
			int n_sourceID = d->bNrInPins;
			int id;

			for (id = 0; id < n_sourceID; id++) {
				USB_DPRINTF_L3(PRINT_MASK_ATTA,
				    uacp->usb_ac_log_handle,
				    "sourceID=0x%x type=0x%x",
				    d->baSourceID[id],
				    units[d->baSourceID[id]].acu_type);

				if (d->baSourceID[id] != 0) {
					ASSERT(p[unit][d->baSourceID[id]] ==
					    B_FALSE);
					p[unit][d->baSourceID[id]] = B_TRUE;
				}
			}

			break;
		}
		case USB_AUDIO_EXTENSION_UNIT:
		{
			usb_audio_extension_unit_descr1_t *d =
			    units[unit].acu_descriptor;
			int n_sourceID = d->bNrInPins;
			int id;

			for (id = 0; id < n_sourceID; id++) {
				USB_DPRINTF_L3(PRINT_MASK_ATTA,
				    uacp->usb_ac_log_handle,
				    "sourceID=0x%x type=0x%x",
				    d->baSourceID[id],
				    units[d->baSourceID[id]].acu_type);

				if (d->baSourceID[id] != 0) {
					ASSERT(p[unit][d->baSourceID[id]] ==
					    B_TRUE);
					p[unit][d->baSourceID[id]] = B_FALSE;
				}
			}

			break;
		}
		case USB_AUDIO_INPUT_TERMINAL:

			break;
		default:
			/*
			 * Ignore the rest because they are not support yet
			 */
			break;
		}
	}

#ifdef DEBUG
	/* display topology in log buffer */
{
	uint_t i, j, l;
	char *buf;

	l = uacp->usb_ac_max_unit * 5;

	buf = kmem_alloc(l, KM_SLEEP);

	USB_DPRINTF_L3(PRINT_MASK_ATTA, uacp->usb_ac_log_handle,
	    "unit types:");

	/* two	strings so they won't be replaced accidentily by tab */
	(void) sprintf(&buf[0], "    ""    ");
	for (i = 1; i < uacp->usb_ac_max_unit; i++) {
		(void) sprintf(&buf[2 + (i*3)], "%02d ", i);
	}
	USB_DPRINTF_L3(PRINT_MASK_ATTA, uacp->usb_ac_log_handle, buf);

	(void) sprintf(&buf[0], "  +-------");
	for (i = 1; i < uacp->usb_ac_max_unit; i++) {
		(void) sprintf(&buf[5+((i-1)*3)], "---");
	}
	USB_DPRINTF_L3(PRINT_MASK_ATTA, uacp->usb_ac_log_handle, buf);

	(void) sprintf(&buf[0], "    ""    ");
	for (i = 1; i < uacp->usb_ac_max_unit; i++) {
		(void) sprintf(&buf[2 + (i*3)], "%02d ",
		    uacp->usb_ac_unit_type[i]);
	}
	USB_DPRINTF_L3(PRINT_MASK_ATTA, uacp->usb_ac_log_handle, buf);
	USB_DPRINTF_L3(PRINT_MASK_ATTA, uacp->usb_ac_log_handle, " ");

	USB_DPRINTF_L3(PRINT_MASK_ATTA, uacp->usb_ac_log_handle,
	    "adjacency matrix:");
	(void) sprintf(&buf[0], "    ""    ");
	for (i = 1; i < uacp->usb_ac_max_unit; i++) {
		(void) sprintf(&buf[2 + (i*3)], "%02d ", i);
	}
	USB_DPRINTF_L3(PRINT_MASK_ATTA, uacp->usb_ac_log_handle, buf);

	(void) sprintf(&buf[0], "  +-------");
	for (i = 1; i < uacp->usb_ac_max_unit; i++) {
		(void) sprintf(&buf[5+((i-1)*3)], "---");
	}
	USB_DPRINTF_L3(PRINT_MASK_ATTA, uacp->usb_ac_log_handle, buf);

	for (i = 1; i < uacp->usb_ac_max_unit; i++) {
		(void) sprintf(&buf[0], "%02d| "" ", i);
		for (j = 1; j < uacp->usb_ac_max_unit; j++) {
			(void) sprintf(&buf[1+(j * 3)], "%2d ", p[i][j]);
		}
		USB_DPRINTF_L3(PRINT_MASK_ATTA, uacp->usb_ac_log_handle, buf);
	}
	kmem_free(buf, l);
}
#endif
}


/*
 * usb_ac_add_unit_descriptor:
 *	take the parsed descriptor in the buffer and store it in the ID unit
 *	array. we grow the unit array if the ID exceeds the current max
 */
static void
usb_ac_add_unit_descriptor(usb_ac_state_t *uacp, uchar_t *buffer,
	size_t buflen)
{
	void	*descr;
	int	len;
	char	*format;
	size_t	size;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, uacp->usb_ac_log_handle,
	    "usb_ac_add_unit_descriptor: 0x%x 0x%x 0x%x",
	    buffer[0], buffer[1], buffer[2]);

	/* doubling the length should allow for padding */
	len = 2 * buffer[0];
	descr = kmem_zalloc(len, KM_SLEEP);

	switch (buffer[2]) {
	case USB_AUDIO_INPUT_TERMINAL:
		format = CS_AC_INPUT_TERM_FORMAT;
		size = CS_AC_INPUT_TERM_SIZE;

		break;
	case USB_AUDIO_OUTPUT_TERMINAL:
		format = CS_AC_OUTPUT_TERM_FORMAT;
		size = CS_AC_OUTPUT_TERM_SIZE;

		break;
	case USB_AUDIO_MIXER_UNIT:
		format = CS_AC_MIXER_UNIT_DESCR1_FORMAT "255c";
		size = CS_AC_MIXER_UNIT_DESCR1_SIZE + buffer[4] - 1;

		break;
	case USB_AUDIO_SELECTOR_UNIT:
		format = CS_AC_SELECTOR_UNIT_DESCR1_FORMAT "255c";
		size = CS_AC_SELECTOR_UNIT_DESCR1_SIZE + buffer[4] - 1;

		break;
	case USB_AUDIO_FEATURE_UNIT:
		format = CS_AC_FEATURE_UNIT_FORMAT "255c";
		size = CS_AC_FEATURE_UNIT_SIZE;

		break;
	case USB_AUDIO_PROCESSING_UNIT:
		format = CS_AC_PROCESSING_UNIT_DESCR1_FORMAT "255c";
		size = CS_AC_PROCESSING_UNIT_DESCR1_SIZE + buffer[6] - 1;

		break;
	case USB_AUDIO_EXTENSION_UNIT:
		format = CS_AC_EXTENSION_UNIT_DESCR1_FORMAT "255c";
		size = CS_AC_EXTENSION_UNIT_DESCR1_SIZE + buffer[6] - 1;

		break;
	default:
		USB_DPRINTF_L2(PRINT_MASK_ATTA,
		    uacp->usb_ac_log_handle,
		    "unsupported descriptor %d", buffer[2]);

		/* ignore this descriptor */
		kmem_free(descr, len);

		return;
	}

	if (usb_parse_data(format, buffer, buflen, descr, len) < size) {
		/* ignore this descriptor */
		kmem_free(descr, len);

		return;
	}

	switch (buffer[2]) {
	case USB_AUDIO_INPUT_TERMINAL:
	{
		usb_audio_input_term_descr_t *d =
		    (usb_audio_input_term_descr_t *)descr;

		USB_DPRINTF_L3(PRINT_MASK_ATTA,
		    uacp->usb_ac_log_handle,
		    "input term: type=0x%x sub=0x%x termid=0x%x\n\t"
		    "termtype=0x%x assoc=0x%x #ch=%d "
		    "chconf=0x%x ich=0x%x iterm=0x%x",
		    d->bDescriptorType, d->bDescriptorSubType,
		    d->bTerminalID, d->wTerminalType,
		    d->bAssocTerminal, d->bNrChannels,
		    d->wChannelConfig, d->iChannelNames,
		    d->iTerminal);

		usb_ac_alloc_unit(uacp, d->bTerminalID);
		uacp->usb_ac_units[d->bTerminalID].acu_descriptor = descr;
		uacp->usb_ac_units[d->bTerminalID].acu_type = buffer[2];
		uacp->usb_ac_units[d->bTerminalID].acu_descr_length = len;

		break;
	}
	case USB_AUDIO_OUTPUT_TERMINAL:
	{
		usb_audio_output_term_descr_t *d =
		    (usb_audio_output_term_descr_t *)descr;

		USB_DPRINTF_L3(PRINT_MASK_ATTA,
		    uacp->usb_ac_log_handle,
		    "output term: type=0x%x sub=0x%x termid=0x%x\n\t"
		    "termtype=0x%x assoc=0x%x sourceID=0x%x iterm=0x%x",
		    d->bDescriptorType, d->bDescriptorSubType,
		    d->bTerminalID, d->wTerminalType,
		    d->bAssocTerminal, d->bSourceID,
		    d->iTerminal);

		usb_ac_alloc_unit(uacp, d->bTerminalID);
		uacp->usb_ac_units[d->bTerminalID].acu_descriptor = descr;
		uacp->usb_ac_units[d->bTerminalID].acu_type = buffer[2];
		uacp->usb_ac_units[d->bTerminalID].acu_descr_length = len;

		break;
	}
	case USB_AUDIO_MIXER_UNIT:
	{
		usb_audio_mixer_unit_descr1_t *d =
		    (usb_audio_mixer_unit_descr1_t *)descr;

		USB_DPRINTF_L3(PRINT_MASK_ATTA,
		    uacp->usb_ac_log_handle,
		    "mixer unit: type=0x%x sub=0x%x unitid=0x%x\n\t"
		    "#pins=0x%x sourceid[0]=0x%x",
		    d->bDescriptorType, d->bDescriptorSubType,
		    d->bUnitID, d->bNrInPins, d->baSourceID[0]);
		usb_ac_alloc_unit(uacp, d->bUnitID);
		uacp->usb_ac_units[d->bUnitID].acu_descriptor = descr;
		uacp->usb_ac_units[d->bUnitID].acu_type = buffer[2];
		uacp->usb_ac_units[d->bUnitID].acu_descr_length = len;

		break;
	}
	case USB_AUDIO_SELECTOR_UNIT:
	{
		usb_audio_selector_unit_descr1_t *d =
		    (usb_audio_selector_unit_descr1_t *)descr;

		USB_DPRINTF_L3(PRINT_MASK_ATTA,
		    uacp->usb_ac_log_handle,
		    "selector unit: type=0x%x sub=0x%x unitid=0x%x\n\t"
		    "#pins=0x%x sourceid[0]=0x%x",
		    d->bDescriptorType, d->bDescriptorSubType,
		    d->bUnitID, d->bNrInPins, d->baSourceID[0]);
		usb_ac_alloc_unit(uacp, d->bUnitID);
		uacp->usb_ac_units[d->bUnitID].acu_descriptor = descr;
		uacp->usb_ac_units[d->bUnitID].acu_type = buffer[2];
		uacp->usb_ac_units[d->bUnitID].acu_descr_length = len;

		break;
	}
	case USB_AUDIO_FEATURE_UNIT:
	{
		usb_audio_feature_unit_descr1_t *d =
		    (usb_audio_feature_unit_descr1_t *)descr;

		USB_DPRINTF_L3(PRINT_MASK_ATTA,
		    uacp->usb_ac_log_handle,
		    "feature unit: type=0x%x sub=0x%x unitid=0x%x\n\t"
		    "sourceid=0x%x size=0x%x",
		    d->bDescriptorType, d->bDescriptorSubType,
		    d->bUnitID, d->bSourceID, d->bControlSize);

		usb_ac_alloc_unit(uacp, d->bUnitID);
		uacp->usb_ac_units[d->bUnitID].acu_descriptor = descr;
		uacp->usb_ac_units[d->bUnitID].acu_type = buffer[2];
		uacp->usb_ac_units[d->bUnitID].acu_descr_length = len;

		break;
	}
	case USB_AUDIO_PROCESSING_UNIT:
	{
		usb_audio_processing_unit_descr1_t *d =
		    (usb_audio_processing_unit_descr1_t *)descr;

		USB_DPRINTF_L3(PRINT_MASK_ATTA,
		    uacp->usb_ac_log_handle,
		    "processing unit: type=0x%x sub=0x%x unitid=0x%x\n\t"
		    "#pins=0x%x sourceid[0]=0x%x",
		    d->bDescriptorType, d->bDescriptorSubType,
		    d->bUnitID, d->bNrInPins, d->baSourceID[0]);
		usb_ac_alloc_unit(uacp, d->bUnitID);
		uacp->usb_ac_units[d->bUnitID].acu_descriptor = descr;
		uacp->usb_ac_units[d->bUnitID].acu_type = buffer[2];
		uacp->usb_ac_units[d->bUnitID].acu_descr_length = len;

		break;
	}
	case USB_AUDIO_EXTENSION_UNIT:
	{
		usb_audio_extension_unit_descr1_t *d =
		    (usb_audio_extension_unit_descr1_t *)descr;

		USB_DPRINTF_L3(PRINT_MASK_ATTA,
		    uacp->usb_ac_log_handle,
		    "mixer unit: type=0x%x sub=0x%x unitid=0x%x\n\t"
		    "#pins=0x%x sourceid[0]=0x%x",
		    d->bDescriptorType, d->bDescriptorSubType,
		    d->bUnitID, d->bNrInPins, d->baSourceID[0]);
		usb_ac_alloc_unit(uacp, d->bUnitID);
		uacp->usb_ac_units[d->bUnitID].acu_descriptor = descr;
		uacp->usb_ac_units[d->bUnitID].acu_type = buffer[2];
		uacp->usb_ac_units[d->bUnitID].acu_descr_length = len;

		break;
	}
	default:
		break;
	}
}


/*
 * usb_ac_alloc_unit:
 *	check if the unit ID is less than max_unit in which case no
 *	extra entries are needed. If more entries are needed, copy over
 *	the existing array into a new larger array
 */
static void
usb_ac_alloc_unit(usb_ac_state_t *uacp, uint_t unit)
{
	usb_ac_unit_list_t *old = NULL;
	uint_t	max_unit;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, uacp->usb_ac_log_handle,
	    "usb_ac_alloc_unit: unit=%d", unit);

	if (uacp->usb_ac_units) {
		if (unit < uacp->usb_ac_max_unit) {
			/* existing array is big enough */

			return;
		}
		old = uacp->usb_ac_units;
		max_unit = uacp->usb_ac_max_unit;
	}

	/* allocate two extra ones */
	unit += 2;
	uacp->usb_ac_max_unit = unit;
	uacp->usb_ac_units = kmem_zalloc(unit *
	    sizeof (usb_ac_unit_list_t), KM_SLEEP);

	if (old) {
		size_t len = max_unit * sizeof (usb_ac_unit_list_t);
		bcopy(old, uacp->usb_ac_units, len);

		kmem_free(old, len);
	}
}


/*
 * usb_ac_free_all_units:
 *	free the entire unit list
 */
static void
usb_ac_free_all_units(usb_ac_state_t *uacp)
{
	uint_t	unit;
	usb_ac_unit_list_t *unitp;

	if (uacp->usb_ac_units == NULL) {

		return;
	}

	USB_DPRINTF_L4(PRINT_MASK_ATTA, uacp->usb_ac_log_handle,
	    "usb_ac_alloc_unit: max_unit=%d", uacp->usb_ac_max_unit);

	for (unit = 0; unit < uacp->usb_ac_max_unit; unit++) {
		unitp = &uacp->usb_ac_units[unit];
		if (unitp) {
			if (unitp->acu_descriptor) {
				kmem_free(unitp->acu_descriptor,
				    unitp->acu_descr_length);
			}
		}
	}

	kmem_free(uacp->usb_ac_units, uacp->usb_ac_max_unit *
	    sizeof (usb_ac_unit_list_t));
}


/*
 * usb_ac_lookup_port_type:
 *	map term type to port type
 *	default just return LINE_IN + LINE_OUT
 */
static int
usb_ac_lookup_port_type(ushort_t termtype)
{
	uint_t i;

	for (i = 0; ; i++) {
		if (usb_ac_term_type_map[i].term_type == 0) {

			break;
		}

		if (usb_ac_term_type_map[i].term_type == termtype) {

			return (usb_ac_term_type_map[i].port_type);
		}
	}

	return (AUDIO_LINE_IN|AUDIO_LINE_OUT);
}


/*
 * usb_ac_update_port:
 *	called for each terminal
 */
/*ARGSUSED*/
static int
usb_ac_update_port(usb_ac_state_t *uacp, uint_t id,
    uint_t dir, uint_t channel, uint_t control, uint_t arg1, uint_t *depth)
{
	if (dir & AUDIO_PLAY) {
		usb_audio_output_term_descr_t *d =
		    (usb_audio_output_term_descr_t *)
		    uacp->usb_ac_units[id].acu_descriptor;
		uint_t port_type =
		    usb_ac_lookup_port_type(d->wTerminalType);

		USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "usb_ac_update_port: dir=%d type=0x%x port type=%d",
		    dir, d->wTerminalType, port_type);

		uacp->usb_ac_output_ports |= port_type;
		uacp->usb_ac_output_ports &= ~AUDIO_LINE_IN;
	} else {
		usb_audio_output_term_descr_t *d =
		    (usb_audio_output_term_descr_t *)
		    uacp->usb_ac_units[id].acu_descriptor;
		uint_t port_type =
		    usb_ac_lookup_port_type(d->wTerminalType);

		USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "usb_ac_update_port: dir=%d type=0x%x port type=%d",
		    dir, d->wTerminalType, port_type);

		uacp->usb_ac_input_ports |=
		    usb_ac_lookup_port_type(d->wTerminalType);
		uacp->usb_ac_input_ports &= ~AUDIO_LINE_OUT;
	}

	return (USB_SUCCESS);
}


/*
 * usb_ac_map_termtype_to_port:
 *	starting from a streaming termtype find all
 *	input or output terminals and OR into uacp->usb_ac_input_ports
 *	or uacp->usb_ac_output_ports;
 */
static void
usb_ac_map_termtype_to_port(usb_ac_state_t *uacp, uint_t dir)
{
	uint_t count = 0;
	uint_t depth = 0;
	uint_t search_type = (dir & AUDIO_PLAY) ?
	    USB_AUDIO_OUTPUT_TERMINAL : USB_AUDIO_INPUT_TERMINAL;

	USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
	    "usb_ac_map_term_to_port: dir=%d", dir);

	(void) usb_ac_traverse_all_units(uacp, dir, search_type, 0,
	    0, USB_AC_FIND_ALL, &count, 0, &depth, usb_ac_update_port);

	ASSERT(depth == 0);
}


/*
 * usb_ac_set_port:
 *	find a selector port (record side only) and set the
 *	input to the matching pin
 */
static uint_t
usb_ac_set_port(usb_ac_state_t *uacp, uint_t dir, uint_t port)
{
	uint_t count = 0;
	uint_t id;
	uint_t depth = 0;

	USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
	    "usb_ac_set_port: dir=%d port=%d", dir, port);

	/* we only support the selector for the record side */
	if (dir & AUDIO_RECORD) {
		id = usb_ac_traverse_all_units(uacp, dir,
		    USB_AUDIO_SELECTOR_UNIT, 0,
		    0, USB_AC_FIND_ONE, &count, port, &depth,
		    usb_ac_set_selector);

		USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "usb_ac_set_port: id=%d count=%d port=%d",
		    id, count, port);

		ASSERT(depth == 0);
	}

	return (USB_SUCCESS);
}


/*
 * usb_ac_match_port:
 *	given the requested port type, find a correspondig term type
 *	Called from usb_ac_traverse_all_units()
 */
/*ARGSUSED*/
static int
usb_ac_match_port(usb_ac_state_t *uacp, uint_t id,
    uint_t dir, uint_t channel, uint_t control, uint_t arg1, uint_t *depth)
{
	uint_t port_type;

	USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
	    "usb_ac_match_port: id=%d dir=%d port=%d",
	    id, dir, arg1);

	if (dir & AUDIO_PLAY) {
		usb_audio_output_term_descr_t *d =
		    (usb_audio_output_term_descr_t *)
		    uacp->usb_ac_units[id].acu_descriptor;
		port_type = usb_ac_lookup_port_type(d->wTerminalType);

		USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "usb_ac_match_port: "
		    "dir=%d type=0x%x port_type=%d port=%d",
		    dir, d->wTerminalType, port_type, arg1);
	} else {
		usb_audio_output_term_descr_t *d =
		    (usb_audio_output_term_descr_t *)
		    uacp->usb_ac_units[id].acu_descriptor;
		port_type = usb_ac_lookup_port_type(d->wTerminalType);

		USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "usb_ac_match_port: "
		    "dir=%d type=0x%x port_type=%d port=%d",
		    dir, d->wTerminalType, port_type, arg1);
	}

	return ((port_type & arg1) ? USB_SUCCESS : USB_FAILURE);
}


/*
 * usb_ac_set_selector:
 *	Called from usb_ac_traverse_all_units()
 *	Find the correct pin and set selector to this pin
 */
/*ARGSUSED*/
static int
usb_ac_set_selector(usb_ac_state_t *uacp, uint_t id,
    uint_t dir, uint_t channel, uint_t control, uint_t arg1, uint_t *depth)
{
	uint_t count = 0;
	uint_t unit = USB_AC_ID_NONE;
	uint_t pin;
	uint_t search_target =
	    (dir & AUDIO_PLAY) ? USB_AUDIO_OUTPUT_TERMINAL :
	    USB_AUDIO_INPUT_TERMINAL;
	usb_audio_selector_unit_descr1_t *d =
	    (usb_audio_selector_unit_descr1_t *)
	    uacp->usb_ac_units[id].acu_descriptor;
	int n_sourceID = d->bNrInPins;
	int rval = USB_FAILURE;

	USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
	    "usb_ac_set_selector: id=%d dir=%d port=%d",
	    id, dir, arg1);

	/*
	 * for each pin, find a term type that matches the
	 * requested port type
	 */
	for (pin = 0; pin < n_sourceID; pin++) {
		if (d->baSourceID[pin] == 0) {

			break;
		}
		unit = d->baSourceID[pin];

		USB_DPRINTF_L3(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "usb_ac_set_selector: pin=%d unit=%d", pin, unit);

		if (uacp->usb_ac_unit_type[unit] == search_target) {
			if (usb_ac_match_port(uacp, unit, dir, channel,
			    control, arg1, depth) == USB_SUCCESS) {

				break;
			} else {
				unit = USB_AC_ID_NONE;

				continue;
			}
		}

		/* find units connected to this unit */
		unit = usb_ac_traverse_connections(uacp, unit,
		    dir, search_target, channel, control,
		    USB_AC_FIND_ONE, &count, arg1, depth,
		    usb_ac_match_port);

		if (unit != USB_AC_ID_NONE) {

			break;
		}
	}


	if (unit != USB_AC_ID_NONE) {
		mblk_t		*data;
		usb_cr_t	cr;
		usb_cb_flags_t	cb_flags;

		USB_DPRINTF_L3(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "usb_ac_set_selector: found id=%d at pin %d", unit, pin);

		mutex_exit(&uacp->usb_ac_mutex);

		data = allocb_wait(1, BPRI_HI, STR_NOSIG, NULL);

		/* pins are 1-based */
		*(data->b_rptr) = (char)++pin;

		if (usb_pipe_sync_ctrl_xfer(
		    uacp->usb_ac_dip,
		    uacp->usb_ac_default_ph,
		    USB_DEV_REQ_HOST_TO_DEV |
		    USB_DEV_REQ_TYPE_CLASS |
		    USB_DEV_REQ_RCPT_IF,	/* bmRequestType */
		    USB_AUDIO_SET_CUR,		/* bRequest */
		    0,				/* wValue */
						/* feature unit and id */
		    (id << 8)| uacp->usb_ac_ifno, /* wIndex */
		    1,				/* wLength */
		    &data,
		    USB_ATTRS_NONE,
		    &cr, &cb_flags,
		    USB_FLAGS_SLEEP) == USB_SUCCESS) {
			USB_DPRINTF_L3(PRINT_MASK_ALL,
			    uacp->usb_ac_log_handle,
			    "set current selection: %d", *data->b_rptr);

			rval = USB_SUCCESS;
		} else {
			USB_DPRINTF_L2(PRINT_MASK_ALL,
			    uacp->usb_ac_log_handle,
			    "set current pin selection failed");
		}
		freemsg(data);

		mutex_enter(&uacp->usb_ac_mutex);
	} else {
		USB_DPRINTF_L2(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "usb_ac_set_selector: nothing found");
	}

	return (rval);
}


/*
 * usb_ac_set_control:
 *	apply func to all units of search_target type for both the
 *	requested channel and master channel
 */
static uint_t
usb_ac_set_control(usb_ac_state_t *uacp, uint_t dir, uint_t search_target,
	uint_t channel, uint_t control, uint_t all_or_one,
	uint_t *count, uint_t arg1,
	int (*func)(usb_ac_state_t *uacp, uint_t unit, uint_t dir,
		uint_t channel, uint_t control, uint_t arg1, uint_t *depth))
{
	uint_t id;
	uint_t depth = 0;

	USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
	    "usb_ac_set_control: dir=%d type=%d ch=%d cntl=%d",
	    dir, search_target, channel, control);


	id = usb_ac_traverse_all_units(uacp, dir, search_target, channel,
	    control, all_or_one, count, arg1, &depth, func);

	if ((channel != 0) &&
	    (((id == USB_AC_ID_NONE) && (all_or_one == USB_AC_FIND_ONE)) ||
	    (all_or_one == USB_AC_FIND_ALL)))  {
		/* try master channel */
		channel = 0;
		id = usb_ac_traverse_all_units(uacp, dir, search_target,
		    channel, control, all_or_one, count, arg1,
		    &depth, func);
	}

	ASSERT(depth == 0);

	return (id);
}


/*
 * usb_ac_traverse_all_units:
 *	traverse all units starting with all IT or OT depending on direction.
 *	If no unit is found for the particular channel, try master channel
 *	If a matching unit is found, apply the function passed by
 *	the caller
 */
static uint_t
usb_ac_traverse_all_units(usb_ac_state_t *uacp, uint_t dir,
	uint_t search_target, uint_t channel, uint_t control,
	uint_t all_or_one, uint_t *count, uint_t arg1, uint_t *depth,
	int (*func)(usb_ac_state_t *uacp, uint_t unit, uint_t dir,
		uint_t channel, uint_t control, uint_t arg1, uint_t *depth))
{
	uint_t unit, start_type, id;

	USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
	    "usb_ac_traverse_all_units: "
	    "dir=%d type=%d ch=%d cntl=%d all=%d depth=%d",
	    dir, search_target, channel, control, all_or_one, *depth);

	start_type = (dir & AUDIO_PLAY) ? USB_AUDIO_INPUT_TERMINAL :
	    USB_AUDIO_OUTPUT_TERMINAL;

	/* keep track of recursion */
	if ((*depth)++ > USB_AC_MAX_DEPTH) {
		USB_DPRINTF_L1(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "Unit topology too complex, giving up");

		return (USB_AC_ID_NONE);
	}

	for (unit = 1; unit < uacp->usb_ac_max_unit; unit++) {
		/* is this an IT or OT? */
		if (uacp->usb_ac_unit_type[unit] != start_type) {

			continue;
		}

		/* start at streaming term types */
		if (dir & AUDIO_PLAY) {
			usb_audio_input_term_descr_t *d =
			    uacp->usb_ac_units[unit].acu_descriptor;
			if (d->wTerminalType !=
			    USB_AUDIO_TERM_TYPE_STREAMING) {

				continue;
			}
		} else {
			usb_audio_output_term_descr_t *d =
			    uacp->usb_ac_units[unit].acu_descriptor;
			if (d->wTerminalType !=
			    USB_AUDIO_TERM_TYPE_STREAMING) {

				continue;
			}
		}

		/* find units connected to this unit */
		id = usb_ac_traverse_connections(uacp, unit, dir,
		    search_target, channel, control, all_or_one, count,
		    arg1, depth, func);

		if ((all_or_one == USB_AC_FIND_ONE) &&
		    (id != USB_AC_ID_NONE)) {
			unit = id;

			break;
		}
	}

	(*depth)--;

	return	((unit < uacp->usb_ac_max_unit) ? unit : USB_AC_ID_NONE);
}


/*
 * usb_ac_set_monitor_gain_control:
 *	search for a feature unit between output terminal (OT) and
 *	input terminal. We are looking for a path between
 *	for example a microphone and a speaker through a feature unit
 *	and mixer
 */
static uint_t
usb_ac_set_monitor_gain_control(usb_ac_state_t *uacp, uint_t dir,
	uint_t search_target, uint_t channel, uint_t control,
	uint_t all_or_one, uint_t *count, uint_t arg1,
	int (*func)(usb_ac_state_t *uacp, uint_t unit, uint_t dir,
		uint_t channel, uint_t control, uint_t arg1, uint_t *depth))
{
	uint_t unit, id;
	uint_t depth = 0;

	USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
	    "usb_ac_set_monitor_gain_control: dir=%d type=%d ch=%d cntl=%d",
	    dir, search_target, channel, control);

	for (unit = 1; unit < uacp->usb_ac_max_unit; unit++) {
		usb_audio_output_term_descr_t *d =
		    uacp->usb_ac_units[unit].acu_descriptor;

		/* is this an OT and not stream type? */
		if ((uacp->usb_ac_unit_type[unit] ==
		    USB_AUDIO_OUTPUT_TERMINAL) &&
		    (d->wTerminalType != USB_AUDIO_TERM_TYPE_STREAMING)) {

			/* find units connected to this unit */
			id = usb_ac_traverse_connections(uacp, unit, dir,
			    search_target, channel, control, all_or_one, count,
			    arg1, &depth, func);

			if ((all_or_one == USB_AC_FIND_ONE) &&
			    (id != USB_AC_ID_NONE)) {

				break;
			}
		}
	}

	ASSERT(depth == 0);

	return (id);
}


/*
 * usb_ac_push/pop_unit
 *	add/remove unit ID to the traverse path
 */
static void
usb_ac_push_unit_id(usb_ac_state_t *uacp, uint_t unit)
{
	USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
	    "usb_ac_push_unit_id: pushing %d at %d", unit,
	    uacp->usb_ac_traverse_path_index);

	uacp->usb_ac_traverse_path[uacp->usb_ac_traverse_path_index++] =
	    (uchar_t)unit;
	ASSERT(uacp->usb_ac_traverse_path_index < uacp->usb_ac_max_unit);
}


static void
usb_ac_pop_unit_id(usb_ac_state_t *uacp, uint_t unit)
{
	USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
	    "usb_ac_push_unit_id: popping %d at %d", unit,
	    uacp->usb_ac_traverse_path_index);

	uacp->usb_ac_traverse_path[uacp->usb_ac_traverse_path_index--] = 0;
}


/*
 * usb_ac_show_traverse_path:
 *	display entire path, just for debugging
 */
static void
usb_ac_show_traverse_path(usb_ac_state_t *uacp)
{
	int i;

	for (i = 0; i < uacp->usb_ac_traverse_path_index; i++) {
		USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "traverse path %d: unit=%d type=%d",
		    i, uacp->usb_ac_traverse_path[i],
		    uacp->usb_ac_unit_type[uacp->usb_ac_traverse_path[i]]);
	}
}


/*
 * usb_ac_check_path:
 *	check for a specified type in the traverse path
 */
static int
usb_ac_check_path(usb_ac_state_t *uacp, uint_t type)
{
	int i;

	for (i = 0; i < uacp->usb_ac_traverse_path_index; i++) {
		uint_t unit = uacp->usb_ac_traverse_path[i];

		if (uacp->usb_ac_unit_type[unit] == type) {

			return (USB_SUCCESS);
		}
	}

	return (USB_FAILURE);
}


/*
 * usb_ac_traverse_connections:
 *	traverse all units and for each unit with the right type, call
 *	func. If the func returns a success and search == USB_AC_FIND_ONE,
 *	we are done. If all is set then we continue until we terminate
 *	and input or output terminal.
 *	For audio play, we traverse columns starting from an input terminal
 *	to an output terminal while for record we traverse rows from output
 *	terminal to input terminal.
 */
static uint_t
usb_ac_traverse_connections(usb_ac_state_t *uacp, uint_t start_unit, uint_t dir,
	uint_t search_target, uint_t channel, uint_t control,
	uint_t all_or_one, uint_t *count, uint_t arg1, uint_t *depth,
	int (*func)(usb_ac_state_t *uacp, uint_t unit, uint_t dir,
		uint_t channel, uint_t control, uint_t arg1, uint_t *depth))
{
	uint_t unit, id;
	uint_t done = (dir & AUDIO_PLAY) ? USB_AUDIO_OUTPUT_TERMINAL :
	    USB_AUDIO_INPUT_TERMINAL;

	USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
	    "usb_ac_traverse_connections: "
	    "start=%d dir=%d type=%d ch=%d cntl=%d all=%d depth=%d",
	    start_unit, dir, search_target, channel, control,
	    all_or_one, *depth);

	/* keep track of recursion depth */
	if ((*depth)++ > USB_AC_MAX_DEPTH) {
		USB_DPRINTF_L1(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "Unit topology too complex, giving up");

		return (USB_AC_ID_NONE);
	}

	usb_ac_push_unit_id(uacp, start_unit);

	for (unit = 1; unit < uacp->usb_ac_max_unit; unit++) {
		uint_t entry = (dir & AUDIO_PLAY) ?
		    uacp->usb_ac_connections[unit][start_unit] :
		    uacp->usb_ac_connections[start_unit][unit];

		if (entry) {
			USB_DPRINTF_L3(PRINT_MASK_ALL,
			    uacp->usb_ac_log_handle,
			    "start=%d unit=%d entry=%d type=%d "
			    "done=%d found=%d",
			    start_unit, unit, entry, search_target, done,
			    uacp->usb_ac_unit_type[unit]);

			/* did we find a matching type? */
			if (uacp->usb_ac_unit_type[unit] == search_target) {
				USB_DPRINTF_L3(PRINT_MASK_ALL,
				    uacp->usb_ac_log_handle,
				    "match: dir=%d unit=%d type=%d",
				    dir, unit, search_target);

				/* yes, no apply function to this unit */
				if (func(uacp, unit, dir, channel,
				    control, arg1, depth) == USB_SUCCESS) {
					(*count)++;

					USB_DPRINTF_L3(PRINT_MASK_ALL,
					    uacp->usb_ac_log_handle,
					    "func returned success, "
					    "unit=%d all=%d", unit,
					    all_or_one);

					/* are we done? */
					if (all_or_one == USB_AC_FIND_ONE) {

						break;
					}
				}
			}

			/* did we find the terminating unit */
			if (uacp->usb_ac_unit_type[unit] == done) {

				continue;
			}
			id = usb_ac_traverse_connections(uacp, unit, dir,
			    search_target, channel, control,
			    all_or_one, count, arg1, depth, func);
			if ((id != USB_AC_ID_NONE) &&
			    (all_or_one == USB_AC_FIND_ONE)) {
				unit = id;

				break;
			}
		}
	}

	(*depth)--;
	usb_ac_pop_unit_id(uacp, start_unit);

	return	((unit < uacp->usb_ac_max_unit) ? unit : USB_AC_ID_NONE);
}


/*
 * Event Management
 *
 * usb_ac_disconnect_event_cb:
 *	The device has been disconnected. we either wait for
 *	detach or a reconnect event.
 */
static int
usb_ac_disconnect_event_cb(dev_info_t *dip)
{
	usb_ac_state_t *uacp = (usb_ac_state_t *)ddi_get_soft_state(
	    usb_ac_statep, ddi_get_instance(dip));
	char *nm = "usb_ac_disconnect_event_cb";

	dinfo("%s: %s - dip=%p\n", uacp->dstr, nm, (void *)dip);

	usb_ac_serialize_access(uacp);

	/* setting to disconnect state will prevent replumbing */
	mutex_enter(&uacp->usb_ac_mutex);
	uacp->usb_ac_dev_state = USB_DEV_DISCONNECTED;

	if (uacp->usb_ac_busy_count) {
		USB_DPRINTF_L0(PRINT_MASK_EVENTS, uacp->usb_ac_log_handle,
		    "device was disconnected while busy. "
		    "Data may have been lost");
	}
	mutex_exit(&uacp->usb_ac_mutex);

	usb_ac_release_access(uacp);
	dinfo("%s: %s done\n", uacp->dstr, nm);

	return (USB_SUCCESS);
}


/*
 * usb_ac_cpr_suspend:
 */
static int
usb_ac_cpr_suspend(dev_info_t *dip)
{
	usb_ac_state_t *uacp = (usb_ac_state_t *)ddi_get_soft_state(
	    usb_ac_statep, ddi_get_instance(dip));

	USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
	    "usb_ac_cpr_suspend: Begin");

	mutex_enter(&uacp->usb_ac_mutex);
	uacp->usb_ac_dev_state = USB_DEV_SUSPENDED;
	mutex_exit(&uacp->usb_ac_mutex);

	USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
	    "usb_ac_cpr_suspend: End");

	return (USB_SUCCESS);
}



/*
 * usb_ac_reconnect_event_cb:
 *	The device was disconnected but this instance not detached, probably
 *	because the device was busy.
 *	if the same device, continue with restoring state
 *	We should either be in the unplumbed state or the plumbed open
 *	state.
 */
static int
usb_ac_reconnect_event_cb(dev_info_t *dip)
{
	usb_ac_state_t *uacp = (usb_ac_state_t *)ddi_get_soft_state(
	    usb_ac_statep, ddi_get_instance(dip));
	char *nm = "usb_ac_reconnect_event_cb";

	dinfo("%s: %s - dip=%p\n", uacp->dstr, nm, (void *)dip);

	mutex_enter(&uacp->usb_ac_mutex);
	mutex_exit(&uacp->usb_ac_mutex);

	usb_ac_serialize_access(uacp);

	/* check the plumbing state */
	mutex_enter(&uacp->usb_ac_mutex);
	uacp->usb_ac_busy_count++;
	if (uacp->usb_ac_plumbing_state ==
	    USB_AC_STATE_PLUMBED) {
		mutex_exit(&uacp->usb_ac_mutex);
		usb_ac_restore_device_state(dip, uacp);
		mutex_enter(&uacp->usb_ac_mutex);
	}
	uacp->usb_ac_busy_count--;

	if (uacp->usb_ac_busy_count) {
		USB_DPRINTF_L0(PRINT_MASK_EVENTS, uacp->usb_ac_log_handle,
		    "busy device has been reconnected");
	}

	mutex_exit(&uacp->usb_ac_mutex);

	usb_ac_release_access(uacp);
	dinfo("%s: %s done\n", uacp->dstr, nm);

	return (USB_SUCCESS);
}


/*
 * usb_ac_cpr_resume:
 *	Restore device state
 */
static void
usb_ac_cpr_resume(dev_info_t *dip)
{
	usb_ac_state_t *uacp = (usb_ac_state_t *)ddi_get_soft_state(
	    usb_ac_statep, ddi_get_instance(dip));

	USB_DPRINTF_L4(PRINT_MASK_EVENTS, uacp->usb_ac_log_handle,
	    "usb_ac_cpr_resume");

	usb_ac_serialize_access(uacp);

	usb_ac_restore_device_state(dip, uacp);

	usb_ac_release_access(uacp);
}


/*
 * usb_ac_restore_device_state:
 *	Set original configuration of the device
 *	enable wrq - this starts new transactions on the control pipe
 */
static void
usb_ac_restore_device_state(dev_info_t *dip, usb_ac_state_t *uacp)
{
	usb_ac_power_t	*uacpm;
	int	rval;

	USB_DPRINTF_L4(PRINT_MASK_ATTA, uacp->usb_ac_log_handle,
	    "usb_ac_restore_device_state:");

	usb_ac_pm_busy_component(uacp);
	(void) pm_raise_power(dip, 0, USB_DEV_OS_FULL_PWR);

	/* Check if we are talking to the same device */
	if (usb_check_same_device(dip, uacp->usb_ac_log_handle,
	    USB_LOG_L0, PRINT_MASK_ALL,
	    USB_CHK_BASIC|USB_CHK_CFG, NULL) != USB_SUCCESS) {
		usb_ac_pm_idle_component(uacp);

		/* change the device state from suspended to disconnected */
		mutex_enter(&uacp->usb_ac_mutex);
		uacp->usb_ac_dev_state = USB_DEV_DISCONNECTED;
		mutex_exit(&uacp->usb_ac_mutex);

		return;
	}

	mutex_enter(&uacp->usb_ac_mutex);
	uacpm = uacp->usb_ac_pm;
	if (uacpm) {
		if (uacpm->acpm_wakeup_enabled) {
			mutex_exit(&uacp->usb_ac_mutex);

			if ((rval = usb_handle_remote_wakeup(uacp->usb_ac_dip,
			    USB_REMOTE_WAKEUP_ENABLE)) != USB_SUCCESS) {

				USB_DPRINTF_L4(PRINT_MASK_ATTA,
				    uacp->usb_ac_log_handle,
				    "usb_ac_restore_device_state: "
				    "remote wakeup "
				    "enable failed, rval=%d", rval);
			}

			mutex_enter(&uacp->usb_ac_mutex);
		}
	}

	/* prevent unplumbing */
	uacp->usb_ac_busy_count++;
	uacp->usb_ac_dev_state = USB_DEV_ONLINE;
	if (uacp->usb_ac_plumbing_state == USB_AC_STATE_PLUMBED) {
		(void) usb_ac_restore_audio_state(uacp, 0);
	}
	uacp->usb_ac_busy_count--;
	mutex_exit(&uacp->usb_ac_mutex);
	usb_ac_pm_idle_component(uacp);
}


/*
 * usb_ac_am_restore_state
 */
static void
usb_ac_am_restore_state(void *arg)
{
	usb_ac_state_t *uacp = (usb_ac_state_t *)arg;

	USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
	    "usb_ac_am_restore_state: Begin");

	usb_ac_serialize_access(uacp);

	mutex_enter(&uacp->usb_ac_mutex);

	if (uacp->usb_ac_plumbing_state ==
	    USB_AC_STATE_PLUMBED_RESTORING) {
		mutex_exit(&uacp->usb_ac_mutex);

		/*
		 * allow hid and usb_as to restore themselves
		 * (some handshake would have been preferable though)
		 */
		delay(USB_AC_RESTORE_DELAY);

		audio_sup_restore_state(uacp->usb_ac_audiohdl);

		mutex_enter(&uacp->usb_ac_mutex);
		uacp->usb_ac_plumbing_state = USB_AC_STATE_PLUMBED;
	}

	/* allow unplumbing */
	uacp->usb_ac_busy_count--;
	mutex_exit(&uacp->usb_ac_mutex);

	usb_ac_release_access(uacp);

	USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
	    "usb_ac_am_restore_state: End");
}


/*
 * usb_ac_restore_audio_state:
 */
static int
usb_ac_restore_audio_state(usb_ac_state_t *uacp, int flag)
{
	ASSERT(mutex_owned(&uacp->usb_ac_mutex));

	USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
	    "usb_ac_restore_audio_state: flag=%d", flag);

	switch (uacp->usb_ac_plumbing_state) {
	case USB_AC_STATE_PLUMBED:
		uacp->usb_ac_plumbing_state =
		    USB_AC_STATE_PLUMBED_RESTORING;

		break;
	case USB_AC_STATE_UNPLUMBED:

		return (USB_SUCCESS);
	case USB_AC_STATE_PLUMBED_RESTORING:
	default:

		return (USB_FAILURE);
	}

	/*
	 * increment busy_count again, it will be decremented
	 * in usb_ac_am_restore_state
	 */
	uacp->usb_ac_busy_count++;

	if (flag & USB_FLAGS_SLEEP) {
		mutex_exit(&uacp->usb_ac_mutex);
		usb_ac_am_restore_state((void *)uacp);
		mutex_enter(&uacp->usb_ac_mutex);
	} else {
		mutex_exit(&uacp->usb_ac_mutex);
		if (usb_async_req(uacp->usb_ac_dip,
		    usb_ac_am_restore_state,
		    (void *)uacp, USB_FLAGS_SLEEP) != USB_SUCCESS) {

			mutex_enter(&uacp->usb_ac_mutex);
			uacp->usb_ac_busy_count--;

			return (USB_FAILURE);
		}
		mutex_enter(&uacp->usb_ac_mutex);
	}

	return (USB_SUCCESS);
}


/*
 * Mixer Callback Management
 * NOTE: all mixer callbacks are serialized. we cannot be closed while
 *	we are in the middle of a callback. There needs to be a
 *	teardown first. We cannot be unplumbed as long as we are
 *	still open.
 *
 * usb_ac_setup:
 *	Send setup to usb_as if the first setup
 *	Check power is done in usb_ac_send_as_cmd()
 */
static int
usb_ac_setup(audiohdl_t ahdl, int flag)
{
	int	rval = AUDIO_SUCCESS;
	usb_ac_state_t *uacp = audio_sup_get_private(ahdl);

	ASSERT(uacp != NULL);

	mutex_enter(&uacp->usb_ac_mutex);

	if (uacp->usb_ac_dev_state != USB_DEV_ONLINE) {
		mutex_exit(&uacp->usb_ac_mutex);

		return (AUDIO_FAILURE);
	}
	mutex_exit(&uacp->usb_ac_mutex);

	usb_ac_serialize_access(uacp);

	if (flag & AUDIO_PLAY) {
		rval = usb_ac_do_setup(ahdl, AUDIO_PLAY);
	}

	if ((rval == USB_SUCCESS) && (flag & AUDIO_RECORD)) {
		rval = usb_ac_do_setup(ahdl, AUDIO_RECORD);
	}

	usb_ac_release_access(uacp);

	return ((rval == USB_SUCCESS) ? AUDIO_SUCCESS : AUDIO_FAILURE);
}


/*
 * usb_ac_do_setup:
 *	Wrapper function for usb_ac_setup which can be called
 *	either from audio framework for usb_ac_set_format
 */
static int
usb_ac_do_setup(audiohdl_t ahdl, int flag)
{
	usb_ac_state_t *uacp = audio_sup_get_private(ahdl);
	usb_ac_plumbed_t	*plumb_infop = NULL;
	usb_ac_streams_info_t	*streams_infop = NULL;
	int	dir;

	ASSERT(uacp != NULL);

	mutex_enter(&uacp->usb_ac_mutex);

	dir = (flag & AUDIO_PLAY) ? AUDIO_PLAY : AUDIO_RECORD;
	plumb_infop = usb_ac_get_plumb_info(uacp, "usb_as", dir);
	ASSERT(plumb_infop != NULL);

	streams_infop = (usb_ac_streams_info_t *)plumb_infop->acp_data;
	ASSERT(streams_infop != NULL);

	/*
	 * Handle multiple setup calls. Pass the setup call to usb_as only
	 * the first time so isoc pipe will be opened only once
	 */
	if (streams_infop->acs_setup_teardown_count++) {
		USB_DPRINTF_L3(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "usb_ac_do_setup: more than one setup, cnt=%d",
		    streams_infop->acs_setup_teardown_count);

		mutex_exit(&uacp->usb_ac_mutex);

		return (USB_SUCCESS);
	}

	/* Send setup command to usb_as */
	if (usb_ac_send_as_cmd(uacp, plumb_infop, USB_AUDIO_SETUP, 0) !=
	    USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "usb_ac_do_setup: failure");

		streams_infop->acs_setup_teardown_count--;

		mutex_exit(&uacp->usb_ac_mutex);

		return (USB_FAILURE);
	}

	mutex_exit(&uacp->usb_ac_mutex);

	return (USB_SUCCESS);
}


/*
 * usb_ac_teardown:
 *	Send teardown to usb_as if the last teardown
 *	Check power is done in usb_ac_send_as_cmd()
 *	NOTE: allow teardown when disconnected
 */
static void
usb_ac_teardown(audiohdl_t ahdl, int flag)
{
	usb_ac_state_t *uacp = audio_sup_get_private(ahdl);

	ASSERT(uacp != NULL);

	usb_ac_serialize_access(uacp);

	if (flag & AUDIO_PLAY) {
		usb_ac_do_teardown(ahdl, AUDIO_PLAY);
	}

	if (flag & AUDIO_RECORD) {
		usb_ac_do_teardown(ahdl, AUDIO_RECORD);
	}

	usb_ac_release_access(uacp);
}


/*
 * usb_ac_do_teardown()
 *	Check power is done in usb_ac_send_as_cmd()
 */
static void
usb_ac_do_teardown(audiohdl_t ahdl, int flag)
{
	usb_ac_state_t		*uacp = audio_sup_get_private(ahdl);
	usb_ac_plumbed_t	*plumb_infop = NULL;
	usb_ac_streams_info_t	*streams_infop = NULL;
	int			dir;

	ASSERT(uacp != NULL);

	mutex_enter(&uacp->usb_ac_mutex);

	dir = (flag & AUDIO_PLAY) ? AUDIO_PLAY : AUDIO_RECORD;
	plumb_infop = usb_ac_get_plumb_info(uacp, "usb_as", dir);
	ASSERT(plumb_infop != NULL);

	streams_infop = (usb_ac_streams_info_t *)plumb_infop->acp_data;
	ASSERT(streams_infop != NULL);

	/* There should be at least one matching setup call */
	ASSERT(streams_infop->acs_setup_teardown_count);

	/*
	 * Handle multiple setup/teardown calls. Pass the call to usb_as
	 * only this is the last teardown so that isoc pipe is closed
	 * only once
	 */
	if (--(streams_infop->acs_setup_teardown_count)) {
		USB_DPRINTF_L3(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "usb_ac_do_teardown: more than one setup/teardown, "
		    "cnt=%d",
		    streams_infop->acs_setup_teardown_count);

		mutex_exit(&uacp->usb_ac_mutex);

		return;
	}

	/* Send teardown command to usb_as */
	if (usb_ac_send_as_cmd(uacp, plumb_infop, USB_AUDIO_TEARDOWN,
	    (void *)NULL) != USB_SUCCESS) {

		USB_DPRINTF_L2(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "usb_ac_do_teardown: failure");

		streams_infop->acs_setup_teardown_count++;

		mutex_exit(&uacp->usb_ac_mutex);

		return;
	}

	mutex_exit(&uacp->usb_ac_mutex);

	USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
	    "usb_ac_do_teardown: End");
}


/*
 * usb_ac_set_config:
 *	This routine will send control commands to get the max
 *	and min gain balance, calculate the gain to be set from the
 *	arguments and send another control command to set it.
 *	Check power is done here since we will access the default pipe
 */
static int
usb_ac_set_config(audiohdl_t ahdl, int command, int flag, int arg1, int arg2)
{
	usb_ac_state_t	*uacp = audio_sup_get_private(ahdl);
	char		*what;
	int		rval = AUDIO_FAILURE;
	uint_t		channel;
	uchar_t 	n_channels = 0;
	uint_t		dir, count;
	short		muteval;

	ASSERT(uacp != NULL);

	mutex_enter(&uacp->usb_ac_mutex);

	if (uacp->usb_ac_plumbing_state < USB_AC_STATE_PLUMBED) {
		mutex_exit(&uacp->usb_ac_mutex);

		return (AUDIO_FAILURE);
	}

	if (uacp->usb_ac_dev_state != USB_DEV_ONLINE) {
		mutex_exit(&uacp->usb_ac_mutex);

		return (AUDIO_FAILURE);
	}
	mutex_exit(&uacp->usb_ac_mutex);
	usb_ac_serialize_access(uacp);
	mutex_enter(&uacp->usb_ac_mutex);

	switch (command) {
	case AM_SET_GAIN:
		/*
		 * Set the gain for a channel. The audio mixer calculates the
		 * impact, if any, on the channel's gain.
		 *
		 *	0 <= gain <= AUDIO_MAX_GAIN
		 *
		 *	arg1 --> gain
		 *	arg2 --> channel #, 0 == left, 1 == right
		 */
		what = "gain";
		channel = ++arg2;
		ASSERT(flag != AUDIO_BOTH);
		dir = (flag & AUDIO_PLAY) ? AUDIO_PLAY : AUDIO_RECORD;

		/*
		 * We service the set_config command when the device is
		 * plumbed and opened.
		 */
		n_channels = usb_ac_get_curr_n_channels(uacp, dir);

		if (channel > n_channels) {
			USB_DPRINTF_L2(PRINT_MASK_ALL,
			    uacp->usb_ac_log_handle,
			    "usb_ac_set_config: channel(%d) passed is "
			    " > n_channels(%d)", channel, n_channels);

			goto done;
		}
		count = 0;
		(void) usb_ac_set_control(uacp, dir,
		    USB_AUDIO_FEATURE_UNIT, channel,
		    USB_AUDIO_VOLUME_CONTROL,
		    USB_AC_FIND_ALL, &count, arg1, usb_ac_set_gain);

		/*
		 * If feature unit id could not be found, it probably means
		 * volume/gain control is not available for this device.
		 * and we just return success if we haven't completed
		 * the registration with the mixer yet
		 */
		if (count == 0) {
			USB_DPRINTF_L2(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
			    "mixer=%d,	no featureID, arg1=%d",
			    uacp->usb_ac_registered_with_mixer, arg1);
			rval = (uacp->usb_ac_registered_with_mixer == 0) ?
			    AUDIO_SUCCESS : AUDIO_FAILURE;
		} else {
			rval = AUDIO_SUCCESS;
		}

		break;
	case AM_SET_PORT:
		what = "port";
		ASSERT(flag != AUDIO_BOTH);
		dir = (flag & AUDIO_PLAY) ? AUDIO_PLAY : AUDIO_RECORD;

		rval = usb_ac_set_port(uacp, dir, arg1);
		rval = (rval == USB_SUCCESS) ? AUDIO_SUCCESS : AUDIO_FAILURE;

		break;
	case AM_SET_MONITOR_GAIN:
		what = "monitor gain";
		channel = ++arg2;
		dir = AUDIO_RECORD;

		/*
		 * We service the set_config command when the device is
		 * plumbed and opened.
		 */
		n_channels = usb_ac_get_curr_n_channels(uacp, dir);

		if (channel > n_channels) {
			USB_DPRINTF_L2(PRINT_MASK_ALL,
			    uacp->usb_ac_log_handle,
			    "usb_ac_set_config: channel(%d) passed is "
			    " > n_channels(%d)", channel, n_channels);

			goto done;
		}
		count = 0;
		(void) usb_ac_set_monitor_gain_control(uacp, dir,
		    USB_AUDIO_INPUT_TERMINAL, channel,
		    USB_AUDIO_VOLUME_CONTROL,
		    USB_AC_FIND_ALL, &count, arg1,
		    usb_ac_set_monitor_gain);

		/*
		 * always return success since we told the mixer
		 * we always support this and sdtaudiocontrol displays
		 * monitor gain regardless.
		 */
		rval = AUDIO_SUCCESS;

		break;
	case AM_OUTPUT_MUTE:
		what = "mute";
		ASSERT(flag != AUDIO_BOTH);
		dir = (flag & AUDIO_PLAY) ? AUDIO_PLAY : AUDIO_RECORD;

		/*
		 * arg1 != 0 --> mute
		 * arg1 == 0 --> unmute
		 * arg2 --> not used
		 */
		muteval = (arg1 == 0) ? USB_AUDIO_MUTE_OFF :
		    USB_AUDIO_MUTE_ON;
		count = 0;
		(void) usb_ac_set_control(uacp, dir,
		    USB_AUDIO_FEATURE_UNIT, 0,
		    USB_AUDIO_MUTE_CONTROL,
		    USB_AC_FIND_ALL, &count, muteval,
		    usb_ac_set_mute);

		rval = (count == 0) ? AUDIO_FAILURE : AUDIO_SUCCESS;

		break;
	case AM_MIC_BOOST:
		what = "mic boost";
		rval = AUDIO_SUCCESS;
		break;
	default:
		what = "unknown";
		rval = AUDIO_FAILURE;
	}

done:
	mutex_exit(&uacp->usb_ac_mutex);

	/* Now it's safe to release access to other routines */
	usb_ac_release_access(uacp);

	USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
	    "usb_ac_set_config: %s done, rval=%d", what, rval);

	return (rval);
}


/*
 * usb_ac_set_monitor_gain:
 *	called for each output terminal which supports
 *	from usb_ac_traverse_connections
 */
static int
usb_ac_set_monitor_gain(usb_ac_state_t *uacp, uint_t unit,
    uint_t dir, uint_t channel, uint_t control, uint_t gain, uint_t *depth)
{
	usb_audio_output_term_descr_t *d =
	    uacp->usb_ac_units[unit].acu_descriptor;

	USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
	    "usb_ac_set_monitor_gain: ");
	USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
	    "id=%d dir=%d ch=%d cntl=%d gain=%d type=%d term type=0x%x",
	    unit, dir, channel, control, gain,
	    uacp->usb_ac_unit_type[unit], d->wTerminalType);

	/* log how we got here */
	usb_ac_push_unit_id(uacp, unit);
	usb_ac_show_traverse_path(uacp);
	usb_ac_pop_unit_id(uacp, unit);

	/* we only care about the ITs connected to real hw inputs */
	switch (d->wTerminalType) {
	case USB_AUDIO_TERM_TYPE_STREAMING:

		return (USB_FAILURE);

	case USB_AUDIO_TERM_TYPE_DT_MICROPHONE:
	case USB_AUDIO_TERM_TYPE_PERS_MICROPHONE:
	case USB_AUDIO_TERM_TYPE_OMNI_DIR_MICROPHONE:
	case USB_AUDIO_TERM_TYPE_MICROPHONE_ARRAY:
	case USB_AUDIO_TERM_TYPE_PROCESSING_MIC_ARRAY:
	default:

		break;
	}

	/*
	 * we can only do this if the microphone is mixed into the
	 * audio output so look for a mixer first
	 */
	if (usb_ac_check_path(uacp, USB_AUDIO_MIXER_UNIT) ==
	    USB_SUCCESS) {
		int i, id;

		/* now look for a feature unit */
		for (i = uacp->usb_ac_traverse_path_index - 1; i >= 0;
		    i--) {
			id = uacp->usb_ac_traverse_path[i];

			switch (uacp->usb_ac_unit_type[id]) {
			case USB_AUDIO_MIXER_UNIT:

				/* the FU should be before the mixer */
				return (USB_FAILURE);

			case USB_AUDIO_FEATURE_UNIT:
				/*
				 * now set the volume
				 */
				if (usb_ac_set_gain(uacp, id, dir, channel,
				    control, gain, depth) != USB_SUCCESS) {

					/* try master channel */
					if (usb_ac_set_gain(uacp, id, dir,
					    0, control, gain, depth) !=
					    USB_SUCCESS) {

						return (USB_FAILURE);
					}
				}

				return (USB_SUCCESS);

			default:
				continue;
			}
		}
	}

	return (USB_FAILURE);
}


/*
 * usb_ac_set_gain is called for each feature unit which supports
 * the requested controls from usb_ac_traverse_connections
 * we still need to check whether this unit supports the requested
 * control.
 */
static int
usb_ac_set_gain(usb_ac_state_t *uacp, uint_t featureID,
    uint_t dir, uint_t channel, uint_t control, uint_t gain, uint_t *depth)
{
	short max, min, current;

	USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
	    "usb_ac_set_gain: id=%d dir=%d ch=%d cntl=%d gain=%d",
	    featureID, dir, channel, control, gain);

	if (usb_ac_feature_unit_check(uacp, featureID,
	    dir, channel, control, gain, depth) != USB_SUCCESS) {

		return (USB_FAILURE);
	}

	if (usb_ac_get_maxmin_volume(uacp, channel,
	    USB_AUDIO_GET_MAX, dir, featureID, &max) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "usb_ac_set_gain: getting max gain failed");

		return (USB_FAILURE);
	}

	USB_DPRINTF_L3(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
	    "usb_ac_set_gain: channel %d, max=%d", channel, max);

	if (usb_ac_get_maxmin_volume(uacp, channel,
	    USB_AUDIO_GET_MIN, dir, featureID, &min) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "usb_ac_set_gain: getting min gain failed");

		return (USB_FAILURE);
	}

	USB_DPRINTF_L3(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
	    "usb_ac_set_gain: channel=%d, min=%d", channel, min);

	if (usb_ac_get_maxmin_volume(uacp, channel,
	    USB_AUDIO_GET_CUR, dir, featureID, &current) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "usb_ac_set_gain: getting cur gain failed");

		return (USB_FAILURE);
	}

	USB_DPRINTF_L3(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
	    "usb_ac_set_gain: channel=%d, cur=%d", channel, current);

	/*
	 * Set the gain for a channel. The audio mixer calculates the
	 * impact, if any, on the channel's gain.
	 *
	 *	0 <= gain <= AUDIO_MAX_GAIN
	 *
	 *	channel #, 0 == left, 1 == right
	 */

	if (gain == 0) {
		gain = USB_AUDIO_VOLUME_SILENCE;
	} else {
		gain = max - ((max - min) * (0x100 - gain))/0x100;
	}

	USB_DPRINTF_L3(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
	    "usb_ac_set_gain: ch=%d dir=%d max=%d min=%d gain=%d",
	    channel, dir, max, min, gain);

	if (usb_ac_set_volume(uacp, channel, gain, dir,
	    featureID) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "usb_ac_set_gain: setting volume failed");

		return (USB_FAILURE);
	}

	/* just curious, read it back, device may round up/down */
	if (usb_ac_get_maxmin_volume(uacp, channel,
	    USB_AUDIO_GET_CUR, dir, featureID, &current) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "usb_ac_set_gain: getting cur gain failed");
	}

	USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
	    "usb_ac_set_gain done: "
	    "id=%d channel=%d, cur=%d gain=%d", featureID, channel,
	    (ushort_t)current, (ushort_t)gain);

	return (USB_SUCCESS);
}


/*
 * usb_ac_set_format
 *	This mixer callback initiates a command to be sent to
 *	usb_as to select an alternate with the passed characteristics
 *	and also to set the sample frequency.
 *	Note that this may be called when a playing is going on in
 *	the streaming interface. To handle that, first stop
 *	playing/recording, close the pipe by sending a teardown
 *	command, send the set_format command down and then reopen
 *	the pipe. Note : (1) audio framework will restart play/record
 *	after a set_format command. (2) Check power is done in
 *	usb_ac_send_as_cmd().
 */
static int
usb_ac_set_format(audiohdl_t ahdl, int flag,
	int sample, int channels, int precision, int encoding)
{
	usb_ac_state_t		*uacp = audio_sup_get_private(ahdl);
	usb_audio_formats_t	*format;
	usb_audio_formats_t	old_format;
	usb_ac_plumbed_t	*plumb_infop;
	usb_ac_streams_info_t	*streams_infop = NULL;
	int			old_setup_teardown_count;
	int			dir;
	int			rval;

	ASSERT(uacp != NULL);

	mutex_enter(&uacp->usb_ac_mutex);
	if (uacp->usb_ac_dev_state != USB_DEV_ONLINE) {
		mutex_exit(&uacp->usb_ac_mutex);

		return (AUDIO_FAILURE);
	}
	mutex_exit(&uacp->usb_ac_mutex);

	usb_ac_serialize_access(uacp);

	ASSERT(flag != AUDIO_BOTH);

	mutex_enter(&uacp->usb_ac_mutex);
	dir = (flag & AUDIO_PLAY) ? AUDIO_PLAY : AUDIO_RECORD;
	plumb_infop = usb_ac_get_plumb_info(uacp, "usb_as", dir);
	if (plumb_infop == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "usb_ac_set_format: no plumb info");
		mutex_exit(&uacp->usb_ac_mutex);

		usb_ac_release_access(uacp);

		return (AUDIO_FAILURE);
	}

	streams_infop = (usb_ac_streams_info_t *)plumb_infop->acp_data;
	ASSERT(streams_infop != NULL);

	/* isoc pipe not open and playing is not in progress */
	if (streams_infop->acs_setup_teardown_count == 0) {

		mutex_exit(&uacp->usb_ac_mutex);

		rval = usb_ac_send_format_cmd(ahdl, dir, sample,
		    channels, precision, encoding);

		usb_ac_release_access(uacp);

		return ((rval == USB_SUCCESS) ?
		    AUDIO_SUCCESS : AUDIO_FAILURE);
	}

	/* isoc pipe is open and playing might be in progress */
	format = &streams_infop->acs_ac_to_as_req.acr_curr_format;

	/* Keep a copy of the old format */
	bcopy((void *)format, (void *)&old_format,
	    sizeof (usb_audio_formats_t));

	ASSERT(streams_infop->acs_setup_teardown_count != 0);

	old_setup_teardown_count = streams_infop->acs_setup_teardown_count;
	streams_infop->acs_setup_teardown_count = 1;

	mutex_exit(&uacp->usb_ac_mutex);

	if (dir == AUDIO_PLAY) {
		usb_ac_do_stop_play(ahdl);
	} else if (dir == AUDIO_RECORD) {
		usb_ac_do_stop_record(ahdl);
	}

	/* This blocks until the current isoc xfer is over */
	usb_ac_do_teardown(ahdl, dir);

	if (usb_ac_send_format_cmd(ahdl, dir, sample,
	    channels, precision, encoding) != USB_SUCCESS) {
		/*
		 * Setting new alternate has failed, try restoring
		 * old one.
		 * If there is a bandwidth failure, hang around
		 * till bandwidth is available. Also we know that
		 * there is a matching alternate, so that can't fail.
		 */
		if (usb_ac_send_format_cmd(ahdl, dir,
		    old_format.fmt_sr, old_format.fmt_chns,
		    old_format.fmt_precision, old_format.fmt_encoding) ==
		    USB_FAILURE) {

			/* We closed the pipe; reopen it */
			(void) usb_ac_do_setup(ahdl, dir);

			mutex_enter(&uacp->usb_ac_mutex);
			streams_infop->acs_setup_teardown_count =
			    old_setup_teardown_count;
			mutex_exit(&uacp->usb_ac_mutex);

			usb_ac_release_access(uacp);

			return (AUDIO_FAILURE);
		}
	}

	/* This should block until successful */
	(void) usb_ac_do_setup(ahdl, dir);

	mutex_enter(&uacp->usb_ac_mutex);
	streams_infop->acs_setup_teardown_count = old_setup_teardown_count;
	mutex_exit(&uacp->usb_ac_mutex);

	usb_ac_release_access(uacp);

	return (AUDIO_SUCCESS);
}


/*
 * usb_ac_get_curr_n_channels:
 *	Return no. of channels from the current format table
 */
static int
usb_ac_get_curr_n_channels(usb_ac_state_t *uacp, int dir)
{
	usb_audio_formats_t *cur_fmt = usb_ac_get_curr_format(uacp, dir);

	return (cur_fmt->fmt_chns);
}


/*
 * usb_ac_get_cur_format:
 *	Get format for the current alternate
 */
static usb_audio_formats_t *
usb_ac_get_curr_format(usb_ac_state_t *uacp, int dir)
{
	usb_ac_plumbed_t *plumb_infop;
	usb_ac_streams_info_t *streams_infop = NULL;

	ASSERT(mutex_owned(&uacp->usb_ac_mutex));

	plumb_infop = usb_ac_get_plumb_info(uacp, "usb_as", dir);
	if (plumb_infop == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "usb_ac_get_curr_format: no plumb info");

		return (NULL);
	}

	streams_infop = (usb_ac_streams_info_t *)plumb_infop->acp_data;
	ASSERT(streams_infop != NULL);

	return (&streams_infop->acs_cur_fmt);
}


/*
 * usb_ac_send_format_cmd
 *	Sets format and get alternate setting that matches with
 *	the format from the usb_as playing or recording interface
 *	Send the set sample freq command down to usb_as.
 */
static int
usb_ac_send_format_cmd(audiohdl_t ahdl, int dir,
	int sample, int channels, int precision, int encoding)
{
	usb_ac_state_t		*uacp = audio_sup_get_private(ahdl);
	usb_audio_formats_t	*format;
	usb_ac_plumbed_t	*plumb_infop = NULL;
	usb_ac_streams_info_t	*streams_infop = NULL;

	ASSERT(uacp != NULL);

	mutex_enter(&uacp->usb_ac_mutex);
	if (uacp->usb_ac_dev_state != USB_DEV_ONLINE) {
		mutex_exit(&uacp->usb_ac_mutex);

		return (USB_FAILURE);
	}

	plumb_infop = usb_ac_get_plumb_info(uacp, "usb_as", dir);
	ASSERT(plumb_infop);

	streams_infop = (usb_ac_streams_info_t *)plumb_infop->acp_data;
	ASSERT(streams_infop != NULL);

	ASSERT(dir == AUDIO_PLAY || dir == AUDIO_RECORD);
	streams_infop->acs_ac_to_as_req.acr_curr_dir = dir;

	USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
	    "usb_ac_send_format_cmd: plumb_infop=0x%p, streams_infop=0x%p",
	    (void *)plumb_infop, (void *)streams_infop);

	format = &(streams_infop->acs_ac_to_as_req.acr_curr_format);
	bzero(format, sizeof (usb_audio_formats_t));

	/* save format info */
	format->fmt_sr		= (uint_t)sample;
	format->fmt_chns	= (uchar_t)channels;
	format->fmt_precision	= (uchar_t)precision;
	format->fmt_encoding	= (uchar_t)encoding;

	streams_infop->acs_cur_fmt = *format;

	/*
	 * Set format for the streaming interface with lower write queue
	 * This boils down to set_alternate  interface command in
	 * usb_as and the reply mp contains the currently active
	 * alternate number that is stored in the as_req structure
	 */
	if (usb_ac_send_as_cmd(uacp, plumb_infop,
	    USB_AUDIO_SET_FORMAT, format) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ALL,
		    uacp->usb_ac_log_handle,
		    "usb_ac_send_format_cmd: failed");
		mutex_exit(&uacp->usb_ac_mutex);

		return (USB_FAILURE);
	} else {
		/* store matching alternate number */
		streams_infop->acs_ac_to_as_req.acr_curr_format.fmt_alt =
		    format->fmt_alt;
	}

	/* Set the sample rate */
	if (usb_ac_send_as_cmd(uacp, plumb_infop, USB_AUDIO_SET_SAMPLE_FREQ,
	    &sample) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "usb_ac_send_format_cmd: setting format failed");

		mutex_exit(&uacp->usb_ac_mutex);

		return (USB_FAILURE);
	}

	mutex_exit(&uacp->usb_ac_mutex);

	return (USB_SUCCESS);
}


/*
 * usb_ac_start_play
 *	Send a start_play command down to usb_as
 *	Check power is done in usb_ac_send_as_cmd()
 */
static int
usb_ac_start_play(audiohdl_t ahdl)
{
	usb_ac_state_t		*uacp = audio_sup_get_private(ahdl);
	usb_audio_formats_t	*cur_fmt;
	usb_ac_plumbed_t	*plumb_infop = NULL;
	int			dir, samples;
	usb_audio_play_req_t	play_req;
	usb_ac_streams_info_t	*streams_infop = NULL;

	ASSERT(uacp != NULL);

	mutex_enter(&uacp->usb_ac_mutex);
	if (uacp->usb_ac_dev_state != USB_DEV_ONLINE) {
		mutex_exit(&uacp->usb_ac_mutex);

		return (AUDIO_FAILURE);
	}
	mutex_exit(&uacp->usb_ac_mutex);

	usb_ac_serialize_access(uacp);

	mutex_enter(&uacp->usb_ac_mutex);

	plumb_infop = usb_ac_get_plumb_info(uacp, "usb_as", AUDIO_PLAY);
	ASSERT(plumb_infop);

	streams_infop = (usb_ac_streams_info_t *)plumb_infop->acp_data;
	ASSERT(streams_infop != NULL);

	USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
	    "usb_ac_start_play: plumb_infop=0x%p, streams_infop=0x%p",
	    (void *)plumb_infop, (void *)streams_infop);

	dir = streams_infop->acs_ac_to_as_req.acr_curr_dir;
	ASSERT(dir == AUDIO_PLAY);

	cur_fmt = &streams_infop->acs_ac_to_as_req.acr_curr_format;

	/* Check for continuous sample rate done in usb_as */
	samples = cur_fmt->fmt_sr * cur_fmt->fmt_chns /
	    uacp->usb_ac_am_ad_info.ad_play.ad_int_rate;
	if (samples & cur_fmt->fmt_chns) {
		samples++;
	}

	play_req.up_samples = samples;
	play_req.up_handle = ahdl;

	/* Send setup command to usb_as */
	if (usb_ac_send_as_cmd(uacp, plumb_infop, USB_AUDIO_START_PLAY,
	    (void *)&play_req) != USB_SUCCESS) {

		USB_DPRINTF_L2(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "usb_ac_start_play: failure");

		mutex_exit(&uacp->usb_ac_mutex);

		usb_ac_release_access(uacp);

		return (AUDIO_FAILURE);
	}

	mutex_exit(&uacp->usb_ac_mutex);

	usb_ac_release_access(uacp);

	return (AUDIO_SUCCESS);
}


/*
 * usb_ac_stop_play:
 *	Wrapper function for usb_ac_do_stop_play and gets
 *	called from mixer framework.
 */
static void
usb_ac_stop_play(audiohdl_t ahdl)
{
	usb_ac_state_t *uacp = audio_sup_get_private(ahdl);

	ASSERT(uacp != NULL);

	mutex_enter(&uacp->usb_ac_mutex);
	if (uacp->usb_ac_dev_state != USB_DEV_ONLINE) {
		mutex_exit(&uacp->usb_ac_mutex);

		return;
	}
	mutex_exit(&uacp->usb_ac_mutex);

	usb_ac_serialize_access(uacp);
	usb_ac_do_stop_play(ahdl);
	usb_ac_release_access(uacp);
}

/*
 * usb_ac_do_pause_play:
 *	Send a pause_play command to usb_as.
 *	Check power is done in usb_ac_send_as_cmd()
 */
static void
usb_ac_do_stop_play(audiohdl_t ahdl)
{
	usb_ac_state_t *uacp = audio_sup_get_private(ahdl);
	usb_ac_plumbed_t	*plumb_infop = NULL;
	usb_ac_streams_info_t	*streams_infop = NULL;

	ASSERT(uacp != NULL);

	mutex_enter(&uacp->usb_ac_mutex);

	plumb_infop = usb_ac_get_plumb_info(uacp, "usb_as", AUDIO_PLAY);
	ASSERT(plumb_infop);

	streams_infop = (usb_ac_streams_info_t *)plumb_infop->acp_data;
	ASSERT(streams_infop != NULL);

	/* Send setup command to usb_as */
	if (usb_ac_send_as_cmd(uacp, plumb_infop, USB_AUDIO_PAUSE_PLAY,
	    (void *)NULL) != USB_SUCCESS) {

		USB_DPRINTF_L2(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "usb_ac_do_pause_play: failure");
	}

	mutex_exit(&uacp->usb_ac_mutex);
}


/*
 * usb_ac_start_record:
 *	Sends a start record command down to usb_as.
 *	Check power is done in usb_ac_send_as_cmd()
 */
static int
usb_ac_start_record(audiohdl_t ahdl)
{
	usb_ac_state_t *uacp = audio_sup_get_private(ahdl);
	usb_ac_plumbed_t	*plumb_infop = NULL;
	usb_ac_streams_info_t	*streams_infop = NULL;

	ASSERT(uacp != NULL);

	mutex_enter(&uacp->usb_ac_mutex);
	if (uacp->usb_ac_dev_state != USB_DEV_ONLINE) {
		mutex_exit(&uacp->usb_ac_mutex);

		return (AUDIO_FAILURE);
	}
	mutex_exit(&uacp->usb_ac_mutex);

	usb_ac_serialize_access(uacp);

	mutex_enter(&uacp->usb_ac_mutex);
	plumb_infop = usb_ac_get_plumb_info(uacp, "usb_as", AUDIO_RECORD);
	ASSERT(plumb_infop);

	streams_infop = (usb_ac_streams_info_t *)plumb_infop->acp_data;
	ASSERT(streams_infop != NULL);

	/* Send setup command to usb_as */
	if (usb_ac_send_as_cmd(uacp, plumb_infop, USB_AUDIO_START_RECORD,
	    (void *)&ahdl) != USB_SUCCESS) {

		USB_DPRINTF_L2(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "usb_ac_start_record: failure");

		mutex_exit(&uacp->usb_ac_mutex);

		usb_ac_release_access(uacp);

		return (AUDIO_FAILURE);
	}

	mutex_exit(&uacp->usb_ac_mutex);

	usb_ac_release_access(uacp);

	return (AUDIO_SUCCESS);
}


/*
 * usb_ac_stop_record:
 *	Wrapper function for usb_ac_do_stop_record and is
 *	called form mixer framework.
 */
static void
usb_ac_stop_record(audiohdl_t ahdl)
{
	usb_ac_state_t *uacp = audio_sup_get_private(ahdl);

	ASSERT(uacp != NULL);

	usb_ac_serialize_access(uacp);
	usb_ac_do_stop_record(ahdl);
	usb_ac_release_access(uacp);
}


/*
 * usb_ac_do_stop_record:
 *	Sends a stop_record command down.
 *	Check power is done in usb_ac_send_as_cmd()
 */
static void
usb_ac_do_stop_record(audiohdl_t ahdl)
{
	usb_ac_state_t *uacp = audio_sup_get_private(ahdl);
	usb_ac_plumbed_t	*plumb_infop = NULL;
	usb_ac_streams_info_t	*streams_infop = NULL;

	ASSERT(uacp != NULL);

	mutex_enter(&uacp->usb_ac_mutex);

	plumb_infop = usb_ac_get_plumb_info(uacp, "usb_as", AUDIO_RECORD);
	ASSERT(plumb_infop != NULL);

	streams_infop = (usb_ac_streams_info_t *)plumb_infop->acp_data;
	ASSERT(streams_infop != NULL);

	/* Send setup command to usb_as */
	if (usb_ac_send_as_cmd(uacp, plumb_infop, USB_AUDIO_STOP_RECORD,
	    NULL) != USB_SUCCESS) {

		USB_DPRINTF_L2(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "usb_ac_do_stop_record: failure");
	}

	mutex_exit(&uacp->usb_ac_mutex);
}


/*
 * Helper Functions for Mixer callbacks
 *
 * usb_ac_get_maxmin_volume:
 *	Send USBA command down to get the maximum or minimum gain balance
 *	Calculate min or max gain balance and return that. Return
 *	USB_FAILURE for failure cases
 */
static int
usb_ac_get_maxmin_volume(usb_ac_state_t *uacp, uint_t channel, int cmd,
    int dir, int feature_unitID, short *max_or_minp)
{
	mblk_t		*data = NULL;
	usb_cr_t	cr;
	usb_cb_flags_t	cb_flags;

	USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
	    "usb_ac_get_maxmin_volume: channel=%d, cmd=%d dir=%d",
	    channel, cmd, dir);

	mutex_exit(&uacp->usb_ac_mutex);

	if (usb_pipe_sync_ctrl_xfer(
	    uacp->usb_ac_dip,
	    uacp->usb_ac_default_ph,
	    USB_DEV_REQ_DEV_TO_HOST |
	    USB_DEV_REQ_TYPE_CLASS |
	    USB_DEV_REQ_RCPT_IF,	/* bmRequestType */
	    cmd,			/* bRequest */
	    (USB_AUDIO_VOLUME_CONTROL << 8) | channel, /* wValue */
					/* feature unit and id */
	    (feature_unitID << 8)| uacp->usb_ac_ifno, /* wIndex */
	    2,				/* wLength */
	    &data,
	    USB_ATTRS_NONE,
	    &cr, &cb_flags,
	    USB_FLAGS_SLEEP) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "usb_ac_get_maxmin_volume: failed, "
		    "cr=%d, cb=0x%x cmd=%d, data=0x%p",
		    cr, cb_flags, cmd, (void *)data);

		freemsg(data);
		mutex_enter(&uacp->usb_ac_mutex);

		return (USB_FAILURE);
	}

	mutex_enter(&uacp->usb_ac_mutex);
	ASSERT(MBLKL(data) == 2);

	*max_or_minp = (*(data->b_rptr+1) << 8) | *data->b_rptr;

	USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
	    "usb_ac_get_maxmin_volume: max_or_min=0x%x", *max_or_minp);

	freemsg(data);

	return (USB_SUCCESS);
}


/*
 * usb_ac_set_volume:
 *	Send USBA command down to set the gain balance
 */
static int
usb_ac_set_volume(usb_ac_state_t *uacp, uint_t channel, short gain, int dir,
    int feature_unitID)
{
	mblk_t		*data = NULL;
	usb_cr_t	cr;
	usb_cb_flags_t	cb_flags;
	int		rval = USB_FAILURE;

	USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
	    "usb_ac_set_volume: channel=%d gain=%d dir=%d FU=%d",
	    channel, gain, dir, feature_unitID);

	mutex_exit(&uacp->usb_ac_mutex);

	/* Construct the mblk_t from gain for sending to USBA */
	data = allocb_wait(4, BPRI_HI, STR_NOSIG, NULL);

	*(data->b_wptr++) = (char)gain;
	*(data->b_wptr++) = (char)(gain >> 8);

	if ((rval = usb_pipe_sync_ctrl_xfer(
	    uacp->usb_ac_dip,
	    uacp->usb_ac_default_ph,
	    USB_DEV_REQ_HOST_TO_DEV |
	    USB_DEV_REQ_TYPE_CLASS |
	    USB_DEV_REQ_RCPT_IF,		/* bmRequestType */
	    USB_AUDIO_SET_CUR,			/* bRequest */
	    (USB_AUDIO_VOLUME_CONTROL << 8) | channel, /* wValue */
						/* feature unit and id */
	    (feature_unitID << 8) | uacp->usb_ac_ifno,	/* wIndex */
	    2,					/* wLength */
	    &data, 0,
	    &cr, &cb_flags, USB_FLAGS_SLEEP)) != USB_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "usb_ac_set_volume: failed, cr=%d cb=0x%x",
		    cr, cb_flags);
	}

	freemsg(data);
	mutex_enter(&uacp->usb_ac_mutex);

	return (rval);
}


/*
 * usb_ac_set_mute is called for each unit that supports the
 * requested control from usb_ac_traverse_connections
 */
static int
usb_ac_set_mute(usb_ac_state_t *uacp, uint_t featureID, uint_t dir,
    uint_t channel, uint_t control, uint_t muteval, uint_t *depth)
{
	mblk_t		*data;
	usb_cr_t	cr;
	usb_cb_flags_t	cb_flags;
	int		rval = USB_FAILURE;

	USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
	    "usb_ac_set_mute: muteval=0x%x, dir=%d", muteval, dir);

	if (usb_ac_feature_unit_check(uacp, featureID,
	    dir, channel, control, 0, depth) != USB_SUCCESS) {

		return (USB_FAILURE);
	}

	mutex_exit(&uacp->usb_ac_mutex);

	/* Construct the mblk_t for sending to USBA */
	data = allocb_wait(1, BPRI_HI, STR_NOSIG, NULL);
	*(data->b_wptr++) = (char)muteval;

	if ((rval = usb_pipe_sync_ctrl_xfer(
	    uacp->usb_ac_dip,
	    uacp->usb_ac_default_ph,
	    USB_DEV_REQ_HOST_TO_DEV |
	    USB_DEV_REQ_TYPE_CLASS |
	    USB_DEV_REQ_RCPT_IF,		/* bmRequestType */
	    USB_AUDIO_SET_CUR,			/* bRequest */
	    (USB_AUDIO_MUTE_CONTROL << 8) | channel, /* wValue */
						/* feature unit and id */
	    (featureID << 8) | uacp->usb_ac_ifno, /* wIndex */
	    1,					/* wLength */
	    &data,
	    0,					/* attributes */
	    &cr, &cb_flags, 0)) != USB_SUCCESS) {

		USB_DPRINTF_L2(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "usb_ac_set_mute: failed, cr=%d cb=0x%x", cr, cb_flags);
	}

	freemsg(data);
	mutex_enter(&uacp->usb_ac_mutex);

	return (rval);
}


/*
 * usb_ac_send_as_cmd:
 *	Allocate message blk, send a command down to usb_as,
 *	wait for the reply and free the message
 *
 *	although not really needed to raise power if sending to as
 *	it seems better to ensure that both interfaces are at full power
 */
static int
usb_ac_send_as_cmd(usb_ac_state_t *uacp, usb_ac_plumbed_t *plumb_infop,
    int cmd, void *arg)
{
	usb_ac_streams_info_t *streams_infop;
	int		rv;
	int		rval;
	ldi_handle_t	lh;
	char		*nm = "usb_ac_send_as_cmd";

	ASSERT(mutex_owned(&uacp->usb_ac_mutex));
	ASSERT(plumb_infop != NULL);

	streams_infop = (usb_ac_streams_info_t *)plumb_infop->acp_data;
	ASSERT(streams_infop != NULL);

	dinfo("%s: %s - cmd=0x%x, arg=0x%p\n", uacp->dstr, nm, cmd, arg);

	lh = plumb_infop->acp_lh;

	rv = ldi_ioctl(lh, cmd, (intptr_t)arg, FKIOCTL, kcred, &rval);
	if (rv != 0) {
		dinfo("%s: %s - ldi_ioctl failed, error=%d\n", uacp->dstr, nm,
		    rv);

		return (USB_FAILURE);
	}

	return (USB_SUCCESS);
}


/*
 * usb_ac_serialize/release_access:
 */
static void
usb_ac_serialize_access(usb_ac_state_t	*uacp)
{
	(void) usb_serialize_access(uacp->usb_ac_ser_acc, USB_WAIT, 0);
}

static void
usb_ac_release_access(usb_ac_state_t *uacp)
{
	usb_release_access(uacp->usb_ac_ser_acc);
}


static void
usb_ac_pm_busy_component(usb_ac_state_t *usb_ac_statep)
{
	ASSERT(!mutex_owned(&usb_ac_statep->usb_ac_mutex));

	if (usb_ac_statep->usb_ac_pm != NULL) {
		mutex_enter(&usb_ac_statep->usb_ac_mutex);
		usb_ac_statep->usb_ac_pm->acpm_pm_busy++;

		USB_DPRINTF_L4(PRINT_MASK_PM,
		    usb_ac_statep->usb_ac_log_handle,
		    "usb_ac_pm_busy_component: %d",
		    usb_ac_statep->usb_ac_pm->acpm_pm_busy);

		mutex_exit(&usb_ac_statep->usb_ac_mutex);

		if (pm_busy_component(usb_ac_statep->usb_ac_dip, 0) !=
		    DDI_SUCCESS) {
			mutex_enter(&usb_ac_statep->usb_ac_mutex);
			usb_ac_statep->usb_ac_pm->acpm_pm_busy--;

			USB_DPRINTF_L2(PRINT_MASK_PM,
			    usb_ac_statep->usb_ac_log_handle,
			    "usb_ac_pm_busy_component failed: %d",
			    usb_ac_statep->usb_ac_pm->acpm_pm_busy);

			mutex_exit(&usb_ac_statep->usb_ac_mutex);
		}
	}
}


static void
usb_ac_pm_idle_component(usb_ac_state_t *usb_ac_statep)
{
	ASSERT(!mutex_owned(&usb_ac_statep->usb_ac_mutex));

	if (usb_ac_statep->usb_ac_pm != NULL) {
		if (pm_idle_component(usb_ac_statep->usb_ac_dip, 0) ==
		    DDI_SUCCESS) {
			mutex_enter(&usb_ac_statep->usb_ac_mutex);
			ASSERT(usb_ac_statep->usb_ac_pm->acpm_pm_busy > 0);
			usb_ac_statep->usb_ac_pm->acpm_pm_busy--;

			USB_DPRINTF_L4(PRINT_MASK_PM,
			    usb_ac_statep->usb_ac_log_handle,
			    "usb_ac_pm_idle_component: %d",
			    usb_ac_statep->usb_ac_pm->acpm_pm_busy);

			mutex_exit(&usb_ac_statep->usb_ac_mutex);
		}
	}
}


/*
 * handle read from plumbed drivers
 */
static void
usb_ac_reader(void *argp)
{
	usb_ac_plumbed_t *acp = (usb_ac_plumbed_t *)argp;
	usb_ac_state_t *uacp = acp->acp_uacp;
	ldi_handle_t lh;
	mblk_t *mp;
	int rv;
	timestruc_t tv = {0};

	mutex_enter(&uacp->usb_ac_mutex);
	lh = acp->acp_lh;
	tv.tv_sec = usb_ac_wait_hid;

	while (acp->acp_flags & ACP_ENABLED) {
		mp = NULL;

		mutex_exit(&uacp->usb_ac_mutex);

		rv = ldi_getmsg(lh, &mp, &tv);

		mutex_enter(&uacp->usb_ac_mutex);

		if ((acp->acp_flags & ACP_ENABLED) && mp != NULL && rv == 0)
			rv = usb_ac_read_msg(acp, mp);

		USB_DPRINTF_L4(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "%s%d read from %s%d, rv=%d",
		    ddi_driver_name(uacp->usb_ac_dip),
		    ddi_get_instance(uacp->usb_ac_dip),
		    ddi_driver_name(acp->acp_dip),
		    ddi_get_instance(acp->acp_dip), rv);
	}
	mutex_exit(&uacp->usb_ac_mutex);
}


/*
 * setup threads to read from the other usb modules that may send unsolicited
 * or asynchronous messages, which is only hid currently
 */
static int
usb_ac_plumb(usb_ac_plumbed_t *acp)
{
	usb_ac_state_t	*uacp = acp->acp_uacp;
	dev_info_t	*dip;
	dev_info_t	*acp_dip;
	int		acp_inst;
	char		*acp_name;
	char		tq_nm[128];
	int		rv = USB_FAILURE;
	char		*nm = "usb_ac_plumb";

	mutex_enter(&uacp->usb_ac_mutex);

	dip = uacp->usb_ac_dip;

	acp_dip = acp->acp_dip;
	acp_inst = ddi_get_instance(acp_dip);
	acp_name = (char *)ddi_driver_name(acp_dip);

	dinfo("%s: %s on %s%d\n", uacp->dstr, nm, acp_name, acp_inst);

	if (strcmp(acp_name, "hid") != 0) {
		rv = USB_SUCCESS;
		goto OUT;
	}

	(void) snprintf(tq_nm, sizeof (tq_nm), "%s_%d_tq",
	    ddi_driver_name(acp_dip), acp_inst);

	acp->acp_tqp = ddi_taskq_create(dip, tq_nm, 1, TASKQ_DEFAULTPRI, 0);
	if (acp->acp_tqp == NULL)
		goto OUT;

	if (ddi_taskq_dispatch(acp->acp_tqp, usb_ac_reader, (void *)acp,
	    DDI_SLEEP) != DDI_SUCCESS)
		goto OUT;

	dinfo("%s: dispatched reader for %s%d\n", uacp->dstr,
	    acp_name, acp_inst);

	rv = USB_SUCCESS;

OUT:
	mutex_exit(&uacp->usb_ac_mutex);

	dinfo("%s: %s on %s%d done, rv=%d\n", uacp->dstr, nm,
	    acp_name, acp_inst, rv);

	return (rv);
}


static void
usb_ac_mux_plumbing_tq(void *arg)
{
	usb_ac_state_t *uacp = (usb_ac_state_t *)arg;

	if (usb_ac_mux_plumbing(uacp) != USB_SUCCESS)
		dwarn("%s: usb_ac_mux_plumbing failed\n", uacp->dstr);
}


static int
usb_ac_do_plumbing(usb_ac_state_t *uacp)
{
	dev_info_t *dip = uacp->usb_ac_dip;
	int inst = ddi_get_instance(dip);
	char tq_nm[128];
	int rv = USB_FAILURE;

	(void) snprintf(tq_nm, sizeof (tq_nm), "%s_%d_tq",
	    ddi_driver_name(dip), inst);

	uacp->tqp = ddi_taskq_create(dip, tq_nm, 1, TASKQ_DEFAULTPRI, 0);
	if (uacp->tqp == NULL) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "usb_ac_do_plumbing: ddi_taskq_create failed");
		goto OUT;
	}

	if (ddi_taskq_dispatch(uacp->tqp, usb_ac_mux_plumbing_tq, (void *)uacp,
	    DDI_SLEEP) != DDI_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "usb_ac_do_plumbing: ddi_taskq_dispatch failed");
		goto OUT;
	}

	rv = USB_SUCCESS;

OUT:
	return (rv);
}



static void
usb_ac_mux_unplumbing_tq(void *arg)
{
	usb_ac_state_t *uacp = (usb_ac_state_t *)arg;

	if (usb_ac_mux_unplumbing(uacp) != USB_SUCCESS)
		dwarn("%s: usb_ac_mux_unplumbing failed\n", uacp->dstr);
}


static int
usb_ac_do_unplumbing(usb_ac_state_t *uacp)
{
	int rv = USB_FAILURE;

	if (uacp->tqp == NULL)
		return (USB_SUCCESS);

	if (ddi_taskq_dispatch(uacp->tqp, usb_ac_mux_unplumbing_tq,
	    (void *)uacp, DDI_SLEEP) != DDI_SUCCESS) {
		USB_DPRINTF_L2(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "usb_ac_do_unplumbing: ddi_taskq_dispatch failed");
		goto OUT;
	}

	dinfo("%s: waiting for unplumb thread\n", uacp->dstr);

	ddi_taskq_wait(uacp->tqp);
	rv = USB_SUCCESS;

	dinfo("%s: unplumb thread done\n", uacp->dstr);

OUT:
	if (uacp->tqp != NULL) {
		ddi_taskq_destroy(uacp->tqp);
		uacp->tqp = NULL;
	}
	return (rv);
}


/*
 * teardown threads to the other usb modules
 * and clear structures as part of unplumbing
 */
static void
usb_ac_unplumb(usb_ac_plumbed_t *acp)
{
	usb_ac_streams_info_t *streams_infop;
	usb_ac_state_t	*uacp = acp->acp_uacp;
	dev_info_t	*acp_dip;
	int		acp_inst;
	char		*nm = "usb_ac_unplumb";
	char		*acp_name;

	acp_dip = acp->acp_dip;
	acp_inst = ddi_get_instance(acp_dip);
	acp_name = (char *)ddi_driver_name(acp_dip);

	dinfo("%s: %s on %s%d\n", uacp->dstr, nm, acp_name, acp_inst);

	if (acp->acp_tqp != NULL) {
		dinfo("%s: %s - destroying taskq for %s%d\n", uacp->dstr, nm,
		    acp_name, acp_inst);

		ddi_taskq_destroy(acp->acp_tqp);
	}

	mutex_enter(&uacp->usb_ac_mutex);

	if (acp->acp_driver == USB_AS_PLUMBED) {
		/*
		 * we bzero the streams info and plumbed structure
		 * since there is no guarantee that the next plumbing
		 * will be identical
		 */
		streams_infop = (usb_ac_streams_info_t *)acp->acp_data;

		/* bzero the relevant plumbing structure */
		bzero(streams_infop, sizeof (usb_ac_streams_info_t));
	}
	bzero(acp, sizeof (usb_ac_plumbed_t));

	mutex_exit(&uacp->usb_ac_mutex);

	dinfo("%s: %s on %s done\n", uacp->dstr, nm, acp_name, acp_inst);
}


/*ARGSUSED*/
static int
usb_ac_mux_plumbing(usb_ac_state_t *uacp)
{
	dev_info_t		*dip;
	char			*nm = "usb_ac_mux_plumbing";

	/* get the usb_ac dip */
	dip = uacp->usb_ac_dip;

	/* Access to the global variables is synchronized */
	mutex_enter(&uacp->usb_ac_mutex);

	dinfo("%s: %s state=%d\n", uacp->dstr, nm,
	    uacp->usb_ac_plumbing_state);

	if (uacp->usb_ac_plumbing_state >= USB_AC_STATE_PLUMBED) {
		mutex_exit(&uacp->usb_ac_mutex);
		dinfo("%s: audio streams driver already plumbed\n",
		    uacp->dstr);

		return (USB_SUCCESS);
	}

	/* usb_as and hid should be attached but double check */
	if (usb_ac_online_siblings(uacp) != USB_SUCCESS) {
		mutex_exit(&uacp->usb_ac_mutex);
		dinfo("%s: no audio streams driver plumbed\n", uacp->dstr);

		return (USB_FAILURE);
	}

	dinfo("%s: (%s) raising power\n", uacp->dstr, nm);
	mutex_exit(&uacp->usb_ac_mutex);

	/* bring the device to full power */
	usb_ac_pm_busy_component(uacp);
	(void) pm_raise_power(dip, 0, USB_DEV_OS_FULL_PWR);

	/* avoid dips disappearing while we are plumbing */
	usb_ac_hold_siblings(uacp);

	mutex_enter(&uacp->usb_ac_mutex);

	/*
	 * walk all siblings and create the usb_ac<->usb_as and
	 * usb_ac<->hid streams. return of 0 indicates no or
	 * partial/failed plumbing
	 */
	if (usb_ac_mux_walk_siblings(uacp) == 0) {
		/* pretend that we are plumbed so we can unplumb */
		uacp->usb_ac_plumbing_state = USB_AC_STATE_PLUMBED;

		mutex_exit(&uacp->usb_ac_mutex);

		(void) usb_ac_mux_unplumbing(uacp);

		dinfo("%s: no audio streams driver plumbed\n", uacp->dstr);

		usb_ac_rele_siblings(uacp);

		usb_ac_pm_idle_component(uacp);

		return (USB_FAILURE);
	}
	uacp->usb_ac_plumbing_state = USB_AC_STATE_PLUMBED;

	/* restore state if we have already registered with the mixer */
	if (uacp->usb_ac_registered_with_mixer) {
		dinfo("%s: already registered with mixer, restoring state\n",
		    uacp->dstr);

		(void) usb_ac_restore_audio_state(uacp, USB_FLAGS_SLEEP);

	} else if (usb_ac_mixer_registration(uacp) != USB_SUCCESS) {
		mutex_exit(&uacp->usb_ac_mutex);

		dwarn("%s: mixer registration failed\n", uacp->dstr);

		(void) usb_ac_mux_unplumbing(uacp);

		usb_ac_rele_siblings(uacp);

		usb_ac_pm_idle_component(uacp);

		return (USB_FAILURE);
	}

	mutex_exit(&uacp->usb_ac_mutex);
	usb_ac_rele_siblings(uacp);

	usb_ac_pm_idle_component(uacp);

	dinfo("%s: %s done\n", uacp->dstr, nm);

	return (USB_SUCCESS);
}


static int
usb_ac_mux_unplumbing(usb_ac_state_t *uacp)
{
	usb_ac_plumbed_t	*acp;
	ldi_handle_t		lh;
	dev_info_t		*acp_dip;
	int			inst;
	int			i;
	dev_t			devt;
	minor_t			minor;
	int			maxlinked = 0;
	char			*nm = "usb_ac_mux_unplumbing";

	mutex_enter(&uacp->usb_ac_mutex);

	dinfo("%s: %s state=%d\n", uacp->dstr, nm, uacp->usb_ac_plumbing_state);

	if (uacp->usb_ac_plumbing_state == USB_AC_STATE_UNPLUMBED) {
		dinfo("%s: %s - already unplumbed!\n", uacp->dstr, nm);
		mutex_exit(&uacp->usb_ac_mutex);

		return (USB_SUCCESS);
	}

	/* usb_ac might not have anything plumbed yet */
	if (uacp->usb_ac_current_plumbed_index == -1) {
		dinfo("%s: %s - nothing plumbed!\n", uacp->dstr, nm);
		uacp->usb_ac_plumbing_state = USB_AC_STATE_UNPLUMBED;
		mutex_exit(&uacp->usb_ac_mutex);

		return (USB_SUCCESS);
	}

	/* do not allow detach if still busy */
	if (uacp->usb_ac_busy_count) {
		dinfo("%s: %s - mux still busy (%d)\n", uacp->dstr, nm,
		    uacp->usb_ac_busy_count);
		mutex_exit(&uacp->usb_ac_mutex);

		return (USB_FAILURE);
	}

	uacp->usb_ac_plumbing_state = USB_AC_STATE_UNPLUMBED;

	/* close ac-as and ac-hid streams */
	maxlinked = uacp->usb_ac_current_plumbed_index + 1;
	dinfo("%s: %s - maxlinked %d\n", uacp->dstr, nm, maxlinked);

	for (i = 0; i < maxlinked; i++) {
		/*
		 * we must save members of usb_ac_plumbed[] before calling
		 * usb_ac_unplumb() because it clears the structure
		 */
		acp = &uacp->usb_ac_plumbed[i];
		lh = acp->acp_lh;
		acp_dip = acp->acp_dip;
		devt = acp->acp_devt;

		if (acp_dip == NULL) {
			dinfo("%s: %s [%d] - skipping\n", uacp->dstr, nm, i);
			continue;
		}

		minor = getminor(devt);
		inst = ddi_get_instance(acp_dip);

		uacp->usb_ac_current_plumbed_index = i;

		dinfo("%s: %s [%d] - %s%d minor 0x%x\n", uacp->dstr, nm, i,
		    ddi_driver_name(acp_dip), inst, minor);

		if (lh != NULL) {
			mutex_exit(&uacp->usb_ac_mutex);

			acp->acp_flags &= ~ACP_ENABLED;

			dinfo("%s: %s [%d] - closing\n", uacp->dstr, nm, i);

			/* must close stream first before destroying thread */
			(void) ldi_close(lh, FREAD|FWRITE, kcred);

			usb_ac_unplumb(acp);

			dinfo("%s: %s [%d] - unplumbed\n", uacp->dstr, nm, i);

			mutex_enter(&uacp->usb_ac_mutex);
		}
	}

	mutex_exit(&uacp->usb_ac_mutex);

	/* Wait till all activity in the default pipe has drained */
	usb_ac_serialize_access(uacp);
	usb_ac_release_access(uacp);

	mutex_enter(&uacp->usb_ac_mutex);
	uacp->usb_ac_current_plumbed_index = -1;
	mutex_exit(&uacp->usb_ac_mutex);

	dinfo("%s: %s done\n", uacp->dstr, nm);

	return (USB_SUCCESS);
}


/*
 * walk all siblings and create the ac<->as and ac<->hid streams
 */
static int
usb_ac_mux_walk_siblings(usb_ac_state_t *uacp)
{
	dev_info_t	*pdip;
	dev_info_t	*child_dip;
	major_t		drv_major;
	minor_t		drv_minor;
	int		drv_instance;
	char		*drv_name;
	dev_t		drv_devt;
	ldi_handle_t	drv_lh;
	ldi_ident_t	li;
	int		error;
	int		count = 0;
	char		*nm = "usb_ac_mux_walk_siblings";

	ASSERT(mutex_owned(&uacp->usb_ac_mutex));

	pdip = ddi_get_parent(uacp->usb_ac_dip);
	child_dip = ddi_get_child(pdip);

	dinfo("%s: %s parent=%s%d\n", uacp->dstr, nm,
	    ddi_driver_name(pdip), ddi_get_instance(pdip));

	while ((child_dip != NULL) && (count < USB_AC_MAX_PLUMBED)) {
		drv_instance = ddi_get_instance(child_dip);
		drv_name = (char *)ddi_driver_name(child_dip);

		dinfo("%s: plumbing %s%d count=%d\n", uacp->dstr,
		    drv_name, drv_instance, count);

		/* ignore own dip */
		if (child_dip == uacp->usb_ac_dip) {
			child_dip = ddi_get_next_sibling(child_dip);
			continue;
		}
		drv_instance = ddi_get_instance(child_dip);

		/* ignore other dip other than usb_as and hid */
		if (strcmp(ddi_driver_name(child_dip), "usb_as") == 0) {
			uacp->usb_ac_plumbed[count].acp_driver = USB_AS_PLUMBED;
			drv_minor = USB_AS_CONSTRUCT_MINOR(drv_instance);
		} else if (strcmp(ddi_driver_name(child_dip), "hid") == 0) {
			uacp->usb_ac_plumbed[count].acp_driver = USB_AH_PLUMBED;
			drv_minor = HID_CONSTRUCT_EXTERNAL_MINOR(drv_instance);
		} else {
			drv_minor = drv_instance;
			uacp->usb_ac_plumbed[count].acp_driver =
			    UNKNOWN_PLUMBED;
			child_dip = ddi_get_next_sibling(child_dip);

			continue;
		}

		if (!i_ddi_devi_attached(child_dip)) {
			child_dip = ddi_get_next_sibling(child_dip);

			continue;
		}

		if (DEVI_IS_DEVICE_REMOVED(child_dip)) {
			child_dip = ddi_get_next_sibling(child_dip);

			continue;
		}

		drv_major = ddi_driver_major(child_dip);

		uacp->usb_ac_current_plumbed_index = count;

		mutex_exit(&uacp->usb_ac_mutex);

		drv_devt = makedevice(drv_major, drv_minor);

		dinfo("%s: opening %s%d devt=(%d, 0x%x)\n", uacp->dstr,
		    drv_name, drv_instance, drv_major, drv_minor);

		error = ldi_ident_from_dip(uacp->usb_ac_dip, &li);
		if (error == 0) {
			uacp->usb_ac_plumbed[count].acp_flags |= ACP_ENABLED;

			error = ldi_open_by_dev(&drv_devt, OTYP_CHR,
			    FREAD|FWRITE, kcred, &drv_lh, li);
			ldi_ident_release(li);
		}

		mutex_enter(&uacp->usb_ac_mutex);
		if (error) {
			dinfo("%s: open of devt=(%d, 0x%x) failed error=%d\n",
			    uacp->dstr, drv_major, drv_minor, error);

			return (0);
		}

		uacp->usb_ac_plumbed[count].acp_uacp = uacp;
		uacp->usb_ac_plumbed[count].acp_devt = drv_devt;
		uacp->usb_ac_plumbed[count].acp_lh = drv_lh;
		uacp->usb_ac_plumbed[count].acp_dip = child_dip;
		uacp->usb_ac_plumbed[count].acp_ifno =
		    usb_get_if_number(child_dip);

		if (uacp->usb_ac_plumbed[count].acp_driver == USB_AS_PLUMBED) {
			/* get registration data */
			if (usb_ac_get_reg_data(uacp, drv_lh, count) !=
			    USB_SUCCESS) {

				dinfo("%s: usb_ac_get_reg_data failed on "
				    "%s%d\n", uacp->dstr,
				    drv_name, drv_instance);

				uacp->usb_ac_plumbed[count].acp_dip = NULL;

				return (0);
			}
		} else if (uacp->usb_ac_plumbed[count].acp_driver ==
		    USB_AH_PLUMBED) {
			int rval;

			dinfo("%s: pushing usb_ah on %s%d\n", uacp->dstr,
			    drv_name, drv_instance);

			mutex_exit(&uacp->usb_ac_mutex);

			/* push usb_ah module on top of hid */
			error = ldi_ioctl(drv_lh, I_PUSH, (intptr_t)"usb_ah",
			    FKIOCTL, kcred, &rval);
			mutex_enter(&uacp->usb_ac_mutex);

			if (error) {
				dinfo("%s: ldi_ioctl I_PUSH failed on "
				    "%s%d, error=%d\n", uacp->dstr,
				    drv_name, drv_instance, error);

				uacp->usb_ac_plumbed[count].acp_dip = NULL;

				/* skip plumbing the hid driver */
				child_dip = ddi_get_next_sibling(child_dip);
				continue;
			}
		} else {
			/* should not be here */
			dinfo("%s: %s - unknown module %s%d\n",
			    uacp->dstr, nm, drv_name, drv_instance);
			count--;

			uacp->usb_ac_plumbed[count].acp_dip = NULL;

			/* skip plumbing an unknown module */
			child_dip = ddi_get_next_sibling(child_dip);
			continue;
		}

		mutex_exit(&uacp->usb_ac_mutex);
		error = usb_ac_plumb(&uacp->usb_ac_plumbed[count]);
		mutex_enter(&uacp->usb_ac_mutex);

		if (error != USB_SUCCESS) {
			dinfo("%s: %s - usb_ac_plumb failed for %s%d\n",
			    uacp->dstr, nm, drv_name, drv_instance);

			return (0);
		}

		dinfo("%s: plumbed %s%d, minor 0x%x\n", uacp->dstr,
		    drv_name, drv_instance, drv_minor);

		child_dip = ddi_get_next_sibling(child_dip);
		count++;
	}

	dinfo("%s: %s - %d drivers plumbed under usb_ac mux", uacp->dstr, nm,
	    count);

	return (count);
}


/*
 * usb_ac_find_default_port:
 */
static int
usb_ac_find_default_port(uint_t port)
{
	int i;

	for (i = 0; i < 32; i++) {
		if (port & (1 << i)) {

			return (1 << i);
		}
	}

	return (0);
}


/*
 * Register with mixer only after first plumbing.
 * Also do not register if earlier reg data
 * couldn't be received from at least one
 * streaming interface
 */
_NOTE(SCHEME_PROTECTS_DATA("private", am_ad_info))

static int
usb_ac_mixer_registration(usb_ac_state_t *uacp)
{
	am_ad_info_t	*info	= &uacp->usb_ac_am_ad_info;
	audio_info_t	*dflts	= &uacp->usb_ac_am_ad_defaults;
	usb_as_registration_t *asreg;
	int		n, nplay, nrec;
	char		*nm = "usb_ac_mixer_registration";

	ASSERT(uacp != NULL);

	dinfo("%s: %s infp=0x%p, dflts=0x%p, already registered=%d\n",
	    uacp->dstr, nm, (void *)info, (void *)dflts,
	    uacp->usb_ac_registered_with_mixer);

	ASSERT(dflts != NULL);
	ASSERT(info != NULL);

	if (uacp->usb_ac_registered_with_mixer) {
		return (USB_SUCCESS);
	}

	for (n = 0; n < USB_AC_MAX_AS_PLUMBED; n++) {
		if (uacp->usb_ac_streams[n].acs_rcvd_reg_data) {
			break;
		}
	}

	/* Haven't found a streaming interface; fail mixer registration */
	if (n > USB_AC_MAX_AS_PLUMBED) {
		dinfo("%s: %s - no streaming interface found\n",
		    uacp->dstr, nm);

		return (USB_FAILURE);
	}

	info->ad_defaults	= dflts;

	dflts->monitor_gain	= 0;
	dflts->output_muted	= B_FALSE;
	dflts->hw_features	= 0;
	dflts->sw_features	= AUDIO_SWFEATURE_MIXER;

	/*
	 * Fill out streaming interface specific stuff
	 * Note that we handle only one playing and one recording
	 * streaming interface at the most
	 */
	nplay = nrec = 0;
	for (n = 0; n < USB_AC_MAX_AS_PLUMBED; n++) {
		int ch, chs, default_gain, id;

		if (uacp->usb_ac_streams[n].acs_rcvd_reg_data == 0) {
			continue;
		}

		asreg = uacp->usb_ac_streams[n].acs_streams_reg;
		if (asreg->reg_valid == 0) {
			continue;
		}

		mutex_exit(&uacp->usb_ac_mutex);

		dinfo("%s: %s [%d] - setting format on %s%d\n",
		    uacp->dstr, nm, n,
		    uacp->usb_ac_streams[n].acs_plumbed->acp_dip);

		/* set first format so get_featureID can be succeed */
		(void) usb_ac_set_format(uacp->usb_ac_audiohdl,
		    asreg->reg_mode,
		    asreg->reg_srs[0],
		    asreg->reg_formats[0].fmt_chns,
		    asreg->reg_formats[0].fmt_precision,
		    asreg->reg_formats[0].fmt_encoding);

		mutex_enter(&uacp->usb_ac_mutex);

		chs = asreg->reg_formats[0].fmt_chns;

		/* check if any channel supports vol. control for this fmt */
		for (ch = 0; ch <= chs; ch++) {
			if ((id = usb_ac_get_featureID(uacp,
			    asreg->reg_mode, ch,
			    USB_AUDIO_VOLUME_CONTROL)) != -1) {
				ddtl("%s: %s [%d] - dir=%d featureID=%d\n",
				    uacp->dstr, nm, n, asreg->reg_mode, id);

				break;
			}
		}
		default_gain = (id == USB_AC_ID_NONE) ?
		    AUDIO_MAX_GAIN : (AUDIO_MAX_GAIN/2);

		ddtl("%s: %s [%d] - mode=%d chs=%d default_gain=%d id=%d\n",
		    uacp->dstr, nm, n, asreg->reg_mode, chs, default_gain, id);

		if (asreg->reg_mode == AUDIO_PLAY) {
			nplay++;
			ASSERT(nplay == 1);

			dflts->play.sample_rate =
			    asreg->reg_srs[0];
			dflts->play.channels	=
			    asreg->reg_formats[0].fmt_chns;
			dflts->play.precision	=
			    asreg->reg_formats[0].fmt_precision;
			dflts->play.encoding	=
			    asreg->reg_formats[0].fmt_encoding;
			dflts->play.gain	= default_gain;
			dflts->play.port	= usb_ac_find_default_port(
			    uacp->usb_ac_output_ports);
			dflts->play.avail_ports = uacp->usb_ac_output_ports;
			dflts->play.mod_ports	= 0;
						/* no support for mixer unit */
			dflts->play.buffer_size = 8*1024;
			dflts->hw_features	|= AUDIO_HWFEATURE_PLAY;

			info->ad_play.ad_mixer_srs.ad_srs = asreg->reg_srs;

			info->ad_play.ad_chs		= asreg->reg_channels;
			info->ad_play.ad_int_rate	= 1000; /* every 1 ms */
			info->ad_play.ad_bsize		= 8 * 1024;
			info->ad_play_comb	= asreg->reg_combinations;
		} else {
			nrec++;
			ASSERT(nrec == 1);

			dflts->record.sample_rate =
			    asreg->reg_srs[0];
			dflts->record.channels	=
			    asreg->reg_formats[0].fmt_chns;
			dflts->record.precision =
			    asreg->reg_formats[0].fmt_precision;
			dflts->record.encoding	=
			    asreg->reg_formats[0].fmt_encoding;
			dflts->record.gain	= default_gain;
			dflts->record.port	= usb_ac_find_default_port(
			    uacp->usb_ac_input_ports);
			dflts->record.avail_ports = uacp->usb_ac_input_ports;
			dflts->record.mod_ports = uacp->usb_ac_input_ports;
			dflts->record.buffer_size = 8*1024;
			dflts->hw_features	|= AUDIO_HWFEATURE_RECORD;

			info->ad_record.ad_mixer_srs.ad_srs = asreg->reg_srs;

			info->ad_record.ad_chs		= asreg->reg_channels;
			info->ad_record.ad_int_rate	= 1000; /* every 1 ms */
			info->ad_record.ad_bsize	= 8 * 1024;
			info->ad_num_mics		= 1;
			info->ad_rec_comb	= asreg->reg_combinations;
		}
	}

	if (nplay && nrec) {
		dflts->hw_features	|= AUDIO_HWFEATURE_DUPLEX;
	}

	/* the rest */
	info->ad_entry		= &usb_ac_entry;
	info->ad_dev_info	= &usb_dev_info;

	dinfo("%s: %s - calling am_attach\n", uacp->dstr, nm);
	mutex_exit(&uacp->usb_ac_mutex);

	if (am_attach(uacp->usb_ac_audiohdl, DDI_ATTACH, info) ==
	    AUDIO_FAILURE) {
		dinfo("%s: %s - am_attach failed\n", uacp->dstr, nm);

		mutex_enter(&uacp->usb_ac_mutex);

		return (USB_FAILURE);
	}

	mutex_enter(&uacp->usb_ac_mutex);

	uacp->usb_ac_registered_with_mixer = 1;

	dinfo("%s: %s - am_attach succeeded\n", uacp->dstr, nm);

	return (USB_SUCCESS);
}


/*
 * get registration data from usb_as driver unless we already
 * have 2 registrations
 */
static int
usb_ac_get_reg_data(usb_ac_state_t *uacp, ldi_handle_t drv_lh, int index)
{
	int n, error, rval;
	usb_as_registration_t *streams_reg;
	char *nm = "usb_ac_get_reg_data";

	dinfo("%s: %s index=%d, mixer registered=%d\n", uacp->dstr, nm, index,
	    uacp->usb_ac_registered_with_mixer);

	/* if already registered, just setup data structures again */
	if (uacp->usb_ac_registered_with_mixer) {

		return (usb_ac_setup_plumbed(uacp, index, -1, -1));
	}

	for (n = 0; n < USB_AC_MAX_AS_PLUMBED; n ++) {
		/*
		 * We haven't received registration data
		 * from n-th streaming interface in the array
		 */
		if (!uacp->usb_ac_streams[n].acs_rcvd_reg_data) {
			break;
		}
	}

	if (n >= USB_AC_MAX_AS_PLUMBED) {
		dwarn("%s: More than 2 streaming interfaces (play "
		    "and/or record) currently not supported\n", uacp->dstr);

		return (USB_FAILURE);
	}

	/* take the stream reg struct with the same index */
	streams_reg = &uacp->usb_ac_streams_reg[n];

	dinfo("%s: regdata from usb_as: streams_reg=0x%p, n=%d\n", uacp->dstr,
	    (void *)streams_reg, n);

	mutex_exit(&uacp->usb_ac_mutex);

	if ((error = ldi_ioctl(drv_lh, USB_AUDIO_MIXER_REGISTRATION,
	    (intptr_t)streams_reg, FKIOCTL, kcred, &rval)) != 0) {
		dinfo("%s: %s - ldi_ioctl failed for mixer registration, "
		    "error=%d", uacp->dstr, nm, error);

		mutex_enter(&uacp->usb_ac_mutex);

		return (USB_FAILURE);
	} else {
		mutex_enter(&uacp->usb_ac_mutex);

		rval = usb_ac_setup_plumbed(uacp, index, n, n);

		dinfo("%s: %s - usb_ac_streams[%d]: "
		    "received_reg_data=%d type=%s", uacp->dstr, nm, index,
		    uacp->usb_ac_streams[n].acs_rcvd_reg_data,
		    ((streams_reg->reg_mode == AUDIO_PLAY) ?
		    "play" : "record"));

		usb_ac_print_reg_data(uacp, streams_reg);

		return (rval);
	}
}


/*
 * setup plumbed and stream info structure, either initially or
 * after replumbing
 * On replumbing, str_idx and reg_idx are -1
 */
static int
usb_ac_setup_plumbed(usb_ac_state_t *uacp, int plb_idx, int str_idx,
    int reg_idx)
{
	int i;
	char *nm = "usb_ac_setup_plumbed";

	dinfo("%s: %s plb_idx=%d str_idx=%d\n", uacp->dstr, nm,
	    plb_idx, str_idx);

	if (str_idx == -1) {
		/* find a free streams info structure */
		for (i = 0; i < USB_AC_MAX_AS_PLUMBED; i++) {
			if (uacp->usb_ac_streams[i].acs_plumbed == NULL) {
				break;
			}
		}
		ASSERT(i < USB_AC_MAX_AS_PLUMBED);
		str_idx = i;
	}

	uacp->usb_ac_plumbed[plb_idx].acp_data =
	    &uacp->usb_ac_streams[str_idx];
	uacp->usb_ac_streams[str_idx].acs_plumbed =
	    &uacp->usb_ac_plumbed[plb_idx];
	uacp->usb_ac_streams[str_idx].acs_rcvd_reg_data = 1;

	if (reg_idx == -1) {
		/*
		 * find the corresponding registration structure, match
		 * on interface number and not on dip since dip may have
		 * changed
		 */
		for (i = 0; i < USB_AC_MAX_AS_PLUMBED; i++) {
			if (uacp->usb_ac_streams_reg[i].reg_ifno ==
			    uacp->usb_ac_plumbed[plb_idx].acp_ifno) {
				break;
			}
		}
		if (i == USB_AC_MAX_AS_PLUMBED) {
			dinfo("%s: %s - no corresponding registration "
			    "structure\n", uacp->dstr, nm);

			return (USB_FAILURE);
		}
		reg_idx = i;
	}
	uacp-> usb_ac_streams[str_idx].acs_streams_reg =
	    &uacp->usb_ac_streams_reg[reg_idx];

	dinfo("%s: %s done - plb_idx=%d str_idx=%d reg_idx=%d", uacp->dstr, nm,
	    plb_idx, str_idx, reg_idx);

	return (USB_SUCCESS);
}


/*
 * function to dump registration data
 */
static void
usb_ac_print_reg_data(usb_ac_state_t *uacp,
    usb_as_registration_t *reg)
{
	int n;

	USB_DPRINTF_L3(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
	    "usb_ac_print_reg_data: Begin valid=%d, play=%d, "
	    "n_formats=%d, compat srs ptr=0x%p",
	    reg->reg_valid, reg->reg_mode, reg->reg_n_formats,
	    (void *)&reg->reg_srs);

	for (n = 0; n < reg->reg_n_formats; n++) {
		USB_DPRINTF_L3(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "format%d: alt=%d chns=%d prec=%d enc=%d", n,
		    reg->reg_formats[n].fmt_alt,
		    reg->reg_formats[n].fmt_chns,
		    reg->reg_formats[n].fmt_precision,
		    reg->reg_formats[n].fmt_encoding);
	}

	USB_DPRINTF_L3(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
	    "combinations: %d %d %d %d %d %d %d %d",
	    reg->reg_combinations[0].ad_prec, reg->reg_combinations[0].ad_enc,
	    reg->reg_combinations[1].ad_prec, reg->reg_combinations[1].ad_enc,
	    reg->reg_combinations[2].ad_prec, reg->reg_combinations[2].ad_enc,
	    reg->reg_combinations[3].ad_prec, reg->reg_combinations[3].ad_enc);


	for (n = 0; n < USB_AS_N_FORMATS; n++) {
		USB_DPRINTF_L3(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "reg_formats[%d] ptr=0x%p", n,
		    (void *)&reg->reg_formats[n]);
	}

	for (n = 0; n < USB_AS_N_CHANNELS; n++) {
		USB_DPRINTF_L3(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "reg_channels[%d]=%d", n, reg->reg_channels[n]);
	}

	for (n = 0; n < USB_AS_N_COMBINATIONS; n++) {
		USB_DPRINTF_L3(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
		    "reg_combinations[%d] ptr=0x%p", n,
		    (void *)&reg->reg_combinations[n]);
	}

	USB_DPRINTF_L3(PRINT_MASK_ALL, uacp->usb_ac_log_handle,
	    "usb_ac_print_reg_data: End");
}


static int
usb_ac_online_siblings(usb_ac_state_t *uacp)
{
	dev_info_t	*pdip, *child_dip;
	int		rval = USB_SUCCESS;
	char		*nm = "usb_ac_online_siblings";

	ASSERT(mutex_owned(&uacp->usb_ac_mutex));

	dinfo("%s: %s\n", uacp->dstr, nm);

	pdip = ddi_get_parent(uacp->usb_ac_dip);

	child_dip = ddi_get_child(pdip);
	while (child_dip != NULL) {

		dinfo("%s: onlining %s%d ref=%d\n", uacp->dstr,
		    ddi_driver_name(child_dip),
		    ddi_get_instance(child_dip),
		    DEVI(child_dip)->devi_ref);

		/* Online the child_dip of usb_as and hid,  if not already */
		if ((strcmp(ddi_driver_name(child_dip), "usb_as") == 0) ||
		    (strcmp(ddi_driver_name(child_dip), "hid") == 0)) {

			mutex_exit(&uacp->usb_ac_mutex);
			if (ndi_devi_online(child_dip, NDI_ONLINE_ATTACH) !=
			    NDI_SUCCESS) {
				dinfo("%s: failed to online device %s%d\n",
				    uacp->dstr,
				    ddi_driver_name(child_dip),
				    ddi_get_instance(child_dip));

				/* only onlining usb_as is fatal */
				if (strcmp(ddi_driver_name(child_dip),
				    "usb_as") == 0) {
					mutex_enter(&uacp->usb_ac_mutex);
					rval = USB_FAILURE;
					break;
				}
			}
			mutex_enter(&uacp->usb_ac_mutex);
		}
		child_dip = ddi_get_next_sibling(child_dip);
	}

	return (rval);
}


/*
 * hold all audio children before or after plumbing
 * online usb_as and hid, if not already
 */
static void
usb_ac_hold_siblings(usb_ac_state_t *uacp)
{
	int		circ;
	dev_info_t	*pdip, *child_dip;
	char		*nm = "usb_ac_hold_siblings";

	dinfo("%s: %s\n", uacp->dstr, nm);

	/* hold all siblings and ourselves */
	pdip = ddi_get_parent(uacp->usb_ac_dip);

	/* hold the children */
	ndi_devi_enter(pdip, &circ);
	child_dip = ddi_get_child(pdip);
	while (child_dip != NULL) {
		ndi_hold_devi(child_dip);

		dinfo("%s: held %s%d ref=%d\n", uacp->dstr,
		    ddi_driver_name(child_dip), ddi_get_instance(child_dip),
		    DEVI(child_dip)->devi_ref);

		child_dip = ddi_get_next_sibling(child_dip);
	}
	ndi_devi_exit(pdip, circ);
}


/*
 * release all audio children before or after plumbing
 */
static void
usb_ac_rele_siblings(usb_ac_state_t *uacp)
{
	int		circ;
	dev_info_t	*pdip, *child_dip;
	char		*nm = "usb_ac_rele_siblings";

	dinfo("%s: %s\n", uacp->dstr, nm);

	/* release all siblings and ourselves */
	pdip = ddi_get_parent(uacp->usb_ac_dip);
	ndi_devi_enter(pdip, &circ);
	child_dip = ddi_get_child(pdip);
	while (child_dip != NULL) {
		ndi_rele_devi(child_dip);

		dinfo("%s: released %s%d ref=%d\n", uacp->dstr,
		    ddi_driver_name(child_dip), ddi_get_instance(child_dip),
		    DEVI(child_dip)->devi_ref);

		child_dip = ddi_get_next_sibling(child_dip);
	}
	ndi_devi_exit(pdip, circ);
}
