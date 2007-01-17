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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * SELECTING state of the client state machine.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <stdio.h>
#include <strings.h>
#include <time.h>
#include <limits.h>
#include <netinet/in.h>
#include <net/route.h>
#include <net/if.h>
#include <netinet/dhcp.h>
#include <netinet/udp.h>
#include <netinet/ip_var.h>
#include <netinet/udp_var.h>
#include <dhcpmsg.h>

#include "states.h"
#include "agent.h"
#include "util.h"
#include "interface.h"
#include "packet.h"
#include "defaults.h"

static stop_func_t	stop_selecting;

/*
 * dhcp_start(): starts DHCP on a state machine
 *
 *   input: iu_tq_t *: unused
 *	    void *: the state machine on which to start DHCP
 *  output: void
 */

/* ARGSUSED */
void
dhcp_start(iu_tq_t *tqp, void *arg)
{
	dhcp_smach_t	*dsmp = arg;

	release_smach(dsmp);

	dhcpmsg(MSG_VERBOSE, "starting DHCP on %s", dsmp->dsm_name);
	dhcp_selecting(dsmp);
}

/*
 * dhcp_selecting(): sends a DISCOVER and sets up reception of OFFERs for
 *		     IPv4, or sends a Solicit and sets up reception of
 *		     Advertisements for DHCPv6.
 *
 *   input: dhcp_smach_t *: the state machine on which to send the DISCOVER
 *  output: void
 */

void
dhcp_selecting(dhcp_smach_t *dsmp)
{
	dhcp_pkt_t		*dpkt;
	const char		*reqhost;
	char			hostfile[PATH_MAX + 1];

	/*
	 * We first set up to collect OFFER/Advertise packets as they arrive.
	 * We then send out DISCOVER/Solicit probes.  Then we wait a
	 * user-tunable number of seconds before seeing if OFFERs/
	 * Advertisements have come in response to our DISCOVER/Solicit.  If
	 * none have come in, we continue to wait, sending out our DISCOVER/
	 * Solicit probes with exponential backoff.  If no OFFER/Advertisement
	 * is ever received, we will wait forever (note that since we're
	 * event-driven though, we're still able to service other state
	 * machines).
	 *
	 * Note that we do an reset_smach() here because we may be landing in
	 * dhcp_selecting() as a result of restarting DHCP, so the state
	 * machine may not be fresh.
	 */

	reset_smach(dsmp);
	if (!set_smach_state(dsmp, SELECTING)) {
		dhcpmsg(MSG_ERROR,
		    "dhcp_selecting: cannot switch to SELECTING state; "
		    "reverting to INIT on %s", dsmp->dsm_name);
		goto failed;

	}

	dsmp->dsm_offer_timer = iu_schedule_timer(tq,
	    dsmp->dsm_offer_wait, dhcp_requesting, dsmp);
	if (dsmp->dsm_offer_timer == -1) {
		dhcpmsg(MSG_ERROR, "dhcp_selecting: cannot schedule to read "
		    "%s packets", dsmp->dsm_isv6 ? "Advertise" : "OFFER");
		goto failed;
	}

	hold_smach(dsmp);

	/*
	 * Assemble and send the DHCPDISCOVER or Solicit message.
	 *
	 * If this fails, we'll wait for the select timer to go off
	 * before trying again.
	 */
	if (dsmp->dsm_isv6) {
		dhcpv6_ia_na_t d6in;

		if ((dpkt = init_pkt(dsmp, DHCPV6_MSG_SOLICIT)) == NULL) {
			dhcpmsg(MSG_ERROR, "dhcp_selecting: unable to set up "
			    "Solicit packet");
			return;
		}

		/* Add an IA_NA option for our controlling LIF */
		d6in.d6in_iaid = htonl(dsmp->dsm_lif->lif_iaid);
		d6in.d6in_t1 = htonl(0);
		d6in.d6in_t2 = htonl(0);
		(void) add_pkt_opt(dpkt, DHCPV6_OPT_IA_NA,
		    (dhcpv6_option_t *)&d6in + 1,
		    sizeof (d6in) - sizeof (dhcpv6_option_t));

		/* Option Request option for desired information */
		(void) add_pkt_prl(dpkt, dsmp);

		/* Enable Rapid-Commit */
		(void) add_pkt_opt(dpkt, DHCPV6_OPT_RAPID_COMMIT, NULL, 0);

		/* xxx add Reconfigure Accept */

		(void) send_pkt_v6(dsmp, dpkt, ipv6_all_dhcp_relay_and_servers,
		    stop_selecting, DHCPV6_SOL_TIMEOUT, DHCPV6_SOL_MAX_RT);
	} else {
		if ((dpkt = init_pkt(dsmp, DISCOVER)) == NULL) {
			dhcpmsg(MSG_ERROR, "dhcp_selecting: unable to set up "
			    "DISCOVER packet");
			return;
		}

		/*
		 * The max DHCP message size option is set to the interface
		 * MTU, minus the size of the UDP and IP headers.
		 */
		(void) add_pkt_opt16(dpkt, CD_MAX_DHCP_SIZE,
		    htons(dsmp->dsm_lif->lif_max - sizeof (struct udpiphdr)));
		(void) add_pkt_opt32(dpkt, CD_LEASE_TIME, htonl(DHCP_PERM));

		(void) add_pkt_opt(dpkt, CD_CLASS_ID, class_id, class_id_len);
		(void) add_pkt_prl(dpkt, dsmp);

		if (df_get_bool(dsmp->dsm_name, dsmp->dsm_isv6,
		    DF_REQUEST_HOSTNAME)) {
			dhcpmsg(MSG_DEBUG,
			    "dhcp_selecting: DF_REQUEST_HOSTNAME");
			(void) snprintf(hostfile, sizeof (hostfile),
			    "/etc/hostname.%s", dsmp->dsm_name);

			if ((reqhost = iffile_to_hostname(hostfile)) != NULL) {
				dhcpmsg(MSG_DEBUG, "dhcp_selecting: host %s",
				    reqhost);
				dsmp->dsm_reqhost = strdup(reqhost);
				if (dsmp->dsm_reqhost != NULL)
					(void) add_pkt_opt(dpkt, CD_HOSTNAME,
					    dsmp->dsm_reqhost,
					    strlen(dsmp->dsm_reqhost));
				else
					dhcpmsg(MSG_WARNING,
					    "dhcp_selecting: cannot allocate "
					    "memory for host name option");
			}
		}
		(void) add_pkt_opt(dpkt, CD_END, NULL, 0);

		(void) send_pkt(dsmp, dpkt, htonl(INADDR_BROADCAST),
		    stop_selecting);
	}
	return;

failed:
	(void) set_smach_state(dsmp, INIT);
	dsmp->dsm_dflags |= DHCP_IF_FAILED;
	ipc_action_finish(dsmp, DHCP_IPC_E_MEMORY);
}

/*
 * dhcp_collect_dlpi(): collects incoming OFFERs, ACKs, and NAKs via DLPI.
 *
 *   input: iu_eh_t *: unused
 *	    int: the file descriptor the mesage arrived on
 *	    short: unused
 *	    iu_event_id_t: the id of this event callback with the handler
 *	    void *: the physical interface that received the message
 *  output: void
 */

/* ARGSUSED */
void
dhcp_collect_dlpi(iu_eh_t *eh, int fd, short events, iu_event_id_t id,
    void *arg)
{
	dhcp_pif_t	*pif = arg;
	PKT_LIST	*plp;
	uchar_t		recv_type;
	const char	*pname;
	dhcp_smach_t	*dsmp;
	uint_t		xid;

	if ((plp = recv_pkt(fd, pif->pif_max, B_FALSE, B_TRUE)) == NULL)
		return;

	recv_type = pkt_recv_type(plp);
	pname = pkt_type_to_string(recv_type, B_FALSE);

	/*
	 * DHCP_PUNTYPED messages are BOOTP server responses.
	 */
	if (!pkt_v4_match(recv_type,
	    DHCP_PACK | DHCP_PNAK | DHCP_POFFER | DHCP_PUNTYPED)) {
		dhcpmsg(MSG_VERBOSE, "dhcp_collect_dlpi: ignored %s packet "
		    "received via DLPI on %s", pname, pif->pif_name);
		free_pkt_entry(plp);
		return;
	}

	/*
	 * Loop through the state machines that match on XID to find one that's
	 * interested in this offer.  If there are none, then discard.
	 */
	xid = pkt_get_xid(plp->pkt, B_FALSE);
	for (dsmp = lookup_smach_by_xid(xid, NULL, B_FALSE); dsmp != NULL;
	    dsmp = lookup_smach_by_xid(xid, dsmp, B_FALSE)) {

		/*
		 * Find state machine on correct interface.
		 */
		if (dsmp->dsm_lif->lif_pif == pif)
			break;
	}

	if (dsmp == NULL) {
		dhcpmsg(MSG_VERBOSE, "dhcp_collect_dlpi: no matching state "
		    "machine for %s packet XID %#x received via DLPI on %s",
		    pname, xid, pif->pif_name);
		free_pkt_entry(plp);
		return;
	}

	/*
	 * Ignore state machines that aren't looking for DLPI messages.
	 */
	if (!dsmp->dsm_using_dlpi) {
		dhcpmsg(MSG_VERBOSE, "dhcp_collect_dlpi: ignore state "
		    "machine for %s packet XID %#x received via DLPI on %s",
		    pname, xid, pif->pif_name);
		free_pkt_entry(plp);
		return;
	}

	if (pkt_v4_match(recv_type, DHCP_PACK | DHCP_PNAK)) {
		if (!dhcp_bound(dsmp, plp)) {
			dhcpmsg(MSG_WARNING, "dhcp_collect_dlpi: dhcp_bound "
			    "failed for %s", dsmp->dsm_name);
			dhcp_restart(dsmp);
			return;
		}
		dhcpmsg(MSG_VERBOSE, "dhcp_collect_dlpi: %s on %s",
		    pname, dsmp->dsm_name);
	} else {
		pkt_smach_enqueue(dsmp, plp);
	}
}

/*
 * stop_selecting(): decides when to stop retransmitting DISCOVERs -- only when
 *		     abandoning the state machine.  For DHCPv6, this timer may
 *		     go off before the offer wait timer.  If so, then this is a
 *		     good time to check for valid Advertisements, so cancel the
 *		     timer and go check.
 *
 *   input: dhcp_smach_t *: the state machine DISCOVERs are being sent on
 *	    unsigned int: the number of DISCOVERs sent so far
 *  output: boolean_t: B_TRUE if retransmissions should stop
 */

/* ARGSUSED1 */
static boolean_t
stop_selecting(dhcp_smach_t *dsmp, unsigned int n_discovers)
{
	/*
	 * If we're using v4 and the underlying LIF we're trying to configure
	 * has been touched by the user, then bail out.
	 */
	if (!dsmp->dsm_isv6 && !verify_lif(dsmp->dsm_lif)) {
		finished_smach(dsmp, DHCP_IPC_E_UNKIF);
		return (B_TRUE);
	}

	if (dsmp->dsm_recv_pkt_list != NULL) {
		dhcp_requesting(NULL, dsmp);
		if (dsmp->dsm_state != SELECTING)
			return (B_TRUE);
	}
	return (B_FALSE);
}
