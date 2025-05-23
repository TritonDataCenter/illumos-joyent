/*
 * Copyright (C) 1997-2003 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * $Id: ip_log.c,v 2.75.2.7 2005/06/11 07:47:44 darrenr Exp $
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2019 Joyent, Inc.
 */

#include <sys/param.h>
#if defined(KERNEL) || defined(_KERNEL)
# undef KERNEL
# undef _KERNEL
# define        KERNEL	1
# define        _KERNEL	1
#endif
#if defined(__NetBSD__) && (NetBSD >= 199905) && !defined(IPFILTER_LKM) && \
    defined(_KERNEL)
# include "opt_ipfilter_log.h"
#endif
#if defined(__FreeBSD__) && !defined(IPFILTER_LKM)
# if defined(_KERNEL)
#  if defined(__FreeBSD_version) && (__FreeBSD_version >= 300000)
#   include "opt_ipfilter.h"
#  endif
# else
#  include <osreldate.h>
# endif
#endif
#ifdef SOLARIS
#undef	SOLARIS
#endif
#if (defined(sun) && (defined(__svr4__) || defined(__SVR4)))
#define	SOLARIS	(1)
#else
#define	SOLARIS	(0)
#endif
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/file.h>
#ifndef _KERNEL
# include <stdio.h>
# include <string.h>
# include <stdlib.h>
# include <ctype.h>
# define _KERNEL
# define KERNEL
# ifdef __OpenBSD__
struct file;
# endif
# include <sys/uio.h>
# undef _KERNEL
# undef KERNEL
#endif
#if __FreeBSD_version >= 220000 && defined(_KERNEL)
# include <sys/fcntl.h>
# include <sys/filio.h>
#else
# include <sys/ioctl.h>
#endif
#include <sys/time.h>
#if defined(_KERNEL)
# include <sys/systm.h>
# if defined(NetBSD) && (__NetBSD_Version__ >= 104000000)
#  include <sys/proc.h>
# endif
#endif /* _KERNEL */
#if !defined(SOLARIS) && !defined(__hpux) && !defined(linux)
# if (NetBSD > 199609) || (OpenBSD > 199603) || (__FreeBSD_version >= 300000)
#  include <sys/dirent.h>
# else
#  include <sys/dir.h>
# endif
# include <sys/mbuf.h>
#else
# if !defined(__hpux) && defined(_KERNEL)
#  include <sys/filio.h>
#  include <sys/cred.h>
#  include <sys/ddi.h>
#  include <sys/sunddi.h>
#  include <sys/ksynch.h>
#  include <sys/kmem.h>
#  include <sys/mkdev.h>
#  include <sys/dditypes.h>
#  include <sys/cmn_err.h>
# endif /* !__hpux */
#endif /* !SOLARIS && !__hpux */
#if !defined(linux)
# include <sys/protosw.h>
#endif
#include <sys/socket.h>

#include <net/if.h>
#ifdef sun
# include <net/af.h>
#endif
#if __FreeBSD_version >= 300000
# include <net/if_var.h>
#endif
#include <net/route.h>
#include <netinet/in.h>
#ifdef __sgi
# include <sys/ddi.h>
# ifdef IFF_DRVRLOCK /* IRIX6 */
#  include <sys/hashing.h>
# endif
#endif
#if !defined(__hpux) && !defined(linux) && \
    !(defined(__sgi) && !defined(IFF_DRVRLOCK)) /*IRIX<6*/
# include <netinet/in_var.h>
#endif
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#ifdef USE_INET6
# include <netinet/icmp6.h>
#endif
#if !defined(linux)
# include <netinet/ip_var.h>
#endif
#ifndef _KERNEL
# include <syslog.h>
#endif
#include "netinet/ip_compat.h"
#include <netinet/tcpip.h>
#include "netinet/ip_fil.h"
#include "netinet/ip_nat.h"
#include "netinet/ip_frag.h"
#include "netinet/ip_state.h"
#include "netinet/ip_auth.h"
#include "netinet/ipf_stack.h"
#if (__FreeBSD_version >= 300000) || defined(__NetBSD__)
# include <sys/malloc.h>
#endif
/* END OF INCLUDES */

#ifdef	IPFILTER_LOG

# if defined(IPL_SELECT)
#  include	<machine/sys/user.h>
#  include	<sys/kthread_iface.h>
#  define	READ_COLLISION	0x001

iplog_select_t	iplog_ss[IPL_LOGMAX+1];

extern int selwait;
# endif /* IPL_SELECT */

/* ipl_magic never changes */
int	ipl_magic[IPL_LOGSIZE] = { IPL_MAGIC, IPL_MAGIC_NAT, IPL_MAGIC_STATE,
				   IPL_MAGIC, IPL_MAGIC, IPL_MAGIC,
				   IPL_MAGIC, IPL_MAGIC };

/* ------------------------------------------------------------------------ */
/* Function:    fr_loginit                                                  */
/* Returns:     int - 0 == success (always returned)                        */
/* Parameters:  Nil                                                         */
/*                                                                          */
/* Initialise log buffers & pointers.  Also iniialised the CRC to a local   */
/* secret for use in calculating the "last log checksum".                   */
/* ------------------------------------------------------------------------ */
int fr_loginit(ifs)
ipf_stack_t *ifs;
{
	int	i;

	for (i = IPL_LOGMAX; i >= 0; i--) {
		ifs->ifs_iplt[i] = NULL;
		ifs->ifs_ipll[i] = NULL;
		ifs->ifs_iplh[i] = &ifs->ifs_iplt[i];
		ifs->ifs_iplused[i] = 0;
		bzero((char *)&ifs->ifs_iplcrc[i], sizeof(ifs->ifs_iplcrc[i]));
# ifdef	IPL_SELECT
		iplog_ss[i].read_waiter = 0;
		iplog_ss[i].state = 0;
# endif
# if defined(linux) && defined(_KERNEL)
		init_waitqueue_head(iplh_linux + i);
# endif
	}

# if defined(SOLARIS) && defined(_KERNEL)
	cv_init(&ifs->ifs_iplwait, "ipl condvar", CV_DRIVER, NULL);
# endif
	MUTEX_INIT(&ifs->ifs_ipl_mutex, "ipf log mutex");

	ifs->ifs_ipl_log_init = 1;

	return 0;
}


/* ------------------------------------------------------------------------ */
/* Function:    fr_logunload                                                */
/* Returns:     Nil                                                         */
/* Parameters:  Nil                                                         */
/*                                                                          */
/* Clean up any log data that has accumulated without being read.           */
/* ------------------------------------------------------------------------ */
void fr_logunload(ifs)
ipf_stack_t *ifs;
{
	int i;

	if (ifs->ifs_ipl_log_init == 0)
		return;

	for (i = IPL_LOGMAX; i >= 0; i--)
		(void) ipflog_clear(i, ifs);

# if defined(SOLARIS) && defined(_KERNEL)
	cv_destroy(&ifs->ifs_iplwait);
# endif
	MUTEX_DESTROY(&ifs->ifs_ipl_mutex);

	ifs->ifs_ipl_log_init = 0;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipflog                                                      */
/* Returns:     int - 0 == success, -1 == failure                           */
/* Parameters:  fin(I)   - pointer to packet information                    */
/*              flags(I) - flags from filter rules                          */
/*                                                                          */
/* Create a log record for a packet given that it has been triggered by a   */
/* rule (or the default setting).  Calculate the transport protocol header  */
/* size using predetermined size of a couple of popular protocols and thus  */
/* how much data to copy into the log, including part of the data body if   */
/* requested.                                                               */
/* ------------------------------------------------------------------------ */
int ipflog(fin, flags)
fr_info_t *fin;
u_int flags;
{
	register size_t hlen;
	int types[2], mlen;
	size_t sizes[2];
	void *ptrs[2];
	ipflog_t ipfl;
	u_char p;
	mb_t *m;
# if defined(SOLARIS) && defined(_KERNEL)
	net_handle_t nif;
	void *ifp;
# else
#  if defined(__hpux) && defined(_KERNEL)
	qif_t *ifp;
#  else
	struct ifnet *ifp;
#  endif
# endif /* SOLARIS */
	ipf_stack_t *ifs = fin->fin_ifs;

	ipfl.fl_nattag.ipt_num[0] = 0;
	m = fin->fin_m;
	ifp = fin->fin_ifp;
	hlen = fin->fin_hlen;
	/*
	 * calculate header size.
	 */
	if (fin->fin_off == 0) {
		p = fin->fin_fi.fi_p;
		if (p == IPPROTO_TCP)
			hlen += MIN(sizeof(tcphdr_t), fin->fin_dlen);
		else if (p == IPPROTO_UDP)
			hlen += MIN(sizeof(udphdr_t), fin->fin_dlen);
		else if (p == IPPROTO_ICMP) {
			struct icmp *icmp;

			icmp = (struct icmp *)fin->fin_dp;

			/*
			 * For ICMP, if the packet is an error packet, also
			 * include the information about the packet which
			 * caused the error.
			 */
			switch (icmp->icmp_type)
			{
			case ICMP_UNREACH :
			case ICMP_SOURCEQUENCH :
			case ICMP_REDIRECT :
			case ICMP_TIMXCEED :
			case ICMP_PARAMPROB :
				hlen += MIN(sizeof(struct icmp) + 8,
					    fin->fin_dlen);
				break;
			default :
				hlen += MIN(sizeof(struct icmp),
					    fin->fin_dlen);
				break;
			}
		}
# ifdef USE_INET6
		else if (p == IPPROTO_ICMPV6) {
			struct icmp6_hdr *icmp;

			icmp = (struct icmp6_hdr *)fin->fin_dp;

			/*
			 * For ICMPV6, if the packet is an error packet, also
			 * include the information about the packet which
			 * caused the error.
			 */
			if (icmp->icmp6_type < 128) {
				hlen += MIN(sizeof(struct icmp6_hdr) + 8,
					    fin->fin_dlen);
			} else {
				hlen += MIN(sizeof(struct icmp6_hdr),
					    fin->fin_dlen);
			}
		}
# endif
	}
	/*
	 * Get the interface number and name to which this packet is
	 * currently associated.
	 */
# if defined(SOLARIS) && defined(_KERNEL)
	ipfl.fl_unit = (u_int)0;
	nif = NULL;
	if (fin->fin_fi.fi_v == 4)
		nif = ifs->ifs_ipf_ipv4;
	else if (fin->fin_fi.fi_v == 6)
		nif = ifs->ifs_ipf_ipv6;
	if (nif != NULL) {
		if (net_getifname(nif, (phy_if_t)ifp,
		    ipfl.fl_ifname, sizeof(ipfl.fl_ifname)) != 0)
			return (-1);
	}

# else
#  if defined(__hpux) && defined(_KERNEL)
	ipfl.fl_unit = (u_int)0;
	(void) strncpy(ipfl.fl_ifname, IFNAME(ifp), sizeof(ipfl.fl_ifname));
#  else
#   if (defined(NetBSD) && (NetBSD <= 1991011) && (NetBSD >= 199603)) || \
       (defined(OpenBSD) && (OpenBSD >= 199603)) || defined(linux) || \
       (defined(__FreeBSD__) && (__FreeBSD_version >= 501113))
	COPYIFNAME(ifp, ipfl.fl_ifname);
#   else
	ipfl.fl_unit = (u_int)ifp->if_unit;
#    if defined(_KERNEL)
	if ((ipfl.fl_ifname[0] = ifp->if_name[0]))
		if ((ipfl.fl_ifname[1] = ifp->if_name[1]))
			if ((ipfl.fl_ifname[2] = ifp->if_name[2]))
				ipfl.fl_ifname[3] = ifp->if_name[3];
#    else
	(void) strncpy(ipfl.fl_ifname, IFNAME(ifp), sizeof(ipfl.fl_ifname));
	ipfl.fl_ifname[sizeof(ipfl.fl_ifname) - 1] = '\0';
#    endif
#   endif
#  endif /* __hpux */
# endif /* SOLARIS */
	mlen = fin->fin_plen - hlen;
	if (!ifs->ifs_ipl_logall) {
		mlen = (flags & FR_LOGBODY) ? MIN(mlen, 128) : 0;
	} else if ((flags & FR_LOGBODY) == 0) {
		mlen = 0;
	}
	if (mlen < 0)
		mlen = 0;
	ipfl.fl_plen = (u_char)mlen;
	ipfl.fl_hlen = (u_char)hlen;
	ipfl.fl_rule = fin->fin_rule;
	(void) strncpy(ipfl.fl_group, fin->fin_group, FR_GROUPLEN);
	if (fin->fin_fr != NULL) {
		ipfl.fl_loglevel = fin->fin_fr->fr_loglevel;
		ipfl.fl_logtag = fin->fin_fr->fr_logtag;
		bcopy(fin->fin_fr->fr_uuid, ipfl.fl_uuid, sizeof (uuid_t));
	} else {
		ipfl.fl_loglevel = 0xffff;
		ipfl.fl_logtag = FR_NOLOGTAG;
		bzero(ipfl.fl_uuid, sizeof (uuid_t));
	}
	if (fin->fin_nattag != NULL)
		bcopy(fin->fin_nattag, (void *)&ipfl.fl_nattag,
		      sizeof(ipfl.fl_nattag));
	ipfl.fl_flags = flags;
	ipfl.fl_dir = fin->fin_out;
	ipfl.fl_lflags = fin->fin_flx;
	ptrs[0] = (void *)&ipfl;
	sizes[0] = sizeof(ipfl);
	types[0] = 0;
# if defined(MENTAT) && defined(_KERNEL)
	/*
	 * Are we copied from the mblk or an aligned array ?
	 */
	if (fin->fin_ip == (ip_t *)m->b_rptr) {
		ptrs[1] = m;
		sizes[1] = hlen + mlen;
		types[1] = 1;
	} else {
		ptrs[1] = fin->fin_ip;
		sizes[1] = hlen + mlen;
		types[1] = 0;
	}
# else
	ptrs[1] = m;
	sizes[1] = hlen + mlen;
	types[1] = 1;
# endif /* MENTAT */
	return ipllog(IPL_LOGIPF, fin, ptrs, sizes, types, 2, fin->fin_ifs);
}


/* ------------------------------------------------------------------------ */
/* Function:    ipllog                                                      */
/* Returns:     int - 0 == success, -1 == failure                           */
/* Parameters:  dev(I)    - device that owns this log record                */
/*              fin(I)    - pointer to packet information                   */
/*              items(I)  - array of pointers to log data                   */
/*              itemsz(I) - array of size of valid memory pointed to        */
/*              types(I)  - type of data pointed to by items pointers       */
/*              cnt(I)    - number of elements in arrays items/itemsz/types */
/*                                                                          */
/* Takes an array of parameters and constructs one record to include the    */
/* miscellaneous packet information, as well as packet data, for reading    */
/* from the log device.                                                     */
/* ------------------------------------------------------------------------ */
int ipllog(dev, fin, items, itemsz, types, cnt, ifs)
int dev;
fr_info_t *fin;
void **items;
size_t *itemsz;
int *types, cnt;
ipf_stack_t *ifs;
{
	caddr_t buf, ptr;
	iplog_t *ipl;
	size_t len;
	int i;
	SPL_INT(s);

	/*
	 * Check to see if this log record has a CRC which matches the last
	 * record logged.  If it does, just up the count on the previous one
	 * rather than create a new one.
	 */
	if (ifs->ifs_ipl_suppress) {
		MUTEX_ENTER(&ifs->ifs_ipl_mutex);
		if ((fin != NULL) && (fin->fin_off == 0)) {
			if ((ifs->ifs_ipll[dev] != NULL) &&
			    bcmp((char *)fin, (char *)&ifs->ifs_iplcrc[dev],
				 FI_LCSIZE) == 0) {
				ifs->ifs_ipll[dev]->ipl_count++;
				MUTEX_EXIT(&ifs->ifs_ipl_mutex);
				return 0;
			}
			bcopy((char *)fin, (char *)&ifs->ifs_iplcrc[dev],
			      FI_LCSIZE);
		} else
			bzero((char *)&ifs->ifs_iplcrc[dev], FI_CSIZE);
		MUTEX_EXIT(&ifs->ifs_ipl_mutex);
	}

	/*
	 * Get the total amount of data to be logged.
	 */
	for (i = 0, len = sizeof(iplog_t); i < cnt; i++)
		len += itemsz[i];

	/*
	 * check that we have space to record this information and can
	 * allocate that much.
	 */
	KMALLOCS(buf, caddr_t, len);
	if (buf == NULL)
		return -1;
	SPL_NET(s);
	MUTEX_ENTER(&ifs->ifs_ipl_mutex);
	if ((ifs->ifs_iplused[dev] + len) > IPFILTER_LOGSIZE) {
		MUTEX_EXIT(&ifs->ifs_ipl_mutex);
		SPL_X(s);
		KFREES(buf, len);
		return -1;
	}
	ifs->ifs_iplused[dev] += len;
	MUTEX_EXIT(&ifs->ifs_ipl_mutex);
	SPL_X(s);

	/*
	 * advance the log pointer to the next empty record and deduct the
	 * amount of space we're going to use.
	 */
	ipl = (iplog_t *)buf;
	ipl->ipl_magic = ipl_magic[dev];
	ipl->ipl_count = 1;
	ipl->ipl_next = NULL;
	ipl->ipl_dsize = len;
#ifdef _KERNEL
	GETKTIME(&ipl->ipl_sec);
#else
	ipl->ipl_sec = 0;
	ipl->ipl_usec = 0;
#endif

	/*
	 * Loop through all the items to be logged, copying each one to the
	 * buffer.  Use bcopy for normal data or the mb_t copyout routine.
	 */
	for (i = 0, ptr = buf + sizeof(*ipl); i < cnt; i++) {
		if (types[i] == 0) {
			bcopy(items[i], ptr, itemsz[i]);
		} else if (types[i] == 1) {
			COPYDATA(items[i], 0, itemsz[i], ptr);
		}
		ptr += itemsz[i];
	}
	SPL_NET(s);
	MUTEX_ENTER(&ifs->ifs_ipl_mutex);
	ifs->ifs_ipll[dev] = ipl;
	*ifs->ifs_iplh[dev] = ipl;
	ifs->ifs_iplh[dev] = &ipl->ipl_next;

	/*
	 * Now that the log record has been completed and added to the queue,
	 * wake up any listeners who may want to read it.
	 */
# if defined(SOLARIS) && defined(_KERNEL)
	cv_signal(&ifs->ifs_iplwait);
	MUTEX_EXIT(&ifs->ifs_ipl_mutex);
# else
	MUTEX_EXIT(&ifs->ifs_ipl_mutex);
	WAKEUP(&ifs->ifs_iplh, dev);
# endif
	SPL_X(s);
# ifdef	IPL_SELECT
	iplog_input_ready(dev);
# endif
	return 0;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipflog_read                                                 */
/* Returns:     int    - 0 == success, else error value.                    */
/* Parameters:  unit(I) - device we are reading from                        */
/*              uio(O)  - pointer to information about where to store data  */
/*                                                                          */
/* Called to handle a read on an IPFilter device.  Returns only complete    */
/* log messages - will not partially copy a log record out to userland.     */
/*                                                                          */
/* NOTE: This function will block and wait for a signal to return data if   */
/* there is none present.  Asynchronous I/O is not implemented.             */
/* ------------------------------------------------------------------------ */
int ipflog_read(unit, uio, ifs)
minor_t unit;
struct uio *uio;
ipf_stack_t *ifs;
{
	size_t dlen, copied;
	int error = 0;
	iplog_t *ipl;
	SPL_INT(s);

	/*
	 * Sanity checks.  Make sure the minor # is valid and we're copying
	 * a valid chunk of data.
	 */
	if (IPL_LOGMAX < unit)
		return ENXIO;
	if (uio->uio_resid == 0)
		return 0;
	if ((uio->uio_resid < sizeof(iplog_t)) ||
	    (uio->uio_resid > ifs->ifs_ipl_logsize))
		return EINVAL;

	/*
	 * Lock the log so we can snapshot the variables.  Wait for a signal
	 * if the log is empty.
	 */
	SPL_NET(s);
	MUTEX_ENTER(&ifs->ifs_ipl_mutex);

	while (ifs->ifs_iplt[unit] == NULL) {
# if defined(SOLARIS) && defined(_KERNEL)
		/*
		 * Prevent a deadlock with ipldetach() - see the "ipfilter
		 * kernel module mutexes and locking" comment block in solaris.c
		 * for details.
		 */
		RWLOCK_EXIT(&ifs->ifs_ipf_global);
		if (!cv_wait_sig(&ifs->ifs_iplwait, &ifs->ifs_ipl_mutex.ipf_lk)) {
			READ_ENTER(&ifs->ifs_ipf_global);
			MUTEX_EXIT(&ifs->ifs_ipl_mutex);
			return EINTR;
		}
		READ_ENTER(&ifs->ifs_ipf_global);
# else
#  if defined(__hpux) && defined(_KERNEL)
		lock_t *l;

#   ifdef IPL_SELECT
		if (uio->uio_fpflags & (FNBLOCK|FNDELAY)) {
			/* this is no blocking system call */
			MUTEX_EXIT(&ifs->ifs_ipl_mutex);
			return 0;
		}
#   endif

		MUTEX_EXIT(&ifs->ifs_ipl_mutex);
		l = get_sleep_lock(&ifs->ifs_iplh[unit]);
		error = sleep(&ifs->ifs_iplh[unit], PZERO+1);
		spinunlock(l);
#  else
#   if defined(__osf__) && defined(_KERNEL)
		error = mpsleep(&ifs->ifs_iplh[unit], PSUSP|PCATCH,  "iplread", 0,
				&ifs->ifs_ipl_mutex, MS_LOCK_SIMPLE);
#   else
		MUTEX_EXIT(&ifs->ifs_ipl_mutex);
		SPL_X(s);
		error = SLEEP(&ifs->ifs_iplh[unit], "ipl sleep");
#   endif /* __osf__ */
#  endif /* __hpux */
		if (error)
			return error;
		SPL_NET(s);
		MUTEX_ENTER(&ifs->ifs_ipl_mutex);
# endif /* SOLARIS */
	}

# if (BSD >= 199101) || defined(__FreeBSD__) || defined(__osf__)
	uio->uio_rw = UIO_READ;
# endif

	for (copied = 0; ((ipl = ifs->ifs_iplt[unit]) != NULL); copied += dlen) {
		dlen = ipl->ipl_dsize;
		if (dlen > uio->uio_resid)
			break;
		/*
		 * Don't hold the mutex over the uiomove call.
		 */
		ifs->ifs_iplt[unit] = ipl->ipl_next;
		ifs->ifs_iplused[unit] -= dlen;
		if (ifs->ifs_iplt[unit] == NULL) {
			ifs->ifs_iplh[unit] = &ifs->ifs_iplt[unit];
			ifs->ifs_ipll[unit] = NULL;
		}
		MUTEX_EXIT(&ifs->ifs_ipl_mutex);
		SPL_X(s);
		error = UIOMOVE((caddr_t)ipl, dlen, UIO_READ, uio);
		if (error) {
			SPL_NET(s);
			MUTEX_ENTER(&ifs->ifs_ipl_mutex);
			ifs->ifs_iplused[unit] += dlen;
			ipl->ipl_next = ifs->ifs_iplt[unit];
			ifs->ifs_iplt[unit] = ipl;
			ifs->ifs_ipll[unit] = ipl;
			if (ifs->ifs_iplh[unit] == &ifs->ifs_iplt[unit]) {
				*ifs->ifs_iplh[unit] = ipl;
				ifs->ifs_iplh[unit] = &ipl->ipl_next;
			}
			break;
		}
		MUTEX_ENTER(&ifs->ifs_ipl_mutex);
		KFREES((caddr_t)ipl, dlen);
		SPL_NET(s);
	}

	MUTEX_EXIT(&ifs->ifs_ipl_mutex);
	SPL_X(s);
	return error;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipflog_clear                                                */
/* Returns:     int    - number of log bytes cleared.                       */
/* Parameters:  unit(I) - device we are reading from                        */
/*                                                                          */
/* Deletes all queued up log records for a given output device.             */
/* ------------------------------------------------------------------------ */
int ipflog_clear(unit, ifs)
minor_t unit;
ipf_stack_t *ifs;
{
	iplog_t *ipl;
	int used;
	SPL_INT(s);

	SPL_NET(s);
	MUTEX_ENTER(&ifs->ifs_ipl_mutex);
	while ((ipl = ifs->ifs_iplt[unit]) != NULL) {
		ifs->ifs_iplt[unit] = ipl->ipl_next;
		KFREES((caddr_t)ipl, ipl->ipl_dsize);
	}
	ifs->ifs_iplh[unit] = &ifs->ifs_iplt[unit];
	ifs->ifs_ipll[unit] = NULL;
	used = ifs->ifs_iplused[unit];
	ifs->ifs_iplused[unit] = 0;
	bzero((char *)&ifs->ifs_iplcrc[unit], FI_CSIZE);
	MUTEX_EXIT(&ifs->ifs_ipl_mutex);
	SPL_X(s);
	return used;
}
#endif /* IPFILTER_LOG */
