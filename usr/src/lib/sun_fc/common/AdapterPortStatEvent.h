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

#ifndef	_ADAPTERPORTEVENT_H
#define	_ADAPTERPORTEVENT_H



#include "Event.h"
#include <hbaapi.h>


/**
 * @memo	    Represents an Adapter Port Statistic Event
 *
 * @doc		    When adapter port statistic events occur on the HBA, an
 *		    event of this type will be sent to registered
 *		    listeners
 */
class AdapterPortStatEvent : public Event {
public:
    enum EVENT_TYPE {
		THRESHOLD = HBA_EVENT_PORT_STAT_THRESHOLD,
		GROWTH = HBA_EVENT_PORT_STAT_GROWTH
	    };
    AdapterPortStatEvent(uint64_t myWwn, EVENT_TYPE myType) :
		    wwn(myWwn), type(myType) { }
    uint64_t getPortWWN() { return (wwn); }
    EVENT_TYPE getType() { return (type); }

private:
    uint64_t wwn;
    EVENT_TYPE type;
};

#endif /* _ADAPTERPORTEVENT_H */
