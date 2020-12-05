/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2020 Joyent, Inc.
 */

#include <sys/tsc.h>
#include <sys/x86_archext.h>
#include <sys/prom_debug.h>
#include <sys/cpuvar.h>

static boolean_t
tsc_calibrate_cpuid(uint64_t *freqp)
{
	uint64_t val;

	PRM_POINT("Attempting to use CPUID instruction for TSC calibration...");

	/*
	 * If we have the TSC frequency from the CPU itself, use it.
	 */
	if ((val = cpuid_tsc_freq(CPU)) != 0) {
		*freqp = val;
		return (B_TRUE);
	}

	return (B_FALSE);
}

static tsc_calibrate_t tsc_calibration_cpuid = {
	.tscc_source = "CPUID",
	.tscc_preference = 100,
	.tscc_calibrate = tsc_calibrate_cpuid,
};
TSC_CALIBRATION_SOURCE(tsc_calibration_cpuid);
