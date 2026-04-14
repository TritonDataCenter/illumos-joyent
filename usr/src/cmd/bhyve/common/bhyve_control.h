/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 *
 * Copyright 2026 Edgecast Cloud LLC.
 */

/*
 * bhyve control socket — Unix-socket control plane consumed by the
 * GZ-side migration agent.  See bhyve_control.c for protocol details.
 */

#ifndef _BHYVE_CONTROL_H_
#define	_BHYVE_CONTROL_H_

struct vmctx;

#ifdef __cplusplus
extern "C" {
#endif

void	bhyve_control_init(struct vmctx *ctx, int ncpus, const char *path);
void	bhyve_control_fini(void);

/*
 * Block the calling thread until cmd_import_state has finished applying
 * a migrated guest's state.  Returns immediately if migrate.listen=true
 * was never set or import has already completed.  Used by bhyverun.c on
 * the destination side to gate vCPU-thread creation on import success.
 */
void	bhyve_control_wait_import(void);

/*
 * Ask every PCI device that registered pe_hibernate to drop its backing
 * fd.  Used on the destination side of a live migration right after
 * pause_all_devices(): with the zvols released, the GZ agent can run
 * the final `zfs recv` before import-state arrives.  Idempotent; a
 * device that never opened an fd (fbuf, viona, xhci, ...) is a no-op.
 *
 * Caller MUST have already paused the devices (blockif_hibernate
 * asserts bc_paused = 1) and paused the vCPUs so no fresh I/O starts.
 */
int	hibernate_all_devices(void);

#ifdef __cplusplus
}
#endif

#endif /* _BHYVE_CONTROL_H_ */
