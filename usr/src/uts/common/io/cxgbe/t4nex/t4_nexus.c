/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source. A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * This file is part of the Chelsio T4 support code.
 *
 * Copyright (C) 2010-2013 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

/*
 * Copyright 2025 Oxide Computer Company
 */

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/pci.h>
#include <sys/atomic.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/open.h>
#include <sys/cred.h>
#include <sys/stat.h>
#include <sys/mkdev.h>
#include <sys/containerof.h>
#include <sys/sensors.h>
#include <sys/firmload.h>
#include <sys/mac_provider.h>
#include <sys/mac_ether.h>
#include <sys/vlan.h>
#include <sys/cpuvar.h>

#include "common/common.h"
#include "common/t4_msg.h"
#include "common/t4_regs.h"
#include "common/t4_extra_regs.h"

/*
 * Nexus driver for Chelsio Terminator Network Adapters (T4/T5/T6)
 *
 * This driver supports the Chelsio Terminator series of network adapters
 * starting with the T4 generation and onward. These adapters present a "unified
 * wire" for managing traditional L2 Ethernet traffic alongside a variety of
 * stateful offloads including the usual TCP/UDP protocols along with storage
 * technology like iSCSI, FCoE, NVMe over fabrics, and others. All of these
 * features coexist on a single ASIC controlled by a single firmware image, thus
 * the "unified wire". While these adapters provide many offload technologies,
 * this driver remains focused on providing L2 Ethernet services as presented by
 * the GLDv3/mac framework. In short, this consists of presenting the device as
 * groups of rings with filtering and steering capabilities along with stateless
 * offloads including checksums and LSO. This nexus driver does not preclude the
 * support of the stateful offload features, but supporting them requires
 * additional work both inside this driver along with general operating system
 * enhancements.
 *
 * Naming & Terminology
 * --------------------
 *
 * CPL:
 *
 *     Chelsio Protocol Language messages. We use these to wrap network data for
 *     Tx and Rx, this wrapping of packets in CPL is referred to by Chelsio as
 *     "tunneled" data. Not be to confused with the more general network
 *     tunneling also known as encapsulation (e.g. IP tunnling, VXLAN, etc).
 *
 * Flit:
 *
 *     A 64-bit (8 byte) quantity. The Chelsio documentation and code divides
 *     communication structures into units of flits. For example, a firmware
 *     command may consist of up to 8 flits (8-bytes x 8 = 64 bytes) where the
 *     command header is always made up of the first two flits and the remaining
 *     6 may be used for variable payload data.
 *
 * Module/Block:
 *
 *     The T4 is comprised of various modules (also referred to as a "block" or
 *     "engine" in some contexts) which work together to provide the services
 *     offered by the chip. For example, the Scatter-Gather Engine (SGE) module
 *     provides the DMA communications used to send and receive traffic.
 *
 * T4:
 *
 *     The short name to represent any Chelsio Terminator ASIC from the T4 and
 *     onward. This includes the T4, T5, and T6 line of parts.
 *
 * Tunneled Traffic:
 *
 *     The Chelsio documentation often refers to sending or receiving "tunneled"
 *     traffic, but it's not referring to the traditional networking terminology
 *     of encapsulated data. Rather, it is referring to traffic that is
 *     sent/received in a non-offload capacity. It's called "tunneled" because
 *     the data is wrapped/"tunneled" in Work Requests and CPL messages. This
 *     driver deals purely in tunneled traffic as it make no use of stateful
 *     offloads.
 *
 * ULPTX
 *
 *    The Upper Layer Processing Transmit module handle DMA access related to
 *    egress traffic.
 *
 * Work Request (WR)
 *
 *    Work Requests are commands and data descriptors use to send Tx packets.
 *
 * Communication
 * -------------
 *
 * Before any requests can be made or any data can be transmitted we must first
 * establish communication with the device. The Chelsio Terminator ASIC, or T4
 * for short, presents four primary methods of communication between the driver
 * and itself.
 *
 * 1. Registers: read/write simple values or bitwise data over PIO
 *
 * 2. Mailboxes: synchronized request/reply structured data over PIO
 *
 * 3. Queues: DMA memory of structured data for control and data plane
 *
 * 4. Interrupts: MSI/MSI-X interrupts for indicating queue status updates or
 *    asynchronous events from the firmware
 *
 * The first access we have is to the registers via our BAR0 mapping. These
 * registers provide control and configuration over many aspects of the
 * different modules that make up the T4.
 *
 * Using the registers we then establish a mailbox which provides structured
 * communication in the form of request/reply commands to the firmware. Both of
 * these methods use Programmed I/O which is fine for administrative control,
 * but inadequate for the latency and throughput demands of the datapath and its
 * associated control plane.
 *
 * For the datapath we use the registers and mailbox to establish queues of DMA
 * memory for transmitting and receiving data. Queues deal in Work Requests
 * (WR), Chelsio Protocol Language messages (CPL), and Freelist buffer pointers
 * (FL). These data structures may subsequently point to other DMA memory
 * (buffers) that hold the data to be transmitted or received along with its
 * associated software descriptors.
 *
 * Finally, the T4 provides various types of interrupt control to asynchronously
 * signal the driver of conditions such as errors, firmware events, and datapath
 * (queue) synchronization via status updates (cidx/pidx).
 *
 * While nothing precludes the driver from consuming directly these forms of
 * communication, most of the interface with the T4 is currently provided by the
 * "common code" interfaces. This common code is, nominally, code shared between
 * the various operating systems for interacting with the T4.
 *
 * Queues (Rings)
 * --------------
 *
 * Queues are circular buffers of DMA memory used to share structured data often
 * referred to as a "descriptor". These circular buffers are also commonly
 * called rings. Where each entry in the ring is a descriptor used for locating
 * and describing data that is meant to be transmitted across or received from
 * the network device.
 *
 * The T4 queues are used in this manner, to share descriptors between the
 * driver and device, but their level of synchronization is not technically a
 * descriptor. Rather, a queue is made up of a number of "host credits". The
 * size of a host credit (sometimes also called an "entry" or "descriptor" in
 * the code) depends on the type of queue and how it is configured. This
 * difference in terminology between "host credit" vs. "descriptor" is mostly
 * pertinent to Egress Queues, which always have 64-byte (8-flit) host credits.
 * Those host credits are used to pass variable-sized Work Requests (WR), the
 * structure which actually acts as the "descriptor", which may be smaller or
 * larger than a single credit. Ingress Queues (IQ) also have variable-sized
 * entries, but the size is determined at queue creation time and is uniform for
 * each entry; therefore IQ entries can be called credits, entries, or
 * descriptors without any real confusion. The official Chelsio documentation
 * also uses mixed terminology, so it's important to keep that in mind. However,
 * regardless of how many credits a descriptor requires, communication always
 * occurs in units of whole credits. A good way to frame this is that queues
 * provide logical rings of descriptors (WRs, CPLs, FLs) on top of physical
 * units of host credits.
 *
 * There are different types of queues for different purposes, but they are all
 * variations of either an Ingress Queue (IQ) or Egress Queue (EQ). As the names
 * suggest, a queue is a unidirectional communication channel: one is the
 * producer and the other side is a consumer. The Ingress Queue provides
 * communication from T4 (producer) to driver (consumer), and the Egress Queue
 * provides communication from the driver (producer) to the T4 (consumer).
 *
 * The producer/consumer synchronize communication in units of host credits. The
 * producer tracks its next host credit to write under the producer index
 * (pidx), and the consumer tracks its next host credit to read under the
 * consumer index (cidx). These values are kept in sync through means such as
 * doorbells (DB), Go-To-Sleep updates (GTS), and interrupts carrying CPL
 * message (e.g. CPL_SGE_EGR_UPDATE).
 *
 * If you read the Terminator Programmer's Guide you will find dicussion about
 * the queue's "context". This is described as an area of memory that dictates
 * various features and behavior of the queue. While this queue context may at
 * one point have been programmed directly, it no longer is. Rather, the various
 * aspects of queue behavior are controlled by parameters passed during the
 * queue creation firmware commands, along with other mechanisms such as
 * registers.
 *
 * Each type of queue also has a "status page" which may optionally be updated
 * with cidx or pidx updates. For EQs this page consumes 1 or 2 credits at the
 * end of the queue. For IQs it consumes 1 entry at the end of the queue.
 *
 * We use EQs to create Tx rings and IQs (plus FLs) to create Rx rings. We
 * create the same number of Tx and Rx queues. So if we have 32 Tx queues, we
 * will also have 32 Rx queues. The number of queues created is based on the
 * port speed. The association from speed to queue count can be found in the
 * t4_queue_counts array.
 *
 * Egress Queues (EQ)
 * ------------------
 *
 * Egress Queues (EQ) provide communication from driver to T4. The driver writes
 * (produces) descriptors to the queue using one or more host credits. It
 * notifies the T4 of these new outstanding host credits by updating its pidx
 * via a doorbell. As new outstanding credits arrive via the doorbell the T4
 * reads (consumes) them to determine what types of descriptors have been sent
 * along with their content. As the T4 consumes host credits it notifies the
 * driver with a programmable combination of status page updates, CPL messages,
 * and interrupts.
 *
 * All EQs use a host credit size of 8 flits (64 bytes). The driver uses these
 * host credits to send Work Requests (WR) to the T4.
 *
 * A WR is variable in size and may be smaller or larger than a single host
 * credit, but communication is always in whole units of credits. It is legal
 * for a WR to span across the end of the queue and warp around, but the
 * contents of the WR may dictate that the wrap-around happens only at certain
 * offsets within the descriptor. A WR may be 16 to 512 bytes long, but must
 * always begin at the start of a host credit, thus all WRs must start at a
 * 64-byte aligned address.
 *
 * At this time the only WRs we use are FW_ETH_TX_PKT_WR and FW_ETH_TX_PKTS_WR.
 *
 * Ingress Queues (IQ)
 * -------------------
 *
 * Ingress Queues (IQ) provide communication from T4 to driver. The T4 produces
 * queue entries for the dirver to consume. Unlike EQs, data passed in IQs is
 * always done as fixed-size entries. That is, each entry in the IQ takes up
 * exactly one credit, and that credit size is determined at creation time. So
 * in that sense you could think of a IQ entry as a descriptor. However, these
 * entries contain different types of data of variable lengths (within in the
 * bounds of the entry/credit size). There are four possible entry sizes, and
 * the entry size dictates the possible messages an IQ can hold. The possibles
 * sizes are 2 flits (16 bytes), 4 flits (32 bytes), 8 flits (64 bytes), and 16
 * flits (128 bytes). Depending on the size, each entry may a contain Freelist
 * buffer completion, CPL message, or a forwarded interrupt destined for another
 * IQ. Which size to use depends on the use case of the IQ.
 *
 * Currently we make use of the 64-byte entry size exclusively.
 *
 * Freelists (FL)
 * --------------
 *
 * A freelist (FL) is a type of EQ used for providing (producing) buffers for
 * the purpose of holding received network data for an associated IQ. The driver
 * produces pointers to DMA data buffers and the associated IQ consumes them as
 * data is received by the device. A freelist is always associated with an IQ; a
 * freelist is never used on its own. An IQ, however, may have no FL associated
 * with it; such is the case for event IQs and interrupt forwarding IQs. An Rx
 * IQ must have one or two FLs associated with it used to store the incoming
 * packet headers and payload. The use of two FLs is for when "header splitting"
 * is enabled: where the headers are placed in one buffer and the payload is
 * placed in the other. Only the first 1024 IQs may have FLs associated with
 * them.
 *
 * A freelist is always made up of buffer "pointers". Each buffer pointer is 1
 * flit (8 bytes) in size and points to DMA memory used to hold packet data. The
 * lowest four bits of the pointer are used as an index into the freelist buffer
 * size array, allowing up to 16 different buffer sizes. This implies that each
 * FL buffer pointer must be at least 16-byte aligned. Each pointer may use a
 * different size. Since EQ communication must happen in units of host credits,
 * and an EQ host credit is 8 flits, it means that the driver must always
 * produce 8 FL buffer pointers per credit. If the driver cannot produce 8
 * buffer pointers, the rest of the credit may be filled with zero-sized
 * pointers ("null" or "zero" buffer) which is to say their size index points to
 * a zero-value entry in the array.
 *
 * The digram below depicts how the FL buffer pointer indexes into the
 * SGE_FL_BUFFER_SZ[N] array.
 *
 * +-------------------+-------------------------+
 * | Buffer Ptr [63:4] | SGE_FL_BUFFER_SIZE[3:0] |
 * +-------------------+-------------------------+
 *                                  |
 *            +---------------------+
 *            v
 * +--------------------+--------------------+
 * | SGE_FL_BUFFER_SZ0  |         0          |  "zero" buffer
 * +--------------------+--------------------+
 * | SGE_FL_BUFFER_SZ1  |        4096        |  4K buffer
 * +--------------------+--------------------+
 *                      .
 *                      .
 *                      .
 * +--------------------+--------------------+
 * | SGE_FL_BUFFER_SZ15 |       16384        |  16K buffer
 * +--------------------+--------------------+
 *
 * FL buffers may have "packing" enabled where a single buffer may be used for
 * multiple packets. This requires that the driver keep track of the current
 * offset within the current FL buffer. When a new buffer is required by the
 * device, because the next packet will not fit in the remaining space of the
 * current buffer, it will consume a new buffer and set a bit in the IQ
 * completion entry to notify the driver. At this point the driver updates its
 * cidx and restarts the offset at zero.
 *
 * If packing is not enabled each new packet starts at a new buffer.
 *
 * This driver currently sets the FL buffer size to 8192 (rx_buf_size) and
 * enables packing.
 *
 * Doorbells, GTS messages, and Interrupts
 * ---------------------------------------
 *
 * The driver and T4 need some way to communicate udpates to the pidx/cidx
 * values of their queues. To achieve this goal, the driver uses a combination
 * of doorbells, GTS messages, status pages, and interrupts.
 *
 * Doorbells
 * ---------
 *
 * The driver informs the T4 of new EQ credits by way of a "doorbell" (DB). A
 * doorbell is a register write directed towards a single queue. The doorbell
 * carries a priority and an incremental update to the pidx value. There are two
 * types of doorbells:
 *
 * 1. Kernel Space doorbells (KDB) which use BAR0.
 * 2. User Space doorbells (UDB) which use BAR2.
 *
 * The "user space" doorbells, while useful for kernel-bypass networking, are
 * also used for regular in-kernel networking. They divide the queue doorbell
 * space into multiple 128 byte segments versus KDB's single address for all
 * queues. They also provide the ability to perform Write-Combining Work
 * Requeusts (DOORBELL_WCWR) and Write-Combining Doorbells (DOORBELL_UDBWC). The
 * WCWR allows you to send a single credit as one write and avoid the need for
 * the T4 to DMA the credit's contents (a WR or FL buffer pointers) from host
 * memory. We currently make use of WCWR for the Tx datapath, but not for
 * writing freelist descriptors.
 *
 * There is some more discussion of doorbells at the t4_doorbells_t definition
 * in adapter.h.
 *
 * EQ Status Updates
 * -----------------
 *
 * This section covers how EQ status updates work. While an FL is technically an
 * EQ it makes no use of these mechanisms because the use of FL buffers (cidx)
 * is tracked implicitly as CPL Rx messages arrive on the associated IQ.
 *
 * The driver can track the EQ cidx either by reading the EQ status page or by
 * asking for a notification via an IQ. This is delivered by way of a
 * CPL_SGE_EGR_UPDATE message. Furthermore, if the IQ this message is destined
 * for has interrupts enabled, an interrupt is generated upon delivery of the
 * message. The EQ status page update and the delivery of this message is
 * controlled by several factors.
 *
 * 1. The EQ context field 'CIDXFlushThresh' (FW_EQ_ETH_CMD.cidxfthresh)
 *    indicates how many consumed credits must be outstanding before the T4
 *    generates a cidx update (both status page update and CPL message).
 *
 * 2. The EQ context field 'FCThreshOverride' (FW_EQ_ETH_CMD.cidxfthresho) tells
 *    the T4 to generate a cidx update anytime cidx==pidx; i.e., when the T4 has
 *    consumed all outstanding credits. This happens regardless if the cidx
 *    flush threshold has been reached or not (thus the "override"). This is
 *    useful for dealing with cases of intermitten transmission where the
 *    threshold may not be reached in a timely manner.
 *
 * 3. The DBQ Timer (see TAF_DBQ_TIMER) provides for sending a cidx notification
 *    anytime the EQ has sat idle (no pidx updates) for a period of time. This
 *    is preferred to method (2) as it allows batching cidx updates while also
 *    recycling consumed credits in a timely manner. This is available starting
 *    with the T6 chip.
 *
 * 4. The FW_EQ_FLUSH_WR (its own WR on the EQ) allows the driver to request
 *    either a status page update, EGR update, or both.
 *
 * 5. The FW_ETH_TX_PKT_WR and FW_ETH_TX_PKTS_WR, used to send packets, allows
 *    the driver to request either a status page update, EGR update, or both as
 *    part of sending the packet.
 *
 * This driver utilizes both the status page and CPL udpates as well as all the
 * methods listed above to generate these updates.
 *
 * GTS Messages
 * ------------
 *
 * The driver sends a GTS (Go To Sleep) message to the T4 to update the SGE
 * about a specific IQ. The message conveys four pieces of information.
 *
 * 1. The Ingress Queue the update is for.
 *
 * 2. The current cidx of the driver.
 *
 * 3. The new timer value for pidx update scheduling (see IQ context
 *    'Update_Scheduling' field).
 *
 * 4. Either a) arming the "Solicited Event" Interrupt or b) setting the new
 *    value for the IQ context 'Update_Scheduling' field. Which one depends on
 *    the IQ context 'GTS_Mode' value.
 *
 * We currently always set 'GTS_Mode=1' which indicates that the GTS 'SEIntArm'
 * value (number 4 above) is used to dictate the new value for the
 * 'Update_Scheduling' field.
 *
 * As the driver processes outstanding IQ credits it uses GTS messages to notify
 * the driver of how many credits it has consumed and optionally re-arm the
 * timer and packet counter notifications.
 *
 * The GTS messages, like the EQ Doorbells, have both kernel and user space
 * registers. We currently only make use of the kernel space register.
 *
 * Ingress Queue Generation Bit
 * ----------------------------
 *
 * Ingress Queues have an alternative method for pidx updates beyond the status
 * page update or an explicit CPL message like is done for Ethernet EQs. They
 * also provide a generation bit as part of each queue entry (credit) which can
 * be used by the driver, after it has received an interrupt indicating new data
 * is available, to determine which entries are newly produced by the device.
 * This method allows you to eschew IQ status page updates altogether, and that
 * is how we use IQs both for our firmware queue as well as our Rx data queues.
 *
 * Freelist Updates
 * ----------------
 *
 * While an FL is technically an EQ we do not make use of explicit EQ status
 * updates to track the FL cidx. Rather, the current FL buffer is tracked
 * implicitly by way of the Rx IQ CPL messages generated as part of incoming
 * traffic. As new packets come in the SGE writes the data in the current FL
 * buffer and writes a new CPL message onto the Rx IQ. These CPL messages allow
 * the driver to track which FL buffer is currently in use by the device and
 * when to move onto the next FL buffer.
 *
 * Interrupts
 * ----------
 *
 * The T4 provides interrupt capability for support of asynchrnous
 * notifications. The primary uses of interrupts consist of the following.
 *
 * 1. Notification of new IQ entries (credits) available for consumption by the
 *    driver. That is, the T4 notifies the host that of its latest IQ pidx value
 *    indicating that there are new credits for host consumption.
 *
 * 2. Notification of new EQ credits available for production by the driver.
 *    That is, the T4 notifies the host of its latest EQ cidx value indicating
 *    that there are new credits avilable for host production.
 *
 * 3. Notification of firmware events (also referred to as the "firmware queue"
 *    or "asynchronous event queue").
 *
 * This driver employs three different strategies for assigning interrupts
 * depending on the type and number of interrupts available. These strategies
 * are listed in order of preference. The solution is chosen by
 * t4_cfg_intrs_queues() and the setup is done by t4_setup_intrs().
 *
 * TIP_PER_PORT
 *
 *     The first strategy is used when we have enough MSI/MSI-X interrupts to
 *     dedicate one to error conditions, one for asynchronous firmware events,
 *     and at least one for Tx/Rx events on each network port on the adapter. A
 *     port may have more than one interrupt, in which case its Tx/Rx queue
 *     events are distributed across those interrupts as evenly as possible. For
 *     example, given a two-port adapter with eight interrupts, one interrupt
 *     would be consumed for error conditions, one for firmware events, and the
 *     remaning six would be divided as three interrupts per port. If each port
 *     has 32 Rx queues, then two interrupts would be responsbile for 11 queues,
 *     and the third interrupt would be responsible for 10.
 *
 *     The error interrupt vector points to the t4_intr_err() function. Errors
 *     are deliverd via registers and are handled by t4_slow_intr_handler().
 *
 *     The asynchronous firmware event interrupt points to the t4_intr_fwq()
 *     function and the events arrive on the firmware queue (sc->sge.fwq).
 *
 *     The per port interrupts point to t4_intr_port_queue() and each port's
 *     events land on one of the per port event queues (port->intr_iqs).
 *
 * TIP_ERR_QUEUES
 *
 *     The second strategy is used when we have only two interrupts. In this
 *     case one of the interrupts is dedicated to errors and the other one is
 *     shared between the firmware events and the port events (Rx/Tx
 *     notifications).
 *
 *     In this case the firmware and port events all land on the firmware queue
 *     which is processed by t4_intr_fwq().
 *
 * TIP_SINGLE
 *
 *     The last strategy is for when we have a single interrupt and everything
 *     needs to share it. In this case the interrupt lands on t4_intr_all() and
 *     all firmware and port events go to the firmware queue.
 *
 * The per-port events queues (port->intr_iq) do not receive any network data
 * themselves. Rather, they are used for two purposes:
 *
 * 1. To handle CPL_SGE_EGR_UPDATE messages; used to notify the driver about the
 *    device's current cidx in a particular EQ. This is how Tx queues know when
 *    they reclaim credits used for sending packets.
 *
 * 2. To handle "forwarded interrupt" notifications; used to notify the driver
 *    that a particular receive IQ has outstanding credits to read. This is how
 *    Rx queues know when there are new packets available to read.
 */

static void *t4_soft_state;

static kmutex_t t4_adapter_list_lock;
static list_t t4_adapter_list;

typedef enum t4_port_speed {
	TPS_1G,
	TPS_10G,
	TPS_25G,
	TPS_40G,
	TPS_50G,
	TPS_100G,
	TPS_200G,
	TPS_400G,
} t4_port_speed_t;

static uint_t t4_getpf(struct adapter *);
static int t4_prep_firmware(struct adapter *);
static int t4_upload_config_file(struct adapter *, uint32_t *, uint32_t *);
static int t4_partition_resources(struct adapter *);
static int t4_init_adap_tweaks(struct adapter *);
static int t4_init_get_params_pre(struct adapter *);
static int t4_init_get_params_post(struct adapter *);
static int t4_init_set_params(struct adapter *);
static void t4_setup_adapter_memwin(struct adapter *);
static uint32_t t4_position_memwin(struct adapter *, int, uint32_t);
static void t4_init_driver_props(struct adapter *);
static int t4_cfg_intrs_queues(struct adapter *);
static int t4_setup_intrs(struct adapter *);
static int t4_add_child_node(struct adapter *, uint_t);
static int t4_remove_child_node(struct adapter *, uint_t);
static kstat_t *t4_setup_kstats(struct adapter *);
static kstat_t *t4_setup_wc_kstats(struct adapter *);
static void t4_port_full_uninit(struct port_info *);
static t4_port_speed_t t4_port_speed(const struct port_info *);

static int t4_temperature_read(void *, sensor_ioctl_scalar_t *);
static int t4_voltage_read(void *, sensor_ioctl_scalar_t *);

static const ksensor_ops_t t4_temp_ops = {
	.kso_kind = ksensor_kind_temperature,
	.kso_scalar = t4_temperature_read
};

static const ksensor_ops_t t4_volt_ops = {
	.kso_kind = ksensor_kind_voltage,
	.kso_scalar = t4_voltage_read
};

static int t4_ufm_getcaps(ddi_ufm_handle_t *, void *, ddi_ufm_cap_t *);
static int t4_ufm_fill_image(ddi_ufm_handle_t *, void *, uint_t,
    ddi_ufm_image_t *);
static int t4_ufm_fill_slot(ddi_ufm_handle_t *, void *, uint_t, uint_t,
    ddi_ufm_slot_t *);
static ddi_ufm_ops_t t4_ufm_ops = {
	.ddi_ufm_op_fill_image = t4_ufm_fill_image,
	.ddi_ufm_op_fill_slot = t4_ufm_fill_slot,
	.ddi_ufm_op_getcaps = t4_ufm_getcaps
};


static int
t4_devo_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **rp)
{
	struct adapter *sc;
	minor_t minor;

	minor = getminor((dev_t)arg);	/* same as instance# in our case */

	if (cmd == DDI_INFO_DEVT2DEVINFO) {
		sc = ddi_get_soft_state(t4_soft_state, minor);
		if (sc == NULL)
			return (DDI_FAILURE);

		ASSERT(sc->dev == (dev_t)arg);
		*rp = (void *)sc->dip;
	} else if (cmd == DDI_INFO_DEVT2INSTANCE)
		*rp = (void *) (unsigned long) minor;
	else
		ASSERT(0);

	return (DDI_SUCCESS);
}

static int
t4_devo_probe(dev_info_t *dip)
{
	int rc, id, *reg;
	uint_t n, pf;

	id = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "device-id", 0xffff);
	if (id == 0xffff)
		return (DDI_PROBE_DONTCARE);

	rc = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "reg", &reg, &n);
	if (rc != DDI_SUCCESS)
		return (DDI_PROBE_DONTCARE);

	pf = PCI_REG_FUNC_G(reg[0]);
	ddi_prop_free(reg);

	/* Prevent driver attachment on any PF except 0 on the FPGA */
	if (id == 0xa000 && pf != 0)
		return (DDI_PROBE_FAILURE);

	return (DDI_PROBE_DONTCARE);
}

static int t4_devo_detach(dev_info_t *, ddi_detach_cmd_t);

static int
t4_devo_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int i = 0;
	int rc = DDI_SUCCESS;
	char name[16];
	ddi_device_acc_attr_t da = {
		.devacc_attr_version = DDI_DEVICE_ATTR_V0,
		.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC,
		.devacc_attr_dataorder = DDI_STRICTORDER_ACC
	};
	ddi_device_acc_attr_t da_bar2 = {
		.devacc_attr_version = DDI_DEVICE_ATTR_V0,
		.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC,
		.devacc_attr_dataorder = DDI_STRICTORDER_ACC
	};

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	/*
	 * Allocate space for soft state.
	 */
	const int instance = ddi_get_instance(dip);
	rc = ddi_soft_state_zalloc(t4_soft_state, instance);
	if (rc != DDI_SUCCESS) {
		cxgb_printf(dip, CE_WARN,
		    "failed to allocate soft state: %d", rc);
		return (DDI_FAILURE);
	}

	struct adapter *sc = ddi_get_soft_state(t4_soft_state, instance);
	sc->dip = dip;
	sc->dev = makedevice(ddi_driver_major(dip), instance);
	mutex_init(&sc->lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&sc->cv, NULL, CV_DRIVER, NULL);
	mutex_init(&sc->sfl_lock, NULL, MUTEX_DRIVER, NULL);
	list_create(&sc->sfl_list, sizeof (struct sge_fl),
	    offsetof(struct sge_fl, sfl_node));
	mutex_init(&sc->mbox_lock, NULL, MUTEX_DRIVER, NULL);
	list_create(&sc->mbox_list, sizeof (t4_mbox_waiter_t),
	    offsetof(t4_mbox_waiter_t, node));

	mutex_enter(&t4_adapter_list_lock);
	list_insert_tail(&t4_adapter_list, sc);
	mutex_exit(&t4_adapter_list_lock);

	sc->pf = t4_getpf(sc);
	if (sc->pf > 8) {
		rc = EINVAL;
		cxgb_printf(dip, CE_WARN,
		    "failed to determine PCI PF# of device");
		goto done;
	}
	sc->mbox = sc->pf;

	/* Initialize the driver properties */
	t4_init_driver_props(sc);
	struct driver_properties *prp = &sc->props;

	/*
	 * Enable access to the PCI config space.
	 */
	rc = pci_config_setup(dip, &sc->pci_regh);
	if (rc != DDI_SUCCESS) {
		cxgb_printf(dip, CE_WARN,
		    "failed to enable PCI config space access: %d", rc);
		goto done;
	}

	/* TODO: Set max read request to 4K */

	/*
	 * Enable BAR0 access.
	 */
	rc = ddi_regs_map_setup(dip, 1, &sc->regp, 0, 0, &da, &sc->regh);
	if (rc != DDI_SUCCESS) {
		cxgb_printf(dip, CE_WARN,
		    "failed to map device registers: %d", rc);
		goto done;
	}

	(void) memset(sc->chan_map, 0xff, sizeof (sc->chan_map));

	/*
	 * Prepare the adapter for operation.
	 */
	rc = -t4_prep_adapter(sc, false);
	if (rc != 0) {
		cxgb_printf(dip, CE_WARN, "failed to prepare adapter: %d", rc);
		goto done;
	}

	/*
	 * Enable BAR2 access.
	 */
	sc->doorbells |= DOORBELL_KDB;
	rc = ddi_regs_map_setup(dip, 2, &sc->bar2_ptr, 0, 0, &da_bar2,
	    &sc->bar2_hdl);
	if (rc != DDI_SUCCESS) {
		cxgb_printf(dip, CE_WARN,
		    "failed to map BAR2 device registers: %d", rc);
		goto done;
	} else {
		if (t4_cver_ge(sc, CHELSIO_T5)) {
			sc->doorbells |= DOORBELL_UDB;
			if (prp->write_combine) {
				/*
				 * Enable write combining on BAR2.  This is the
				 * userspace doorbell BAR and is split into 128B
				 * (UDBS_SEG_SIZE) doorbell regions, each
				 * associated with an egress queue.  The first
				 * 64B has the doorbell and the second 64B can
				 * be used to submit a tx work request with an
				 * implicit doorbell.
				 */
				sc->doorbells &= ~DOORBELL_UDB;
				sc->doorbells |= (DOORBELL_WCWR |
				    DOORBELL_UDBWC);

				const uint32_t stat_mode =
				    t4_cver_ge(sc, CHELSIO_T6) ?
				    V_T6_STATMODE(0) : V_STATMODE(0);
				t4_write_reg(sc, A_SGE_STAT_CFG,
				    V_STATSOURCE_T5(7) | stat_mode);
			}
		}
	}

	/*
	 * Do this really early.  Note that minor number = instance.
	 */
	(void) snprintf(name, sizeof (name), "%s,%d", T4_NEXUS_NAME, instance);
	rc = ddi_create_minor_node(dip, name, S_IFCHR, instance,
	    DDI_NT_NEXUS, 0);
	if (rc != DDI_SUCCESS) {
		cxgb_printf(dip, CE_WARN,
		    "failed to create device node: %d", rc);
		rc = DDI_SUCCESS; /* carry on */
	}

	/* Do this early. Memory window is required for loading config file. */
	t4_setup_adapter_memwin(sc);

	/* Prepare the firmware for operation */
	rc = t4_prep_firmware(sc);
	if (rc != 0)
		goto done; /* error message displayed already */

	rc = t4_init_adap_tweaks(sc);
	if (rc != 0)
		goto done;

	rc = t4_init_get_params_pre(sc);
	if (rc != 0)
		goto done; /* error message displayed already */

	t4_sge_init(sc);

	if (sc->flags & TAF_MASTER_PF) {
		/* get basic stuff going */
		rc = -t4_fw_initialize(sc, sc->mbox);
		if (rc != 0) {
			cxgb_printf(sc->dip, CE_WARN,
			    "early init failed: %d.\n", rc);
			goto done;
		}
	}

	rc = t4_init_get_params_post(sc);
	if (rc != 0)
		goto done; /* error message displayed already */

	rc = t4_init_set_params(sc);
	if (rc != 0)
		goto done; /* error message displayed already */

	/*
	 * TODO: This is the place to call t4_set_filter_mode()
	 */

	t4_write_reg(sc, A_TP_SHIFT_CNT,
	    V_SYNSHIFTMAX(6) |
	    V_RXTSHIFTMAXR1(4) |
	    V_RXTSHIFTMAXR2(15) |
	    V_PERSHIFTBACKOFFMAX(8) |
	    V_PERSHIFTMAX(8) |
	    V_KEEPALIVEMAXR1(4) |
	    V_KEEPALIVEMAXR2(9));
	t4_write_reg(sc, A_ULP_RX_TDDP_PSZ, V_HPZ0(PAGE_SHIFT - 12));

	/*
	 * Work-around for bug 2619
	 * Set DisableVlan field in TP_RSS_CONFIG_VRT register so that the
	 * VLAN tag extraction is disabled.
	 */
	t4_set_reg_field(sc, A_TP_RSS_CONFIG_VRT, F_DISABLEVLAN, F_DISABLEVLAN);

	/* Store filter mode */
	t4_read_indirect(sc, A_TP_PIO_ADDR, A_TP_PIO_DATA, &sc->filter_mode, 1,
	    A_TP_VLAN_PRI_MAP);

	/*
	 * First pass over all the ports - allocate VIs and initialize some
	 * basic parameters like mac address, port type, etc.  We also figure
	 * out whether a port is 10G or 1G and use that information when
	 * calculating how many interrupts to attempt to allocate.
	 */
	for_each_port(sc, i) {
		struct port_info *pi;

		pi = kmem_zalloc(sizeof (*pi), KM_SLEEP);
		sc->port[i] = pi;

		/* These must be set before t4_port_init */
		pi->adapter = sc;
		pi->port_id = i;
	}

	/* Allocate the vi and initialize parameters like mac addr */
	rc = -t4_port_init(sc, sc->mbox, sc->pf, 0);
	if (rc) {
		cxgb_printf(dip, CE_WARN, "unable to initialize port: %d", rc);
		goto done;
	}

	for_each_port(sc, i) {
		struct port_info *pi = sc->port[i];

		mutex_init(&pi->lock, NULL, MUTEX_DRIVER, NULL);
		pi->mtu = ETHERMTU;

		pi->tmr_idx = prp->ethq_tmr_idx;
		pi->pktc_idx = prp->ethq_pktc_idx;
		pi->dbq_timer_idx = prp->dbq_timer_idx;

		pi->xact_addr_filt = -1;
	}

	if ((rc = t4_cfg_intrs_queues(sc)) != 0) {
		goto done; /* error message displayed already */
	}

	const struct t4_intrs_queues *iaq = &sc->intr_queue_cfg;
	struct sge_info *sge = &sc->sge;
	sge->rxq =
	    kmem_zalloc(sge->rxq_count * sizeof (struct sge_rxq), KM_SLEEP);
	sge->txq =
	    kmem_zalloc(sge->txq_count * sizeof (struct sge_txq), KM_SLEEP);
	sge->iqmap =
	    kmem_zalloc(sge->iqmap_sz * sizeof (struct sge_iq *), KM_SLEEP);
	sge->eqmap =
	    kmem_zalloc(sge->eqmap_sz * sizeof (struct sge_eq *), KM_SLEEP);

	sc->intr_handle =
	    kmem_zalloc(iaq->intr_count * sizeof (ddi_intr_handle_t),
	    KM_SLEEP);

	/*
	 * Enable hw checksumming and LSO for all ports by default.
	 * They can be disabled using ndd (hw_csum and hw_lso).
	 */
	for_each_port(sc, i) {
		sc->port[i]->features |= (CXGBE_HW_CSUM | CXGBE_HW_LSO);
	}

	/* Setup Interrupts. */
	if ((rc = t4_setup_intrs(sc)) != DDI_SUCCESS) {
		goto done;
	}
	sc->flags |= TAF_INTR_ALLOC;

	if ((rc = ksensor_create_scalar_pcidev(dip, SENSOR_KIND_TEMPERATURE,
	    &t4_temp_ops, sc, "temp", &sc->temp_sensor)) != 0) {
		cxgb_printf(dip, CE_WARN, "failed to create temperature "
		    "sensor: %d", rc);
		rc = DDI_FAILURE;
		goto done;
	}

	if ((rc = ksensor_create_scalar_pcidev(dip, SENSOR_KIND_VOLTAGE,
	    &t4_volt_ops, sc, "vdd", &sc->volt_sensor)) != 0) {
		cxgb_printf(dip, CE_WARN, "failed to create voltage "
		    "sensor: %d", rc);
		rc = DDI_FAILURE;
		goto done;
	}


	if ((rc = ddi_ufm_init(dip, DDI_UFM_CURRENT_VERSION, &t4_ufm_ops,
	    &sc->ufm_hdl, sc)) != 0) {
		cxgb_printf(dip, CE_WARN, "failed to enable UFM ops: %d", rc);
		rc = DDI_FAILURE;
		goto done;
	}
	ddi_ufm_update(sc->ufm_hdl);

	if ((rc = t4_alloc_evt_iqs(sc)) != 0) {
		cxgb_printf(dip, CE_WARN, "failed to alloc FWQ: %d", rc);
		rc = DDI_FAILURE;
		goto done;
	}

	if (sc->intr_cap & DDI_INTR_FLAG_BLOCK) {
		rc = ddi_intr_block_enable(sc->intr_handle, iaq->intr_count);

		if (rc != DDI_SUCCESS) {
			cxgb_printf(dip, CE_WARN, "failed to enable intr "
			    "block: %d", rc);
			rc = DDI_FAILURE;
			goto done;
		}
	} else {
		for (i = 0; i < iaq->intr_count; i++) {
			rc = ddi_intr_enable(sc->intr_handle[i]);
			if (rc != DDI_SUCCESS) {
				cxgb_printf(dip, CE_WARN, "failed to enable "
				    "intr %d: %d", i, rc);
				rc = DDI_FAILURE;
				goto done;
			}
		}
	}
	t4_intr_enable(sc);

	/*
	 * At this point, adapter-level initialization can be considered
	 * successful.  The ports themselves will be initialized later when mac
	 * attaches/starts them via cxgbe.
	 */
	sc->flags |= TAF_INIT_DONE;
	ddi_report_dev(dip);

	/*
	 * Hardware/Firmware/etc. Version/Revision IDs.
	 */
	t4_dump_version_info(sc);

	sc->ksp = t4_setup_kstats(sc);
	sc->ksp_stat = t4_setup_wc_kstats(sc);
	sc->params.drv_memwin = MEMWIN_NIC;

done:
	if (rc != DDI_SUCCESS) {
		(void) t4_devo_detach(dip, DDI_DETACH);

		/* rc may have errno style errors or DDI errors */
		rc = DDI_FAILURE;
	}

	return (rc);
}

static int
t4_devo_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int i = 0;
	struct port_info *pi;
	struct sge_info *s;

	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	const int instance = ddi_get_instance(dip);
	struct adapter *sc = ddi_get_soft_state(t4_soft_state, instance);
	if (sc == NULL)
		return (DDI_SUCCESS);

	struct t4_intrs_queues *iaq = &sc->intr_queue_cfg;

	if (sc->flags & TAF_INIT_DONE) {
		t4_intr_disable(sc);
		for_each_port(sc, i) {
			pi = sc->port[i];
			if (pi && pi->flags & TPF_INIT_DONE)
				t4_port_full_uninit(pi);
		}

		if (sc->intr_cap & DDI_INTR_FLAG_BLOCK) {
			(void) ddi_intr_block_disable(sc->intr_handle,
			    iaq->intr_count);
		} else {
			for (i = 0; i < iaq->intr_count; i++)
				(void) ddi_intr_disable(sc->intr_handle[i]);
		}

		t4_free_evt_iqs(sc);

		sc->flags &= ~TAF_INIT_DONE;
	}

	/* Safe to call no matter what */
	if (sc->ufm_hdl != NULL) {
		ddi_ufm_fini(sc->ufm_hdl);
		sc->ufm_hdl = NULL;
	}
	(void) ksensor_remove(dip, KSENSOR_ALL_IDS);
	ddi_prop_remove_all(dip);
	ddi_remove_minor_node(dip, NULL);

	if (sc->ksp != NULL)
		kstat_delete(sc->ksp);
	if (sc->ksp_stat != NULL)
		kstat_delete(sc->ksp_stat);

	s = &sc->sge;
	if (s->rxq != NULL)
		kmem_free(s->rxq, s->rxq_count * sizeof (struct sge_rxq));
	if (s->txq != NULL)
		kmem_free(s->txq, s->txq_count * sizeof (struct sge_txq));
	if (s->iqmap != NULL)
		kmem_free(s->iqmap, s->iqmap_sz * sizeof (struct sge_iq *));
	if (s->eqmap != NULL)
		kmem_free(s->eqmap, s->eqmap_sz * sizeof (struct sge_eq *));

	if (s->rxbuf_cache != NULL)
		kmem_cache_destroy(s->rxbuf_cache);

	if (sc->flags & TAF_INTR_ALLOC) {
		for (int i = 0; i < iaq->intr_count; i++) {
			int rc = ddi_intr_remove_handler(sc->intr_handle[i]);
			if (rc != DDI_SUCCESS) {
				cxgb_printf(sc->dip, CE_WARN, "failed to "
				    "remove interrupt handler %d for type: %d "
				    "plan: %d: %d", i, iaq->intr_type,
				    iaq->intr_plan, rc);
			}

			rc = ddi_intr_free(sc->intr_handle[i]);
			if (rc != DDI_SUCCESS) {
				cxgb_printf(sc->dip, CE_WARN, "failed to free "
				    "interrupt %d for type: %d plan: %d: %d", i,
				    iaq->intr_type, iaq->intr_plan, rc);

			}
		}
		sc->flags &= ~TAF_INTR_ALLOC;
	}

	if (sc->intr_handle != NULL) {
		kmem_free(sc->intr_handle,
		    iaq->intr_count * sizeof (*sc->intr_handle));
	}

	for_each_port(sc, i) {
		pi = sc->port[i];
		if (pi != NULL) {
			if (pi->intr_iqs != NULL) {
				kmem_free(pi->intr_iqs,
				    sizeof (pi->intr_iqs[0]) *
				    sc->intr_queue_cfg.intr_per_port);
			}
			mutex_destroy(&pi->lock);
			kmem_free(pi, sizeof (*pi));
		}
	}

	if (sc->flags & FW_OK)
		(void) t4_fw_bye(sc, sc->mbox);

	if (sc->bar2_hdl != NULL) {
		ddi_regs_map_free(&sc->bar2_hdl);
		sc->bar2_hdl = NULL;
		sc->bar2_ptr = NULL;
	}

	if (sc->regh != NULL) {
		ddi_regs_map_free(&sc->regh);
		sc->regh = NULL;
		sc->regp = NULL;
	}

	if (sc->pci_regh != NULL) {
		pci_config_teardown(&sc->pci_regh);
	}

	mutex_enter(&t4_adapter_list_lock);
	list_remove(&t4_adapter_list, sc);
	mutex_exit(&t4_adapter_list_lock);

	mutex_destroy(&sc->mbox_lock);
	mutex_destroy(&sc->lock);
	cv_destroy(&sc->cv);
	mutex_destroy(&sc->sfl_lock);

#ifdef DEBUG
	bzero(sc, sizeof (*sc));
#endif
	ddi_soft_state_free(t4_soft_state, instance);

	return (DDI_SUCCESS);
}

static int
t4_devo_quiesce(dev_info_t *dip)
{
	int instance;
	struct adapter *sc;

	instance = ddi_get_instance(dip);
	sc = ddi_get_soft_state(t4_soft_state, instance);
	if (sc == NULL)
		return (DDI_SUCCESS);

	t4_set_reg_field(sc, A_SGE_CONTROL, F_GLOBALENABLE, 0);
	t4_intr_disable(sc);
	t4_write_reg(sc, A_PL_RST, F_PIORSTMODE | F_PIORST);

	return (DDI_SUCCESS);
}

static int
t4_bus_ctl(dev_info_t *dip, dev_info_t *rdip, ddi_ctl_enum_t op, void *arg,
    void *result)
{
	char s[4];
	struct port_info *pi;
	dev_info_t *child = (dev_info_t *)arg;

	switch (op) {
	case DDI_CTLOPS_REPORTDEV:
		if (rdip == NULL)
			return (DDI_FAILURE);
		cmn_err(CE_CONT, "?t4nexus: %s%d\n",
		    ddi_driver_name(rdip), ddi_get_instance(rdip));
		return (DDI_SUCCESS);

	case DDI_CTLOPS_INITCHILD:
		pi = ddi_get_parent_data(child);
		if (pi == NULL)
			return (DDI_NOT_WELL_FORMED);
		(void) snprintf(s, sizeof (s), "%d", pi->port_id);
		ddi_set_name_addr(child, s);
		return (DDI_SUCCESS);

	case DDI_CTLOPS_UNINITCHILD:
		ddi_set_name_addr(child, NULL);
		return (DDI_SUCCESS);

	case DDI_CTLOPS_ATTACH:
	case DDI_CTLOPS_DETACH:
		return (DDI_SUCCESS);

	default:
		return (ddi_ctlops(dip, rdip, op, arg, result));
	}
}

/* From a provided "cxgbe@0" string, parse the device number */
static bool
t4_parse_devnum(const char *devname, uint_t *inst_nump)
{
	const size_t name_sz = strlen(devname) + 1;
	char *name_copy = i_ddi_strdup(devname, KM_SLEEP);

	bool res = false;
	char *nodename, *addrname = NULL;
	i_ddi_parse_name(name_copy, &nodename, &addrname, NULL);
	if (addrname == NULL || strcmp(T4_PORT_NAME, nodename) != 0) {
		goto done;
	}

	ulong_t num;
	if (ddi_strtoul(addrname, NULL, 10, &num) != 0 || num > UINT_MAX) {
		goto done;
	}
	*inst_nump = (uint_t)num;
	res = true;

done:
	kmem_free(name_copy, name_sz);
	return (res);
}

static int
t4_bus_config(dev_info_t *dip, uint_t flags, ddi_bus_config_op_t op, void *arg,
    dev_info_t **cdipp)
{
	struct adapter *sc =
	    ddi_get_soft_state(t4_soft_state, ddi_get_instance(dip));

	if (op == BUS_CONFIG_ONE) {
		uint_t dev_num;

		if (!t4_parse_devnum((const char *)arg, &dev_num)) {
			return (NDI_FAILURE);
		}
		if (t4_add_child_node(sc, dev_num) != 0) {
			return (NDI_FAILURE);
		}

		flags |= NDI_ONLINE_ATTACH;

	} else if (op == BUS_CONFIG_ALL || op == BUS_CONFIG_DRIVER) {
		int i;

		/* Allocate and bind all child device nodes */
		for_each_port(sc, i) {
			(void) t4_add_child_node(sc, (uint_t)i);
		}
		flags |= NDI_ONLINE_ATTACH;
	}

	return (ndi_busop_bus_config(dip, flags, op, arg, cdipp, 0));
}

static int
t4_bus_unconfig(dev_info_t *dip, uint_t flags, ddi_bus_config_op_t op,
    void *arg)
{
	struct adapter *sc
	    = ddi_get_soft_state(t4_soft_state, ddi_get_instance(dip));

	if (op == BUS_UNCONFIG_ONE ||
	    op == BUS_UNCONFIG_ALL ||
	    op == BUS_UNCONFIG_DRIVER) {
		flags |= NDI_UNCONFIG;
	}

	int rc = ndi_busop_bus_unconfig(dip, flags, op, arg);
	if (rc != 0)
		return (rc);

	if (op == BUS_UNCONFIG_ONE) {
		uint_t dev_num;

		if (!t4_parse_devnum((const char *)arg, &dev_num)) {
			return (NDI_FAILURE);
		}

		rc = t4_remove_child_node(sc, dev_num);
	} else if (op == BUS_UNCONFIG_ALL || op == BUS_UNCONFIG_DRIVER) {
		uint_t i;

		for_each_port(sc, i) {
			(void) t4_remove_child_node(sc, i);
		}
	}

	return (rc);
}

static int
t4_cb_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	struct adapter *sc;

	if (otyp != OTYP_CHR) {
		return (EINVAL);
	}

	sc = ddi_get_soft_state(t4_soft_state, getminor(*devp));
	if (sc == NULL) {
		return (ENXIO);
	}

	return (atomic_cas_uint(&sc->open, 0, EBUSY));
}

static int
t4_cb_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	struct adapter *sc = ddi_get_soft_state(t4_soft_state, getminor(dev));

	if (sc == NULL) {
		return (EINVAL);
	}

	(void) atomic_swap_uint(&sc->open, 0);
	return (0);
}

static int
t4_cb_ioctl(dev_t dev, int cmd, intptr_t d, int mode, cred_t *credp, int *rp)
{
	if (crgetuid(credp) != 0) {
		return (EPERM);
	}

	struct adapter *sc = ddi_get_soft_state(t4_soft_state, getminor(dev));

	if (sc == NULL) {
		return (EINVAL);
	}

	return (t4_ioctl(sc, cmd, (void *)d, mode));
}

static uint_t
t4_getpf(struct adapter *sc)
{
	int *data;
	uint_t n;

	const int rc = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, sc->dip,
	    DDI_PROP_DONTPASS, "reg", &data, &n);
	if (rc != DDI_SUCCESS) {
		return (UINT_MAX);
	}

	const uint_t pf = PCI_REG_FUNC_G(data[0]);
	ddi_prop_free(data);

	return (pf);
}

/*
 * Install a compatible firmware (if required), establish contact with it,
 * become the master, and reset the device.
 */
static int
t4_prep_firmware(struct adapter *sc)
{
	int rc;

	/* Contact firmware, request master */
	enum dev_state state;
	rc = t4_fw_hello(sc, sc->mbox, sc->mbox, MASTER_MUST, &state);
	if (rc < 0) {
		rc = -rc;
		cxgb_printf(sc->dip, CE_WARN,
		    "failed to connect to the firmware: %d.", rc);
		return (rc);
	}

	if (rc == sc->mbox)
		sc->flags |= TAF_MASTER_PF;

	/* We may need FW version info for later reporting */
	(void) t4_get_version_info(sc);

	const char *fw_file = NULL;
	switch (CHELSIO_CHIP_VERSION(sc->params.chip)) {
	case CHELSIO_T4:
		fw_file = "t4fw.bin";
		break;
	case CHELSIO_T5:
		fw_file = "t5fw.bin";
		break;
	case CHELSIO_T6:
		fw_file = "t6fw.bin";
		break;
	default:
		cxgb_printf(sc->dip, CE_WARN, "Adapter type not supported\n");
		return (EINVAL);
	}

	firmware_handle_t fw_hdl;
	if (firmware_open(T4_PORT_NAME, fw_file, &fw_hdl) != 0) {
		cxgb_printf(sc->dip, CE_WARN, "Could not open %s\n", fw_file);
		return (EINVAL);
	}

	const size_t fw_size = firmware_get_size(fw_hdl);
	if (fw_size < sizeof (struct fw_hdr)) {
		cxgb_printf(sc->dip, CE_WARN, "%s is too small (%lu bytes)\n",
		    fw_file, fw_size);
		(void) firmware_close(fw_hdl);
		return (EINVAL);
	}
	if (fw_size > FLASH_FW_MAX_SIZE) {
		cxgb_printf(sc->dip, CE_WARN,
		    "%s is too large (%lu bytes, max allowed is %lu)\n",
		    fw_file, fw_size, FLASH_FW_MAX_SIZE);
		(void) firmware_close(fw_hdl);
		return (EFBIG);
	}

	unsigned char *fw_data = kmem_zalloc(fw_size, KM_SLEEP);
	if (firmware_read(fw_hdl, 0, fw_data, fw_size) != 0) {
		cxgb_printf(sc->dip, CE_WARN, "Failed to read from %s\n",
		    fw_file);
		(void) firmware_close(fw_hdl);
		kmem_free(fw_data, fw_size);
		return (EINVAL);
	}
	(void) firmware_close(fw_hdl);

	const struct fw_hdr *hdr = (struct fw_hdr *)fw_data;
	struct fw_info fi;
	bzero(&fi, sizeof (fi));
	fi.chip				= CHELSIO_CHIP_VERSION(sc->params.chip);
	fi.fw_hdr.fw_ver		= hdr->fw_ver;
	fi.fw_hdr.chip			= hdr->chip;
	fi.fw_hdr.intfver_nic		= hdr->intfver_nic;
	fi.fw_hdr.intfver_vnic		= hdr->intfver_vnic;
	fi.fw_hdr.intfver_ofld		= hdr->intfver_ofld;
	fi.fw_hdr.intfver_ri		= hdr->intfver_ri;
	fi.fw_hdr.intfver_iscsipdu	= hdr->intfver_iscsipdu;
	fi.fw_hdr.intfver_iscsi		= hdr->intfver_iscsi;
	fi.fw_hdr.intfver_fcoepdu	= hdr->intfver_fcoepdu;
	fi.fw_hdr.intfver_fcoe		= hdr->intfver_fcoe;

	/* allocate memory to read the header of the firmware on the card */
	struct fw_hdr *card_fw = kmem_zalloc(sizeof (struct fw_hdr), KM_SLEEP);

	int reset = 1;
	rc = -t4_prep_fw(sc, &fi, fw_data, fw_size, card_fw,
	    sc->props.t4_fw_install, state, &reset);

	kmem_free(card_fw, sizeof (*card_fw));
	kmem_free(fw_data, fw_size);

	if (rc != 0) {
		cxgb_printf(sc->dip, CE_WARN,
		    "failed to install firmware: %d", rc);
		return (rc);
	} else {
		/* refresh */
		(void) t4_check_fw_version(sc);
	}

	/* Reset device */
	rc = -t4_fw_reset(sc, sc->mbox, F_PIORSTMODE | F_PIORST);
	if (rc != 0) {
		cxgb_printf(sc->dip, CE_WARN,
		    "firmware reset failed: %d.", rc);
		if (rc != ETIMEDOUT && rc != EIO)
			(void) t4_fw_bye(sc, sc->mbox);
		return (rc);
	}

	/* Partition adapter resources as specified in the config file. */
	if (sc->flags & TAF_MASTER_PF) {
		/* Handle default vs special T4 config file */

		rc = t4_partition_resources(sc);
		if (rc != 0) {
			return (rc);
		}
	}

	sc->flags |= FW_OK;
	return (0);
}

struct memwin {
	uint32_t base;
	uint32_t aperture;
};

static const struct memwin t4_memwin[] = {
	{ MEMWIN0_BASE, MEMWIN0_APERTURE },
	{ MEMWIN1_BASE, MEMWIN1_APERTURE },
	{ MEMWIN2_BASE, MEMWIN2_APERTURE }
};

static const struct memwin t5_memwin[] = {
	{ MEMWIN0_BASE, MEMWIN0_APERTURE },
	{ MEMWIN1_BASE, MEMWIN1_APERTURE },
	{ MEMWIN2_BASE_T5, MEMWIN2_APERTURE_T5 },
};

#define	FW_PARAM_DEV(param) \
	(V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DEV) | \
	    V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DEV_##param))
#define	FW_PARAM_PFVF(param) \
	(V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_PFVF) | \
	    V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_PFVF_##param))

/*
 * Verify that the memory range specified by the memtype/offset/len pair is
 * valid and lies entirely within the memtype specified.  The global address of
 * the start of the range is returned in addr.
 */
static int
t4_validate_mt_off_len(struct adapter *sc, int mtype, uint32_t off, int len,
    uint32_t *addr)
{
	uint32_t em, addr_len, maddr, mlen;

	/* Memory can only be accessed in naturally aligned 4 byte units */
	if (off & 3 || len & 3 || len == 0)
		return (EINVAL);

	em = t4_read_reg(sc, A_MA_TARGET_MEM_ENABLE);
	switch (mtype) {
		case MEM_EDC0:
			if (!(em & F_EDRAM0_ENABLE))
				return (EINVAL);
			addr_len = t4_read_reg(sc, A_MA_EDRAM0_BAR);
			maddr = G_EDRAM0_BASE(addr_len) << 20;
			mlen = G_EDRAM0_SIZE(addr_len) << 20;
			break;
		case MEM_EDC1:
			if (!(em & F_EDRAM1_ENABLE))
				return (EINVAL);
			addr_len = t4_read_reg(sc, A_MA_EDRAM1_BAR);
			maddr = G_EDRAM1_BASE(addr_len) << 20;
			mlen = G_EDRAM1_SIZE(addr_len) << 20;
			break;
		case MEM_MC:
			if (!(em & F_EXT_MEM_ENABLE))
				return (EINVAL);
			addr_len = t4_read_reg(sc, A_MA_EXT_MEMORY_BAR);
			maddr = G_EXT_MEM_BASE(addr_len) << 20;
			mlen = G_EXT_MEM_SIZE(addr_len) << 20;
			break;
		case MEM_MC1:
			if (t4_cver_eq(sc, CHELSIO_T4) ||
			    !(em & F_EXT_MEM1_ENABLE)) {
				return (EINVAL);
			}
			addr_len = t4_read_reg(sc, A_MA_EXT_MEMORY1_BAR);
			maddr = G_EXT_MEM1_BASE(addr_len) << 20;
			mlen = G_EXT_MEM1_SIZE(addr_len) << 20;
			break;
		default:
			return (EINVAL);
	}

	if (mlen > 0 && off < mlen && off + len <= mlen) {
		*addr = maddr + off;    /* global address */
		return (0);
	}

	return (EFAULT);
}

static void
t4_memwin_info(struct adapter *sc, int win, uint32_t *base, uint32_t *aperture)
{
	const struct memwin *mw;

	if (t4_cver_eq(sc, CHELSIO_T4)) {
		mw = &t4_memwin[win];
	} else {
		mw = &t5_memwin[win];
	}

	if (base != NULL)
		*base = mw->base;
	if (aperture != NULL)
		*aperture = mw->aperture;
}

/*
 * Upload configuration file to card's memory.
 */
static int
t4_upload_config_file(struct adapter *sc, uint32_t *mt, uint32_t *ma)
{
	int rc = 0;
	size_t cflen, cfbaselen;
	uint_t i, n;
	uint32_t param, val, addr, mtype, maddr;
	uint32_t off, mw_base, mw_aperture;
	uint32_t *cfdata, *cfbase;
	firmware_handle_t fw_hdl;
	const char *cfg_file = NULL;

	/* Figure out where the firmware wants us to upload it. */
	param = FW_PARAM_DEV(CF);
	rc = -t4_query_params(sc, sc->mbox, sc->pf, 0, 1, &param, &val);
	if (rc != 0) {
		/* Firmwares without config file support will fail this way */
		cxgb_printf(sc->dip, CE_WARN,
		    "failed to query config file location: %d.\n", rc);
		return (rc);
	}
	*mt = mtype = G_FW_PARAMS_PARAM_Y(val);
	*ma = maddr = G_FW_PARAMS_PARAM_Z(val) << 16;

	switch (CHELSIO_CHIP_VERSION(sc->params.chip)) {
	case CHELSIO_T4:
		cfg_file = "t4fw_cfg.txt";
		break;
	case CHELSIO_T5:
		cfg_file = "t5fw_cfg.txt";
		break;
	case CHELSIO_T6:
		cfg_file = "t6fw_cfg.txt";
		break;
	default:
		cxgb_printf(sc->dip, CE_WARN, "Invalid Adapter detected\n");
		return (EINVAL);
	}

	if (firmware_open(T4_PORT_NAME, cfg_file, &fw_hdl) != 0) {
		cxgb_printf(sc->dip, CE_WARN, "Could not open %s\n", cfg_file);
		return (EINVAL);
	}

	cflen = firmware_get_size(fw_hdl);
	/*
	 * Truncate the length to a multiple of uint32_ts. The configuration
	 * text files have trailing comments (and hopefully always will) so
	 * nothing important is lost.
	 */
	cflen &= ~3;

	if (cflen > FLASH_CFG_MAX_SIZE) {
		cxgb_printf(sc->dip, CE_WARN,
		    "config file too long (%d, max allowed is %d).  ",
		    cflen, FLASH_CFG_MAX_SIZE);
		(void) firmware_close(fw_hdl);
		return (EFBIG);
	}

	rc = t4_validate_mt_off_len(sc, mtype, maddr, cflen, &addr);
	if (rc != 0) {
		cxgb_printf(sc->dip, CE_WARN,
		    "%s: addr (%d/0x%x) or len %d is not valid: %d.  "
		    "Will try to use the config on the card, if any.\n",
		    __func__, mtype, maddr, cflen, rc);
		(void) firmware_close(fw_hdl);
		return (EFAULT);
	}

	cfbaselen = cflen;
	cfbase = cfdata = kmem_zalloc(cflen, KM_SLEEP);
	if (firmware_read(fw_hdl, 0, cfdata, cflen) != 0) {
		cxgb_printf(sc->dip, CE_WARN, "Failed to read from %s\n",
		    cfg_file);
		(void) firmware_close(fw_hdl);
		kmem_free(cfbase, cfbaselen);
		return (EINVAL);
	}
	(void) firmware_close(fw_hdl);

	t4_memwin_info(sc, 2, &mw_base, &mw_aperture);
	while (cflen) {
		off = t4_position_memwin(sc, 2, addr);
		n = min(cflen, mw_aperture - off);
		for (i = 0; i < n; i += 4)
			t4_write_reg(sc, mw_base + off + i, *cfdata++);
		cflen -= n;
		addr += n;
	}

	kmem_free(cfbase, cfbaselen);

	return (rc);
}

/*
 * Partition chip resources for use between various PFs, VFs, etc.  This is done
 * by uploading the firmware configuration file to the adapter and instructing
 * the firmware to process it.
 */
static int
t4_partition_resources(struct adapter *sc)
{
	int rc;
	uint32_t mtype, maddr;

	rc = t4_upload_config_file(sc, &mtype, &maddr);
	if (rc != 0) {
		mtype = FW_MEMTYPE_CF_FLASH;
		maddr = t4_flash_cfg_addr(sc);
	}

	struct fw_caps_config_cmd caps;
	bzero(&caps, sizeof (caps));
	caps.op_to_write = BE_32(V_FW_CMD_OP(FW_CAPS_CONFIG_CMD) |
	    F_FW_CMD_REQUEST | F_FW_CMD_READ);
	caps.cfvalid_to_len16 = BE_32(F_FW_CAPS_CONFIG_CMD_CFVALID |
	    V_FW_CAPS_CONFIG_CMD_MEMTYPE_CF(mtype) |
	    V_FW_CAPS_CONFIG_CMD_MEMADDR64K_CF(maddr >> 16) |
	    FW_LEN16(struct fw_caps_config_cmd));

	rc = -t4_wr_mbox(sc, sc->mbox, &caps, sizeof (caps), &caps);
	if (rc != 0) {
		cxgb_printf(sc->dip, CE_WARN,
		    "failed to pre-process config file: %d.\n", rc);
		return (rc);
	}

	if (caps.finicsum != caps.cfcsum) {
		cxgb_printf(sc->dip, CE_WARN,
		    "WARNING: config file checksum mismatch: %08x %08x\n",
		    caps.finicsum, caps.cfcsum);
	}
	sc->cfcsum = caps.cfcsum;

	/* Disable unused offloads and features */
	caps.toecaps = 0;
	caps.iscsicaps = 0;
	caps.rdmacaps = 0;
	caps.fcoecaps = 0;
	caps.cryptocaps = 0;

	/* TODO: Disable VNIC cap for now */
	caps.niccaps &= BE_16(~FW_CAPS_CONFIG_NIC_VM);

	caps.op_to_write = BE_32(V_FW_CMD_OP(FW_CAPS_CONFIG_CMD) |
	    F_FW_CMD_REQUEST | F_FW_CMD_WRITE);
	caps.cfvalid_to_len16 = BE_32(FW_LEN16(caps));
	rc = -t4_wr_mbox(sc, sc->mbox, &caps, sizeof (caps), NULL);
	if (rc != 0) {
		cxgb_printf(sc->dip, CE_WARN,
		    "failed to process config file: %d.\n", rc);
		return (rc);
	}

	return (0);
}

/*
 * Tweak configuration based on module parameters, etc.  Most of these have
 * defaults assigned to them by Firmware Configuration Files (if we're using
 * them) but need to be explicitly set if we're using hard-coded
 * initialization.  But even in the case of using Firmware Configuration
 * Files, we'd like to expose the ability to change these via module
 * parameters so these are essentially common tweaks/settings for
 * Configuration Files and hard-coded initialization ...
 */
static int
t4_init_adap_tweaks(struct adapter *sc)
{
	int rx_dma_offset = 2; /* Offset of RX packets into DMA buffers */

	/*
	 * Fix up various Host-Dependent Parameters like Page Size, Cache
	 * Line Size, etc.  The firmware default is for a 4KB Page Size and
	 * 64B Cache Line Size ...
	 */
	(void) t4_fixup_host_params_compat(sc, PAGE_SIZE, _CACHE_LINE_SIZE,
	    T5_LAST_REV);

	t4_set_reg_field(sc, A_SGE_CONTROL, V_PKTSHIFT(M_PKTSHIFT),
	    V_PKTSHIFT(rx_dma_offset));

	return (0);
}
/*
 * Retrieve parameters that are needed (or nice to have) prior to calling
 * t4_sge_init and t4_fw_initialize.
 */
static int
t4_init_get_params_pre(struct adapter *sc)
{
	int rc;
	uint32_t param[2], val[2];

	/*
	 * Grab the raw VPD parameters.
	 */
	rc = -t4_get_raw_vpd_params(sc, &sc->params.vpd);
	if (rc != 0) {
		cxgb_printf(sc->dip, CE_WARN,
		    "failed to query VPD parameters (pre_init): %d.\n", rc);
		return (rc);
	}

	param[0] = FW_PARAM_DEV(PORTVEC);
	param[1] = FW_PARAM_DEV(CCLK);
	rc = -t4_query_params(sc, sc->mbox, sc->pf, 0, 2, param, val);
	if (rc != 0) {
		cxgb_printf(sc->dip, CE_WARN,
		    "failed to query parameters (pre_init): %d.\n", rc);
		return (rc);
	}

	if (val[0] == 0) {
		cxgb_printf(sc->dip, CE_WARN, "no usable ports");
		return (ENODEV);
	}

	sc->params.portvec = val[0];
	sc->params.nports = 0;
	while (val[0]) {
		sc->params.nports++;
		val[0] &= val[0] - 1;
	}
	sc->params.vpd.cclk = val[1];

	/* Read device log parameters. */
	struct fw_devlog_cmd cmd;
	bzero(&cmd, sizeof (cmd));
	cmd.op_to_write = BE_32(V_FW_CMD_OP(FW_DEVLOG_CMD) |
	    F_FW_CMD_REQUEST | F_FW_CMD_READ);
	cmd.retval_len16 = BE_32(FW_LEN16(struct fw_devlog_cmd));

	rc = -t4_wr_mbox(sc, sc->mbox, &cmd, sizeof (cmd), &cmd);
	if (rc != 0) {
		cxgb_printf(sc->dip, CE_WARN,
		    "failed to get devlog parameters: %d.\n", rc);

		/* devlog isn't critical for device operation */
		bzero(&sc->params.devlog, sizeof (sc->params.devlog));
		rc = 0;
	} else {
		const uint32_t info =
		    BE_32(cmd.memtype_devlog_memaddr16_devlog);
		struct devlog_params *dlog = &sc->params.devlog;

		dlog->memtype = G_FW_DEVLOG_CMD_MEMTYPE_DEVLOG(info);
		dlog->start = G_FW_DEVLOG_CMD_MEMADDR16_DEVLOG(info) << 4;
		dlog->size = BE_32(cmd.memsize_devlog);
	}

	return (rc);
}

/*
 * Retrieve various parameters that are of interest to the driver.  The device
 * has been initialized by the firmware at this point.
 */
static int
t4_init_get_params_post(struct adapter *sc)
{
	int rc;
	uint32_t param[4], val[4];

	param[0] = FW_PARAM_PFVF(IQFLINT_START);
	param[1] = FW_PARAM_PFVF(EQ_START);
	param[2] = FW_PARAM_PFVF(IQFLINT_END);
	param[3] = FW_PARAM_PFVF(EQ_END);
	rc = -t4_query_params(sc, sc->mbox, sc->pf, 0, 4, param, val);
	if (rc != 0) {
		cxgb_printf(sc->dip, CE_WARN,
		    "failed to query parameters (post_init): %d.\n", rc);
		return (rc);
	}

	sc->sge.iqmap_start = val[0];
	sc->sge.eqmap_start = val[1];
	sc->sge.iqmap_sz = (val[2] - sc->sge.iqmap_start) + 1;
	sc->sge.eqmap_sz = (val[3] - sc->sge.eqmap_start) + 1;

	/* Check if DBQ timer is available for tracking egress completions */
	param[0] = (V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DEV) |
	    V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DEV_DBQ_TIMERTICK));
	rc = t4_query_params(sc, sc->mbox, sc->pf, 0, 1, param, val);
	if (rc == 0) {
		sc->sge.dbq_timer_tick = val[0];
		rc = t4_read_sge_dbqtimers(sc,
		    ARRAY_SIZE(sc->sge.dbq_timers), sc->sge.dbq_timers);
		if (rc == 0) {
			sc->flags |= TAF_DBQ_TIMER;

			/*
			 * Expose DBQ timer values as property, converting them
			 * to plain `int` as required.
			 */
			int tmp_encode[ARRAY_SIZE(sc->sge.dbq_timers)];
			for (uint_t i = 0; i < ARRAY_SIZE(sc->sge.dbq_timers);
			    i++) {
				tmp_encode[i] = sc->sge.dbq_timers[i];
			};
			(void) ddi_prop_update_int_array(sc->dev, sc->dip,
			    "tx-reclaim-timer-us-values",
			    tmp_encode, SGE_NTIMERS);
		} else {
			sc->sge.dbq_timer_tick = 0;
		}
	}

	/*
	 * Now that we know if the DBQ timer is present, tune the properties for
	 * hold-off parameter defaults.
	 */
	struct driver_properties *prp = &sc->props;
	if ((sc->flags & TAF_DBQ_TIMER) != 0) {
		/*
		 * Choose default DBQ timer index to be closest to 100us.  With
		 * that available, more aggressive coalescing on the FWQ is
		 * unnecessary, so shorter hold-off parameters are fine there.
		 */
		prp->dbq_timer_idx = t4_choose_dbq_timer(sc, 100);
		prp->fwq_tmr_idx = t4_choose_holdoff_timer(sc, 10);
		prp->fwq_pktc_idx = t4_choose_holdoff_pktcnt(sc, -1);
	} else {
		/*
		 * Without the DBQ timer, we fall back to the
		 * CIDXFlushThresholdOverride mechanism for TX completions,
		 * which can result in many more notifications, depending on the
		 * traffic pattern.  More aggressive interrupt coalescing on the
		 * firmware queue (where such notifications land) is recommended
		 * to deal with it.
		 *
		 * Pick values closest to a hold-off of 100us and/or 32 entries.
		 */
		prp->fwq_tmr_idx = t4_choose_holdoff_timer(sc, 100);
		prp->fwq_pktc_idx = t4_choose_holdoff_pktcnt(sc, 32);
	}
	sc->sge.fwq_tmr_idx = prp->fwq_tmr_idx;
	sc->sge.fwq_pktc_idx = prp->fwq_pktc_idx;

	rc = -t4_get_pfres(sc);
	if (rc != 0) {
		cxgb_printf(sc->dip, CE_WARN,
		    "failed to query PF resource params: %d.\n", rc);
		return (rc);
	}

	/* These are finalized by FW initialization, load their values now */
	val[0] = t4_read_reg(sc, A_TP_TIMER_RESOLUTION);
	sc->params.tp.tre = G_TIMERRESOLUTION(val[0]);
	sc->params.tp.dack_re = G_DELAYEDACKRESOLUTION(val[0]);
	t4_read_mtu_tbl(sc, sc->params.mtus, NULL);
	(void) t4_init_sge_params(sc);

	return (0);
}

static int
t4_init_set_params(struct adapter *sc)
{
	uint32_t param, val;

	/* ask for encapsulated CPLs */
	param = FW_PARAM_PFVF(CPLFW4MSG_ENCAP);
	val = 1;
	(void) t4_set_params(sc, sc->mbox, sc->pf, 0, 1, &param, &val);

	return (0);
}

/* TODO: verify */
static void
t4_setup_adapter_memwin(struct adapter *sc)
{
	pci_regspec_t *data;
	int rc;
	uint_t n;
	uintptr_t bar0;
	uintptr_t mem_win0_base, mem_win1_base, mem_win2_base;
	uintptr_t mem_win2_aperture;

	rc = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, sc->dip,
	    DDI_PROP_DONTPASS, "assigned-addresses", (int **)&data, &n);
	if (rc != DDI_SUCCESS) {
		cxgb_printf(sc->dip, CE_WARN,
		    "failed to lookup \"assigned-addresses\" property: %d", rc);
		return;
	}
	n /= sizeof (*data);

	bar0 = ((uint64_t)data[0].pci_phys_mid << 32) | data[0].pci_phys_low;
	ddi_prop_free(data);

	if (t4_cver_eq(sc, CHELSIO_T4)) {
		mem_win0_base = bar0 + MEMWIN0_BASE;
		mem_win1_base = bar0 + MEMWIN1_BASE;
		mem_win2_base = bar0 + MEMWIN2_BASE;
		mem_win2_aperture = MEMWIN2_APERTURE;
	} else {
		/* For T5, only relative offset inside the PCIe BAR is passed */
		mem_win0_base = MEMWIN0_BASE;
		mem_win1_base = MEMWIN1_BASE;
		mem_win2_base = MEMWIN2_BASE_T5;
		mem_win2_aperture = MEMWIN2_APERTURE_T5;
	}

	t4_write_reg(sc, PCIE_MEM_ACCESS_REG(A_PCIE_MEM_ACCESS_BASE_WIN, 0),
	    mem_win0_base | V_BIR(0) |
	    V_WINDOW(ilog2(MEMWIN0_APERTURE) - 10));

	t4_write_reg(sc, PCIE_MEM_ACCESS_REG(A_PCIE_MEM_ACCESS_BASE_WIN, 1),
	    mem_win1_base | V_BIR(0) |
	    V_WINDOW(ilog2(MEMWIN1_APERTURE) - 10));

	t4_write_reg(sc, PCIE_MEM_ACCESS_REG(A_PCIE_MEM_ACCESS_BASE_WIN, 2),
	    mem_win2_base | V_BIR(0) |
	    V_WINDOW(ilog2(mem_win2_aperture) - 10));

	/* flush */
	(void) t4_read_reg(sc,
	    PCIE_MEM_ACCESS_REG(A_PCIE_MEM_ACCESS_BASE_WIN, 2));
}

/*
 * Positions the memory window such that it can be used to access the specified
 * address in the chip's address space.  The return value is the offset of addr
 * from the start of the window.
 */
static uint32_t
t4_position_memwin(struct adapter *sc, int n, uint32_t addr)
{
	uint32_t start, pf;
	uint32_t reg;

	if (addr & 3) {
		cxgb_printf(sc->dip, CE_WARN,
		    "addr (0x%x) is not at a 4B boundary.\n", addr);
		return (EFAULT);
	}

	if (t4_cver_eq(sc, CHELSIO_T4)) {
		pf = 0;
		start = addr & ~0xf;    /* start must be 16B aligned */
	} else {
		pf = V_PFNUM(sc->pf);
		start = addr & ~0x7f;   /* start must be 128B aligned */
	}
	reg = PCIE_MEM_ACCESS_REG(A_PCIE_MEM_ACCESS_OFFSET, n);

	t4_write_reg(sc, reg, start | pf);
	(void) t4_read_reg(sc, reg);

	return (addr - start);
}

static int
prop_lookup_int(struct adapter *sc, char *name, int defval)
{
	int rc;

	rc = ddi_prop_get_int(sc->dev, sc->dip, DDI_PROP_DONTPASS, name, -1);
	if (rc != -1)
		return (rc);

	return (ddi_prop_get_int(DDI_DEV_T_ANY, sc->dip, DDI_PROP_DONTPASS,
	    name, defval));
}

static bool
prop_lookup_bool(struct adapter *sc, char *name, bool defval)
{
	int rc;

	rc = ddi_prop_get_int(sc->dev, sc->dip, DDI_PROP_DONTPASS, name, -1);
	if (rc == -1) {
		rc = ddi_prop_get_int(DDI_DEV_T_ANY, sc->dip, DDI_PROP_DONTPASS,
		    name, -1);
	}

	if (rc != -1) {
		return (rc != 0);
	} else {
		return (defval);
	}
}

const uint_t t4_holdoff_timer_default[SGE_NTIMERS] = {5, 10, 20, 50, 100, 200};
const uint_t t4_holdoff_pktcnt_default[SGE_NCOUNTERS] = {1, 8, 16, 32};

static void
t4_init_driver_props(struct adapter *sc)
{
	struct driver_properties *p = &sc->props;
	dev_t dev = sc->dev;
	dev_info_t *dip = sc->dip;
	int val;

	/*
	 * For now, just use the defaults for the hold-off timers and counters.
	 *
	 * They can be turned back into writable properties if/when there is a
	 * demonstrable need.
	 */
	for (uint_t i = 0; i < SGE_NTIMERS; i++) {
		p->holdoff_timer_us[i] = t4_holdoff_timer_default[i];
	}
	for (uint_t i = 0; i < SGE_NCOUNTERS; i++) {
		p->holdoff_pktcnt[i] = t4_holdoff_pktcnt_default[i];
	}
	(void) ddi_prop_update_int_array(dev, dip, "holdoff-timer-us-values",
	    (int *)p->holdoff_timer_us, SGE_NTIMERS);
	(void) ddi_prop_update_int_array(dev, dip, "holdoff-pkt-counter-values",
	    (int *)p->holdoff_pktcnt, SGE_NCOUNTERS);

	p->ethq_tmr_idx = prop_lookup_int(sc, "holdoff-timer-idx", 0);
	p->ethq_pktc_idx = prop_lookup_int(sc, "holdoff-pktc-idx", 2);

	(void) ddi_prop_update_int(dev, dip, "holdoff-timer-idx",
	    p->ethq_tmr_idx);
	(void) ddi_prop_update_int(dev, dip, "holdoff-pktc-idx",
	    p->ethq_pktc_idx);

	/* The size (number of host credits) of the tx queue. */
	val = prop_lookup_int(sc, "qsize-txq", T4_TX_DEF_QSIZE);
	p->qsize_txq = MAX(val, 128);
	p->qsize_txq = MIN(p->qsize_txq, T4_MAX_EQ_SIZE);
	if (p->qsize_txq != val) {
		cxgb_printf(dip, CE_WARN,
		    "using %d instead of %d as the tx queue size",
		    p->qsize_txq, val);
	}
	(void) ddi_prop_update_int(dev, dip, "qsize-txq", p->qsize_txq);

	/*
	 * The size (number of entries/host credits) of the rx queue. The device
	 * requires that all IQs be sized to a multiple of 16.
	 */
	val = prop_lookup_int(sc, "qsize-rxq", T4_RX_DEF_QSIZE);
	p->qsize_rxq = MAX(val, 128) & ~15;
	p->qsize_rxq = MIN(p->qsize_rxq, SGE_MAX_IQ_SIZE);
	if (p->qsize_rxq != val) {
		cxgb_printf(dip, CE_WARN,
		    "using %u instead of %d as the rx queue size",
		    p->qsize_rxq, val);
	}
	(void) ddi_prop_update_int(dev, dip, "qsize-rxq", p->qsize_rxq);

	p->write_combine = prop_lookup_bool(sc, "write-combine", true);
	(void) ddi_prop_update_int(dev, dip, "write-combine",
	    p->write_combine ? 1 : 0);

	p->t4_fw_install = prop_lookup_int(sc, "t4_fw_install", 1);
	if (p->t4_fw_install != 0 && p->t4_fw_install != 2)
		p->t4_fw_install = 1;
	(void) ddi_prop_update_int(dev, dip, "t4_fw_install", p->t4_fw_install);
}

/*
 * Permit artificial clamping of interrupts for device.
 * Provided mainly for development and testing purposes.
 */
static int t4_intr_count_clamp = 0;

/*
 * Queue counts to allocate per-port based on device speed.
 *
 * These have been picked somewhat arbitrarily, and should be further
 * scrutinized with additional testing.
 */
#define	T4_QCNT(speed, num)	[speed] = { speed, num, num }
static const struct t4_queue_count {
	t4_port_speed_t tqc_speed;
	uint_t		tqc_rxq_count;
	uint_t		tqc_txq_count;
} t4_queue_counts[] = {
	T4_QCNT(TPS_1G, 2),
	T4_QCNT(TPS_10G, 8),
	T4_QCNT(TPS_25G, 16),
	T4_QCNT(TPS_40G, 24),
	T4_QCNT(TPS_50G, 24),
	T4_QCNT(TPS_100G, 32),
	T4_QCNT(TPS_200G, 48),
	T4_QCNT(TPS_400G, 64),
};

static int
t4_cfg_intrs_queues(struct adapter *sc)
{
	struct t4_intrs_queues *iaq = &sc->intr_queue_cfg;
	int rc;

	bzero(iaq, sizeof (*iaq));

	int supported_itypes;
	rc = ddi_intr_get_supported_types(sc->dip, &supported_itypes);
	if (rc != DDI_SUCCESS) {
		cxgb_printf(sc->dip, CE_WARN,
		    "failed to determine supported interrupt types: %d", rc);
		return (rc);
	}

	const int intr_types[] = {
		DDI_INTR_TYPE_MSIX, DDI_INTR_TYPE_MSI, DDI_INTR_TYPE_FIXED,
	};
	const char *intr_str[] = { "MSI-X", "MSI", "Fixed" };
	int itype = -1;

	for (uint_t i = 0; i < ARRAY_SIZE(intr_types); i++) {
		itype = intr_types[i];
		if ((itype & supported_itypes) == 0) {
			continue;
		}

		rc = ddi_intr_get_navail(sc->dip, itype, &iaq->intr_avail);
		if (rc != DDI_SUCCESS || iaq->intr_avail < 0) {
			cxgb_printf(sc->dip, CE_WARN, "failed to query "
			    "available interrupts for type %s: %d", intr_str[i],
			    rc);
			continue;
		}

		/*
		 * The device error and FWQ interrupts are hard-coded to indexes
		 * 0 and 1, respectively.  We require at least two interrupts be
		 * available for MSI(-X) in order to cover both of those cases.
		 */
		if (iaq->intr_avail >= 2 ||
		    (iaq->intr_avail == 1 && itype == DDI_INTR_TYPE_FIXED)) {
			break;
		}
	}

	if (iaq->intr_avail == 0) {
		cxgb_printf(sc->dip, CE_WARN, "failed to get any interrupts "
		    "after querying all types");
		return (rc);
	}

	ASSERT3S(iaq->intr_avail, >, 0);
	iaq->intr_type = itype;
	iaq->intr_count = iaq->intr_avail;

	/* Permit artificial clamping of consumed interrupts. */
	if (t4_intr_count_clamp > 1) {
		iaq->intr_count = MIN(iaq->intr_avail, t4_intr_count_clamp);
	}

	const uint_t port_count = sc->params.nports;

	iaq->intr_per_port = 0;
	/* One IQ for the FWQ */
	iaq->num_iqs = 1;

	if (iaq->intr_count == 1) {
		iaq->intr_plan = TIP_SINGLE;
	} else if (iaq->intr_count == 2 || iaq->intr_count < (port_count + 2)) {
		iaq->intr_plan = TIP_ERR_QUEUES;
	} else {
		/*
		 * We know the interrupt count is at least equal to
		 * port_count+2, and thus we should always have at least
		 * one event interrupt per port.
		 */
		VERIFY(iaq->intr_count >= (port_count + 2));
		iaq->intr_plan = TIP_PER_PORT;
		iaq->intr_per_port = (iaq->intr_count - 2) / port_count;
		VERIFY3U(iaq->intr_per_port, >, 0);
		iaq->num_iqs += iaq->intr_per_port * port_count;
	}

	const struct pf_resources *pfres = &sc->params.pfres;
	if (pfres->niqflint <= 1) {
		/* We cannot achieve much with a single IQ */
		cxgb_printf(sc->dip, CE_WARN,
		    "inadequate IQ resources available");
		return (DDI_FAILURE);
	}

	const uint_t port_iqs = pfres->niqflint - iaq->num_iqs;
	/*
	 * Every RX queue needs an IQ capable of interrupts (for the receive
	 * notifications) as well as an EQ (for posting the freelist entries to
	 * the device.  Half of the total EQs are left for TXQs.
	 */
	const uint_t max_rxq = MIN(port_iqs, pfres->neq / 2);

	/* Every TX queue needs an ethernet-capable EQ. */
	const uint_t max_txq = MIN(pfres->nethctrl, pfres->neq / 2);

	if ((max_rxq / port_count) == 0) {
		cxgb_printf(sc->dip, CE_WARN,
		    "inadequate RX queue resources available");
		return (DDI_FAILURE);
	} else if ((max_txq / port_count) == 0) {
		cxgb_printf(sc->dip, CE_WARN,
		    "inadequate TX queue resources available");
		return (DDI_FAILURE);
	}

	/* Clamp max queue counts to number of CPUs */
	iaq->port_max_rxq = MIN(max_rxq, ncpus);
	iaq->port_max_txq = MIN(max_txq, ncpus);

	VERIFY(iaq->intr_count > 0);
	VERIFY(iaq->port_max_rxq != 0);
	VERIFY(iaq->port_max_txq != 0);
	VERIFY(iaq->num_iqs != 0);

	/*
	 * Determine per-port queue counts based on maximum port speed.
	 *
	 * This is a bit unfortunate, since there does not seem to be a way to
	 * query the maximum possible speed for a port independent of any
	 * installed transceiver.  If a transceiver of lesser speed capability
	 * is installed in a port, that port will clamp its own reported
	 * capabilities to those of the transceiver.
	 *
	 * Our compromise is to size queue allocations based on the fastest port
	 * we can find.  This will be less than ideal for adapters with
	 * heterogeneous port configurations or systems where transceivers of
	 * differing speed capabilities are swapped in after the driver
	 * initializes the adapter(s).
	 */
	t4_port_speed_t max_speed = TPS_1G;
	for (uint_t i = 0; i < port_count; i++) {
		max_speed = MAX(max_speed, t4_port_speed(sc->port[i]));
	}
	ASSERT(max_speed < ARRAY_SIZE(t4_queue_counts));
	const struct t4_queue_count *qc = &t4_queue_counts[max_speed];

	uint_t rxq_idx = 0, txq_idx = 0;
	for (uint_t i = 0; i < port_count; i++) {
		struct port_info *pi = sc->port[i];

		/* Clamp to per-port maximums */
		pi->rxq_count = MIN(qc->tqc_rxq_count, iaq->port_max_rxq);
		pi->txq_count = MIN(qc->tqc_txq_count, iaq->port_max_txq);

		pi->rxq_start = rxq_idx;
		pi->txq_start = txq_idx;
		rxq_idx += pi->rxq_count;
		txq_idx += pi->txq_count;
	}

	struct sge_info *sge = &sc->sge;
	sge->rxq_count = rxq_idx;
	sge->txq_count = txq_idx;

	cxgb_printf(sc->dip, CE_NOTE, "(%u rxq, %u txq total) %d %s.",
	    rxq_idx, txq_idx, iaq->intr_count,
	    iaq->intr_type == DDI_INTR_TYPE_MSIX ? "MSI-X interrupts" :
	    iaq->intr_type == DDI_INTR_TYPE_MSI ? "MSI interrupts" :
	    "fixed interrupt");

	return (DDI_SUCCESS);
}

static int
t4_setup_port_intrs(struct adapter *sc, int *handlers)
{
	int rc = 0;
	const struct t4_intrs_queues *iaq = &sc->intr_queue_cfg;

	for (uint_t i = 0; i < sc->params.nports; i++) {
		struct port_info *port = sc->port[i];

		port->intr_iqs = kmem_zalloc(iaq->intr_per_port *
		    sizeof (t4_sge_iq_t), KM_SLEEP);

		for (uint_t j = 0; j < iaq->intr_per_port; j++) {
			uint_t intr_idx = 2 + (i * iaq->intr_per_port) + j;
			VERIFY3S(intr_idx, <, iaq->intr_count);
			ddi_intr_handle_t ihdl = sc->intr_handle[intr_idx];
			rc = ddi_intr_add_handler(ihdl, t4_intr_port_queue,
			    &port->intr_iqs[j], NULL);
			if (rc != DDI_SUCCESS) {
				/*
				 * Previously installed handlers are cleaned up
				 * by the parent function.
				 */
				cxgb_printf(sc->dip, CE_WARN, "failed to add "
				    "interrupt handler %u for type: %d plan: "
				    "%d: %d", intr_idx, iaq->intr_type,
				    iaq->intr_plan, rc);
				return (rc);
			}
			*handlers += 1;
		}
	}

	return (DDI_SUCCESS);
}

static int
t4_setup_intrs(struct adapter *sc)
{
	const struct t4_intrs_queues *iaq = &sc->intr_queue_cfg;
	const int intr_count = iaq->intr_count;
	const int intr_type = iaq->intr_type;
	int allocated = 0;
	int handlers = 0;

	int rc = ddi_intr_alloc(sc->dip, sc->intr_handle, intr_type, 0,
	    intr_count, &allocated, DDI_INTR_ALLOC_STRICT);
	if (rc != DDI_SUCCESS) {
		cxgb_printf(sc->dip, CE_WARN,
		    "failed to allocate %d interrupt(s) of type %d: %d, %d",
		    intr_count, intr_type, rc, allocated);
		goto fail;
	}

	VERIFY3U(intr_count, ==, allocated); /* allocation was STRICT */

	rc = ddi_intr_get_cap(sc->intr_handle[0], &sc->intr_cap);
	if (rc != DDI_SUCCESS) {
		cxgb_printf(sc->dip, CE_WARN, "failed to get interrupt "
		    "capabilities for type %d: %d", intr_type, rc);
		goto fail;
	}

	rc = ddi_intr_get_pri(sc->intr_handle[0], &sc->intr_pri);
	if (rc != DDI_SUCCESS) {
		cxgb_printf(sc->dip, CE_WARN, "failed to get interrupt "
		    "priority for type %d: %d", intr_type, rc);
		goto fail;
	}

	switch (iaq->intr_plan) {
	case TIP_SINGLE:
		ASSERT3U(intr_count, ==, 1);
		rc = ddi_intr_add_handler(sc->intr_handle[0], t4_intr_all, sc,
		    NULL);
		if (rc != DDI_SUCCESS) {
			cxgb_printf(sc->dip, CE_WARN, "failed to add interrupt "
			    "handler %u for type: %d plan: %d: %d", handlers,
			    intr_type, iaq->intr_plan, rc);
			goto fail;
		}
		handlers++;
		break;

	case TIP_ERR_QUEUES:
		VERIFY3U(intr_count, ==, 2);
		rc = ddi_intr_add_handler(sc->intr_handle[0], t4_intr_err, sc,
		    NULL);
		if (rc != DDI_SUCCESS) {
			cxgb_printf(sc->dip, CE_WARN, "failed to add interrupt "
			    "handler %u for type: %d plan: %d: %d", handlers,
			    intr_type, iaq->intr_plan, rc);
			goto fail;
		}
		handlers++;

		rc = ddi_intr_add_handler(sc->intr_handle[1], t4_intr_fwq, sc,
		    NULL);
		if (rc != DDI_SUCCESS) {
			cxgb_printf(sc->dip, CE_WARN, "failed to add interrupt "
			    "handler %u for type: %d plan: %d: %d", handlers,
			    intr_type, iaq->intr_plan, rc);
			goto fail;
		}
		handlers++;
		break;

	case TIP_PER_PORT:
		VERIFY3U(intr_count, >=, 2 + sc->params.nports);
		rc = ddi_intr_add_handler(sc->intr_handle[0], t4_intr_err, sc,
		    NULL);
		if (rc != DDI_SUCCESS) {
			cxgb_printf(sc->dip, CE_WARN, "failed to add interrupt "
			    "handler %u for type: %d plan: %d: %d", handlers,
			    intr_type, iaq->intr_plan, rc);
			goto fail;
		}
		handlers++;

		rc =  ddi_intr_add_handler(sc->intr_handle[1], t4_intr_fwq, sc,
		    NULL);
		if (rc != DDI_SUCCESS) {
			cxgb_printf(sc->dip, CE_WARN, "failed to add interrupt "
			    "handler %u for type: %d plan: %d: %d", handlers,
			    intr_type, iaq->intr_plan, rc);
			goto fail;
		}
		handlers++;

		rc = t4_setup_port_intrs(sc, &handlers);

		if (rc != DDI_SUCCESS) {
			goto fail;
		}

		break;
	}

	return (DDI_SUCCESS);

fail:
	for (int i = 0; i < handlers; i++) {
		rc = ddi_intr_remove_handler(sc->intr_handle[i]);
		if (rc != DDI_SUCCESS) {
			/*
			 * We tried our best, the only thing left is to log the
			 * failure and move on.
			 */
			cxgb_printf(sc->dip, CE_WARN, "failed to remove "
			    "interrupt handler %d for type: %d plan: %d: %d", i,
			    intr_type, iaq->intr_plan, rc);
		}
	}

	for (int i = 0; i < allocated; i++) {
		rc = ddi_intr_free(sc->intr_handle[i]);
		if (rc != DDI_SUCCESS) {
			cxgb_printf(sc->dip, CE_WARN, "failed to free "
			    "interrupt %d for type: %d plan: %d: %d", i,
			    intr_type, iaq->intr_plan, rc);
		}
	}

	return (DDI_FAILURE);
}

static int
t4_add_child_node(struct adapter *sc, uint_t idx)
{

	if (idx >= sc->params.nports)
		return (EINVAL);

	struct port_info *pi = sc->port[idx];
	if (pi == NULL) {
		/* t4_port_init failed earlier */
		return (ENODEV);
	}

	PORT_LOCK(pi);
	if (pi->dip != NULL) {
		PORT_UNLOCK(pi);
		/* EEXIST really, but then bus_config fails */
		return (0);
	}

	const int rc =
	    ndi_devi_alloc(sc->dip, T4_PORT_NAME, DEVI_SID_NODEID, &pi->dip);
	if (rc != DDI_SUCCESS || pi->dip == NULL) {
		PORT_UNLOCK(pi);
		return (ENOMEM);
	}

	(void) ddi_set_parent_data(pi->dip, pi);
	(void) ndi_devi_bind_driver(pi->dip, 0);

	PORT_UNLOCK(pi);
	return (0);
}

static int
t4_remove_child_node(struct adapter *sc, uint_t idx)
{
	if (idx >= sc->params.nports)
		return (EINVAL);

	struct port_info *pi = sc->port[idx];
	if (pi == NULL)
		return (ENODEV);

	PORT_LOCK(pi);
	if (pi->dip == NULL) {
		PORT_UNLOCK(pi);
		return (ENODEV);
	}

	const int rc = ndi_devi_free(pi->dip);
	if (rc == 0)
		pi->dip = NULL;

	PORT_UNLOCK(pi);
	return (rc);
}

struct t4_port_speed_def {
	uint32_t	tpsd_cap;
	t4_port_speed_t	tpsd_speed;
	const char	*tpsd_name;
};
#define	T4_PORT_SPEED_DEF(speed)			\
{							\
	.tpsd_cap = FW_PORT_CAP32_SPEED_ ## speed,	\
	.tpsd_speed = TPS_ ## speed,			\
	.tpsd_name = #speed,				\
}

static const struct t4_port_speed_def t4_port_speeds[] = {
	T4_PORT_SPEED_DEF(400G),
	T4_PORT_SPEED_DEF(200G),
	T4_PORT_SPEED_DEF(100G),
	T4_PORT_SPEED_DEF(50G),
	T4_PORT_SPEED_DEF(40G),
	T4_PORT_SPEED_DEF(25G),
	T4_PORT_SPEED_DEF(10G),
	T4_PORT_SPEED_DEF(1G),
};

/*
 * Get maximum advertised speed of this port.
 *
 * This is, unfortunately, impacted by the installed transceiver at the time of
 * query.
 */
static t4_port_speed_t
t4_port_speed(const struct port_info *pi)
{
	ASSERT(pi != NULL);

	const uint32_t pcap = pi->link_cfg.pcaps;
	for (uint_t i = 0; i < ARRAY_SIZE(t4_port_speeds); i++) {
		if (t4_port_speeds[i].tpsd_cap & pcap) {
			return (t4_port_speeds[i].tpsd_speed);
		}
	}

	/* Fall back to 1G for unknown speeds */
	return (TPS_1G);
}

static const char *
t4_port_speed_name(const struct port_info *pi)
{
	if (pi == NULL) {
		return ("-");
	}

	const uint32_t pcap = pi->link_cfg.pcaps;
	for (uint_t i = 0; i < ARRAY_SIZE(t4_port_speeds); i++) {
		if (t4_port_speeds[i].tpsd_cap & pcap) {
			return (t4_port_speeds[i].tpsd_name);
		}
	}

	return ("-");
}

#define	KS_INIT_U64(kstatp,  n)	\
	kstat_named_init(&kstatp->n, #n, KSTAT_DATA_UINT64)
#define	KS_INIT_CHAR(kstatp, n)	\
	kstat_named_init(&kstatp->n, #n, KSTAT_DATA_CHAR)
#define	KS_INIT_STR(kstatp, n)	\
	kstat_named_init(&kstatp->n, #n, KSTAT_DATA_STRING)
#define	KS_SET_U64(kstatp, n, v)	kstatp->n.value.ul = (v)
#define	KS_SET_CHAR(kstatp, n, ...)	\
	(void) snprintf(kstatp->n.value.c, 16,  __VA_ARGS__)
#define	KS_SET_STR(kstatp, n, v)	\
	kstat_named_setstr(&kstatp->n, v)

/*
 * t4nex:X:config
 */
struct t4_kstats {
	kstat_named_t chip_ver;
	kstat_named_t fw_vers;
	kstat_named_t tp_vers;
	kstat_named_t driver_version;
	kstat_named_t serial_number;
	kstat_named_t ec_level;
	kstat_named_t id;
	kstat_named_t core_clock;
	kstat_named_t port_cnt;
	kstat_named_t port_type;
};

static kstat_t *
t4_setup_kstats(struct adapter *sc)
{
	const ulong_t ndata = sizeof (struct t4_kstats) /
	    sizeof (kstat_named_t);
	kstat_t *ksp = kstat_create(T4_NEXUS_NAME, ddi_get_instance(sc->dip),
	    "config", "nexus", KSTAT_TYPE_NAMED, ndata, 0);
	if (ksp == NULL) {
		cxgb_printf(sc->dip, CE_WARN, "failed to initialize kstats.");
		return (NULL);
	}

	struct t4_kstats *kstatp = (struct t4_kstats *)ksp->ks_data;

	KS_INIT_U64(kstatp, chip_ver);
	KS_INIT_CHAR(kstatp, fw_vers);
	KS_INIT_CHAR(kstatp, tp_vers);
	KS_INIT_CHAR(kstatp, driver_version);
	KS_INIT_STR(kstatp, serial_number);
	KS_INIT_STR(kstatp, ec_level);
	KS_INIT_STR(kstatp, id);
	KS_INIT_U64(kstatp, core_clock);
	KS_INIT_U64(kstatp, port_cnt);
	KS_INIT_CHAR(kstatp, port_type);

	KS_SET_U64(kstatp, chip_ver, sc->params.chip);
	KS_SET_CHAR(kstatp, fw_vers, "%d.%d.%d.%d",
	    G_FW_HDR_FW_VER_MAJOR(sc->params.fw_vers),
	    G_FW_HDR_FW_VER_MINOR(sc->params.fw_vers),
	    G_FW_HDR_FW_VER_MICRO(sc->params.fw_vers),
	    G_FW_HDR_FW_VER_BUILD(sc->params.fw_vers));
	KS_SET_CHAR(kstatp, tp_vers, "%d.%d.%d.%d",
	    G_FW_HDR_FW_VER_MAJOR(sc->params.tp_vers),
	    G_FW_HDR_FW_VER_MINOR(sc->params.tp_vers),
	    G_FW_HDR_FW_VER_MICRO(sc->params.tp_vers),
	    G_FW_HDR_FW_VER_BUILD(sc->params.tp_vers));
	KS_SET_CHAR(kstatp, driver_version, DRV_VERSION);

	const struct vpd_params *vpd = &sc->params.vpd;
	KS_SET_STR(kstatp, serial_number, (const char *)vpd->sn);
	KS_SET_STR(kstatp, ec_level, (const char *)vpd->ec);
	KS_SET_STR(kstatp, id, (const char *)vpd->id);
	KS_SET_U64(kstatp, core_clock, vpd->cclk);
	KS_SET_U64(kstatp, port_cnt, sc->params.nports);

	KS_SET_CHAR(kstatp, port_type, "%s/%s/%s/%s",
	    t4_port_speed_name(sc->port[0]),
	    t4_port_speed_name(sc->port[1]),
	    t4_port_speed_name(sc->port[2]),
	    t4_port_speed_name(sc->port[3]));

	/* Do NOT set ksp->ks_update.  These kstats do not change. */

	/* Install the kstat */
	ksp->ks_private = (void *)sc;
	kstat_install(ksp);

	return (ksp);
}

/*
 * t4nex:X:stat
 */
struct t4_wc_kstats {
	kstat_named_t write_coal_success;
	kstat_named_t write_coal_failure;
};

static int
t4_update_wc_kstats(kstat_t *ksp, int rw)
{
	struct t4_wc_kstats *kstatp = (struct t4_wc_kstats *)ksp->ks_data;
	struct adapter *sc = ksp->ks_private;

	if (rw == KSTAT_WRITE)
		return (0);

	if (t4_cver_ge(sc, CHELSIO_T5)) {
		const uint32_t wc_total = t4_read_reg(sc, A_SGE_STAT_TOTAL);
		const uint32_t wc_failure = t4_read_reg(sc, A_SGE_STAT_MATCH);
		KS_SET_U64(kstatp, write_coal_success, wc_total - wc_failure);
		KS_SET_U64(kstatp, write_coal_failure, wc_failure);
	}

	return (0);
}

static kstat_t *
t4_setup_wc_kstats(struct adapter *sc)
{
	kstat_t *ksp;
	struct t4_wc_kstats *kstatp;

	const uint_t ndata =
	    sizeof (struct t4_wc_kstats) / sizeof (kstat_named_t);
	ksp = kstat_create(T4_NEXUS_NAME, ddi_get_instance(sc->dip), "stats",
	    "nexus", KSTAT_TYPE_NAMED, ndata, 0);
	if (ksp == NULL) {
		cxgb_printf(sc->dip, CE_WARN, "failed to initialize kstats.");
		return (NULL);
	}

	kstatp = (struct t4_wc_kstats *)ksp->ks_data;

	KS_INIT_U64(kstatp, write_coal_success);
	KS_INIT_U64(kstatp, write_coal_failure);

	ksp->ks_update = t4_update_wc_kstats;
	/* Install the kstat */
	ksp->ks_private = (void *)sc;
	kstat_install(ksp);

	return (ksp);
}

/*
 * cxgbe:X:fec
 *
 * This provides visibility into the errors that have been found by the
 * different FEC subsystems. While it's tempting to combine the two different
 * FEC types logically, the data that the errors tell us are pretty different
 * between the two. Firecode is strictly per-lane, but RS has parts that are
 * related to symbol distribution to lanes and also to the overall channel.
 */
struct cxgbe_port_fec_kstats {
	kstat_named_t rs_corr;
	kstat_named_t rs_uncorr;
	kstat_named_t rs_sym0_corr;
	kstat_named_t rs_sym1_corr;
	kstat_named_t rs_sym2_corr;
	kstat_named_t rs_sym3_corr;
	kstat_named_t fc_lane0_corr;
	kstat_named_t fc_lane0_uncorr;
	kstat_named_t fc_lane1_corr;
	kstat_named_t fc_lane1_uncorr;
	kstat_named_t fc_lane2_corr;
	kstat_named_t fc_lane2_uncorr;
	kstat_named_t fc_lane3_corr;
	kstat_named_t fc_lane3_uncorr;
};

static uint32_t
t4_read_fec_pair(struct port_info *pi, uint32_t lo_reg, uint32_t high_reg)
{
	struct adapter *sc = pi->adapter;
	const uint8_t port = pi->tx_chan;

	const uint32_t low = t4_read_reg(sc, T5_PORT_REG(port, lo_reg));
	const uint32_t high = t4_read_reg(sc, T5_PORT_REG(port, high_reg));
	return ((low & 0xffff) | ((high & 0xffff) << 16));
}

static int
t4_update_fec_kstats(kstat_t *ksp, int rw)
{
	struct cxgbe_port_fec_kstats *fec = ksp->ks_data;
	struct port_info *pi = ksp->ks_private;

	if (rw == KSTAT_WRITE) {
		return (EACCES);
	}

	/*
	 * First go ahead and gather RS related stats.
	 */
	fec->rs_corr.value.ui64 +=
	    t4_read_fec_pair(pi, T6_RS_FEC_CCW_LO, T6_RS_FEC_CCW_HI);
	fec->rs_uncorr.value.ui64 +=
	    t4_read_fec_pair(pi, T6_RS_FEC_NCCW_LO, T6_RS_FEC_NCCW_HI);
	fec->rs_sym0_corr.value.ui64 +=
	    t4_read_fec_pair(pi, T6_RS_FEC_SYMERR0_LO, T6_RS_FEC_SYMERR0_HI);
	fec->rs_sym1_corr.value.ui64 +=
	    t4_read_fec_pair(pi, T6_RS_FEC_SYMERR1_LO, T6_RS_FEC_SYMERR1_HI);
	fec->rs_sym2_corr.value.ui64 +=
	    t4_read_fec_pair(pi, T6_RS_FEC_SYMERR2_LO, T6_RS_FEC_SYMERR2_HI);
	fec->rs_sym3_corr.value.ui64 +=
	    t4_read_fec_pair(pi, T6_RS_FEC_SYMERR3_LO, T6_RS_FEC_SYMERR3_HI);

	/*
	 * Now go through and try to grab Firecode/BASE-R stats.
	 */
	fec->fc_lane0_corr.value.ui64 +=
	    t4_read_fec_pair(pi, T6_FC_FEC_L0_CERR_LO, T6_FC_FEC_L0_CERR_HI);
	fec->fc_lane0_uncorr.value.ui64 +=
	    t4_read_fec_pair(pi, T6_FC_FEC_L0_NCERR_LO, T6_FC_FEC_L0_NCERR_HI);
	fec->fc_lane1_corr.value.ui64 +=
	    t4_read_fec_pair(pi, T6_FC_FEC_L1_CERR_LO, T6_FC_FEC_L1_CERR_HI);
	fec->fc_lane1_uncorr.value.ui64 +=
	    t4_read_fec_pair(pi, T6_FC_FEC_L1_NCERR_LO, T6_FC_FEC_L1_NCERR_HI);
	fec->fc_lane2_corr.value.ui64 +=
	    t4_read_fec_pair(pi, T6_FC_FEC_L2_CERR_LO, T6_FC_FEC_L2_CERR_HI);
	fec->fc_lane2_uncorr.value.ui64 +=
	    t4_read_fec_pair(pi, T6_FC_FEC_L2_NCERR_LO, T6_FC_FEC_L2_NCERR_HI);
	fec->fc_lane3_corr.value.ui64 +=
	    t4_read_fec_pair(pi, T6_FC_FEC_L3_CERR_LO, T6_FC_FEC_L3_CERR_HI);
	fec->fc_lane3_uncorr.value.ui64 +=
	    t4_read_fec_pair(pi, T6_FC_FEC_L3_NCERR_LO, T6_FC_FEC_L3_NCERR_HI);

	return (0);
}

static kstat_t *
t4_init_fec_kstats(struct port_info *pi)
{
	kstat_t *ksp;
	struct cxgbe_port_fec_kstats *kstatp;

	if (!t4_cver_ge(pi->adapter, CHELSIO_T6)) {
		return (NULL);
	}

	ksp = kstat_create(T4_PORT_NAME, ddi_get_instance(pi->dip), "fec",
	    "net", KSTAT_TYPE_NAMED, sizeof (struct cxgbe_port_fec_kstats) /
	    sizeof (kstat_named_t), 0);
	if (ksp == NULL) {
		cxgb_printf(pi->dip, CE_WARN, "failed to initialize fec "
		    "kstats.");
		return (NULL);
	}

	kstatp = ksp->ks_data;
	KS_INIT_U64(kstatp, rs_corr);
	KS_INIT_U64(kstatp, rs_uncorr);
	KS_INIT_U64(kstatp, rs_sym0_corr);
	KS_INIT_U64(kstatp, rs_sym1_corr);
	KS_INIT_U64(kstatp, rs_sym2_corr);
	KS_INIT_U64(kstatp, rs_sym3_corr);
	KS_INIT_U64(kstatp, fc_lane0_corr);
	KS_INIT_U64(kstatp, fc_lane0_uncorr);
	KS_INIT_U64(kstatp, fc_lane1_corr);
	KS_INIT_U64(kstatp, fc_lane1_uncorr);
	KS_INIT_U64(kstatp, fc_lane2_corr);
	KS_INIT_U64(kstatp, fc_lane2_uncorr);
	KS_INIT_U64(kstatp, fc_lane3_corr);
	KS_INIT_U64(kstatp, fc_lane3_uncorr);

	ksp->ks_update = t4_update_fec_kstats;
	ksp->ks_private = pi;
	kstat_install(ksp);

	return (ksp);
}

int
t4_port_full_init(struct port_info *pi)
{
	struct adapter *sc = pi->adapter;
	struct sge_rxq *rxq;
	int rc, i;

	ASSERT((pi->flags & TPF_INIT_DONE) == 0);

	/* Allocate TX/RX/FL queues for this port. */
	if ((rc = t4_port_queues_init(pi)) != 0) {
		goto done;
	}

	/* Setup RSS for this port. */
	uint16_t *rss = kmem_zalloc(pi->rxq_count * sizeof (*rss), KM_SLEEP);
	for_each_rxq(pi, i, rxq) {
		rss[i] = rxq->iq.tsi_abs_id;
	}
	rc = -t4_config_rss_range(sc, sc->mbox, pi->viid, 0,
	    pi->rss_size, rss, pi->rxq_count);
	kmem_free(rss, pi->rxq_count * sizeof (*rss));
	if (rc != 0) {
		cxgb_printf(pi->dip, CE_WARN, "rss_config failed: %d", rc);
		goto done;
	}

	t4_port_kstats_init(pi);
	pi->ksp_fec = t4_init_fec_kstats(pi);

	pi->flags |= TPF_INIT_DONE;

done:
	if (rc != 0) {
		/*
		 * Clean up any state resulting which may be lingering due to
		 * failure part way through initialization.
		 */
		t4_port_full_uninit(pi);
	}

	return (rc);
}

/*
 * Idempotent.
 */
static void
t4_port_full_uninit(struct port_info *pi)
{
	if (pi->ksp_fec != NULL) {
		kstat_delete(pi->ksp_fec);
		pi->ksp_fec = NULL;
	}
	t4_port_kstats_fini(pi);
	t4_port_queues_fini(pi);
	pi->flags &= ~TPF_INIT_DONE;
}

void
t4_fatal_err(struct adapter *sc)
{
	t4_set_reg_field(sc, A_SGE_CONTROL, F_GLOBALENABLE, 0);
	t4_intr_disable(sc);
	cxgb_printf(sc->dip, CE_WARN,
	    "encountered fatal error, adapter stopped.");
}

int
t4_os_find_pci_capability(struct adapter *sc, uint8_t cap)
{
	const uint16_t stat = pci_config_get16(sc->pci_regh, PCI_CONF_STAT);
	if ((stat & PCI_STAT_CAP) == 0) {
		return (0);
	}

	uint8_t cap_ptr = pci_config_get8(sc->pci_regh, PCI_CONF_CAP_PTR);
	while (cap_ptr) {
		uint8_t cap_id =
		    pci_config_get8(sc->pci_regh, cap_ptr + PCI_CAP_ID);
		if (cap_id == cap) {
			return (cap_ptr);
		}
		cap_ptr =
		    pci_config_get8(sc->pci_regh, cap_ptr + PCI_CAP_NEXT_PTR);
	}

	return (0);
}

void
t4_os_portmod_changed(struct adapter *sc, int idx)
{
	static const char *mod_str[] = {
		NULL, "LR", "SR", "ER", "TWINAX", "active TWINAX", "LRM"
	};
	struct port_info *pi = sc->port[idx];

	if (pi->mod_type == FW_PORT_MOD_TYPE_NONE)
		cxgb_printf(pi->dip, CE_NOTE, "transceiver unplugged.");
	else if (pi->mod_type == FW_PORT_MOD_TYPE_UNKNOWN)
		cxgb_printf(pi->dip, CE_NOTE,
		    "unknown transceiver inserted.\n");
	else if (pi->mod_type == FW_PORT_MOD_TYPE_NOTSUPPORTED)
		cxgb_printf(pi->dip, CE_NOTE,
		    "unsupported transceiver inserted.\n");
	else if (pi->mod_type > 0 && pi->mod_type < ARRAY_SIZE(mod_str))
		cxgb_printf(pi->dip, CE_NOTE, "%s transceiver inserted.\n",
		    mod_str[pi->mod_type]);
	else
		cxgb_printf(pi->dip, CE_NOTE, "transceiver (type %d) inserted.",
		    pi->mod_type);

	if ((pi->flags & TPF_OPEN) != 0 && pi->link_cfg.new_module) {
		pi->link_cfg.redo_l1cfg = true;
	}
}

void
t4_os_set_hw_addr(struct adapter *sc, int idx, const uint8_t *hw_addr)
{
	bcopy(hw_addr, sc->port[idx]->hw_addr, ETHERADDRL);
}

/* Add thread to list of consumers waiting to access adapter mailbox */
void
t4_mbox_waiter_add(struct adapter *sc, t4_mbox_waiter_t *ent)
{
	mutex_enter(&sc->mbox_lock);
	ent->thread = curthread;
	list_insert_tail(&sc->mbox_list, ent);
	mutex_exit(&sc->mbox_lock);
}

/* Remove thread from list of consumers waiting to access adapter mailbox */
void
t4_mbox_waiter_remove(struct adapter *sc, t4_mbox_waiter_t *ent)
{
	ASSERT(ent->thread == curthread);

	mutex_enter(&sc->mbox_lock);
	const bool was_owner = (list_head(&sc->mbox_list) == ent);
	list_remove(&sc->mbox_list, ent);

	if (was_owner && !list_is_empty(&sc->mbox_list)) {
		/*
		 * Wake the other threads waiting on the mbox as we are vacating
		 * the "owner" slot.
		 */
		cv_broadcast(&sc->mbox_cv);
	}
	mutex_exit(&sc->mbox_lock);
}

/*
 * Wait for the current thread, which has called t4_mbox_waiter_add(), to become
 * the "owner" of the adapter mailbox (head of the waiter list).
 *
 * Returns true if current thread is the owner, else false if we slept/spun for
 * `wait_us` and are not yet owner (and thus should recheck adapter status).
 */
bool
t4_mbox_wait_owner(struct adapter *sc, uint_t wait_us, bool sleep_ok)
{
	mutex_enter(&sc->mbox_lock);
	t4_mbox_waiter_t *head = list_head(&sc->mbox_list);
	ASSERT(head != NULL);

	if (head->thread == curthread) {
		mutex_exit(&sc->mbox_lock);
		return (true);
	}

	if (!sleep_ok) {
		mutex_exit(&sc->mbox_lock);
		drv_usecwait(wait_us);

		mutex_enter(&sc->mbox_lock);
		head = list_head(&sc->mbox_list);
		ASSERT(head != NULL);
		bool is_owner = head->thread == curthread;
		mutex_exit(&sc->mbox_lock);
		return (is_owner);
	}

	/*
	 * Using a singal-aware wait would be more courteous here, but much of
	 * the logic which ultimately accesses the device mbox is ill-equipped
	 * to handle gracefully EINTR failures.
	 */
	const int res = cv_reltimedwait(&sc->mbox_cv, &sc->mbox_lock,
	    USEC_TO_TICK(wait_us), TR_MICROSEC);
	if (res > 0) {
		head = list_head(&sc->mbox_list);
		ASSERT(head != NULL);
		if (head->thread == curthread) {
			/*
			 * CV was signaled and this thread now occupies the head
			 * of the list (indicating mbox ownership).
			 */
			mutex_exit(&sc->mbox_lock);
			return (true);
		}
	}
	mutex_exit(&sc->mbox_lock);
	return (false);
}


uint32_t
t4_read_reg(struct adapter *sc, uint32_t reg)
{
	const uint32_t val = ddi_get32(sc->regh, (uint32_t *)(sc->regp + reg));
	DTRACE_PROBE3(t4__reg__read, struct adapter *, sc, uint32_t, reg,
	    uint64_t, val);
	return (val);
}

void
t4_write_reg(struct adapter *sc, uint32_t reg, uint32_t val)
{
	DTRACE_PROBE3(t4__reg__write, struct adapter *, sc, uint32_t, reg,
	    uint64_t, val);
	ddi_put32(sc->regh, (uint32_t *)(sc->regp + reg), val);
}

uint64_t
t4_read_reg64(struct adapter *sc, uint32_t reg)
{
	const uint64_t val = ddi_get64(sc->regh, (uint64_t *)(sc->regp + reg));
	DTRACE_PROBE3(t4__reg__read, struct adapter *, sc, uint32_t, reg,
	    uint64_t, val);
	return (val);
}

void
t4_write_reg64(struct adapter *sc, uint32_t reg, uint64_t val)
{
	DTRACE_PROBE3(t4__reg__write, struct adapter *, sc, uint32_t, reg,
	    uint64_t, val);
	ddi_put64(sc->regh, (uint64_t *)(sc->regp + reg), val);
}

static int
t4_sensor_read(struct adapter *sc, uint32_t diag, uint32_t *valp)
{
	int rc;
	uint32_t param, val;

	ADAPTER_LOCK(sc);
	param = V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DEV) |
	    V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DEV_DIAG) |
	    V_FW_PARAMS_PARAM_Y(diag);
	rc = -t4_query_params(sc, sc->mbox, sc->pf, 0, 1, &param, &val);
	ADAPTER_UNLOCK(sc);

	if (rc != 0) {
		return (rc);
	} else if (val == 0) {
		return (EIO);
	}

	*valp = val;
	return (0);
}

static int
t4_temperature_read(void *arg, sensor_ioctl_scalar_t *scalar)
{
	int ret;
	struct adapter *sc = arg;
	uint32_t val;

	ret = t4_sensor_read(sc, FW_PARAM_DEV_DIAG_TMP, &val);
	if (ret != 0) {
		return (ret);
	}

	/*
	 * The device measures temperature in units of 1 degree Celsius. We
	 * don't know its precision.
	 */
	scalar->sis_unit = SENSOR_UNIT_CELSIUS;
	scalar->sis_gran = 1;
	scalar->sis_prec = 0;
	scalar->sis_value = val;

	return (0);
}

static int
t4_voltage_read(void *arg, sensor_ioctl_scalar_t *scalar)
{
	int ret;
	struct adapter *sc = arg;
	uint32_t val;

	ret = t4_sensor_read(sc, FW_PARAM_DEV_DIAG_VDD, &val);
	if (ret != 0) {
		return (ret);
	}

	scalar->sis_unit = SENSOR_UNIT_VOLTS;
	scalar->sis_gran = 1000;
	scalar->sis_prec = 0;
	scalar->sis_value = val;

	return (0);
}

/*
 * While the hardware supports the ability to read and write the flash image,
 * this is not currently wired up.
 */
static int
t4_ufm_getcaps(ddi_ufm_handle_t *ufmh, void *arg, ddi_ufm_cap_t *caps)
{
	*caps = DDI_UFM_CAP_REPORT;
	return (0);
}

static int
t4_ufm_fill_image(ddi_ufm_handle_t *ufmh, void *arg, uint_t imgno,
    ddi_ufm_image_t *imgp)
{
	if (imgno != 0) {
		return (EINVAL);
	}

	ddi_ufm_image_set_desc(imgp, "Firmware");
	ddi_ufm_image_set_nslots(imgp, 1);

	return (0);
}

static int
t4_ufm_fill_slot_version(nvlist_t *nvl, const char *key, uint32_t vers)
{
	char buf[128];

	if (vers == 0) {
		return (0);
	}

	if (snprintf(buf, sizeof (buf), "%u.%u.%u.%u",
	    G_FW_HDR_FW_VER_MAJOR(vers), G_FW_HDR_FW_VER_MINOR(vers),
	    G_FW_HDR_FW_VER_MICRO(vers), G_FW_HDR_FW_VER_BUILD(vers)) >=
	    sizeof (buf)) {
		return (EOVERFLOW);
	}

	return (nvlist_add_string(nvl, key, buf));
}

static int
t4_ufm_fill_slot(ddi_ufm_handle_t *ufmh, void *arg, uint_t imgno, uint_t slotno,
    ddi_ufm_slot_t *slotp)
{
	int ret;
	struct adapter *sc = arg;
	nvlist_t *misc = NULL;
	char buf[128];

	if (imgno != 0 || slotno != 0) {
		return (EINVAL);
	}

	if (snprintf(buf, sizeof (buf), "%u.%u.%u.%u",
	    G_FW_HDR_FW_VER_MAJOR(sc->params.fw_vers),
	    G_FW_HDR_FW_VER_MINOR(sc->params.fw_vers),
	    G_FW_HDR_FW_VER_MICRO(sc->params.fw_vers),
	    G_FW_HDR_FW_VER_BUILD(sc->params.fw_vers)) >= sizeof (buf)) {
		return (EOVERFLOW);
	}

	ddi_ufm_slot_set_version(slotp, buf);

	(void) nvlist_alloc(&misc, NV_UNIQUE_NAME, KM_SLEEP);
	if ((ret = t4_ufm_fill_slot_version(misc, "TP Microcode",
	    sc->params.tp_vers)) != 0) {
		goto err;
	}

	if ((ret = t4_ufm_fill_slot_version(misc, "Bootstrap",
	    sc->params.bs_vers)) != 0) {
		goto err;
	}

	if ((ret = t4_ufm_fill_slot_version(misc, "Expansion ROM",
	    sc->params.er_vers)) != 0) {
		goto err;
	}

	if ((ret = nvlist_add_uint32(misc, "Serial Configuration",
	    sc->params.scfg_vers)) != 0) {
		goto err;
	}

	if ((ret = nvlist_add_uint32(misc, "VPD Version",
	    sc->params.vpd_vers)) != 0) {
		goto err;
	}

	ddi_ufm_slot_set_misc(slotp, misc);
	ddi_ufm_slot_set_attrs(slotp, DDI_UFM_ATTR_ACTIVE |
	    DDI_UFM_ATTR_WRITEABLE | DDI_UFM_ATTR_READABLE);
	return (0);

err:
	nvlist_free(misc);
	return (ret);

}

int
t4_cxgbe_attach(struct port_info *pi, dev_info_t *dip)
{
	ASSERT(pi != NULL);

	mac_register_t *mac = mac_alloc(MAC_VERSION);
	if (mac == NULL) {
		return (DDI_FAILURE);
	}

	size_t prop_size;
	const char **props = t4_get_priv_props(pi, &prop_size);

	mac->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	mac->m_driver = pi;
	mac->m_dip = dip;
	mac->m_src_addr = pi->hw_addr;
	mac->m_callbacks = &t4_mac_callbacks;
	mac->m_max_sdu = pi->mtu;
	/* mac_register() treats this as const, so we can cast it away */
	mac->m_priv_props = (char **)props;
	mac->m_margin = VLAN_TAGSZ;
	mac->m_v12n = MAC_VIRT_LEVEL1;

	mac_handle_t mh = NULL;
	const int rc = mac_register(mac, &mh);
	mac_free(mac);
	kmem_free(props, prop_size);
	if (rc != 0) {
		return (DDI_FAILURE);
	}

	pi->mh = mh;

	/*
	 * Link state from this point onwards to the time interface is plumbed,
	 * should be set to LINK_STATE_UNKNOWN. The mac should be updated about
	 * the link state as either LINK_STATE_UP or LINK_STATE_DOWN based on
	 * the actual link state detection after interface plumb.
	 */
	mac_link_update(mh, LINK_STATE_UNKNOWN);

	return (DDI_SUCCESS);
}

int
t4_cxgbe_detach(struct port_info *pi)
{
	ASSERT(pi != NULL);
	ASSERT(pi->mh != NULL);

	if (mac_unregister(pi->mh) == 0) {
		pi->mh = NULL;
		return (DDI_SUCCESS);
	}

	return (DDI_FAILURE);
}

struct cb_ops t4_cb_ops = {
	.cb_open =		t4_cb_open,
	.cb_close =		t4_cb_close,
	.cb_strategy =		nodev,
	.cb_print =		nodev,
	.cb_dump =		nodev,
	.cb_read =		nodev,
	.cb_write =		nodev,
	.cb_ioctl =		t4_cb_ioctl,
	.cb_devmap =		nodev,
	.cb_mmap =		nodev,
	.cb_segmap =		nodev,
	.cb_chpoll =		nochpoll,
	.cb_prop_op =		ddi_prop_op,
	.cb_flag =		D_MP,
	.cb_rev =		CB_REV,
	.cb_aread =		nodev,
	.cb_awrite =		nodev
};

struct bus_ops t4_bus_ops = {
	.busops_rev =		BUSO_REV,
	.bus_ctl =		t4_bus_ctl,
	.bus_prop_op =		ddi_bus_prop_op,
	.bus_config =		t4_bus_config,
	.bus_unconfig =		t4_bus_unconfig,
};

static struct dev_ops t4_dev_ops = {
	.devo_rev =		DEVO_REV,
	.devo_getinfo =		t4_devo_getinfo,
	.devo_identify =	nulldev,
	.devo_probe =		t4_devo_probe,
	.devo_attach =		t4_devo_attach,
	.devo_detach =		t4_devo_detach,
	.devo_reset =		nodev,
	.devo_cb_ops =		&t4_cb_ops,
	.devo_bus_ops =		&t4_bus_ops,
	.devo_quiesce =		&t4_devo_quiesce,
};

static struct modldrv t4nex_modldrv = {
	.drv_modops =		&mod_driverops,
	.drv_linkinfo =		"Chelsio T4-T6 nexus " DRV_VERSION,
	.drv_dev_ops =		&t4_dev_ops
};

static struct modlinkage t4nex_modlinkage = {
	.ml_rev =		MODREV_1,
	.ml_linkage =		{&t4nex_modldrv, NULL},
};

int
_init(void)
{
	int rc;

	rc = ddi_soft_state_init(&t4_soft_state, sizeof (struct adapter), 0);
	if (rc != 0) {
		return (rc);
	}

	mutex_init(&t4_adapter_list_lock, NULL, MUTEX_DRIVER, NULL);
	list_create(&t4_adapter_list, sizeof (adapter_t),
	    offsetof(adapter_t, node));
	t4_debug_init();

	rc = mod_install(&t4nex_modlinkage);
	if (rc != 0) {
		ddi_soft_state_fini(&t4_soft_state);
		mutex_destroy(&t4_adapter_list_lock);
		list_destroy(&t4_adapter_list);
		t4_debug_fini();
	}

	return (rc);
}

int
_fini(void)
{
	const int rc = mod_remove(&t4nex_modlinkage);
	if (rc != 0) {
		return (rc);
	}

	mutex_destroy(&t4_adapter_list_lock);
	list_destroy(&t4_adapter_list);
	ddi_soft_state_fini(&t4_soft_state);
	t4_debug_fini();

	return (0);
}

int
_info(struct modinfo *mi)
{
	return (mod_info(&t4nex_modlinkage, mi));
}
