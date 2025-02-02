// SPDX-License-Identifier: GPL-2.0
/*
 * I/O Processor (IOP) ADB Driver
 * Written and (C) 1999 by Joshua M. Thompson (funaho@jurai.org)
 * Based on via-cuda.c by Paul Mackerras.
 *
 * 1999-07-01 (jmt) - First implementation for new driver architecture.
 *
 * 1999-07-31 (jmt) - First working version.
 *
 * TODO:
 *
 * o Implement SRQ handling.
 */

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/proc_fs.h>

<<<<<<< HEAD
#include <asm/macintosh.h> 
#include <asm/macints.h> 
=======
#include <asm/macintosh.h>
#include <asm/macints.h>
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
#include <asm/mac_iop.h>
#include <asm/mac_oss.h>
#include <asm/adb_iop.h>

<<<<<<< HEAD
#include <linux/adb.h> 
=======
#include <linux/adb.h>
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533

/*#define DEBUG_ADB_IOP*/

static struct adb_request *current_req;
static struct adb_request *last_req;
#if 0
static unsigned char reply_buff[16];
static unsigned char *reply_ptr;
#endif

static enum adb_iop_state {
<<<<<<< HEAD
    idle,
    sending,
    awaiting_reply
=======
	idle,
	sending,
	awaiting_reply
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
} adb_iop_state;

static void adb_iop_start(void);
static int adb_iop_probe(void);
static int adb_iop_init(void);
static int adb_iop_send_request(struct adb_request *, int);
static int adb_iop_write(struct adb_request *);
static int adb_iop_autopoll(int);
static void adb_iop_poll(void);
static int adb_iop_reset_bus(void);

struct adb_driver adb_iop_driver = {
	.name         = "ISM IOP",
	.probe        = adb_iop_probe,
	.init         = adb_iop_init,
	.send_request = adb_iop_send_request,
	.autopoll     = adb_iop_autopoll,
	.poll         = adb_iop_poll,
	.reset_bus    = adb_iop_reset_bus
};

static void adb_iop_end_req(struct adb_request *req, int state)
{
	req->complete = 1;
	current_req = req->next;
<<<<<<< HEAD
	if (req->done) (*req->done)(req);
=======
	if (req->done)
		(*req->done)(req);
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
	adb_iop_state = state;
}

/*
 * Completion routine for ADB commands sent to the IOP.
 *
 * This will be called when a packet has been successfully sent.
 */

static void adb_iop_complete(struct iop_msg *msg)
{
	struct adb_request *req;
	unsigned long flags;

	local_irq_save(flags);

	req = current_req;
	if ((adb_iop_state == sending) && req && req->reply_expected) {
		adb_iop_state = awaiting_reply;
	}

	local_irq_restore(flags);
}

/*
 * Listen for ADB messages from the IOP.
 *
 * This will be called when unsolicited messages (usually replies to TALK
 * commands or autopoll packets) are received.
 */

static void adb_iop_listen(struct iop_msg *msg)
{
<<<<<<< HEAD
	struct adb_iopmsg *amsg = (struct adb_iopmsg *) msg->message;
=======
	struct adb_iopmsg *amsg = (struct adb_iopmsg *)msg->message;
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
	struct adb_request *req;
	unsigned long flags;
#ifdef DEBUG_ADB_IOP
	int i;
#endif

	local_irq_save(flags);

	req = current_req;

#ifdef DEBUG_ADB_IOP
	printk("adb_iop_listen %p: rcvd packet, %d bytes: %02X %02X", req,
<<<<<<< HEAD
		(uint) amsg->count + 2, (uint) amsg->flags, (uint) amsg->cmd);
	for (i = 0; i < amsg->count; i++)
		printk(" %02X", (uint) amsg->data[i]);
=======
	       (uint)amsg->count + 2, (uint)amsg->flags, (uint)amsg->cmd);
	for (i = 0; i < amsg->count; i++)
		printk(" %02X", (uint)amsg->data[i]);
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
	printk("\n");
#endif

	/* Handle a timeout. Timeout packets seem to occur even after */
	/* we've gotten a valid reply to a TALK, so I'm assuming that */
	/* a "timeout" is actually more like an "end-of-data" signal. */
	/* We need to send back a timeout packet to the IOP to shut   */
	/* it up, plus complete the current request, if any.          */

	if (amsg->flags & ADB_IOP_TIMEOUT) {
		msg->reply[0] = ADB_IOP_TIMEOUT | ADB_IOP_AUTOPOLL;
		msg->reply[1] = 0;
		msg->reply[2] = 0;
		if (req && (adb_iop_state != idle)) {
			adb_iop_end_req(req, idle);
		}
	} else {
		/* TODO: is it possible for more than one chunk of data  */
		/*       to arrive before the timeout? If so we need to */
		/*       use reply_ptr here like the other drivers do.  */
		if ((adb_iop_state == awaiting_reply) &&
		    (amsg->flags & ADB_IOP_EXPLICIT)) {
			req->reply_len = amsg->count + 1;
			memcpy(req->reply, &amsg->cmd, req->reply_len);
		} else {
			adb_input(&amsg->cmd, amsg->count + 1,
				  amsg->flags & ADB_IOP_AUTOPOLL);
		}
		memcpy(msg->reply, msg->message, IOP_MSG_LEN);
	}
	iop_complete_message(msg);
	local_irq_restore(flags);
}

/*
 * Start sending an ADB packet, IOP style
 *
 * There isn't much to do other than hand the packet over to the IOP
 * after encapsulating it in an adb_iopmsg.
 */

static void adb_iop_start(void)
{
	unsigned long flags;
	struct adb_request *req;
	struct adb_iopmsg amsg;
#ifdef DEBUG_ADB_IOP
	int i;
#endif

	/* get the packet to send */
	req = current_req;
<<<<<<< HEAD
	if (!req) return;
=======
	if (!req)
		return;
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533

	local_irq_save(flags);

#ifdef DEBUG_ADB_IOP
	printk("adb_iop_start %p: sending packet, %d bytes:", req, req->nbytes);
<<<<<<< HEAD
	for (i = 0 ; i < req->nbytes ; i++)
		printk(" %02X", (uint) req->data[i]);
=======
	for (i = 0; i < req->nbytes; i++)
		printk(" %02X", (uint)req->data[i]);
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
	printk("\n");
#endif

	/* The IOP takes MacII-style packets, so */
	/* strip the initial ADB_PACKET byte.    */

	amsg.flags = ADB_IOP_EXPLICIT;
	amsg.count = req->nbytes - 2;

	/* amsg.data immediately follows amsg.cmd, effectively making */
	/* amsg.cmd a pointer to the beginning of a full ADB packet.  */
	memcpy(&amsg.cmd, req->data + 1, req->nbytes - 1);

	req->sent = 1;
	adb_iop_state = sending;
	local_irq_restore(flags);

	/* Now send it. The IOP manager will call adb_iop_complete */
	/* when the packet has been sent.                          */

<<<<<<< HEAD
	iop_send_message(ADB_IOP, ADB_CHAN, req,
			 sizeof(amsg), (__u8 *) &amsg, adb_iop_complete);
=======
	iop_send_message(ADB_IOP, ADB_CHAN, req, sizeof(amsg), (__u8 *)&amsg,
			 adb_iop_complete);
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
}

int adb_iop_probe(void)
{
<<<<<<< HEAD
	if (!iop_ism_present) return -ENODEV;
=======
	if (!iop_ism_present)
		return -ENODEV;
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
	return 0;
}

int adb_iop_init(void)
{
	printk("adb: IOP ISM driver v0.4 for Unified ADB.\n");
	iop_listen(ADB_IOP, ADB_CHAN, adb_iop_listen, "ADB");
	return 0;
}

int adb_iop_send_request(struct adb_request *req, int sync)
{
	int err;

	err = adb_iop_write(req);
<<<<<<< HEAD
	if (err) return err;

	if (sync) {
		while (!req->complete) adb_iop_poll();
=======
	if (err)
		return err;

	if (sync) {
		while (!req->complete)
			adb_iop_poll();
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
	}
	return 0;
}

static int adb_iop_write(struct adb_request *req)
{
	unsigned long flags;

	if ((req->nbytes < 2) || (req->data[0] != ADB_PACKET)) {
		req->complete = 1;
		return -EINVAL;
	}

	local_irq_save(flags);

	req->next = NULL;
	req->sent = 0;
	req->complete = 0;
	req->reply_len = 0;

	if (current_req != 0) {
		last_req->next = req;
		last_req = req;
	} else {
		current_req = req;
		last_req = req;
	}

	local_irq_restore(flags);
<<<<<<< HEAD
	if (adb_iop_state == idle) adb_iop_start();
=======

	if (adb_iop_state == idle)
		adb_iop_start();
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
	return 0;
}

int adb_iop_autopoll(int devs)
{
	/* TODO: how do we enable/disable autopoll? */
	return 0;
}

void adb_iop_poll(void)
{
<<<<<<< HEAD
	if (adb_iop_state == idle) adb_iop_start();
=======
	if (adb_iop_state == idle)
		adb_iop_start();
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
	iop_ism_irq_poll(ADB_IOP);
}

int adb_iop_reset_bus(void)
{
	struct adb_request req = {
		.reply_expected = 0,
		.nbytes = 2,
		.data = { ADB_PACKET, 0 },
	};

	adb_iop_write(&req);
	while (!req.complete) {
		adb_iop_poll();
		schedule();
	}

	return 0;
}
