/*
 * ASIX AX88179/178A USB 3.0/2.0 to Gigabit Ethernet Devices
 *
 * Copyright (C) 2011-2013 ASIX
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
<<<<<<< HEAD
 */

#include <linux/module.h>
#include <linux/etherdevice.h>
#include <linux/mii.h>
#include <linux/usb.h>
#include <linux/crc32.h>
#include <linux/usb/usbnet.h>
#include <uapi/linux/mdio.h>
#include <linux/mdio.h>

#define AX88179_PHY_ID				0x03
#define AX_EEPROM_LEN				0x100
#define AX88179_EEPROM_MAGIC			0x17900b95
#define AX_MCAST_FLTSIZE			8
#define AX_MAX_MCAST				64
#define AX_INT_PPLS_LINK			((u32)BIT(16))
#define AX_RXHDR_L4_TYPE_MASK			0x1c
#define AX_RXHDR_L4_TYPE_UDP			4
#define AX_RXHDR_L4_TYPE_TCP			16
#define AX_RXHDR_L3CSUM_ERR			2
#define AX_RXHDR_L4CSUM_ERR			1
#define AX_RXHDR_CRC_ERR			((u32)BIT(29))
#define AX_RXHDR_DROP_ERR			((u32)BIT(31))
#define AX_ACCESS_MAC				0x01
#define AX_ACCESS_PHY				0x02
#define AX_ACCESS_EEPROM			0x04
#define AX_ACCESS_EFUS				0x05
#define AX_PAUSE_WATERLVL_HIGH			0x54
#define AX_PAUSE_WATERLVL_LOW			0x55

#define PHYSICAL_LINK_STATUS			0x02
	#define	AX_USB_SS		0x04
	#define	AX_USB_HS		0x02

#define GENERAL_STATUS				0x03
/* Check AX88179 version. UA1:Bit2 = 0,  UA2:Bit2 = 1 */
	#define	AX_SECLD		0x04

#define AX_SROM_ADDR				0x07
#define AX_SROM_CMD				0x0a
	#define EEP_RD			0x04
	#define EEP_BUSY		0x10

#define AX_SROM_DATA_LOW			0x08
#define AX_SROM_DATA_HIGH			0x09

#define AX_RX_CTL				0x0b
	#define AX_RX_CTL_DROPCRCERR	0x0100
	#define AX_RX_CTL_IPE		0x0200
	#define AX_RX_CTL_START		0x0080
	#define AX_RX_CTL_AP		0x0020
	#define AX_RX_CTL_AM		0x0010
	#define AX_RX_CTL_AB		0x0008
	#define AX_RX_CTL_AMALL		0x0002
	#define AX_RX_CTL_PRO		0x0001
	#define AX_RX_CTL_STOP		0x0000

#define AX_NODE_ID				0x10
#define AX_MULFLTARY				0x16

#define AX_MEDIUM_STATUS_MODE			0x22
	#define AX_MEDIUM_GIGAMODE	0x01
	#define AX_MEDIUM_FULL_DUPLEX	0x02
	#define AX_MEDIUM_EN_125MHZ	0x08
	#define AX_MEDIUM_RXFLOW_CTRLEN	0x10
	#define AX_MEDIUM_TXFLOW_CTRLEN	0x20
	#define AX_MEDIUM_RECEIVE_EN	0x100
	#define AX_MEDIUM_PS		0x200
	#define AX_MEDIUM_JUMBO_EN	0x8040

#define AX_MONITOR_MOD				0x24
	#define AX_MONITOR_MODE_RWLC	0x02
	#define AX_MONITOR_MODE_RWMP	0x04
	#define AX_MONITOR_MODE_PMEPOL	0x20
	#define AX_MONITOR_MODE_PMETYPE	0x40

#define AX_GPIO_CTRL				0x25
	#define AX_GPIO_CTRL_GPIO3EN	0x80
	#define AX_GPIO_CTRL_GPIO2EN	0x40
	#define AX_GPIO_CTRL_GPIO1EN	0x20

#define AX_PHYPWR_RSTCTL			0x26
	#define AX_PHYPWR_RSTCTL_BZ	0x0010
	#define AX_PHYPWR_RSTCTL_IPRL	0x0020
	#define AX_PHYPWR_RSTCTL_AT	0x1000

#define AX_RX_BULKIN_QCTRL			0x2e
#define AX_CLK_SELECT				0x33
	#define AX_CLK_SELECT_BCS	0x01
	#define AX_CLK_SELECT_ACS	0x02
	#define AX_CLK_SELECT_ULR	0x08

#define AX_RXCOE_CTL				0x34
	#define AX_RXCOE_IP		0x01
	#define AX_RXCOE_TCP		0x02
	#define AX_RXCOE_UDP		0x04
	#define AX_RXCOE_TCPV6		0x20
	#define AX_RXCOE_UDPV6		0x40

#define AX_TXCOE_CTL				0x35
	#define AX_TXCOE_IP		0x01
	#define AX_TXCOE_TCP		0x02
	#define AX_TXCOE_UDP		0x04
	#define AX_TXCOE_TCPV6		0x20
	#define AX_TXCOE_UDPV6		0x40

#define AX_LEDCTRL				0x73

#define GMII_PHY_PHYSR				0x11
	#define GMII_PHY_PHYSR_SMASK	0xc000
	#define GMII_PHY_PHYSR_GIGA	0x8000
	#define GMII_PHY_PHYSR_100	0x4000
	#define GMII_PHY_PHYSR_FULL	0x2000
	#define GMII_PHY_PHYSR_LINK	0x400

#define GMII_LED_ACT				0x1a
	#define	GMII_LED_ACTIVE_MASK	0xff8f
	#define	GMII_LED0_ACTIVE	BIT(4)
	#define	GMII_LED1_ACTIVE	BIT(5)
	#define	GMII_LED2_ACTIVE	BIT(6)

#define GMII_LED_LINK				0x1c
	#define	GMII_LED_LINK_MASK	0xf888
	#define	GMII_LED0_LINK_10	BIT(0)
	#define	GMII_LED0_LINK_100	BIT(1)
	#define	GMII_LED0_LINK_1000	BIT(2)
	#define	GMII_LED1_LINK_10	BIT(4)
	#define	GMII_LED1_LINK_100	BIT(5)
	#define	GMII_LED1_LINK_1000	BIT(6)
	#define	GMII_LED2_LINK_10	BIT(8)
	#define	GMII_LED2_LINK_100	BIT(9)
	#define	GMII_LED2_LINK_1000	BIT(10)
	#define	LED0_ACTIVE		BIT(0)
	#define	LED0_LINK_10		BIT(1)
	#define	LED0_LINK_100		BIT(2)
	#define	LED0_LINK_1000		BIT(3)
	#define	LED0_FD			BIT(4)
	#define	LED0_USB3_MASK		0x001f
	#define	LED1_ACTIVE		BIT(5)
	#define	LED1_LINK_10		BIT(6)
	#define	LED1_LINK_100		BIT(7)
	#define	LED1_LINK_1000		BIT(8)
	#define	LED1_FD			BIT(9)
	#define	LED1_USB3_MASK		0x03e0
	#define	LED2_ACTIVE		BIT(10)
	#define	LED2_LINK_1000		BIT(13)
	#define	LED2_LINK_100		BIT(12)
	#define	LED2_LINK_10		BIT(11)
	#define	LED2_FD			BIT(14)
	#define	LED_VALID		BIT(15)
	#define	LED2_USB3_MASK		0x7c00

#define GMII_PHYPAGE				0x1e
#define GMII_PHY_PAGE_SELECT			0x1f
	#define GMII_PHY_PGSEL_EXT	0x0007
	#define GMII_PHY_PGSEL_PAGE0	0x0000
	#define GMII_PHY_PGSEL_PAGE3	0x0003
	#define GMII_PHY_PGSEL_PAGE5	0x0005

struct ax88179_data {
	u8  eee_enabled;
	u8  eee_active;
	u16 rxctl;
	u16 reserved;
};

struct ax88179_int_data {
	__le32 intdata1;
	__le32 intdata2;
};

static const struct {
	unsigned char ctrl, timer_l, timer_h, size, ifg;
} AX88179_BULKIN_SIZE[] =	{
	{7, 0x4f, 0,	0x12, 0xff},
	{7, 0x20, 3,	0x16, 0xff},
	{7, 0xae, 7,	0x18, 0xff},
	{7, 0xcc, 0x4c, 0x18, 8},
};

static int __ax88179_read_cmd(struct usbnet *dev, u8 cmd, u16 value, u16 index,
			      u16 size, void *data, int in_pm)
{
	int ret;
	int (*fn)(struct usbnet *, u8, u8, u16, u16, void *, u16);

	BUG_ON(!dev);

	if (!in_pm)
		fn = usbnet_read_cmd;
	else
		fn = usbnet_read_cmd_nopm;

	ret = fn(dev, cmd, USB_DIR_IN | USB_TYPE_VENDOR | USB_RECIP_DEVICE,
		 value, index, data, size);

	if (unlikely(ret < 0))
		netdev_warn(dev->net, "Failed to read reg index 0x%04x: %d\n",
			    index, ret);

	return ret;
}

static int __ax88179_write_cmd(struct usbnet *dev, u8 cmd, u16 value, u16 index,
			       u16 size, void *data, int in_pm)
{
	int ret;
	int (*fn)(struct usbnet *, u8, u8, u16, u16, const void *, u16);

	BUG_ON(!dev);

	if (!in_pm)
		fn = usbnet_write_cmd;
	else
		fn = usbnet_write_cmd_nopm;

	ret = fn(dev, cmd, USB_DIR_OUT | USB_TYPE_VENDOR | USB_RECIP_DEVICE,
		 value, index, data, size);

	if (unlikely(ret < 0))
		netdev_warn(dev->net, "Failed to write reg index 0x%04x: %d\n",
			    index, ret);

	return ret;
}

static void ax88179_write_cmd_async(struct usbnet *dev, u8 cmd, u16 value,
				    u16 index, u16 size, void *data)
{
	u16 buf;

	if (2 == size) {
		buf = *((u16 *)data);
		cpu_to_le16s(&buf);
		usbnet_write_cmd_async(dev, cmd, USB_DIR_OUT | USB_TYPE_VENDOR |
				       USB_RECIP_DEVICE, value, index, &buf,
				       size);
	} else {
		usbnet_write_cmd_async(dev, cmd, USB_DIR_OUT | USB_TYPE_VENDOR |
				       USB_RECIP_DEVICE, value, index, data,
				       size);
	}
}

static int ax88179_read_cmd_nopm(struct usbnet *dev, u8 cmd, u16 value,
				 u16 index, u16 size, void *data)
{
	int ret;

	if (2 == size) {
		u16 buf;
		ret = __ax88179_read_cmd(dev, cmd, value, index, size, &buf, 1);
		le16_to_cpus(&buf);
		*((u16 *)data) = buf;
	} else if (4 == size) {
		u32 buf;
		ret = __ax88179_read_cmd(dev, cmd, value, index, size, &buf, 1);
		le32_to_cpus(&buf);
		*((u32 *)data) = buf;
	} else {
		ret = __ax88179_read_cmd(dev, cmd, value, index, size, data, 1);
	}

	return ret;
}

static int ax88179_write_cmd_nopm(struct usbnet *dev, u8 cmd, u16 value,
				  u16 index, u16 size, void *data)
{
	int ret;

	if (2 == size) {
		u16 buf;
		buf = *((u16 *)data);
		cpu_to_le16s(&buf);
		ret = __ax88179_write_cmd(dev, cmd, value, index,
					  size, &buf, 1);
	} else {
		ret = __ax88179_write_cmd(dev, cmd, value, index,
					  size, data, 1);
	}

	return ret;
}

static int ax88179_read_cmd(struct usbnet *dev, u8 cmd, u16 value, u16 index,
			    u16 size, void *data)
{
	int ret;

	if (2 == size) {
		u16 buf;
		ret = __ax88179_read_cmd(dev, cmd, value, index, size, &buf, 0);
		le16_to_cpus(&buf);
		*((u16 *)data) = buf;
	} else if (4 == size) {
		u32 buf;
		ret = __ax88179_read_cmd(dev, cmd, value, index, size, &buf, 0);
		le32_to_cpus(&buf);
		*((u32 *)data) = buf;
	} else {
		ret = __ax88179_read_cmd(dev, cmd, value, index, size, data, 0);
	}

	return ret;
}

static int ax88179_write_cmd(struct usbnet *dev, u8 cmd, u16 value, u16 index,
			     u16 size, void *data)
{
	int ret;

	if (2 == size) {
		u16 buf;
		buf = *((u16 *)data);
		cpu_to_le16s(&buf);
		ret = __ax88179_write_cmd(dev, cmd, value, index,
					  size, &buf, 0);
	} else {
		ret = __ax88179_write_cmd(dev, cmd, value, index,
					  size, data, 0);
	}

	return ret;
}

static void ax88179_status(struct usbnet *dev, struct urb *urb)
{
	struct ax88179_int_data *event;
	u32 link;

	if (urb->actual_length < 8)
		return;

	event = urb->transfer_buffer;
	le32_to_cpus((void *)&event->intdata1);

	link = (((__force u32)event->intdata1) & AX_INT_PPLS_LINK) >> 16;

	if (netif_carrier_ok(dev->net) != link) {
		usbnet_link_change(dev, link, 1);
		netdev_info(dev->net, "ax88179 - Link status is: %d\n", link);
	}
}

static int ax88179_mdio_read(struct net_device *netdev, int phy_id, int loc)
{
	struct usbnet *dev = netdev_priv(netdev);
	u16 res;

	ax88179_read_cmd(dev, AX_ACCESS_PHY, phy_id, (__u16)loc, 2, &res);
	return res;
}

static void ax88179_mdio_write(struct net_device *netdev, int phy_id, int loc,
			       int val)
{
	struct usbnet *dev = netdev_priv(netdev);
	u16 res = (u16) val;

	ax88179_write_cmd(dev, AX_ACCESS_PHY, phy_id, (__u16)loc, 2, &res);
}

static inline int ax88179_phy_mmd_indirect(struct usbnet *dev, u16 prtad,
					   u16 devad)
{
	u16 tmp16;
	int ret;

	tmp16 = devad;
	ret = ax88179_write_cmd(dev, AX_ACCESS_PHY, AX88179_PHY_ID,
				MII_MMD_CTRL, 2, &tmp16);

	tmp16 = prtad;
	ret = ax88179_write_cmd(dev, AX_ACCESS_PHY, AX88179_PHY_ID,
				MII_MMD_DATA, 2, &tmp16);

	tmp16 = devad | MII_MMD_CTRL_NOINCR;
	ret = ax88179_write_cmd(dev, AX_ACCESS_PHY, AX88179_PHY_ID,
				MII_MMD_CTRL, 2, &tmp16);

	return ret;
}

static int
ax88179_phy_read_mmd_indirect(struct usbnet *dev, u16 prtad, u16 devad)
{
	int ret;
	u16 tmp16;

	ax88179_phy_mmd_indirect(dev, prtad, devad);

	ret = ax88179_read_cmd(dev, AX_ACCESS_PHY, AX88179_PHY_ID,
			       MII_MMD_DATA, 2, &tmp16);
	if (ret < 0)
		return ret;

	return tmp16;
}

static int
ax88179_phy_write_mmd_indirect(struct usbnet *dev, u16 prtad, u16 devad,
			       u16 data)
{
	int ret;

	ax88179_phy_mmd_indirect(dev, prtad, devad);

	ret = ax88179_write_cmd(dev, AX_ACCESS_PHY, AX88179_PHY_ID,
				MII_MMD_DATA, 2, &data);

	if (ret < 0)
		return ret;

	return 0;
}

static int ax88179_suspend(struct usb_interface *intf, pm_message_t message)
{
	struct usbnet *dev = usb_get_intfdata(intf);
	u16 tmp16;
	u8 tmp8;

	usbnet_suspend(intf, message);

	/* Disable RX path */
	ax88179_read_cmd_nopm(dev, AX_ACCESS_MAC, AX_MEDIUM_STATUS_MODE,
			      2, 2, &tmp16);
	tmp16 &= ~AX_MEDIUM_RECEIVE_EN;
	ax88179_write_cmd_nopm(dev, AX_ACCESS_MAC, AX_MEDIUM_STATUS_MODE,
			       2, 2, &tmp16);

	/* Force bulk-in zero length */
	ax88179_read_cmd_nopm(dev, AX_ACCESS_MAC, AX_PHYPWR_RSTCTL,
			      2, 2, &tmp16);

	tmp16 |= AX_PHYPWR_RSTCTL_BZ | AX_PHYPWR_RSTCTL_IPRL;
	ax88179_write_cmd_nopm(dev, AX_ACCESS_MAC, AX_PHYPWR_RSTCTL,
			       2, 2, &tmp16);

	/* change clock */
	tmp8 = 0;
	ax88179_write_cmd_nopm(dev, AX_ACCESS_MAC, AX_CLK_SELECT, 1, 1, &tmp8);

	/* Configure RX control register => stop operation */
	tmp16 = AX_RX_CTL_STOP;
	ax88179_write_cmd_nopm(dev, AX_ACCESS_MAC, AX_RX_CTL, 2, 2, &tmp16);

	return 0;
}

/* This function is used to enable the autodetach function. */
/* This function is determined by offset 0x43 of EEPROM */
static int ax88179_auto_detach(struct usbnet *dev, int in_pm)
{
	u16 tmp16;
	u8 tmp8;
	int (*fnr)(struct usbnet *, u8, u16, u16, u16, void *);
	int (*fnw)(struct usbnet *, u8, u16, u16, u16, void *);

	if (!in_pm) {
		fnr = ax88179_read_cmd;
		fnw = ax88179_write_cmd;
	} else {
		fnr = ax88179_read_cmd_nopm;
		fnw = ax88179_write_cmd_nopm;
	}

	if (fnr(dev, AX_ACCESS_EEPROM, 0x43, 1, 2, &tmp16) < 0)
		return 0;

	if ((tmp16 == 0xFFFF) || (!(tmp16 & 0x0100)))
		return 0;

	/* Enable Auto Detach bit */
	tmp8 = 0;
	fnr(dev, AX_ACCESS_MAC, AX_CLK_SELECT, 1, 1, &tmp8);
	tmp8 |= AX_CLK_SELECT_ULR;
	fnw(dev, AX_ACCESS_MAC, AX_CLK_SELECT, 1, 1, &tmp8);

	fnr(dev, AX_ACCESS_MAC, AX_PHYPWR_RSTCTL, 2, 2, &tmp16);
	tmp16 |= AX_PHYPWR_RSTCTL_AT;
	fnw(dev, AX_ACCESS_MAC, AX_PHYPWR_RSTCTL, 2, 2, &tmp16);

	return 0;
}

static int ax88179_resume(struct usb_interface *intf)
{
	struct usbnet *dev = usb_get_intfdata(intf);
	u16 tmp16;
	u8 tmp8;

	usbnet_link_change(dev, 0, 0);

	/* Power up ethernet PHY */
	tmp16 = 0;
	ax88179_write_cmd_nopm(dev, AX_ACCESS_MAC, AX_PHYPWR_RSTCTL,
			       2, 2, &tmp16);
	udelay(1000);

	tmp16 = AX_PHYPWR_RSTCTL_IPRL;
	ax88179_write_cmd_nopm(dev, AX_ACCESS_MAC, AX_PHYPWR_RSTCTL,
			       2, 2, &tmp16);
	msleep(200);

	/* Ethernet PHY Auto Detach*/
	ax88179_auto_detach(dev, 1);

	/* Enable clock */
	ax88179_read_cmd_nopm(dev, AX_ACCESS_MAC,  AX_CLK_SELECT, 1, 1, &tmp8);
	tmp8 |= AX_CLK_SELECT_ACS | AX_CLK_SELECT_BCS;
	ax88179_write_cmd_nopm(dev, AX_ACCESS_MAC, AX_CLK_SELECT, 1, 1, &tmp8);
	msleep(100);

	/* Configure RX control register => start operation */
	tmp16 = AX_RX_CTL_DROPCRCERR | AX_RX_CTL_IPE | AX_RX_CTL_START |
		AX_RX_CTL_AP | AX_RX_CTL_AMALL | AX_RX_CTL_AB;
	ax88179_write_cmd_nopm(dev, AX_ACCESS_MAC, AX_RX_CTL, 2, 2, &tmp16);

	return usbnet_resume(intf);
}

static void
ax88179_get_wol(struct net_device *net, struct ethtool_wolinfo *wolinfo)
{
	struct usbnet *dev = netdev_priv(net);
	u8 opt;

	if (ax88179_read_cmd(dev, AX_ACCESS_MAC, AX_MONITOR_MOD,
			     1, 1, &opt) < 0) {
		wolinfo->supported = 0;
		wolinfo->wolopts = 0;
		return;
	}

	wolinfo->supported = WAKE_PHY | WAKE_MAGIC;
	wolinfo->wolopts = 0;
	if (opt & AX_MONITOR_MODE_RWLC)
		wolinfo->wolopts |= WAKE_PHY;
	if (opt & AX_MONITOR_MODE_RWMP)
		wolinfo->wolopts |= WAKE_MAGIC;
}

static int
ax88179_set_wol(struct net_device *net, struct ethtool_wolinfo *wolinfo)
{
	struct usbnet *dev = netdev_priv(net);
	u8 opt = 0;

	if (wolinfo->wolopts & ~(WAKE_PHY | WAKE_MAGIC))
		return -EINVAL;

	if (wolinfo->wolopts & WAKE_PHY)
		opt |= AX_MONITOR_MODE_RWLC;
	if (wolinfo->wolopts & WAKE_MAGIC)
		opt |= AX_MONITOR_MODE_RWMP;

	if (ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_MONITOR_MOD,
			      1, 1, &opt) < 0)
		return -EINVAL;

	return 0;
}

static int ax88179_get_eeprom_len(struct net_device *net)
{
	return AX_EEPROM_LEN;
}

static int
ax88179_get_eeprom(struct net_device *net, struct ethtool_eeprom *eeprom,
		   u8 *data)
{
	struct usbnet *dev = netdev_priv(net);
	u16 *eeprom_buff;
	int first_word, last_word;
	int i, ret;

	if (eeprom->len == 0)
		return -EINVAL;

	eeprom->magic = AX88179_EEPROM_MAGIC;

	first_word = eeprom->offset >> 1;
	last_word = (eeprom->offset + eeprom->len - 1) >> 1;
	eeprom_buff = kmalloc_array(last_word - first_word + 1, sizeof(u16),
				    GFP_KERNEL);
	if (!eeprom_buff)
		return -ENOMEM;

	/* ax88179/178A returns 2 bytes from eeprom on read */
	for (i = first_word; i <= last_word; i++) {
		ret = __ax88179_read_cmd(dev, AX_ACCESS_EEPROM, i, 1, 2,
					 &eeprom_buff[i - first_word],
					 0);
		if (ret < 0) {
			kfree(eeprom_buff);
			return -EIO;
		}
	}

	memcpy(data, (u8 *)eeprom_buff + (eeprom->offset & 1), eeprom->len);
	kfree(eeprom_buff);
	return 0;
}

static int ax88179_get_link_ksettings(struct net_device *net,
				      struct ethtool_link_ksettings *cmd)
{
	struct usbnet *dev = netdev_priv(net);

	mii_ethtool_get_link_ksettings(&dev->mii, cmd);

	return 0;
}

static int ax88179_set_link_ksettings(struct net_device *net,
				      const struct ethtool_link_ksettings *cmd)
{
	struct usbnet *dev = netdev_priv(net);
	return mii_ethtool_set_link_ksettings(&dev->mii, cmd);
}

static int
ax88179_ethtool_get_eee(struct usbnet *dev, struct ethtool_eee *data)
{
	int val;

	/* Get Supported EEE */
	val = ax88179_phy_read_mmd_indirect(dev, MDIO_PCS_EEE_ABLE,
					    MDIO_MMD_PCS);
	if (val < 0)
		return val;
	data->supported = mmd_eee_cap_to_ethtool_sup_t(val);

	/* Get advertisement EEE */
	val = ax88179_phy_read_mmd_indirect(dev, MDIO_AN_EEE_ADV,
					    MDIO_MMD_AN);
	if (val < 0)
		return val;
	data->advertised = mmd_eee_adv_to_ethtool_adv_t(val);

	/* Get LP advertisement EEE */
	val = ax88179_phy_read_mmd_indirect(dev, MDIO_AN_EEE_LPABLE,
					    MDIO_MMD_AN);
	if (val < 0)
		return val;
	data->lp_advertised = mmd_eee_adv_to_ethtool_adv_t(val);

	return 0;
}

static int
ax88179_ethtool_set_eee(struct usbnet *dev, struct ethtool_eee *data)
{
	u16 tmp16 = ethtool_adv_to_mmd_eee_adv_t(data->advertised);

	return ax88179_phy_write_mmd_indirect(dev, MDIO_AN_EEE_ADV,
					      MDIO_MMD_AN, tmp16);
}

static int ax88179_chk_eee(struct usbnet *dev)
{
	struct ethtool_cmd ecmd = { .cmd = ETHTOOL_GSET };
	struct ax88179_data *priv = (struct ax88179_data *)dev->data;

	mii_ethtool_gset(&dev->mii, &ecmd);

	if (ecmd.duplex & DUPLEX_FULL) {
		int eee_lp, eee_cap, eee_adv;
		u32 lp, cap, adv, supported = 0;

		eee_cap = ax88179_phy_read_mmd_indirect(dev,
							MDIO_PCS_EEE_ABLE,
							MDIO_MMD_PCS);
		if (eee_cap < 0) {
			priv->eee_active = 0;
			return false;
		}

		cap = mmd_eee_cap_to_ethtool_sup_t(eee_cap);
		if (!cap) {
			priv->eee_active = 0;
			return false;
		}

		eee_lp = ax88179_phy_read_mmd_indirect(dev,
						       MDIO_AN_EEE_LPABLE,
						       MDIO_MMD_AN);
		if (eee_lp < 0) {
			priv->eee_active = 0;
			return false;
		}

		eee_adv = ax88179_phy_read_mmd_indirect(dev,
							MDIO_AN_EEE_ADV,
							MDIO_MMD_AN);

		if (eee_adv < 0) {
			priv->eee_active = 0;
			return false;
		}

		adv = mmd_eee_adv_to_ethtool_adv_t(eee_adv);
		lp = mmd_eee_adv_to_ethtool_adv_t(eee_lp);
		supported = (ecmd.speed == SPEED_1000) ?
			     SUPPORTED_1000baseT_Full :
			     SUPPORTED_100baseT_Full;

		if (!(lp & adv & supported)) {
			priv->eee_active = 0;
			return false;
		}

		priv->eee_active = 1;
		return true;
	}

	priv->eee_active = 0;
	return false;
}

static void ax88179_disable_eee(struct usbnet *dev)
{
	u16 tmp16;

	tmp16 = GMII_PHY_PGSEL_PAGE3;
	ax88179_write_cmd(dev, AX_ACCESS_PHY, AX88179_PHY_ID,
			  GMII_PHY_PAGE_SELECT, 2, &tmp16);

	tmp16 = 0x3246;
	ax88179_write_cmd(dev, AX_ACCESS_PHY, AX88179_PHY_ID,
			  MII_PHYADDR, 2, &tmp16);

	tmp16 = GMII_PHY_PGSEL_PAGE0;
	ax88179_write_cmd(dev, AX_ACCESS_PHY, AX88179_PHY_ID,
			  GMII_PHY_PAGE_SELECT, 2, &tmp16);
}

static void ax88179_enable_eee(struct usbnet *dev)
{
	u16 tmp16;

	tmp16 = GMII_PHY_PGSEL_PAGE3;
	ax88179_write_cmd(dev, AX_ACCESS_PHY, AX88179_PHY_ID,
			  GMII_PHY_PAGE_SELECT, 2, &tmp16);

	tmp16 = 0x3247;
	ax88179_write_cmd(dev, AX_ACCESS_PHY, AX88179_PHY_ID,
			  MII_PHYADDR, 2, &tmp16);

	tmp16 = GMII_PHY_PGSEL_PAGE5;
	ax88179_write_cmd(dev, AX_ACCESS_PHY, AX88179_PHY_ID,
			  GMII_PHY_PAGE_SELECT, 2, &tmp16);

	tmp16 = 0x0680;
	ax88179_write_cmd(dev, AX_ACCESS_PHY, AX88179_PHY_ID,
			  MII_BMSR, 2, &tmp16);

	tmp16 = GMII_PHY_PGSEL_PAGE0;
	ax88179_write_cmd(dev, AX_ACCESS_PHY, AX88179_PHY_ID,
			  GMII_PHY_PAGE_SELECT, 2, &tmp16);
}

static int ax88179_get_eee(struct net_device *net, struct ethtool_eee *edata)
{
	struct usbnet *dev = netdev_priv(net);
	struct ax88179_data *priv = (struct ax88179_data *)dev->data;

	edata->eee_enabled = priv->eee_enabled;
	edata->eee_active = priv->eee_active;

	return ax88179_ethtool_get_eee(dev, edata);
}

static int ax88179_set_eee(struct net_device *net, struct ethtool_eee *edata)
{
	struct usbnet *dev = netdev_priv(net);
	struct ax88179_data *priv = (struct ax88179_data *)dev->data;
	int ret = -EOPNOTSUPP;

	priv->eee_enabled = edata->eee_enabled;
	if (!priv->eee_enabled) {
		ax88179_disable_eee(dev);
	} else {
		priv->eee_enabled = ax88179_chk_eee(dev);
		if (!priv->eee_enabled)
			return -EOPNOTSUPP;

		ax88179_enable_eee(dev);
	}

	ret = ax88179_ethtool_set_eee(dev, edata);
	if (ret)
		return ret;

	mii_nway_restart(&dev->mii);

	usbnet_link_change(dev, 0, 0);
=======
 *
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2022    ASIX Electronic Corporation    All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details
 *
 * You should have received a copy of the GNU General Public License along with
 * this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include "ax_main.h"
#include "ax88179_178a.h"

struct _ax_buikin_setting AX88179_BULKIN_SIZE[] = {
	{7, 0x70, 0,	0x0C, 0x0f},
	{7, 0x70, 0,	0x0C, 0x0f},
	{7, 0x20, 3,	0x16, 0xff},
	{7, 0xae, 7,	0x18, 0xff},
};
const struct ethtool_ops ax88179_ethtool_ops = {
	.get_drvinfo	= ax_get_drvinfo,
#if KERNEL_VERSION(4, 10, 0) > LINUX_VERSION_CODE
	.get_settings	= ax_get_settings,
	.set_settings	= ax_set_settings,
#else
	.get_link_ksettings = ax_get_link_ksettings,
	.set_link_ksettings = ax_set_link_ksettings,
#endif
	.get_link	= ethtool_op_get_link,
	.get_msglevel	= ax_get_msglevel,
	.set_msglevel	= ax_set_msglevel,
	.get_wol	= ax_get_wol,
	.set_wol	= ax_set_wol,
	.get_ts_info	= ethtool_op_get_ts_info,
	.get_strings	= ax_get_strings,
	.get_sset_count = ax_get_sset_count,
	.get_ethtool_stats = ax_get_ethtool_stats,
	.get_regs_len	= ax_get_regs_len,
	.get_regs	= ax_get_regs,
};

int ax88179_signature(struct ax_device *axdev, struct _ax_ioctl_command *info)
{
	strlcpy(info->sig, AX88179_SIGNATURE, sizeof(info->sig));
	return 0;
}

int ax88179_read_eeprom(struct ax_device *axdev, struct _ax_ioctl_command *info)
{
	u8 i;
	u16 tmp;
	u8 value;
	unsigned short *buf;

	if (info->buf != NULL) {
		buf = kmalloc_array(info->size, sizeof(unsigned short),
				    GFP_KERNEL);
		if (!buf) {
#if KERNEL_VERSION(2, 6, 34) <= LINUX_VERSION_CODE
			netdev_err(axdev->netdev,
				   "Cannot allocate memory for buffer");
#endif
			return -ENOMEM;
		}
	} else {
		netdev_info(axdev->netdev,
			    "The EEPROM buffer cannot be NULL. \r\n");
		return -EINVAL;
	}

	if (info->type == 0) {
		for (i = 0; i < info->size; i++) {

			if (ax_write_cmd(axdev, AX_ACCESS_MAC,
					      AX_SROM_ADDR, 1, 1, &i) < 0) {
				kfree(buf);
				return -EINVAL;
			}

			value = EEP_RD;
			if (ax_write_cmd(axdev, AX_ACCESS_MAC,
					      AX_SROM_CMD, 1, 1, &value) < 0) {
				kfree(buf);
				return -EINVAL;
			}

			do {
				ax_read_cmd(axdev, AX_ACCESS_MAC,
						 AX_SROM_CMD, 1, 1, &value, 0);
			} while (value & EEP_BUSY);

			if (ax_read_cmd(axdev, AX_ACCESS_MAC,
					     AX_SROM_DATA_LOW, 2, 2,
					     &tmp, 1) < 0) {
				kfree(buf);
				return -EINVAL;
			}

			*(buf + i) = be16_to_cpu(tmp);

			if (i == (info->size - 1))
				break;
		}
	} else {
		for (i = 0; i < info->size; i++) {
			if (ax_read_cmd(axdev, AX_ACCESS_EFUSE, i,
					     1, 2, &tmp, 1) < 0) {
				kfree(buf);
				return -EINVAL;
			}
			*(buf + i) = be16_to_cpu(tmp);
			if (i == (info->size - 1))
				break;
		}
	}

	if (copy_to_user(info->buf, buf, sizeof(unsigned short) * info->size)) {
		kfree(buf);
		return -EFAULT;
	}

	kfree(buf);

	return 0;
}

int ax88179_write_eeprom(struct ax_device *axdev,
			 struct _ax_ioctl_command *info)
{
	int i;
	u16 data, csum = 0;
	unsigned short *buf;

	if (info->buf != NULL) {
		buf = kmalloc_array(info->size, sizeof(unsigned short),
				    GFP_KERNEL);
		if (!buf) {
#if KERNEL_VERSION(2, 6, 34) <= LINUX_VERSION_CODE
			netdev_err(axdev->netdev,
				   "Cannot allocate memory for buffer");
#endif
			return -ENOMEM;
		}
		if (copy_from_user(buf, info->buf,
				   sizeof(unsigned short) * info->size)) {
			kfree(buf);
			return -EFAULT;
		}
	} else {
		netdev_err(axdev->netdev,
			   "The EEPROM buffer cannot be NULL. \r\n");
		return -EINVAL;
	}

	if (info->type == 0) {
		if ((*(buf) >> 8) & 0x01) {
			netdev_info(axdev->netdev,
				"Cannot be set to muliticast MAC address, ");
			netdev_info(axdev->netdev,
				"bit0 of Node ID-0 cannot be set to 1. \r\n");
			kfree(buf);
			return -EINVAL;
		}

		csum = (*(buf + 3) & 0xff) + ((*(buf + 3) >> 8) & 0xff) +
		       (*(buf + 4) & 0xff) + ((*(buf + 4) >> 8) & 0xff);
		csum = 0xff - ((csum >> 8) + (csum & 0xff));
		data = ((*(buf + 5)) & 0xff) | (csum << 8);
		*(buf + 5) = data;

		for (i = 0; i < info->size; i++) {
			data = cpu_to_be16(*(buf + i));
			if (ax_write_cmd(axdev, AX_ACCESS_EEPROM,
					      i, 1, 2, &data) < 0) {
				kfree(buf);
				return -EINVAL;
			}

			mdelay(info->delay);
		}
	} else if (info->type == 1) {
		if ((*(buf) >> 8) & 0x01) {
			netdev_info(axdev->netdev,
				"Cannot be set to muliticast MAC address, ");
			netdev_info(axdev->netdev,
				"bit0 of Node ID-0 cannot be set to 1. \r\n");
			kfree(buf);
			return -EINVAL;
		}

		for (i = 0; i < info->size; i++)
			csum += (*(buf + i)&0xff) + ((*(buf + i) >> 8)&0xff);

		csum -= ((*(buf + 0x19) >> 8) & 0xff);
		while (csum > 255)
			csum = (csum & 0x00FF) + ((csum >> 8) & 0x00FF);
		csum = 0xFF - csum;

		data = ((*(buf + 0x19)) & 0xff) | (csum << 8);
		*(buf + 0x19) = data;

		if (ax_write_cmd(axdev, AX_WRITE_EFUSE_EN,
				      0, 0, 0, NULL) < 0) {
			kfree(buf);
			return -EINVAL;
		}

		mdelay(info->delay);

		for (i = 0; i < info->size; i++) {
			data = cpu_to_be16(*(buf + i));
			if (ax_write_cmd(axdev, AX_ACCESS_EFUSE,
					      i, 1, 2, &data) < 0) {
				kfree(buf);
				return -EINVAL;
			}

			mdelay(info->delay);
		}

		if (ax_write_cmd(axdev, AX_WRITE_EFUSE_DIS,
				 0, 0, 0, NULL) < 0) {
			kfree(buf);
			return -EINVAL;
		}

		mdelay(info->delay);
	} else if (info->type == 2) {
		if (ax_read_cmd(axdev, AX_ACCESS_EFUSE,
				0, 1, 2, &data, 1) < 0) {
			kfree(buf);
			return -EINVAL;
		}

		if (data == 0xFFFF)
			info->type = 0;
		else
			info->type = 1;
	} else {
		kfree(buf);
		return -EINVAL;
	}

	kfree(buf);
	return 0;
}

IOCTRL_TABLE ax88179_tbl[] = {
	ax88179_signature,
	NULL,//ax_usb_command,
	ax88179_read_eeprom,
	ax88179_write_eeprom,
};

#if KERNEL_VERSION(5, 15, 0) <= LINUX_VERSION_CODE
int ax88179_siocdevprivate(struct net_device *netdev, struct ifreq *rq,
			   void __user *udata, int cmd)
{
	struct ax_device *axdev = netdev_priv(netdev);
	struct _ax_ioctl_command info;
	struct _ax_ioctl_command *uptr =
				(struct _ax_ioctl_command *) rq->ifr_data;
	int ret = 0;

	switch (cmd) {
	case AX_PRIVATE:
		if (copy_from_user(&info, uptr,
				   sizeof(struct _ax_ioctl_command)))
			return -EFAULT;

		if ((*ax88179_tbl[info.ioctl_cmd])(axdev, &info) < 0) {
			netdev_info(netdev, "ax88179_tbl, return -EFAULT");
			return -EFAULT;
		}

		if (copy_to_user(uptr, &info, sizeof(struct _ax_ioctl_command)))
			return -EFAULT;

		break;
	default:
		ret = -EOPNOTSUPP;
	}
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533

	return ret;
}

<<<<<<< HEAD
static int ax88179_ioctl(struct net_device *net, struct ifreq *rq, int cmd)
{
	struct usbnet *dev = netdev_priv(net);
	return generic_mii_ioctl(&dev->mii, if_mii(rq), cmd, NULL);
}

static const struct ethtool_ops ax88179_ethtool_ops = {
	.get_link		= ethtool_op_get_link,
	.get_msglevel		= usbnet_get_msglevel,
	.set_msglevel		= usbnet_set_msglevel,
	.get_wol		= ax88179_get_wol,
	.set_wol		= ax88179_set_wol,
	.get_eeprom_len		= ax88179_get_eeprom_len,
	.get_eeprom		= ax88179_get_eeprom,
	.get_eee		= ax88179_get_eee,
	.set_eee		= ax88179_set_eee,
	.nway_reset		= usbnet_nway_reset,
	.get_link_ksettings	= ax88179_get_link_ksettings,
	.set_link_ksettings	= ax88179_set_link_ksettings,
};

static void ax88179_set_multicast(struct net_device *net)
{
	struct usbnet *dev = netdev_priv(net);
	struct ax88179_data *data = (struct ax88179_data *)dev->data;
	u8 *m_filter = ((u8 *)dev->data) + 12;

	data->rxctl = (AX_RX_CTL_START | AX_RX_CTL_AB | AX_RX_CTL_IPE);

	if (net->flags & IFF_PROMISC) {
		data->rxctl |= AX_RX_CTL_PRO;
	} else if (net->flags & IFF_ALLMULTI ||
		   netdev_mc_count(net) > AX_MAX_MCAST) {
		data->rxctl |= AX_RX_CTL_AMALL;
	} else if (netdev_mc_empty(net)) {
		/* just broadcast and directed */
	} else {
		/* We use the 20 byte dev->data for our 8 byte filter buffer
		 * to avoid allocating memory that is tricky to free later
		 */
		u32 crc_bits;
		struct netdev_hw_addr *ha;

		memset(m_filter, 0, AX_MCAST_FLTSIZE);

		netdev_for_each_mc_addr(ha, net) {
			crc_bits = ether_crc(ETH_ALEN, ha->addr) >> 26;
			*(m_filter + (crc_bits >> 3)) |= (1 << (crc_bits & 7));
		}

		ax88179_write_cmd_async(dev, AX_ACCESS_MAC, AX_MULFLTARY,
					AX_MCAST_FLTSIZE, AX_MCAST_FLTSIZE,
					m_filter);

		data->rxctl |= AX_RX_CTL_AM;
	}

	ax88179_write_cmd_async(dev, AX_ACCESS_MAC, AX_RX_CTL,
				2, 2, &data->rxctl);
}

static int
ax88179_set_features(struct net_device *net, netdev_features_t features)
{
	u8 tmp;
	struct usbnet *dev = netdev_priv(net);
	netdev_features_t changed = net->features ^ features;

	if (changed & NETIF_F_IP_CSUM) {
		ax88179_read_cmd(dev, AX_ACCESS_MAC, AX_TXCOE_CTL, 1, 1, &tmp);
		tmp ^= AX_TXCOE_TCP | AX_TXCOE_UDP;
		ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_TXCOE_CTL, 1, 1, &tmp);
	}

	if (changed & NETIF_F_IPV6_CSUM) {
		ax88179_read_cmd(dev, AX_ACCESS_MAC, AX_TXCOE_CTL, 1, 1, &tmp);
		tmp ^= AX_TXCOE_TCPV6 | AX_TXCOE_UDPV6;
		ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_TXCOE_CTL, 1, 1, &tmp);
	}

	if (changed & NETIF_F_RXCSUM) {
		ax88179_read_cmd(dev, AX_ACCESS_MAC, AX_RXCOE_CTL, 1, 1, &tmp);
		tmp ^= AX_RXCOE_IP | AX_RXCOE_TCP | AX_RXCOE_UDP |
		       AX_RXCOE_TCPV6 | AX_RXCOE_UDPV6;
		ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_RXCOE_CTL, 1, 1, &tmp);
	}

	return 0;
}

static int ax88179_change_mtu(struct net_device *net, int new_mtu)
{
	struct usbnet *dev = netdev_priv(net);
	u16 tmp16;

	net->mtu = new_mtu;
	dev->hard_mtu = net->mtu + net->hard_header_len;

	if (net->mtu > 1500) {
		ax88179_read_cmd(dev, AX_ACCESS_MAC, AX_MEDIUM_STATUS_MODE,
				 2, 2, &tmp16);
		tmp16 |= AX_MEDIUM_JUMBO_EN;
		ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_MEDIUM_STATUS_MODE,
				  2, 2, &tmp16);
	} else {
		ax88179_read_cmd(dev, AX_ACCESS_MAC, AX_MEDIUM_STATUS_MODE,
				 2, 2, &tmp16);
		tmp16 &= ~AX_MEDIUM_JUMBO_EN;
		ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_MEDIUM_STATUS_MODE,
				  2, 2, &tmp16);
	}

	/* max qlen depend on hard_mtu and rx_urb_size */
	usbnet_update_max_qlen(dev);

	return 0;
}

static int ax88179_set_mac_addr(struct net_device *net, void *p)
{
	struct usbnet *dev = netdev_priv(net);
	struct sockaddr *addr = p;
	int ret;

	if (netif_running(net))
		return -EBUSY;
	if (!is_valid_ether_addr(addr->sa_data))
		return -EADDRNOTAVAIL;

	memcpy(net->dev_addr, addr->sa_data, ETH_ALEN);

	/* Set the MAC address */
	ret = ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_NODE_ID, ETH_ALEN,
				 ETH_ALEN, net->dev_addr);
=======
int ax88179_ioctl(struct net_device *netdev, struct ifreq *rq, int cmd)
{
	struct ax_device *axdev = netdev_priv(netdev);

	return generic_mii_ioctl(&axdev->mii, if_mii(rq), cmd, NULL);
}
#else
int ax88179_ioctl(struct net_device *netdev, struct ifreq *rq, int cmd)
{
	struct ax_device *axdev = netdev_priv(netdev);
	struct _ax_ioctl_command info;
	struct _ax_ioctl_command *uptr =
				(struct _ax_ioctl_command *) rq->ifr_data;

	switch (cmd) {
	case AX_PRIVATE:
		if (copy_from_user(&info, uptr,
				   sizeof(struct _ax_ioctl_command)))
			return -EFAULT;

		if ((*ax88179_tbl[info.ioctl_cmd])(axdev, &info) < 0) {
			netdev_info(netdev, "ax88179_tbl, return -EFAULT");
			return -EFAULT;
		}

		if (copy_to_user(uptr, &info, sizeof(struct _ax_ioctl_command)))
			return -EFAULT;

		break;
	default:
		return  generic_mii_ioctl(&axdev->mii, if_mii(rq), cmd, NULL);
	}
	return 0;
}
#endif

void ax88179_set_multicast(struct net_device *net)
{
	struct ax_device *axdev = netdev_priv(net);
	u8 *m_filter = axdev->m_filter;
	int mc_count = 0;

	if (!test_bit(AX_ENABLE, &axdev->flags))
		return;

#if KERNEL_VERSION(2, 6, 35) > LINUX_VERSION_CODE
	mc_count = net->mc_count;
#else
	mc_count = netdev_mc_count(net);
#endif

	axdev->rxctl = (AX_RX_CTL_START | AX_RX_CTL_AB);

	if (net->flags & IFF_PROMISC) {
		axdev->rxctl |= AX_RX_CTL_PRO;
	} else if (net->flags & IFF_ALLMULTI
		   || mc_count > AX_MAX_MCAST) {
		axdev->rxctl |= AX_RX_CTL_AMALL;
	} else if (mc_count == 0) {
	} else {
		u32 crc_bits;
#if KERNEL_VERSION(2, 6, 35) > LINUX_VERSION_CODE
		struct dev_mc_list *mc_list = net->mc_list;
		int i = 0;

		memset(m_filter, 0, AX_MCAST_FILTER_SIZE);

		for (i = 0; i < net->mc_count; i++) {
			crc_bits = ether_crc(ETH_ALEN,
					     mc_list->dmi_addr) >> 26;
			*(m_filter + (crc_bits >> 3)) |=
				1 << (crc_bits & 7);
			mc_list = mc_list->next;
		}
#else
		struct netdev_hw_addr *ha = NULL;

		memset(m_filter, 0, AX_MCAST_FILTER_SIZE);
		netdev_for_each_mc_addr(ha, net) {
			crc_bits = ether_crc(ETH_ALEN, ha->addr) >> 26;
			*(m_filter + (crc_bits >> 3)) |=
				1 << (crc_bits & 7);
		}
#endif
		ax_write_cmd_async(axdev, AX_ACCESS_MAC,
					AX_MULTI_FILTER_ARRY,
					AX_MCAST_FILTER_SIZE,
					AX_MCAST_FILTER_SIZE, m_filter);

		axdev->rxctl |= AX_RX_CTL_AM;
	}

	ax_write_cmd_async(axdev, AX_ACCESS_MAC, AX_RX_CTL,
				2, 2, &axdev->rxctl);
}

int ax88179_set_mac_addr(struct net_device *netdev, void *p)
{
	struct ax_device *axdev = netdev_priv(netdev);
	struct sockaddr *addr = p;
	int ret;

	if (!is_valid_ether_addr(addr->sa_data))
		return -EADDRNOTAVAIL;

	if (netif_running(netdev))
		return -EBUSY;

	memcpy(netdev->dev_addr, addr->sa_data, ETH_ALEN);

	ret = ax_write_cmd(axdev, AX_ACCESS_MAC, AX_NODE_ID, ETH_ALEN,
			   ETH_ALEN, netdev->dev_addr);
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
	if (ret < 0)
		return ret;

	return 0;
<<<<<<< HEAD
}

static const struct net_device_ops ax88179_netdev_ops = {
	.ndo_open		= usbnet_open,
	.ndo_stop		= usbnet_stop,
	.ndo_start_xmit		= usbnet_start_xmit,
	.ndo_tx_timeout		= usbnet_tx_timeout,
	.ndo_get_stats64	= usbnet_get_stats64,
	.ndo_change_mtu		= ax88179_change_mtu,
	.ndo_set_mac_address	= ax88179_set_mac_addr,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_do_ioctl		= ax88179_ioctl,
	.ndo_set_rx_mode	= ax88179_set_multicast,
	.ndo_set_features	= ax88179_set_features,
};

static int ax88179_check_eeprom(struct usbnet *dev)
{
	u8 i, buf, eeprom[20];
	u16 csum, delay = HZ / 10;
	unsigned long jtimeout;

	/* Read EEPROM content */
	for (i = 0; i < 6; i++) {
		buf = i;
		if (ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_SROM_ADDR,
				      1, 1, &buf) < 0)
			return -EINVAL;

		buf = EEP_RD;
		if (ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_SROM_CMD,
				      1, 1, &buf) < 0)
			return -EINVAL;

		jtimeout = jiffies + delay;
		do {
			ax88179_read_cmd(dev, AX_ACCESS_MAC, AX_SROM_CMD,
					 1, 1, &buf);

			if (time_after(jiffies, jtimeout))
				return -EINVAL;

		} while (buf & EEP_BUSY);

		__ax88179_read_cmd(dev, AX_ACCESS_MAC, AX_SROM_DATA_LOW,
				   2, 2, &eeprom[i * 2], 0);
=======

}

static int ax88179_check_eeprom(struct ax_device *axdev)
{
	u8 i = 0;
	u8 buf[2];
	u8 eeprom[20];
	u16 csum = 0, delay = HZ / 10;

	for (i = 0 ; i < 6; i++) {
		buf[0] = i;
		if (ax_write_cmd(axdev, AX_ACCESS_MAC, AX_SROM_ADDR,
				      1, 1, buf) < 0)
			return -EINVAL;

		buf[0] = EEP_RD;
		if (ax_write_cmd(axdev, AX_ACCESS_MAC, AX_SROM_CMD,
				      1, 1, buf) < 0)
			return -EINVAL;

		do {
			ax_read_cmd(axdev, AX_ACCESS_MAC, AX_SROM_CMD,
					 1, 1, buf, 0);

			if (time_after(jiffies, (jiffies + delay)))
				return -EINVAL;
		} while (buf[0] & EEP_BUSY);

		ax_read_cmd(axdev, AX_ACCESS_MAC, AX_SROM_DATA_LOW,
				 2, 2, &eeprom[i * 2], 0);
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533

		if ((i == 0) && (eeprom[0] == 0xFF))
			return -EINVAL;
	}

	csum = eeprom[6] + eeprom[7] + eeprom[8] + eeprom[9];
	csum = (csum >> 8) + (csum & 0xff);
<<<<<<< HEAD
	if ((csum + eeprom[10]) != 0xff)
=======

	if ((csum + eeprom[10]) == 0xff)
		return 0;
	else
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
		return -EINVAL;

	return 0;
}

<<<<<<< HEAD
static int ax88179_check_efuse(struct usbnet *dev, u16 *ledmode)
{
	u8	i;
	u8	efuse[64];
	u16	csum = 0;

	if (ax88179_read_cmd(dev, AX_ACCESS_EFUS, 0, 64, 64, efuse) < 0)
		return -EINVAL;

	if (*efuse == 0xFF)
=======
static int ax88179_check_efuse(struct ax_device *axdev, void *ledmode)
{
	u8	i = 0;
	u16	csum = 0;
	u8	efuse[64];

	if (ax_read_cmd(axdev, AX_ACCESS_EFUSE, 0, 64, 64, efuse, 0) < 0)
		return -EINVAL;

	if (efuse[0] == 0xFF)
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
		return -EINVAL;

	for (i = 0; i < 64; i++)
		csum = csum + efuse[i];

	while (csum > 255)
		csum = (csum & 0x00FF) + ((csum >> 8) & 0x00FF);

<<<<<<< HEAD
	if (csum != 0xFF)
		return -EINVAL;

	*ledmode = (efuse[51] << 8) | efuse[52];

	return 0;
}

static int ax88179_convert_old_led(struct usbnet *dev, u16 *ledvalue)
{
	u16 led;

	/* Loaded the old eFuse LED Mode */
	if (ax88179_read_cmd(dev, AX_ACCESS_EEPROM, 0x3C, 1, 2, &led) < 0)
		return -EINVAL;

	led >>= 8;
	switch (led) {
=======
	if (csum == 0xFF) {
		memcpy((u8 *)ledmode, &efuse[51], 2);
		return 0;
	} else
		return -EINVAL;

	return 0;
}

static int ax88179_convert_old_led(struct ax_device *axdev, u8 efuse, void *ledvalue)
{
	u8 ledmode = 0;
	u16 reg16;
	u16 led = 0;

	/* loaded the old eFuse LED Mode */
	if (efuse) {
		if (ax_read_cmd(axdev, AX_ACCESS_EFUSE, 0x18,
				     1, 2, &reg16, 1) < 0)
			return -EINVAL;
		ledmode = (u8)(reg16 & 0xFF);
	} else { /* loaded the old EEprom LED Mode */
		if (ax_read_cmd(axdev, AX_ACCESS_EEPROM, 0x3C,
				     1, 2, &reg16, 1) < 0)
			return -EINVAL;
		ledmode = (u8) (reg16 >> 8);
	}
	netdev_dbg(axdev->netdev, "Old LED Mode = %02X\n", ledmode);

	switch (ledmode) {
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
	case 0xFF:
		led = LED0_ACTIVE | LED1_LINK_10 | LED1_LINK_100 |
		      LED1_LINK_1000 | LED2_ACTIVE | LED2_LINK_10 |
		      LED2_LINK_100 | LED2_LINK_1000 | LED_VALID;
		break;
	case 0xFE:
		led = LED0_ACTIVE | LED1_LINK_1000 | LED2_LINK_100 | LED_VALID;
		break;
	case 0xFD:
		led = LED0_ACTIVE | LED1_LINK_1000 | LED2_LINK_100 |
		      LED2_LINK_10 | LED_VALID;
		break;
	case 0xFC:
		led = LED0_ACTIVE | LED1_ACTIVE | LED1_LINK_1000 | LED2_ACTIVE |
		      LED2_LINK_100 | LED2_LINK_10 | LED_VALID;
		break;
	default:
		led = LED0_ACTIVE | LED1_LINK_10 | LED1_LINK_100 |
		      LED1_LINK_1000 | LED2_ACTIVE | LED2_LINK_10 |
		      LED2_LINK_100 | LED2_LINK_1000 | LED_VALID;
		break;
	}

<<<<<<< HEAD
	*ledvalue = led;
=======
	memcpy((u8 *)ledvalue, &led, 2);
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533

	return 0;
}

<<<<<<< HEAD
static int ax88179_led_setting(struct usbnet *dev)
{
	u8 ledfd, value = 0;
	u16 tmp, ledact, ledlink, ledvalue = 0, delay = HZ / 10;
	unsigned long jtimeout;

	/* Check AX88179 version. UA1 or UA2*/
	ax88179_read_cmd(dev, AX_ACCESS_MAC, GENERAL_STATUS, 1, 1, &value);

	if (!(value & AX_SECLD)) {	/* UA1 */
		value = AX_GPIO_CTRL_GPIO3EN | AX_GPIO_CTRL_GPIO2EN |
			AX_GPIO_CTRL_GPIO1EN;
		if (ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_GPIO_CTRL,
=======
static void ax88179_Gether_setting(struct ax_device *axdev)
{
	u16 reg16;

	reg16 = 0x03;
	ax_write_cmd(axdev, AX_ACCESS_PHY, AX88179_PHY_ID,
			  31, 2, &reg16);
	reg16 = 0x3246;
	ax_write_cmd(axdev, AX_ACCESS_PHY, AX88179_PHY_ID,
			  25, 2, &reg16);
	reg16 = 0;
	ax_write_cmd(axdev, AX_ACCESS_PHY, AX88179_PHY_ID,
			  31, 2, &reg16);
}

static int ax88179_LED_setting(struct ax_device *axdev)
{
	u16 ledvalue = 0, delay = HZ / 10;
	u16 ledact, ledlink;
	u16 reg16;
	u8 value;

	ax_read_cmd(axdev, AX_ACCESS_MAC, GENERAL_STATUS, 1, 1, &value, 0);

	if (!(value & AX_SECLD)) {
		value = AX_GPIO_CTRL_GPIO3EN | AX_GPIO_CTRL_GPIO2EN |
			AX_GPIO_CTRL_GPIO1EN;
		if (ax_write_cmd(axdev, AX_ACCESS_MAC, AX_GPIO_CTRL,
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
				      1, 1, &value) < 0)
			return -EINVAL;
	}

<<<<<<< HEAD
	/* Check EEPROM */
	if (!ax88179_check_eeprom(dev)) {
		value = 0x42;
		if (ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_SROM_ADDR,
=======
	if (!ax88179_check_eeprom(axdev)) {
		value = 0x42;
		if (ax_write_cmd(axdev, AX_ACCESS_MAC, AX_SROM_ADDR,
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
				      1, 1, &value) < 0)
			return -EINVAL;

		value = EEP_RD;
<<<<<<< HEAD
		if (ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_SROM_CMD,
				      1, 1, &value) < 0)
			return -EINVAL;

		jtimeout = jiffies + delay;
		do {
			ax88179_read_cmd(dev, AX_ACCESS_MAC, AX_SROM_CMD,
					 1, 1, &value);

			if (time_after(jiffies, jtimeout))
				return -EINVAL;

		} while (value & EEP_BUSY);

		ax88179_read_cmd(dev, AX_ACCESS_MAC, AX_SROM_DATA_HIGH,
				 1, 1, &value);
		ledvalue = (value << 8);

		ax88179_read_cmd(dev, AX_ACCESS_MAC, AX_SROM_DATA_LOW,
				 1, 1, &value);
		ledvalue |= value;

		/* load internal ROM for defaule setting */
		if ((ledvalue == 0xFFFF) || ((ledvalue & LED_VALID) == 0))
			ax88179_convert_old_led(dev, &ledvalue);

	} else if (!ax88179_check_efuse(dev, &ledvalue)) {
		if ((ledvalue == 0xFFFF) || ((ledvalue & LED_VALID) == 0))
			ax88179_convert_old_led(dev, &ledvalue);
	} else {
		ax88179_convert_old_led(dev, &ledvalue);
	}

	tmp = GMII_PHY_PGSEL_EXT;
	ax88179_write_cmd(dev, AX_ACCESS_PHY, AX88179_PHY_ID,
			  GMII_PHY_PAGE_SELECT, 2, &tmp);

	tmp = 0x2c;
	ax88179_write_cmd(dev, AX_ACCESS_PHY, AX88179_PHY_ID,
			  GMII_PHYPAGE, 2, &tmp);

	ax88179_read_cmd(dev, AX_ACCESS_PHY, AX88179_PHY_ID,
			 GMII_LED_ACT, 2, &ledact);

	ax88179_read_cmd(dev, AX_ACCESS_PHY, AX88179_PHY_ID,
			 GMII_LED_LINK, 2, &ledlink);
=======
		if (ax_write_cmd(axdev, AX_ACCESS_MAC, AX_SROM_CMD,
				      1, 1, &value) < 0)
			return -EINVAL;

		do {
			ax_read_cmd(axdev, AX_ACCESS_MAC, AX_SROM_CMD,
					 1, 1, &value, 0);

			ax_read_cmd(axdev, AX_ACCESS_MAC, AX_SROM_CMD,
					 1, 1, &value, 0);

			if (time_after(jiffies, (jiffies + delay)))
				return -EINVAL;
		} while (value & EEP_BUSY);

		ax_read_cmd(axdev, AX_ACCESS_MAC, AX_SROM_DATA_HIGH,
				 1, 1, &value, 0);
		ledvalue = (value << 8);
		ax_read_cmd(axdev, AX_ACCESS_MAC, AX_SROM_DATA_LOW,
				 1, 1, &value, 0);
		ledvalue |= value;

		if ((ledvalue == 0xFFFF) || ((ledvalue & LED_VALID) == 0))
			ax88179_convert_old_led(axdev, 0, &ledvalue);

	} else if (!ax88179_check_efuse(axdev, &ledvalue)) {
		if ((ledvalue == 0xFFFF) || ((ledvalue & LED_VALID) == 0))
			ax88179_convert_old_led(axdev, 0, &ledvalue);
	} else {
		ax88179_convert_old_led(axdev, 0, &ledvalue);
	}

	reg16 = GMII_PHY_PAGE_SELECT_EXT;
	ax_write_cmd(axdev, AX_ACCESS_PHY, AX88179_PHY_ID,
			  GMII_PHY_PAGE_SELECT, 2, &reg16);

	reg16 = 0x2c;
	ax_write_cmd(axdev, AX_ACCESS_PHY, AX88179_PHY_ID,
			  GMII_PHYPAGE, 2, &reg16);

	ax_read_cmd(axdev, AX_ACCESS_PHY, AX88179_PHY_ID,
			 GMII_LED_ACTIVE, 2, &ledact, 1);

	ax_read_cmd(axdev, AX_ACCESS_PHY, AX88179_PHY_ID,
			 GMII_LED_LINK, 2, &ledlink, 1);
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533

	ledact &= GMII_LED_ACTIVE_MASK;
	ledlink &= GMII_LED_LINK_MASK;

	if (ledvalue & LED0_ACTIVE)
		ledact |= GMII_LED0_ACTIVE;
<<<<<<< HEAD

	if (ledvalue & LED1_ACTIVE)
		ledact |= GMII_LED1_ACTIVE;

=======
	if (ledvalue & LED1_ACTIVE)
		ledact |= GMII_LED1_ACTIVE;
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
	if (ledvalue & LED2_ACTIVE)
		ledact |= GMII_LED2_ACTIVE;

	if (ledvalue & LED0_LINK_10)
		ledlink |= GMII_LED0_LINK_10;
<<<<<<< HEAD

	if (ledvalue & LED1_LINK_10)
		ledlink |= GMII_LED1_LINK_10;

=======
	if (ledvalue & LED1_LINK_10)
		ledlink |= GMII_LED1_LINK_10;
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
	if (ledvalue & LED2_LINK_10)
		ledlink |= GMII_LED2_LINK_10;

	if (ledvalue & LED0_LINK_100)
		ledlink |= GMII_LED0_LINK_100;
<<<<<<< HEAD

	if (ledvalue & LED1_LINK_100)
		ledlink |= GMII_LED1_LINK_100;

=======
	if (ledvalue & LED1_LINK_100)
		ledlink |= GMII_LED1_LINK_100;
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
	if (ledvalue & LED2_LINK_100)
		ledlink |= GMII_LED2_LINK_100;

	if (ledvalue & LED0_LINK_1000)
		ledlink |= GMII_LED0_LINK_1000;
<<<<<<< HEAD

	if (ledvalue & LED1_LINK_1000)
		ledlink |= GMII_LED1_LINK_1000;

	if (ledvalue & LED2_LINK_1000)
		ledlink |= GMII_LED2_LINK_1000;

	tmp = ledact;
	ax88179_write_cmd(dev, AX_ACCESS_PHY, AX88179_PHY_ID,
			  GMII_LED_ACT, 2, &tmp);

	tmp = ledlink;
	ax88179_write_cmd(dev, AX_ACCESS_PHY, AX88179_PHY_ID,
			  GMII_LED_LINK, 2, &tmp);

	tmp = GMII_PHY_PGSEL_PAGE0;
	ax88179_write_cmd(dev, AX_ACCESS_PHY, AX88179_PHY_ID,
			  GMII_PHY_PAGE_SELECT, 2, &tmp);

	/* LED full duplex setting */
	ledfd = 0;
	if (ledvalue & LED0_FD)
		ledfd |= 0x01;
	else if ((ledvalue & LED0_USB3_MASK) == 0)
		ledfd |= 0x02;

	if (ledvalue & LED1_FD)
		ledfd |= 0x04;
	else if ((ledvalue & LED1_USB3_MASK) == 0)
		ledfd |= 0x08;

	if (ledvalue & LED2_FD)
		ledfd |= 0x10;
	else if ((ledvalue & LED2_USB3_MASK) == 0)
		ledfd |= 0x20;

	ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_LEDCTRL, 1, 1, &ledfd);
=======
	if (ledvalue & LED1_LINK_1000)
		ledlink |= GMII_LED1_LINK_1000;
	if (ledvalue & LED2_LINK_1000)
		ledlink |= GMII_LED2_LINK_1000;

	ax_write_cmd(axdev, AX_ACCESS_PHY, AX88179_PHY_ID,
			  GMII_LED_ACTIVE, 2, &ledact);

	ax_write_cmd(axdev, AX_ACCESS_PHY, AX88179_PHY_ID,
			  GMII_LED_LINK, 2, &ledlink);

	reg16 = GMII_PHY_PAGE_SELECT_PAGE0;
	ax_write_cmd(axdev, AX_ACCESS_PHY, AX88179_PHY_ID,
			  GMII_PHY_PAGE_SELECT, 2, &reg16);

	/* LED full duplex setting */
	reg16 = 0;
	if (ledvalue & LED0_FD)
		reg16 |= 0x01;
	else if ((ledvalue & LED0_USB3_MASK) == 0)
		reg16 |= 0x02;

	if (ledvalue & LED1_FD)
		reg16 |= 0x04;
	else if ((ledvalue & LED1_USB3_MASK) == 0)
		reg16 |= 0x08;

	if (ledvalue & LED2_FD) /* LED2_FD */
		reg16 |= 0x10;
	else if ((ledvalue & LED2_USB3_MASK) == 0) /* LED2_USB3 */
		reg16 |= 0x20;

	ax_write_cmd(axdev, AX_ACCESS_MAC, 0x73, 1, 1, &reg16);
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533

	return 0;
}

<<<<<<< HEAD
static int ax88179_bind(struct usbnet *dev, struct usb_interface *intf)
{
	u8 buf[5];
	u16 *tmp16;
	u8 *tmp;
	struct ax88179_data *ax179_data = (struct ax88179_data *)dev->data;
	struct ethtool_eee eee_data;

	usbnet_get_endpoints(dev, intf);

	tmp16 = (u16 *)buf;
	tmp = (u8 *)buf;

	memset(ax179_data, 0, sizeof(*ax179_data));

	/* Power up ethernet PHY */
	*tmp16 = 0;
	ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_PHYPWR_RSTCTL, 2, 2, tmp16);
	*tmp16 = AX_PHYPWR_RSTCTL_IPRL;
	ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_PHYPWR_RSTCTL, 2, 2, tmp16);
	msleep(200);

	*tmp = AX_CLK_SELECT_ACS | AX_CLK_SELECT_BCS;
	ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_CLK_SELECT, 1, 1, tmp);
	msleep(100);

	ax88179_read_cmd(dev, AX_ACCESS_MAC, AX_NODE_ID, ETH_ALEN,
			 ETH_ALEN, dev->net->dev_addr);
	memcpy(dev->net->perm_addr, dev->net->dev_addr, ETH_ALEN);

	/* RX bulk configuration */
	memcpy(tmp, &AX88179_BULKIN_SIZE[0], 5);
	ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_RX_BULKIN_QCTRL, 5, 5, tmp);

	dev->rx_urb_size = 1024 * 20;

	*tmp = 0x34;
	ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_PAUSE_WATERLVL_LOW, 1, 1, tmp);

	*tmp = 0x52;
	ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_PAUSE_WATERLVL_HIGH,
			  1, 1, tmp);

	dev->net->netdev_ops = &ax88179_netdev_ops;
	dev->net->ethtool_ops = &ax88179_ethtool_ops;
	dev->net->needed_headroom = 8;
	dev->net->max_mtu = 4088;

	/* Initialize MII structure */
	dev->mii.dev = dev->net;
	dev->mii.mdio_read = ax88179_mdio_read;
	dev->mii.mdio_write = ax88179_mdio_write;
	dev->mii.phy_id_mask = 0xff;
	dev->mii.reg_num_mask = 0xff;
	dev->mii.phy_id = 0x03;
	dev->mii.supports_gmii = 1;

	dev->net->features |= NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM |
			      NETIF_F_RXCSUM;

	dev->net->hw_features |= NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM |
				 NETIF_F_RXCSUM;

	/* Enable checksum offload */
	*tmp = AX_RXCOE_IP | AX_RXCOE_TCP | AX_RXCOE_UDP |
	       AX_RXCOE_TCPV6 | AX_RXCOE_UDPV6;
	ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_RXCOE_CTL, 1, 1, tmp);

	*tmp = AX_TXCOE_IP | AX_TXCOE_TCP | AX_TXCOE_UDP |
	       AX_TXCOE_TCPV6 | AX_TXCOE_UDPV6;
	ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_TXCOE_CTL, 1, 1, tmp);

	/* Configure RX control register => start operation */
	*tmp16 = AX_RX_CTL_DROPCRCERR | AX_RX_CTL_IPE | AX_RX_CTL_START |
		 AX_RX_CTL_AP | AX_RX_CTL_AMALL | AX_RX_CTL_AB;
	ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_RX_CTL, 2, 2, tmp16);

	*tmp = AX_MONITOR_MODE_PMETYPE | AX_MONITOR_MODE_PMEPOL |
	       AX_MONITOR_MODE_RWMP;
	ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_MONITOR_MOD, 1, 1, tmp);

	/* Configure default medium type => giga */
	*tmp16 = AX_MEDIUM_RECEIVE_EN | AX_MEDIUM_TXFLOW_CTRLEN |
		 AX_MEDIUM_RXFLOW_CTRLEN | AX_MEDIUM_FULL_DUPLEX |
		 AX_MEDIUM_GIGAMODE;
	ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_MEDIUM_STATUS_MODE,
			  2, 2, tmp16);

	ax88179_led_setting(dev);

	ax179_data->eee_enabled = 0;
	ax179_data->eee_active = 0;

	ax88179_disable_eee(dev);

	ax88179_ethtool_get_eee(dev, &eee_data);
	eee_data.advertised = 0;
	ax88179_ethtool_set_eee(dev, &eee_data);

	/* Restart autoneg */
	mii_nway_restart(&dev->mii);

	usbnet_link_change(dev, 0, 0);
=======
static void ax88179_EEE_setting(struct ax_device *axdev)
{
	u16 reg16;
	/* Disable */
	reg16 = 0x07;
	ax_write_cmd(axdev, AX_ACCESS_PHY, AX88179_PHY_ID,
				GMII_PHY_MACR, 2, &reg16);
	reg16 = 0x3c;
	ax_write_cmd(axdev, AX_ACCESS_PHY, AX88179_PHY_ID,
				GMII_PHY_MAADR, 2, &reg16);
	reg16 = 0x4007;
	ax_write_cmd(axdev, AX_ACCESS_PHY, AX88179_PHY_ID,
				GMII_PHY_MACR, 2, &reg16);
	reg16 = 0x00;
	ax_write_cmd(axdev, AX_ACCESS_PHY, AX88179_PHY_ID,
				GMII_PHY_MAADR, 2, &reg16);
}

static int ax88179_AutoDetach(struct ax_device *axdev, int in_pm)
{
	u16 reg16;
	usb_read_function fnr;
	usb_write_function fnw;

	if (!in_pm) {
		fnr = ax_read_cmd;
		fnw = ax_write_cmd;
	} else {
		fnr = ax_read_cmd_nopm;
		fnw = ax_write_cmd_nopm;
	}

	if (fnr(axdev, AX_ACCESS_EEPROM, 0x43, 1, 2, &reg16, 1) < 0)
		return 0;

	if ((reg16 == 0xFFFF) || (!(reg16 & 0x0100)))
		return 0;

	reg16 = 0;
	fnr(axdev, AX_ACCESS_MAC, AX_CLK_SELECT, 1, 1, &reg16, 0);
	reg16 |= AX_CLK_SELECT_ULR;
	fnw(axdev, AX_ACCESS_MAC, AX_CLK_SELECT, 1, 1, &reg16);

	fnr(axdev, AX_ACCESS_MAC, AX_PHYPWR_RSTCTL, 2, 2, &reg16, 1);
	reg16 |= AX_PHYPWR_RSTCTL_AUTODETACH;
	fnw(axdev, AX_ACCESS_MAC, AX_PHYPWR_RSTCTL, 2, 2, &reg16);

	return 0;
}

static int ax88179_hw_init(struct ax_device *axdev)
{
	u32 reg32;
	u16 reg16;
	u8 reg8;
	u8 buf[6] = {0};

	reg32 = 0;
	ax_write_cmd(axdev, 0x81, 0x310, 0, 4, &reg32);

	reg16 = 0;
	ax_write_cmd(axdev, AX_ACCESS_MAC, AX_PHYPWR_RSTCTL, 2, 2, &reg16);
	reg16 = AX_PHYPWR_RSTCTL_IPRL;
	ax_write_cmd(axdev, AX_ACCESS_MAC, AX_PHYPWR_RSTCTL, 2, 2, &reg16);
	msleep(200);

	reg8 = AX_CLK_SELECT_ACS | AX_CLK_SELECT_BCS;
	ax_write_cmd(axdev, AX_ACCESS_MAC, AX_CLK_SELECT, 1, 1, &reg8);
	msleep(100);

	ax88179_AutoDetach(axdev, 0);

	memcpy(buf, &AX88179_BULKIN_SIZE[0], 5);
	ax_write_cmd(axdev, AX_ACCESS_MAC, AX_RX_BULKIN_QCTRL, 5, 5, buf);

	reg8 = 0x34;
	ax_write_cmd(axdev, AX_ACCESS_MAC, AX_PAUSE_WATERLVL_LOW,
			  1, 1, &reg8);

	reg8 = 0x52;
	ax_write_cmd(axdev, AX_ACCESS_MAC, AX_PAUSE_WATERLVL_HIGH,
			  1, 1, &reg8);

	ax_write_cmd(axdev, 0x91, 0, 0, 0, NULL);

	reg8 = AX_RXCOE_IP | AX_RXCOE_TCP | AX_RXCOE_UDP |
	       AX_RXCOE_TCPV6 | AX_RXCOE_UDPV6;
	ax_write_cmd(axdev, AX_ACCESS_MAC, AX_RXCOE_CTL, 1, 1, &reg8);

	reg8 = AX_TXCOE_IP | AX_TXCOE_TCP | AX_TXCOE_UDP |
	       AX_TXCOE_TCPV6 | AX_TXCOE_UDPV6;
	ax_write_cmd(axdev, AX_ACCESS_MAC, AX_TXCOE_CTL, 1, 1, &reg8);

	reg8 = AX_MONITOR_MODE_PMETYPE | AX_MONITOR_MODE_PMEPOL |
	       AX_MONITOR_MODE_RWLC | AX_MONITOR_MODE_RWMP;
	ax_write_cmd(axdev, AX_ACCESS_MAC, AX_MONITOR_MODE, 1, 1, &reg8);

	ax88179_LED_setting(axdev);

	ax88179_EEE_setting(axdev);

	ax88179_Gether_setting(axdev);

	ax_set_tx_qlen(axdev);

	mii_nway_restart(&axdev->mii);

	return 0;

}

static int ax88179_bind(struct ax_device *axdev)
{
	struct net_device *netdev = axdev->netdev;

	PRINT_VERSION(axdev, AX_DRIVER_STRING_179_178A);

	netdev->features    |= NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM |
			       NETIF_F_SG | NETIF_F_TSO | NETIF_F_FRAGLIST;
	netdev->hw_features |= NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM |
			       NETIF_F_SG | NETIF_F_TSO | NETIF_F_FRAGLIST;

	axdev->tx_casecade_size = TX_CASECADES_SIZE;
	axdev->gso_max_size = AX_GSO_DEFAULT_SIZE;
	axdev->mii.supports_gmii = 1;
	axdev->mii.dev = netdev;
	axdev->mii.mdio_read = ax_mdio_read;
	axdev->mii.mdio_write = ax_mdio_write;
	axdev->mii.phy_id_mask = 0xff;
	axdev->mii.reg_num_mask = 0xff;
	axdev->mii.phy_id = AX88179_PHY_ID;
	axdev->mii.force_media = 0;
	axdev->mii.advertising = ADVERTISE_10HALF | ADVERTISE_10FULL |
				 ADVERTISE_100HALF | ADVERTISE_100FULL;
	netif_set_gso_max_size(netdev, axdev->gso_max_size);

	axdev->bin_setting.custom = 1;
	axdev->tx_align_len = 4;

	netdev->ethtool_ops = &ax88179_ethtool_ops;
	axdev->netdev->netdev_ops = &ax88179_netdev_ops;
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533

	return 0;
}

<<<<<<< HEAD
static void ax88179_unbind(struct usbnet *dev, struct usb_interface *intf)
{
	u16 tmp16;

	/* Configure RX control register => stop operation */
	tmp16 = AX_RX_CTL_STOP;
	ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_RX_CTL, 2, 2, &tmp16);

	tmp16 = 0;
	ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_CLK_SELECT, 1, 1, &tmp16);

	/* Power down ethernet PHY */
	tmp16 = 0;
	ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_PHYPWR_RSTCTL, 2, 2, &tmp16);
}

static void
ax88179_rx_checksum(struct sk_buff *skb, u32 *pkt_hdr)
{
	skb->ip_summed = CHECKSUM_NONE;

	/* checksum error bit is set */
=======
static void ax88179_unbind(struct ax_device *axdev)
{

}

static int ax88179_stop(struct ax_device *axdev)
{
	u16 reg16;

	reg16 = AX_RX_CTL_STOP;
	ax_write_cmd(axdev, AX_ACCESS_MAC, AX_MEDIUM_STATUS_MODE, 2, 2, &reg16);

	reg16 = 0;
	ax_write_cmd(axdev, AX_ACCESS_MAC, AX_CLK_SELECT, 1, 1, &reg16);

	reg16 = AX_PHYPWR_RSTCTL_BZ;
	ax_write_cmd(axdev, AX_ACCESS_MAC, AX_PHYPWR_RSTCTL, 2, 2, &reg16);
	msleep(200);

	return 0;
}

static int ax88179_link_reset(struct ax_device *axdev)
{
	u8 reg8[5], link_sts;
	u16 mode, reg16, delay;
	u32 reg32;

	mode = AX_MEDIUM_TXFLOW_CTRLEN | AX_MEDIUM_RXFLOW_CTRLEN;

	ax_read_cmd_nopm(axdev, AX_ACCESS_MAC, PHYSICAL_LINK_STATUS,
			 1, 1, &link_sts, 0);
	ax_read_cmd_nopm(axdev, AX_ACCESS_PHY, AX88179_PHY_ID,
			 GMII_PHY_PHYSR, 2, &reg16, 1);

	if (!(reg16 & GMII_PHY_PHYSR_LINK)) {
		return -1;
	} else if (GMII_PHY_PHYSR_GIGA == (reg16 & GMII_PHY_PHYSR_SMASK)) {
		mode |= AX_MEDIUM_GIGAMODE;
		if (axdev->netdev->mtu > 1500)
			mode |= AX_MEDIUM_JUMBO_EN;

		if (link_sts & AX_USB_SS)
			memcpy(reg8, &AX88179_BULKIN_SIZE[0], 5);
		else if (link_sts & AX_USB_HS)
			memcpy(reg8, &AX88179_BULKIN_SIZE[1], 5);
		else
			memcpy(reg8, &AX88179_BULKIN_SIZE[3], 5);
	} else if (GMII_PHY_PHYSR_100 == (reg16 & GMII_PHY_PHYSR_SMASK)) {
		mode |= AX_MEDIUM_PS;
		if (link_sts & (AX_USB_SS | AX_USB_HS))
			memcpy(reg8, &AX88179_BULKIN_SIZE[2], 5);
		else
			memcpy(reg8, &AX88179_BULKIN_SIZE[3], 5);
	} else {
		memcpy(reg8, &AX88179_BULKIN_SIZE[3], 5);
	}

	ax_write_cmd_nopm(axdev, AX_ACCESS_MAC, AX_RX_BULKIN_QCTRL, 5, 5, reg8);

	if (reg16 & GMII_PHY_PHYSR_FULL)
		mode |= AX_MEDIUM_FULL_DUPLEX;

	ax_read_cmd_nopm(axdev, 0x81, 0x8c, 0, 4, &reg32, 1);
	delay = HZ / 2;
	if (reg32 & 0x40000000) {
		unsigned long jtimeout;
		u16 temp16 = 0;

		ax_write_cmd_nopm(axdev, AX_ACCESS_MAC, AX_RX_CTL,
				  2, 2, &temp16);
		ax_write_cmd_nopm(axdev, AX_ACCESS_MAC, AX_MEDIUM_STATUS_MODE,
				  2, 2, &mode);

		jtimeout = jiffies + delay;
		while (time_before(jiffies, jtimeout)) {
			ax_read_cmd_nopm(axdev, 0x81, 0x8c, 0, 4, &reg32, 1);

			if (!(reg32 & 0x40000000))
				break;

			reg32 = 0x80000000;
			ax_write_cmd(axdev, 0x81, 0x8c, 0, 4, &reg32);
		}

		temp16 = AX_RX_CTL_DROPCRCERR | AX_RX_CTL_START |
			 AX_RX_CTL_AP | AX_RX_CTL_AMALL | AX_RX_CTL_AB;
		ax_write_cmd_nopm(axdev, AX_ACCESS_MAC, AX_RX_CTL,
				  2, 2, &temp16);
	}

	axdev->rxctl |= AX_RX_CTL_DROPCRCERR | AX_RX_CTL_START | AX_RX_CTL_AB;
	ax_write_cmd_nopm(axdev, AX_ACCESS_MAC, AX_RX_CTL,
			  2, 2, &axdev->rxctl);

	mode |= AX_MEDIUM_RECEIVE_EN;
	ax_write_cmd_nopm(axdev, AX_ACCESS_MAC, AX_MEDIUM_STATUS_MODE,
			  2, 2, &mode);

	return 0;
}


static int ax88179_tx_fixup(struct ax_device *axdev, struct tx_desc *desc)
{
	struct sk_buff_head skb_head, *tx_queue = &axdev->tx_queue[0];
	struct net_device_stats *stats = &axdev->netdev->stats;
	int remain, ret;
	u8 *tx_data;

	__skb_queue_head_init(&skb_head);
	spin_lock(&tx_queue->lock);
	skb_queue_splice_init(tx_queue, &skb_head);
	spin_unlock(&tx_queue->lock);

	tx_data = desc->head;
	desc->skb_num = 0;
	desc->skb_len = 0;
	remain = axdev->tx_casecade_size;

	while (remain >= ETH_ZLEN + 8) {
		struct sk_buff *skb;
		u32 *tx_hdr1, *tx_hdr2;

		skb = __skb_dequeue(&skb_head);
		if (!skb)
			break;

		if ((skb->len + AX_TX_HEADER_LEN) > remain &&
		    (skb_shinfo(skb)->gso_size == 0)) {
			__skb_queue_head(&skb_head, skb);
			break;
		}

		memset(tx_data, 0, AX_TX_HEADER_LEN);
		tx_hdr1 = (u32 *)tx_data;
		tx_hdr2 = tx_hdr1 + 1;
		*tx_hdr1 = skb->len;
		*tx_hdr2 = skb_shinfo(skb)->gso_size;
		cpu_to_le32s(tx_hdr1);
		cpu_to_le32s(tx_hdr2);
		tx_data += 8;

		if (skb_copy_bits(skb, 0, tx_data, skb->len) < 0) {
			stats->tx_dropped++;
			dev_kfree_skb_any(skb);
			continue;
		}

		tx_data += skb->len;
		desc->skb_len += skb->len;
		desc->skb_num += skb_shinfo(skb)->gso_segs ?: 1;
		dev_kfree_skb_any(skb);

		tx_data = __tx_buf_align(tx_data, axdev->tx_align_len);
		if (*tx_hdr2 > 0)
			break;
		remain = axdev->tx_casecade_size -
			 (int)((void *)tx_data - desc->head);
	}

	if (!skb_queue_empty(&skb_head)) {
		spin_lock(&tx_queue->lock);
		skb_queue_splice(&skb_head, tx_queue);
		spin_unlock(&tx_queue->lock);
	}

	netif_tx_lock(axdev->netdev);

	if (netif_queue_stopped(axdev->netdev) &&
	    skb_queue_len(tx_queue) < axdev->tx_qlen) {
		netif_wake_queue(axdev->netdev);
	}

	netif_tx_unlock(axdev->netdev);

	ret = usb_autopm_get_interface_async(axdev->intf);
	if (ret < 0)
		goto out_tx_fill;

	usb_fill_bulk_urb(desc->urb, axdev->udev,
			  usb_sndbulkpipe(axdev->udev, 3),
			  desc->head, (int)(tx_data - (u8 *)desc->head),
			  (usb_complete_t)ax_write_bulk_callback, desc);

	ret = usb_submit_urb(desc->urb, GFP_ATOMIC);
	if (ret < 0)
		usb_autopm_put_interface_async(axdev->intf);

out_tx_fill:
	return ret;
}

static void ax88179_rx_checksum(struct sk_buff *skb, u32 *pkt_hdr)
{
	skb->ip_summed = CHECKSUM_NONE;

>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
	if ((*pkt_hdr & AX_RXHDR_L3CSUM_ERR) ||
	    (*pkt_hdr & AX_RXHDR_L4CSUM_ERR))
		return;

<<<<<<< HEAD
	/* It must be a TCP or UDP packet with a valid checksum */
=======
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
	if (((*pkt_hdr & AX_RXHDR_L4_TYPE_MASK) == AX_RXHDR_L4_TYPE_TCP) ||
	    ((*pkt_hdr & AX_RXHDR_L4_TYPE_MASK) == AX_RXHDR_L4_TYPE_UDP))
		skb->ip_summed = CHECKSUM_UNNECESSARY;
}

<<<<<<< HEAD
static int ax88179_rx_fixup(struct usbnet *dev, struct sk_buff *skb)
{
	struct sk_buff *ax_skb;
	int pkt_cnt;
	u32 rx_hdr;
	u16 hdr_off;
	u32 *pkt_hdr;

	/* This check is no longer done by usbnet */
	if (skb->len < dev->net->hard_header_len)
		return 0;

	skb_trim(skb, skb->len - 4);
	memcpy(&rx_hdr, skb_tail_pointer(skb), 4);
	le32_to_cpus(&rx_hdr);

	pkt_cnt = (u16)rx_hdr;
	hdr_off = (u16)(rx_hdr >> 16);
	pkt_hdr = (u32 *)(skb->data + hdr_off);

	while (pkt_cnt--) {
		u16 pkt_len;

		le32_to_cpus(pkt_hdr);
		pkt_len = (*pkt_hdr >> 16) & 0x1fff;

		/* Check CRC or runt packet */
		if ((*pkt_hdr & AX_RXHDR_CRC_ERR) ||
		    (*pkt_hdr & AX_RXHDR_DROP_ERR)) {
			skb_pull(skb, (pkt_len + 7) & 0xFFF8);
			pkt_hdr++;
			continue;
		}

		if (pkt_cnt == 0) {
			skb->len = pkt_len;
			/* Skip IP alignment pseudo header */
			skb_pull(skb, 2);
			skb_set_tail_pointer(skb, skb->len);
			skb->truesize = pkt_len + sizeof(struct sk_buff);
			ax88179_rx_checksum(skb, pkt_hdr);
			return 1;
		}

		ax_skb = skb_clone(skb, GFP_ATOMIC);
		if (ax_skb) {
			ax_skb->len = pkt_len;
			/* Skip IP alignment pseudo header */
			skb_pull(ax_skb, 2);
			skb_set_tail_pointer(ax_skb, ax_skb->len);
			ax_skb->truesize = pkt_len + sizeof(struct sk_buff);
			ax88179_rx_checksum(ax_skb, pkt_hdr);
			usbnet_skb_return(dev, ax_skb);
		} else {
			return 0;
		}

		skb_pull(skb, (pkt_len + 7) & 0xFFF8);
		pkt_hdr++;
	}
	return 1;
}

static struct sk_buff *
ax88179_tx_fixup(struct usbnet *dev, struct sk_buff *skb, gfp_t flags)
{
	u32 tx_hdr1, tx_hdr2;
	int frame_size = dev->maxpacket;
	int mss = skb_shinfo(skb)->gso_size;
	int headroom;

	tx_hdr1 = skb->len;
	tx_hdr2 = mss;
	if (((skb->len + 8) % frame_size) == 0)
		tx_hdr2 |= 0x80008000;	/* Enable padding */

	headroom = skb_headroom(skb) - 8;

	if ((skb_header_cloned(skb) || headroom < 0) &&
	    pskb_expand_head(skb, headroom < 0 ? 8 : 0, 0, GFP_ATOMIC)) {
		dev_kfree_skb_any(skb);
		return NULL;
	}

	skb_push(skb, 4);
	cpu_to_le32s(&tx_hdr2);
	skb_copy_to_linear_data(skb, &tx_hdr2, 4);

	skb_push(skb, 4);
	cpu_to_le32s(&tx_hdr1);
	skb_copy_to_linear_data(skb, &tx_hdr1, 4);

	return skb;
}

static int ax88179_link_reset(struct usbnet *dev)
{
	struct ax88179_data *ax179_data = (struct ax88179_data *)dev->data;
	u8 tmp[5], link_sts;
	u16 mode, tmp16, delay = HZ / 10;
	u32 tmp32 = 0x40000000;
	unsigned long jtimeout;

	jtimeout = jiffies + delay;
	while (tmp32 & 0x40000000) {
		mode = 0;
		ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_RX_CTL, 2, 2, &mode);
		ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_RX_CTL, 2, 2,
				  &ax179_data->rxctl);

		/*link up, check the usb device control TX FIFO full or empty*/
		ax88179_read_cmd(dev, 0x81, 0x8c, 0, 4, &tmp32);

		if (time_after(jiffies, jtimeout))
			return 0;
	}

	mode = AX_MEDIUM_RECEIVE_EN | AX_MEDIUM_TXFLOW_CTRLEN |
	       AX_MEDIUM_RXFLOW_CTRLEN;

	ax88179_read_cmd(dev, AX_ACCESS_MAC, PHYSICAL_LINK_STATUS,
			 1, 1, &link_sts);

	ax88179_read_cmd(dev, AX_ACCESS_PHY, AX88179_PHY_ID,
			 GMII_PHY_PHYSR, 2, &tmp16);

	if (!(tmp16 & GMII_PHY_PHYSR_LINK)) {
		return 0;
	} else if (GMII_PHY_PHYSR_GIGA == (tmp16 & GMII_PHY_PHYSR_SMASK)) {
		mode |= AX_MEDIUM_GIGAMODE | AX_MEDIUM_EN_125MHZ;
		if (dev->net->mtu > 1500)
			mode |= AX_MEDIUM_JUMBO_EN;

		if (link_sts & AX_USB_SS)
			memcpy(tmp, &AX88179_BULKIN_SIZE[0], 5);
		else if (link_sts & AX_USB_HS)
			memcpy(tmp, &AX88179_BULKIN_SIZE[1], 5);
		else
			memcpy(tmp, &AX88179_BULKIN_SIZE[3], 5);
	} else if (GMII_PHY_PHYSR_100 == (tmp16 & GMII_PHY_PHYSR_SMASK)) {
		mode |= AX_MEDIUM_PS;

		if (link_sts & (AX_USB_SS | AX_USB_HS))
			memcpy(tmp, &AX88179_BULKIN_SIZE[2], 5);
		else
			memcpy(tmp, &AX88179_BULKIN_SIZE[3], 5);
	} else {
		memcpy(tmp, &AX88179_BULKIN_SIZE[3], 5);
	}

	/* RX bulk configuration */
	ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_RX_BULKIN_QCTRL, 5, 5, tmp);

	dev->rx_urb_size = (1024 * (tmp[3] + 2));

	if (tmp16 & GMII_PHY_PHYSR_FULL)
		mode |= AX_MEDIUM_FULL_DUPLEX;
	ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_MEDIUM_STATUS_MODE,
			  2, 2, &mode);

	ax179_data->eee_enabled = ax88179_chk_eee(dev);

	netif_carrier_on(dev->net);
=======
static void ax88179_rx_fixup
(struct ax_device *axdev, struct rx_desc *desc, int *work_done, int budget)
{
	u8 *rx_data;
	u32 const actual_length = desc->urb->actual_length;
	u32 rx_hdr = 0, pkt_hdr = 0, pkt_hdr_curr = 0, hdr_off = 0;
	u32 aa = 0;
	int pkt_cnt = 0;
	struct net_device *netdev = axdev->netdev;
	struct net_device_stats *stats = ax_get_stats(netdev);

	memcpy(&rx_hdr, (((u8 *)desc->head) + actual_length - 4),
	       sizeof(rx_hdr));
	le32_to_cpus(&rx_hdr);

	pkt_cnt = rx_hdr & 0xFF;
	pkt_hdr_curr = hdr_off = rx_hdr >> 16;

	aa = (actual_length - (((pkt_cnt + 2) & 0xFE) * 4));
	if ((aa != hdr_off) ||
	    (hdr_off >= desc->urb->actual_length) ||
	    (pkt_cnt == 0)) {
		desc->urb->actual_length = 0;
		stats->rx_length_errors++;
		return;
	}

	rx_data = desc->head;
	while (pkt_cnt--) {
		u32 pkt_len;
		struct sk_buff *skb;

		memcpy(&pkt_hdr, (((u8 *)desc->head) + pkt_hdr_curr),
		       sizeof(pkt_hdr));
		pkt_hdr_curr += 4;

		le32_to_cpus(&pkt_hdr);
		pkt_len = (pkt_hdr >> 16) & 0x1FFF;

		if (pkt_hdr & AX_RXHDR_CRC_ERR) {
			stats->rx_crc_errors++;
			goto find_next_rx;
		}
		if (pkt_hdr & AX_RXHDR_DROP_ERR) {
			stats->rx_dropped++;
			goto find_next_rx;
		}

		skb = napi_alloc_skb(napi, pkt_len);
		if (!skb) {
			stats->rx_dropped++;
			goto find_next_rx;
		}

		memcpy(skb->data, rx_data, pkt_len);
		skb_put(skb, pkt_len);

		ax88179_rx_checksum(skb, &pkt_hdr);

		skb->protocol = eth_type_trans(skb, netdev);

		if (*work_done < budget) {
			napi_gro_receive(&axdev->napi, skb);
			*work_done += 1;
			stats->rx_packets++;
			stats->rx_bytes += pkt_len;
		} else {
			__skb_queue_tail(&axdev->rx_queue, skb);
		}
find_next_rx:
		rx_data += (pkt_len + 7) & 0xFFF8;
	}
}

static int ax88179_system_suspend(struct ax_device *axdev)
{
	u16 reg16;

	ax_read_cmd_nopm(axdev, AX_ACCESS_MAC, AX_MEDIUM_STATUS_MODE,
			 2, 2, &reg16, 1);
	reg16 &= ~AX_MEDIUM_RECEIVE_EN;
	ax_write_cmd_nopm(axdev, AX_ACCESS_MAC, AX_MEDIUM_STATUS_MODE,
			  2, 2, &reg16);

	ax_read_cmd_nopm(axdev, AX_ACCESS_MAC, AX_PHYPWR_RSTCTL,
			 2, 2, &reg16, 1);
	reg16 |= AX_PHYPWR_RSTCTL_IPRL;
	ax_write_cmd_nopm(axdev, AX_ACCESS_MAC, AX_PHYPWR_RSTCTL,
			  2, 2, &reg16);

	reg16 = AX_RX_CTL_STOP;
	ax_write_cmd_nopm(axdev, AX_ACCESS_MAC, AX_RX_CTL, 2, 2, &reg16);
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533

	return 0;
}

<<<<<<< HEAD
static int ax88179_reset(struct usbnet *dev)
{
	u8 buf[5];
	u16 *tmp16;
	u8 *tmp;
	struct ax88179_data *ax179_data = (struct ax88179_data *)dev->data;
	struct ethtool_eee eee_data;

	tmp16 = (u16 *)buf;
	tmp = (u8 *)buf;

	/* Power up ethernet PHY */
	*tmp16 = 0;
	ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_PHYPWR_RSTCTL, 2, 2, tmp16);

	*tmp16 = AX_PHYPWR_RSTCTL_IPRL;
	ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_PHYPWR_RSTCTL, 2, 2, tmp16);
	msleep(200);

	*tmp = AX_CLK_SELECT_ACS | AX_CLK_SELECT_BCS;
	ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_CLK_SELECT, 1, 1, tmp);
	msleep(100);

	/* Ethernet PHY Auto Detach*/
	ax88179_auto_detach(dev, 0);

	ax88179_read_cmd(dev, AX_ACCESS_MAC, AX_NODE_ID, ETH_ALEN, ETH_ALEN,
			 dev->net->dev_addr);

	/* RX bulk configuration */
	memcpy(tmp, &AX88179_BULKIN_SIZE[0], 5);
	ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_RX_BULKIN_QCTRL, 5, 5, tmp);

	dev->rx_urb_size = 1024 * 20;

	*tmp = 0x34;
	ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_PAUSE_WATERLVL_LOW, 1, 1, tmp);

	*tmp = 0x52;
	ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_PAUSE_WATERLVL_HIGH,
			  1, 1, tmp);

	dev->net->features |= NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM |
			      NETIF_F_RXCSUM;

	dev->net->hw_features |= NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM |
				 NETIF_F_RXCSUM;

	/* Enable checksum offload */
	*tmp = AX_RXCOE_IP | AX_RXCOE_TCP | AX_RXCOE_UDP |
	       AX_RXCOE_TCPV6 | AX_RXCOE_UDPV6;
	ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_RXCOE_CTL, 1, 1, tmp);

	*tmp = AX_TXCOE_IP | AX_TXCOE_TCP | AX_TXCOE_UDP |
	       AX_TXCOE_TCPV6 | AX_TXCOE_UDPV6;
	ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_TXCOE_CTL, 1, 1, tmp);

	/* Configure RX control register => start operation */
	*tmp16 = AX_RX_CTL_DROPCRCERR | AX_RX_CTL_IPE | AX_RX_CTL_START |
		 AX_RX_CTL_AP | AX_RX_CTL_AMALL | AX_RX_CTL_AB;
	ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_RX_CTL, 2, 2, tmp16);

	*tmp = AX_MONITOR_MODE_PMETYPE | AX_MONITOR_MODE_PMEPOL |
	       AX_MONITOR_MODE_RWMP;
	ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_MONITOR_MOD, 1, 1, tmp);

	/* Configure default medium type => giga */
	*tmp16 = AX_MEDIUM_RECEIVE_EN | AX_MEDIUM_TXFLOW_CTRLEN |
		 AX_MEDIUM_RXFLOW_CTRLEN | AX_MEDIUM_FULL_DUPLEX |
		 AX_MEDIUM_GIGAMODE;
	ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_MEDIUM_STATUS_MODE,
			  2, 2, tmp16);

	ax88179_led_setting(dev);

	ax179_data->eee_enabled = 0;
	ax179_data->eee_active = 0;

	ax88179_disable_eee(dev);

	ax88179_ethtool_get_eee(dev, &eee_data);
	eee_data.advertised = 0;
	ax88179_ethtool_set_eee(dev, &eee_data);

	/* Restart autoneg */
	mii_nway_restart(&dev->mii);

	usbnet_link_change(dev, 0, 0);
=======
static int ax88179_system_resume(struct ax_device *axdev)
{
	u16 reg16;
	u8 reg8;

	reg16 = 0;
	ax_write_cmd_nopm(axdev, AX_ACCESS_MAC, AX_PHYPWR_RSTCTL, 2, 2, &reg16);
#if KERNEL_VERSION(2, 6, 36) <= LINUX_VERSION_CODE
	usleep_range(1000, 2000);
#else
	msleep(20);
#endif
	reg16 = AX_PHYPWR_RSTCTL_IPRL;
	ax_write_cmd_nopm(axdev, AX_ACCESS_MAC, AX_PHYPWR_RSTCTL, 2, 2, &reg16);
	msleep(500);

	ax88179_AutoDetach(axdev, 1);

	ax_read_cmd_nopm(axdev, AX_ACCESS_MAC,  AX_CLK_SELECT, 1, 1, &reg8, 0);
	reg8 |= AX_CLK_SELECT_ACS | AX_CLK_SELECT_BCS;
	ax_write_cmd_nopm(axdev, AX_ACCESS_MAC, AX_CLK_SELECT, 1, 1, &reg8);
	msleep(200);

	reg16 = AX_RX_CTL_START | AX_RX_CTL_AP |
		AX_RX_CTL_AMALL | AX_RX_CTL_AB;
	ax_write_cmd_nopm(axdev, AX_ACCESS_MAC, AX_RX_CTL, 2, 2, &reg16);
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533

	return 0;
}

<<<<<<< HEAD
static int ax88179_stop(struct usbnet *dev)
{
	u16 tmp16;

	ax88179_read_cmd(dev, AX_ACCESS_MAC, AX_MEDIUM_STATUS_MODE,
			 2, 2, &tmp16);
	tmp16 &= ~AX_MEDIUM_RECEIVE_EN;
	ax88179_write_cmd(dev, AX_ACCESS_MAC, AX_MEDIUM_STATUS_MODE,
			  2, 2, &tmp16);

	return 0;
}

static const struct driver_info ax88179_info = {
	.description = "ASIX AX88179 USB 3.0 Gigabit Ethernet",
	.bind = ax88179_bind,
	.unbind = ax88179_unbind,
	.status = ax88179_status,
	.link_reset = ax88179_link_reset,
	.reset = ax88179_reset,
	.stop = ax88179_stop,
	.flags = FLAG_ETHER | FLAG_FRAMING_AX,
	.rx_fixup = ax88179_rx_fixup,
	.tx_fixup = ax88179_tx_fixup,
};

static const struct driver_info ax88178a_info = {
	.description = "ASIX AX88178A USB 2.0 Gigabit Ethernet",
	.bind = ax88179_bind,
	.unbind = ax88179_unbind,
	.status = ax88179_status,
	.link_reset = ax88179_link_reset,
	.reset = ax88179_reset,
	.stop = ax88179_stop,
	.flags = FLAG_ETHER | FLAG_FRAMING_AX,
	.rx_fixup = ax88179_rx_fixup,
	.tx_fixup = ax88179_tx_fixup,
};

static const struct driver_info cypress_GX3_info = {
	.description = "Cypress GX3 SuperSpeed to Gigabit Ethernet Controller",
	.bind = ax88179_bind,
	.unbind = ax88179_unbind,
	.status = ax88179_status,
	.link_reset = ax88179_link_reset,
	.reset = ax88179_reset,
	.stop = ax88179_stop,
	.flags = FLAG_ETHER | FLAG_FRAMING_AX,
	.rx_fixup = ax88179_rx_fixup,
	.tx_fixup = ax88179_tx_fixup,
};

static const struct driver_info dlink_dub1312_info = {
	.description = "D-Link DUB-1312 USB 3.0 to Gigabit Ethernet Adapter",
	.bind = ax88179_bind,
	.unbind = ax88179_unbind,
	.status = ax88179_status,
	.link_reset = ax88179_link_reset,
	.reset = ax88179_reset,
	.stop = ax88179_stop,
	.flags = FLAG_ETHER | FLAG_FRAMING_AX,
	.rx_fixup = ax88179_rx_fixup,
	.tx_fixup = ax88179_tx_fixup,
};

static const struct driver_info sitecom_info = {
	.description = "Sitecom USB 3.0 to Gigabit Adapter",
	.bind = ax88179_bind,
	.unbind = ax88179_unbind,
	.status = ax88179_status,
	.link_reset = ax88179_link_reset,
	.reset = ax88179_reset,
	.stop = ax88179_stop,
	.flags = FLAG_ETHER | FLAG_FRAMING_AX,
	.rx_fixup = ax88179_rx_fixup,
	.tx_fixup = ax88179_tx_fixup,
};

static const struct driver_info samsung_info = {
	.description = "Samsung USB Ethernet Adapter",
	.bind = ax88179_bind,
	.unbind = ax88179_unbind,
	.status = ax88179_status,
	.link_reset = ax88179_link_reset,
	.reset = ax88179_reset,
	.stop = ax88179_stop,
	.flags = FLAG_ETHER | FLAG_FRAMING_AX,
	.rx_fixup = ax88179_rx_fixup,
	.tx_fixup = ax88179_tx_fixup,
};

static const struct driver_info lenovo_info = {
	.description = "Lenovo OneLinkDock Gigabit LAN",
	.bind = ax88179_bind,
	.unbind = ax88179_unbind,
	.status = ax88179_status,
	.link_reset = ax88179_link_reset,
	.reset = ax88179_reset,
	.stop = ax88179_stop,
	.flags = FLAG_ETHER | FLAG_FRAMING_AX,
	.rx_fixup = ax88179_rx_fixup,
	.tx_fixup = ax88179_tx_fixup,
};

static const struct driver_info belkin_info = {
	.description = "Belkin USB Ethernet Adapter",
	.bind	= ax88179_bind,
	.unbind = ax88179_unbind,
	.status = ax88179_status,
	.link_reset = ax88179_link_reset,
	.reset	= ax88179_reset,
	.stop	= ax88179_stop,
	.flags	= FLAG_ETHER | FLAG_FRAMING_AX,
	.rx_fixup = ax88179_rx_fixup,
	.tx_fixup = ax88179_tx_fixup,
};

static const struct usb_device_id products[] = {
{
	/* ASIX AX88179 10/100/1000 */
	USB_DEVICE(0x0b95, 0x1790),
	.driver_info = (unsigned long)&ax88179_info,
}, {
	/* ASIX AX88178A 10/100/1000 */
	USB_DEVICE(0x0b95, 0x178a),
	.driver_info = (unsigned long)&ax88178a_info,
}, {
	/* Cypress GX3 SuperSpeed to Gigabit Ethernet Bridge Controller */
	USB_DEVICE(0x04b4, 0x3610),
	.driver_info = (unsigned long)&cypress_GX3_info,
}, {
	/* D-Link DUB-1312 USB 3.0 to Gigabit Ethernet Adapter */
	USB_DEVICE(0x2001, 0x4a00),
	.driver_info = (unsigned long)&dlink_dub1312_info,
}, {
	/* Sitecom USB 3.0 to Gigabit Adapter */
	USB_DEVICE(0x0df6, 0x0072),
	.driver_info = (unsigned long)&sitecom_info,
}, {
	/* Samsung USB Ethernet Adapter */
	USB_DEVICE(0x04e8, 0xa100),
	.driver_info = (unsigned long)&samsung_info,
}, {
	/* Lenovo OneLinkDock Gigabit LAN */
	USB_DEVICE(0x17ef, 0x304b),
	.driver_info = (unsigned long)&lenovo_info,
}, {
	/* Belkin B2B128 USB 3.0 Hub + Gigabit Ethernet Adapter */
	USB_DEVICE(0x050d, 0x0128),
	.driver_info = (unsigned long)&belkin_info,
},
	{ },
};
MODULE_DEVICE_TABLE(usb, products);

static struct usb_driver ax88179_178a_driver = {
	.name =		"ax88179_178a",
	.id_table =	products,
	.probe =	usbnet_probe,
	.suspend =	ax88179_suspend,
	.resume =	ax88179_resume,
	.reset_resume =	ax88179_resume,
	.disconnect =	usbnet_disconnect,
	.supports_autosuspend = 1,
	.disable_hub_initiated_lpm = 1,
};

module_usb_driver(ax88179_178a_driver);

MODULE_DESCRIPTION("ASIX AX88179/178A based USB 3.0/2.0 Gigabit Ethernet Devices");
MODULE_LICENSE("GPL");
=======
const struct driver_info ax88179_info = {
	.bind = ax88179_bind,
	.unbind = ax88179_unbind,
	.hw_init = ax88179_hw_init,
	.stop = ax88179_stop,
	.link_reset = ax88179_link_reset,
	.rx_fixup = ax88179_rx_fixup,
	.tx_fixup = ax88179_tx_fixup,
	.system_suspend = ax88179_system_suspend,
	.system_resume = ax88179_system_resume,
	.napi_weight = AX88179_NAPI_WEIGHT,
	.buf_rx_size = AX88179_BUF_RX_SIZE,
};
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
