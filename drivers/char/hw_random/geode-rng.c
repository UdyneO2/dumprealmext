/*
 * RNG driver for AMD Geode RNGs
 *
 * Copyright 2005 (c) MontaVista Software, Inc.
 *
 * with the majority of the code coming from:
 *
 * Hardware driver for the Intel/AMD/VIA Random Number Generators (RNG)
 * (c) Copyright 2003 Red Hat Inc <jgarzik@redhat.com>
 *
 * derived from
 *
 * Hardware driver for the AMD 768 Random Number Generator (RNG)
 * (c) Copyright 2001 Red Hat Inc
 *
 * derived from
 *
 * Hardware driver for Intel i810 Random Number Generator (RNG)
 * Copyright 2000,2001 Jeff Garzik <jgarzik@pobox.com>
 * Copyright 2000,2001 Philipp Rumpf <prumpf@mandrakesoft.com>
 *
 * This file is licensed under  the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include <linux/delay.h>
#include <linux/hw_random.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>


#define PFX	KBUILD_MODNAME ": "

#define GEODE_RNG_DATA_REG   0x50
#define GEODE_RNG_STATUS_REG 0x54

/*
 * Data for PCI driver interface
 *
 * This data only exists for exporting the supported
 * PCI ids via MODULE_DEVICE_TABLE.  We do not actually
 * register a pci_driver, because someone else might one day
 * want to register another driver on the same PCI id.
 */
static const struct pci_device_id pci_tbl[] = {
	{ PCI_VDEVICE(AMD, PCI_DEVICE_ID_AMD_LX_AES), 0, },
	{ 0, },	/* terminate list */
};
MODULE_DEVICE_TABLE(pci, pci_tbl);

<<<<<<< HEAD

static int geode_rng_data_read(struct hwrng *rng, u32 *data)
{
	void __iomem *mem = (void __iomem *)rng->priv;
=======
struct amd_geode_priv {
	struct pci_dev *pcidev;
	void __iomem *membase;
};

static int geode_rng_data_read(struct hwrng *rng, u32 *data)
{
	struct amd_geode_priv *priv = (struct amd_geode_priv *)rng->priv;
	void __iomem *mem = priv->membase;
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533

	*data = readl(mem + GEODE_RNG_DATA_REG);

	return 4;
}

static int geode_rng_data_present(struct hwrng *rng, int wait)
{
<<<<<<< HEAD
	void __iomem *mem = (void __iomem *)rng->priv;
=======
	struct amd_geode_priv *priv = (struct amd_geode_priv *)rng->priv;
	void __iomem *mem = priv->membase;
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
	int data, i;

	for (i = 0; i < 20; i++) {
		data = !!(readl(mem + GEODE_RNG_STATUS_REG));
		if (data || !wait)
			break;
		udelay(10);
	}
	return data;
}


static struct hwrng geode_rng = {
	.name		= "geode",
	.data_present	= geode_rng_data_present,
	.data_read	= geode_rng_data_read,
};


static int __init mod_init(void)
{
	int err = -ENODEV;
	struct pci_dev *pdev = NULL;
	const struct pci_device_id *ent;
	void __iomem *mem;
	unsigned long rng_base;
<<<<<<< HEAD
=======
	struct amd_geode_priv *priv;
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533

	for_each_pci_dev(pdev) {
		ent = pci_match_id(pci_tbl, pdev);
		if (ent)
			goto found;
	}
	/* Device not found. */
<<<<<<< HEAD
	goto out;

found:
	rng_base = pci_resource_start(pdev, 0);
	if (rng_base == 0)
		goto out;
	err = -ENOMEM;
	mem = ioremap(rng_base, 0x58);
	if (!mem)
		goto out;
	geode_rng.priv = (unsigned long)mem;
=======
	return err;

found:
	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv) {
		err = -ENOMEM;
		goto put_dev;
	}

	rng_base = pci_resource_start(pdev, 0);
	if (rng_base == 0)
		goto free_priv;
	err = -ENOMEM;
	mem = ioremap(rng_base, 0x58);
	if (!mem)
		goto free_priv;

	geode_rng.priv = (unsigned long)priv;
	priv->membase = mem;
	priv->pcidev = pdev;
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533

	pr_info("AMD Geode RNG detected\n");
	err = hwrng_register(&geode_rng);
	if (err) {
		pr_err(PFX "RNG registering failed (%d)\n",
		       err);
		goto err_unmap;
	}
<<<<<<< HEAD
out:
=======
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
	return err;

err_unmap:
	iounmap(mem);
<<<<<<< HEAD
	goto out;
=======
free_priv:
	kfree(priv);
put_dev:
	pci_dev_put(pdev);
	return err;
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
}

static void __exit mod_exit(void)
{
<<<<<<< HEAD
	void __iomem *mem = (void __iomem *)geode_rng.priv;

	hwrng_unregister(&geode_rng);
	iounmap(mem);
=======
	struct amd_geode_priv *priv;

	priv = (struct amd_geode_priv *)geode_rng.priv;
	hwrng_unregister(&geode_rng);
	iounmap(priv->membase);
	pci_dev_put(priv->pcidev);
	kfree(priv);
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
}

module_init(mod_init);
module_exit(mod_exit);

MODULE_DESCRIPTION("H/W RNG driver for AMD Geode LX CPUs");
MODULE_LICENSE("GPL");
