/**
 * BMA220 Digital triaxial acceleration sensor driver
 *
 * Copyright (c) 2016, Intel Corporation.
 *
 * This file is subject to the terms and conditions of version 2 of
 * the GNU General Public License. See the file COPYING in the main
 * directory of this archive for more details.
 */

#include <linux/acpi.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/iio/buffer.h>
#include <linux/iio/iio.h>
#include <linux/iio/sysfs.h>
#include <linux/spi/spi.h>
#include <linux/iio/trigger_consumer.h>
#include <linux/iio/triggered_buffer.h>

#define BMA220_REG_ID				0x00
#define BMA220_REG_ACCEL_X			0x02
#define BMA220_REG_ACCEL_Y			0x03
#define BMA220_REG_ACCEL_Z			0x04
#define BMA220_REG_RANGE			0x11
#define BMA220_REG_SUSPEND			0x18

#define BMA220_CHIP_ID				0xDD
#define BMA220_READ_MASK			0x80
#define BMA220_RANGE_MASK			0x03
#define BMA220_DATA_SHIFT			2
#define BMA220_SUSPEND_SLEEP			0xFF
#define BMA220_SUSPEND_WAKE			0x00

#define BMA220_DEVICE_NAME			"bma220"
#define BMA220_SCALE_AVAILABLE			"0.623 1.248 2.491 4.983"

#define BMA220_ACCEL_CHANNEL(index, reg, axis) {			\
	.type = IIO_ACCEL,						\
	.address = reg,							\
	.modified = 1,							\
	.channel2 = IIO_MOD_##axis,					\
	.info_mask_separate = BIT(IIO_CHAN_INFO_RAW),			\
	.info_mask_shared_by_type = BIT(IIO_CHAN_INFO_SCALE),		\
	.scan_index = index,						\
	.scan_type = {							\
		.sign = 's',						\
		.realbits = 6,						\
		.storagebits = 8,					\
		.shift = BMA220_DATA_SHIFT,				\
		.endianness = IIO_CPU,					\
	},								\
}

enum bma220_axis {
	AXIS_X,
	AXIS_Y,
	AXIS_Z,
};

static IIO_CONST_ATTR(in_accel_scale_available, BMA220_SCALE_AVAILABLE);

static struct attribute *bma220_attributes[] = {
	&iio_const_attr_in_accel_scale_available.dev_attr.attr,
	NULL,
};

static const struct attribute_group bma220_attribute_group = {
	.attrs = bma220_attributes,
};

static const int bma220_scale_table[][4] = {
	{0, 623000}, {1, 248000}, {2, 491000}, {4, 983000}
};

struct bma220_data {
	struct spi_device *spi_device;
	struct mutex lock;
<<<<<<< HEAD
	s8 buffer[16]; /* 3x8-bit channels + 5x8 padding + 8x8 timestamp */
=======
	struct {
		s8 chans[3];
		/* Ensure timestamp is naturally aligned. */
		s64 timestamp __aligned(8);
	} scan;
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
	u8 tx_buf[2] ____cacheline_aligned;
};

static const struct iio_chan_spec bma220_channels[] = {
	BMA220_ACCEL_CHANNEL(0, BMA220_REG_ACCEL_X, X),
	BMA220_ACCEL_CHANNEL(1, BMA220_REG_ACCEL_Y, Y),
	BMA220_ACCEL_CHANNEL(2, BMA220_REG_ACCEL_Z, Z),
	IIO_CHAN_SOFT_TIMESTAMP(3),
};

static inline int bma220_read_reg(struct spi_device *spi, u8 reg)
{
	return spi_w8r8(spi, reg | BMA220_READ_MASK);
}

static const unsigned long bma220_accel_scan_masks[] = {
	BIT(AXIS_X) | BIT(AXIS_Y) | BIT(AXIS_Z),
	0
};

static irqreturn_t bma220_trigger_handler(int irq, void *p)
{
	int ret;
	struct iio_poll_func *pf = p;
	struct iio_dev *indio_dev = pf->indio_dev;
	struct bma220_data *data = iio_priv(indio_dev);
	struct spi_device *spi = data->spi_device;

	mutex_lock(&data->lock);
	data->tx_buf[0] = BMA220_REG_ACCEL_X | BMA220_READ_MASK;
<<<<<<< HEAD
	ret = spi_write_then_read(spi, data->tx_buf, 1, data->buffer,
=======
	ret = spi_write_then_read(spi, data->tx_buf, 1, &data->scan.chans,
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
				  ARRAY_SIZE(bma220_channels) - 1);
	if (ret < 0)
		goto err;

<<<<<<< HEAD
	iio_push_to_buffers_with_timestamp(indio_dev, data->buffer,
=======
	iio_push_to_buffers_with_timestamp(indio_dev, &data->scan,
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
					   pf->timestamp);
err:
	mutex_unlock(&data->lock);
	iio_trigger_notify_done(indio_dev->trig);

	return IRQ_HANDLED;
}

static int bma220_read_raw(struct iio_dev *indio_dev,
			   struct iio_chan_spec const *chan,
			   int *val, int *val2, long mask)
{
	int ret;
	u8 range_idx;
	struct bma220_data *data = iio_priv(indio_dev);

	switch (mask) {
	case IIO_CHAN_INFO_RAW:
		ret = bma220_read_reg(data->spi_device, chan->address);
		if (ret < 0)
			return -EINVAL;
		*val = sign_extend32(ret >> BMA220_DATA_SHIFT, 5);
		return IIO_VAL_INT;
	case IIO_CHAN_INFO_SCALE:
		ret = bma220_read_reg(data->spi_device, BMA220_REG_RANGE);
		if (ret < 0)
			return ret;
		range_idx = ret & BMA220_RANGE_MASK;
		*val = bma220_scale_table[range_idx][0];
		*val2 = bma220_scale_table[range_idx][1];
		return IIO_VAL_INT_PLUS_MICRO;
	}

	return -EINVAL;
}

static int bma220_write_raw(struct iio_dev *indio_dev,
			    struct iio_chan_spec const *chan,
			    int val, int val2, long mask)
{
	int i;
	int ret;
	int index = -1;
	struct bma220_data *data = iio_priv(indio_dev);

	switch (mask) {
	case IIO_CHAN_INFO_SCALE:
		for (i = 0; i < ARRAY_SIZE(bma220_scale_table); i++)
			if (val == bma220_scale_table[i][0] &&
			    val2 == bma220_scale_table[i][1]) {
				index = i;
				break;
			}
		if (index < 0)
			return -EINVAL;

		mutex_lock(&data->lock);
		data->tx_buf[0] = BMA220_REG_RANGE;
		data->tx_buf[1] = index;
		ret = spi_write(data->spi_device, data->tx_buf,
				sizeof(data->tx_buf));
		if (ret < 0)
			dev_err(&data->spi_device->dev,
				"failed to set measurement range\n");
		mutex_unlock(&data->lock);

		return 0;
	}

	return -EINVAL;
}

static const struct iio_info bma220_info = {
	.read_raw		= bma220_read_raw,
	.write_raw		= bma220_write_raw,
	.attrs			= &bma220_attribute_group,
};

static int bma220_init(struct spi_device *spi)
{
	int ret;

	ret = bma220_read_reg(spi, BMA220_REG_ID);
	if (ret != BMA220_CHIP_ID)
		return -ENODEV;

	/* Make sure the chip is powered on */
	ret = bma220_read_reg(spi, BMA220_REG_SUSPEND);
	if (ret < 0)
		return ret;
	else if (ret == BMA220_SUSPEND_WAKE)
		return bma220_read_reg(spi, BMA220_REG_SUSPEND);

	return 0;
}

static int bma220_deinit(struct spi_device *spi)
{
	int ret;

	/* Make sure the chip is powered off */
	ret = bma220_read_reg(spi, BMA220_REG_SUSPEND);
	if (ret < 0)
		return ret;
	else if (ret == BMA220_SUSPEND_SLEEP)
		return bma220_read_reg(spi, BMA220_REG_SUSPEND);

	return 0;
}

static int bma220_probe(struct spi_device *spi)
{
	int ret;
	struct iio_dev *indio_dev;
	struct bma220_data *data;

	indio_dev = devm_iio_device_alloc(&spi->dev, sizeof(*data));
	if (!indio_dev) {
		dev_err(&spi->dev, "iio allocation failed!\n");
		return -ENOMEM;
	}

	data = iio_priv(indio_dev);
	data->spi_device = spi;
	spi_set_drvdata(spi, indio_dev);
	mutex_init(&data->lock);

	indio_dev->dev.parent = &spi->dev;
	indio_dev->info = &bma220_info;
	indio_dev->name = BMA220_DEVICE_NAME;
	indio_dev->modes = INDIO_DIRECT_MODE;
	indio_dev->channels = bma220_channels;
	indio_dev->num_channels = ARRAY_SIZE(bma220_channels);
	indio_dev->available_scan_masks = bma220_accel_scan_masks;

	ret = bma220_init(data->spi_device);
	if (ret < 0)
		return ret;

	ret = iio_triggered_buffer_setup(indio_dev, iio_pollfunc_store_time,
					 bma220_trigger_handler, NULL);
	if (ret < 0) {
		dev_err(&spi->dev, "iio triggered buffer setup failed\n");
		goto err_suspend;
	}

	ret = iio_device_register(indio_dev);
	if (ret < 0) {
		dev_err(&spi->dev, "iio_device_register failed\n");
		iio_triggered_buffer_cleanup(indio_dev);
		goto err_suspend;
	}

	return 0;

err_suspend:
	return bma220_deinit(spi);
}

static int bma220_remove(struct spi_device *spi)
{
	struct iio_dev *indio_dev = spi_get_drvdata(spi);

	iio_device_unregister(indio_dev);
	iio_triggered_buffer_cleanup(indio_dev);

	return bma220_deinit(spi);
}

#ifdef CONFIG_PM_SLEEP
static int bma220_suspend(struct device *dev)
{
	struct bma220_data *data =
			iio_priv(spi_get_drvdata(to_spi_device(dev)));

	/* The chip can be suspended/woken up by a simple register read. */
	return bma220_read_reg(data->spi_device, BMA220_REG_SUSPEND);
}

static int bma220_resume(struct device *dev)
{
	struct bma220_data *data =
			iio_priv(spi_get_drvdata(to_spi_device(dev)));

	return bma220_read_reg(data->spi_device, BMA220_REG_SUSPEND);
}

static SIMPLE_DEV_PM_OPS(bma220_pm_ops, bma220_suspend, bma220_resume);

#define BMA220_PM_OPS (&bma220_pm_ops)
#else
#define BMA220_PM_OPS NULL
#endif

static const struct spi_device_id bma220_spi_id[] = {
	{"bma220", 0},
	{}
};

static const struct acpi_device_id bma220_acpi_id[] = {
	{"BMA0220", 0},
	{}
};

MODULE_DEVICE_TABLE(spi, bma220_spi_id);

static struct spi_driver bma220_driver = {
	.driver = {
		.name = "bma220_spi",
		.pm = BMA220_PM_OPS,
		.acpi_match_table = ACPI_PTR(bma220_acpi_id),
	},
	.probe =            bma220_probe,
	.remove =           bma220_remove,
	.id_table =         bma220_spi_id,
};

module_spi_driver(bma220_driver);

MODULE_AUTHOR("Tiberiu Breana <tiberiu.a.breana@intel.com>");
MODULE_DESCRIPTION("BMA220 acceleration sensor driver");
MODULE_LICENSE("GPL v2");
