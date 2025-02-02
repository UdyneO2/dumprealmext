/*
 * gpio_backlight.c - Simple GPIO-controlled backlight
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/backlight.h>
#include <linux/err.h>
#include <linux/fb.h>
#include <linux/gpio.h> /* Only for legacy support */
#include <linux/gpio/consumer.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_gpio.h>
#include <linux/platform_data/gpio_backlight.h>
#include <linux/platform_device.h>
#include <linux/slab.h>

struct gpio_backlight {
	struct device *dev;
	struct device *fbdev;

	struct gpio_desc *gpiod;
	int def_value;
};

static int gpio_backlight_update_status(struct backlight_device *bl)
{
	struct gpio_backlight *gbl = bl_get_data(bl);
	int brightness = bl->props.brightness;

	if (bl->props.power != FB_BLANK_UNBLANK ||
	    bl->props.fb_blank != FB_BLANK_UNBLANK ||
	    bl->props.state & (BL_CORE_SUSPENDED | BL_CORE_FBBLANK))
		brightness = 0;

	gpiod_set_value_cansleep(gbl->gpiod, brightness);

	return 0;
}

static int gpio_backlight_check_fb(struct backlight_device *bl,
				   struct fb_info *info)
{
	struct gpio_backlight *gbl = bl_get_data(bl);

<<<<<<< HEAD
	return gbl->fbdev == NULL || gbl->fbdev == info->dev;
=======
	return gbl->fbdev == NULL || gbl->fbdev == info->device;
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
}

static const struct backlight_ops gpio_backlight_ops = {
	.options	= BL_CORE_SUSPENDRESUME,
	.update_status	= gpio_backlight_update_status,
	.check_fb	= gpio_backlight_check_fb,
};

static int gpio_backlight_probe_dt(struct platform_device *pdev,
				   struct gpio_backlight *gbl)
{
	struct device *dev = &pdev->dev;
	struct device_node *np = dev->of_node;
<<<<<<< HEAD
	enum gpiod_flags flags;
	int ret;

	gbl->def_value = of_property_read_bool(np, "default-on");
	flags = gbl->def_value ? GPIOD_OUT_HIGH : GPIOD_OUT_LOW;

	gbl->gpiod = devm_gpiod_get(dev, NULL, flags);
=======
	int ret;

	gbl->def_value = of_property_read_bool(np, "default-on");

	gbl->gpiod = devm_gpiod_get(dev, NULL, GPIOD_ASIS);
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
	if (IS_ERR(gbl->gpiod)) {
		ret = PTR_ERR(gbl->gpiod);

		if (ret != -EPROBE_DEFER) {
			dev_err(dev,
				"Error: The gpios parameter is missing or invalid.\n");
		}
		return ret;
	}

	return 0;
}

<<<<<<< HEAD
=======
static int gpio_backlight_initial_power_state(struct gpio_backlight *gbl)
{
	struct device_node *node = gbl->dev->of_node;

	/* Not booted with device tree or no phandle link to the node */
	if (!node || !node->phandle)
		return gbl->def_value ? FB_BLANK_UNBLANK : FB_BLANK_POWERDOWN;

	/* if the enable GPIO is disabled, do not enable the backlight */
	if (gpiod_get_value_cansleep(gbl->gpiod) == 0)
		return FB_BLANK_POWERDOWN;

	return FB_BLANK_UNBLANK;
}


>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
static int gpio_backlight_probe(struct platform_device *pdev)
{
	struct gpio_backlight_platform_data *pdata =
		dev_get_platdata(&pdev->dev);
	struct backlight_properties props;
	struct backlight_device *bl;
	struct gpio_backlight *gbl;
	struct device_node *np = pdev->dev.of_node;
	int ret;

	if (!pdata && !np) {
		dev_err(&pdev->dev,
			"failed to find platform data or device tree node.\n");
		return -ENODEV;
	}

	gbl = devm_kzalloc(&pdev->dev, sizeof(*gbl), GFP_KERNEL);
	if (gbl == NULL)
		return -ENOMEM;

	gbl->dev = &pdev->dev;

	if (np) {
		ret = gpio_backlight_probe_dt(pdev, gbl);
		if (ret)
			return ret;
	} else {
		/*
		 * Legacy platform data GPIO retrieveal. Do not expand
		 * the use of this code path, currently only used by one
		 * SH board.
		 */
		unsigned long flags = GPIOF_DIR_OUT;

		gbl->fbdev = pdata->fbdev;
		gbl->def_value = pdata->def_value;
		flags |= gbl->def_value ? GPIOF_INIT_HIGH : GPIOF_INIT_LOW;

		ret = devm_gpio_request_one(gbl->dev, pdata->gpio, flags,
					    pdata ? pdata->name : "backlight");
		if (ret < 0) {
			dev_err(&pdev->dev, "unable to request GPIO\n");
			return ret;
		}
		gbl->gpiod = gpio_to_desc(pdata->gpio);
		if (!gbl->gpiod)
			return -EINVAL;
	}

	memset(&props, 0, sizeof(props));
	props.type = BACKLIGHT_RAW;
	props.max_brightness = 1;
	bl = devm_backlight_device_register(&pdev->dev, dev_name(&pdev->dev),
					&pdev->dev, gbl, &gpio_backlight_ops,
					&props);
	if (IS_ERR(bl)) {
		dev_err(&pdev->dev, "failed to register backlight\n");
		return PTR_ERR(bl);
	}

<<<<<<< HEAD
	bl->props.brightness = gbl->def_value;
=======
	bl->props.power = gpio_backlight_initial_power_state(gbl);
	bl->props.brightness = 1;

>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
	backlight_update_status(bl);

	platform_set_drvdata(pdev, bl);
	return 0;
}

#ifdef CONFIG_OF
static struct of_device_id gpio_backlight_of_match[] = {
	{ .compatible = "gpio-backlight" },
	{ /* sentinel */ }
};

MODULE_DEVICE_TABLE(of, gpio_backlight_of_match);
#endif

static struct platform_driver gpio_backlight_driver = {
	.driver		= {
		.name		= "gpio-backlight",
		.of_match_table = of_match_ptr(gpio_backlight_of_match),
	},
	.probe		= gpio_backlight_probe,
};

module_platform_driver(gpio_backlight_driver);

MODULE_AUTHOR("Laurent Pinchart <laurent.pinchart@ideasonboard.com>");
MODULE_DESCRIPTION("GPIO-based Backlight Driver");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:gpio-backlight");
