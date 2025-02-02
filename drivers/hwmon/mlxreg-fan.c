// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
//
// Copyright (c) 2018 Mellanox Technologies. All rights reserved.
// Copyright (c) 2018 Vadim Pasternak <vadimp@mellanox.com>

#include <linux/bitops.h>
#include <linux/device.h>
#include <linux/hwmon.h>
#include <linux/module.h>
#include <linux/platform_data/mlxreg.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>
#include <linux/thermal.h>

#define MLXREG_FAN_MAX_TACHO		12
#define MLXREG_FAN_MAX_STATE		10
#define MLXREG_FAN_MIN_DUTY		51	/* 20% */
#define MLXREG_FAN_MAX_DUTY		255	/* 100% */
/*
 * Minimum and maximum FAN allowed speed in percent: from 20% to 100%. Values
 * MLXREG_FAN_MAX_STATE + x, where x is between 2 and 10 are used for
 * setting FAN speed dynamic minimum. For example, if value is set to 14 (40%)
 * cooling levels vector will be set to 4, 4, 4, 4, 4, 5, 6, 7, 8, 9, 10 to
 * introduce PWM speed in percent: 40, 40, 40, 40, 40, 50, 60. 70, 80, 90, 100.
 */
#define MLXREG_FAN_SPEED_MIN			(MLXREG_FAN_MAX_STATE + 2)
#define MLXREG_FAN_SPEED_MAX			(MLXREG_FAN_MAX_STATE * 2)
#define MLXREG_FAN_SPEED_MIN_LEVEL		2	/* 20 percent */
#define MLXREG_FAN_TACHO_SAMPLES_PER_PULSE_DEF	44
#define MLXREG_FAN_TACHO_DIVIDER_DEF		1132
/*
 * FAN datasheet defines the formula for RPM calculations as RPM = 15/t-high.
 * The logic in a programmable device measures the time t-high by sampling the
 * tachometer every t-sample (with the default value 11.32 uS) and increment
 * a counter (N) as long as the pulse has not change:
 * RPM = 15 / (t-sample * (K + Regval)), where:
 * Regval: is the value read from the programmable device register;
 *  - 0xff - represents tachometer fault;
 *  - 0xfe - represents tachometer minimum value , which is 4444 RPM;
 *  - 0x00 - represents tachometer maximum value , which is 300000 RPM;
 * K: is 44 and it represents the minimum allowed samples per pulse;
 * N: is equal K + Regval;
 * In order to calculate RPM from the register value the following formula is
 * used: RPM = 15 / ((Regval + K) * 11.32) * 10^(-6)), which in  the
 * default case is modified to:
 * RPM = 15000000 * 100 / ((Regval + 44) * 1132);
 * - for Regval 0x00, RPM will be 15000000 * 100 / (44 * 1132) = 30115;
 * - for Regval 0xfe, RPM will be 15000000 * 100 / ((254 + 44) * 1132) = 4446;
 * In common case the formula is modified to:
 * RPM = 15000000 * 100 / ((Regval + samples) * divider).
 */
#define MLXREG_FAN_GET_RPM(rval, d, s)	(DIV_ROUND_CLOSEST(15000000 * 100, \
					 ((rval) + (s)) * (d)))
#define MLXREG_FAN_GET_FAULT(val, mask) (!((val) ^ (mask)))
#define MLXREG_FAN_PWM_DUTY2STATE(duty)	(DIV_ROUND_CLOSEST((duty) *	\
					 MLXREG_FAN_MAX_STATE,		\
					 MLXREG_FAN_MAX_DUTY))
#define MLXREG_FAN_PWM_STATE2DUTY(stat)	(DIV_ROUND_CLOSEST((stat) *	\
					 MLXREG_FAN_MAX_DUTY,		\
					 MLXREG_FAN_MAX_STATE))

/*
 * struct mlxreg_fan_tacho - tachometer data (internal use):
 *
 * @connected: indicates if tachometer is connected;
 * @reg: register offset;
 * @mask: fault mask;
 */
struct mlxreg_fan_tacho {
	bool connected;
	u32 reg;
	u32 mask;
};

/*
 * struct mlxreg_fan_pwm - PWM data (internal use):
 *
 * @connected: indicates if PWM is connected;
 * @reg: register offset;
 */
struct mlxreg_fan_pwm {
	bool connected;
	u32 reg;
};

/*
 * struct mlxreg_fan - private data (internal use):
 *
 * @dev: basic device;
 * @regmap: register map of parent device;
 * @tacho: tachometer data;
 * @pwm: PWM data;
 * @samples: minimum allowed samples per pulse;
 * @divider: divider value for tachometer RPM calculation;
 * @cooling: cooling device levels;
 * @cdev: cooling device;
 */
struct mlxreg_fan {
	struct device *dev;
	void *regmap;
	struct mlxreg_core_platform_data *pdata;
	struct mlxreg_fan_tacho tacho[MLXREG_FAN_MAX_TACHO];
	struct mlxreg_fan_pwm pwm;
	int samples;
	int divider;
	u8 cooling_levels[MLXREG_FAN_MAX_STATE + 1];
	struct thermal_cooling_device *cdev;
};

static int
mlxreg_fan_read(struct device *dev, enum hwmon_sensor_types type, u32 attr,
		int channel, long *val)
{
	struct mlxreg_fan *fan = dev_get_drvdata(dev);
	struct mlxreg_fan_tacho *tacho;
	u32 regval;
	int err;

	switch (type) {
	case hwmon_fan:
		tacho = &fan->tacho[channel];
		switch (attr) {
		case hwmon_fan_input:
			err = regmap_read(fan->regmap, tacho->reg, &regval);
			if (err)
				return err;

<<<<<<< HEAD
=======
			if (MLXREG_FAN_GET_FAULT(regval, tacho->mask)) {
				/* FAN is broken - return zero for FAN speed. */
				*val = 0;
				return 0;
			}

>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
			*val = MLXREG_FAN_GET_RPM(regval, fan->divider,
						  fan->samples);
			break;

		case hwmon_fan_fault:
			err = regmap_read(fan->regmap, tacho->reg, &regval);
			if (err)
				return err;

			*val = MLXREG_FAN_GET_FAULT(regval, tacho->mask);
			break;

		default:
			return -EOPNOTSUPP;
		}
		break;

	case hwmon_pwm:
		switch (attr) {
		case hwmon_pwm_input:
			err = regmap_read(fan->regmap, fan->pwm.reg, &regval);
			if (err)
				return err;

			*val = regval;
			break;

		default:
			return -EOPNOTSUPP;
		}
		break;

	default:
		return -EOPNOTSUPP;
	}

	return 0;
}

static int
mlxreg_fan_write(struct device *dev, enum hwmon_sensor_types type, u32 attr,
		 int channel, long val)
{
	struct mlxreg_fan *fan = dev_get_drvdata(dev);

	switch (type) {
	case hwmon_pwm:
		switch (attr) {
		case hwmon_pwm_input:
			if (val < MLXREG_FAN_MIN_DUTY ||
			    val > MLXREG_FAN_MAX_DUTY)
				return -EINVAL;
			return regmap_write(fan->regmap, fan->pwm.reg, val);
		default:
			return -EOPNOTSUPP;
		}
		break;

	default:
		return -EOPNOTSUPP;
	}

	return -EOPNOTSUPP;
}

static umode_t
mlxreg_fan_is_visible(const void *data, enum hwmon_sensor_types type, u32 attr,
		      int channel)
{
	switch (type) {
	case hwmon_fan:
		if (!(((struct mlxreg_fan *)data)->tacho[channel].connected))
			return 0;

		switch (attr) {
		case hwmon_fan_input:
		case hwmon_fan_fault:
			return 0444;
		default:
			break;
		}
		break;

	case hwmon_pwm:
		if (!(((struct mlxreg_fan *)data)->pwm.connected))
			return 0;

		switch (attr) {
		case hwmon_pwm_input:
			return 0644;
		default:
			break;
		}
		break;

	default:
		break;
	}

	return 0;
}

static const u32 mlxreg_fan_hwmon_fan_config[] = {
	HWMON_F_INPUT | HWMON_F_FAULT,
	HWMON_F_INPUT | HWMON_F_FAULT,
	HWMON_F_INPUT | HWMON_F_FAULT,
	HWMON_F_INPUT | HWMON_F_FAULT,
	HWMON_F_INPUT | HWMON_F_FAULT,
	HWMON_F_INPUT | HWMON_F_FAULT,
	HWMON_F_INPUT | HWMON_F_FAULT,
	HWMON_F_INPUT | HWMON_F_FAULT,
	HWMON_F_INPUT | HWMON_F_FAULT,
	HWMON_F_INPUT | HWMON_F_FAULT,
	HWMON_F_INPUT | HWMON_F_FAULT,
	HWMON_F_INPUT | HWMON_F_FAULT,
	0
};

static const struct hwmon_channel_info mlxreg_fan_hwmon_fan = {
	.type = hwmon_fan,
	.config = mlxreg_fan_hwmon_fan_config,
};

static const u32 mlxreg_fan_hwmon_pwm_config[] = {
	HWMON_PWM_INPUT,
	0
};

static const struct hwmon_channel_info mlxreg_fan_hwmon_pwm = {
	.type = hwmon_pwm,
	.config = mlxreg_fan_hwmon_pwm_config,
};

static const struct hwmon_channel_info *mlxreg_fan_hwmon_info[] = {
	&mlxreg_fan_hwmon_fan,
	&mlxreg_fan_hwmon_pwm,
	NULL
};

static const struct hwmon_ops mlxreg_fan_hwmon_hwmon_ops = {
	.is_visible = mlxreg_fan_is_visible,
	.read = mlxreg_fan_read,
	.write = mlxreg_fan_write,
};

static const struct hwmon_chip_info mlxreg_fan_hwmon_chip_info = {
	.ops = &mlxreg_fan_hwmon_hwmon_ops,
	.info = mlxreg_fan_hwmon_info,
};

static int mlxreg_fan_get_max_state(struct thermal_cooling_device *cdev,
				    unsigned long *state)
{
	*state = MLXREG_FAN_MAX_STATE;
	return 0;
}

static int mlxreg_fan_get_cur_state(struct thermal_cooling_device *cdev,
				    unsigned long *state)

{
	struct mlxreg_fan *fan = cdev->devdata;
	u32 regval;
	int err;

	err = regmap_read(fan->regmap, fan->pwm.reg, &regval);
	if (err) {
		dev_err(fan->dev, "Failed to query PWM duty\n");
		return err;
	}

	*state = MLXREG_FAN_PWM_DUTY2STATE(regval);

	return 0;
}

static int mlxreg_fan_set_cur_state(struct thermal_cooling_device *cdev,
				    unsigned long state)

{
	struct mlxreg_fan *fan = cdev->devdata;
	unsigned long cur_state;
<<<<<<< HEAD
	u32 regval;
	int i;
=======
	int i, config = 0;
	u32 regval;
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
	int err;

	/*
	 * Verify if this request is for changing allowed FAN dynamical
	 * minimum. If it is - update cooling levels accordingly and update
	 * state, if current state is below the newly requested minimum state.
	 * For example, if current state is 5, and minimal state is to be
	 * changed from 4 to 6, fan->cooling_levels[0 to 5] will be changed all
	 * from 4 to 6. And state 5 (fan->cooling_levels[4]) should be
	 * overwritten.
	 */
	if (state >= MLXREG_FAN_SPEED_MIN && state <= MLXREG_FAN_SPEED_MAX) {
<<<<<<< HEAD
=======
		/*
		 * This is configuration change, which is only supported through sysfs.
		 * For configuration non-zero value is to be returned to avoid thermal
		 * statistics update.
		 */
		config = 1;
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
		state -= MLXREG_FAN_MAX_STATE;
		for (i = 0; i < state; i++)
			fan->cooling_levels[i] = state;
		for (i = state; i <= MLXREG_FAN_MAX_STATE; i++)
			fan->cooling_levels[i] = i;

		err = regmap_read(fan->regmap, fan->pwm.reg, &regval);
		if (err) {
			dev_err(fan->dev, "Failed to query PWM duty\n");
			return err;
		}

		cur_state = MLXREG_FAN_PWM_DUTY2STATE(regval);
		if (state < cur_state)
<<<<<<< HEAD
			return 0;
=======
			return config;
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533

		state = cur_state;
	}

	if (state > MLXREG_FAN_MAX_STATE)
		return -EINVAL;

	/* Normalize the state to the valid speed range. */
	state = fan->cooling_levels[state];
	err = regmap_write(fan->regmap, fan->pwm.reg,
			   MLXREG_FAN_PWM_STATE2DUTY(state));
	if (err) {
		dev_err(fan->dev, "Failed to write PWM duty\n");
		return err;
	}
<<<<<<< HEAD
	return 0;
=======
	return config;
>>>>>>> 122d1576a6713c615b6766b155a48c3edfd2f533
}

static const struct thermal_cooling_device_ops mlxreg_fan_cooling_ops = {
	.get_max_state	= mlxreg_fan_get_max_state,
	.get_cur_state	= mlxreg_fan_get_cur_state,
	.set_cur_state	= mlxreg_fan_set_cur_state,
};

static int mlxreg_fan_config(struct mlxreg_fan *fan,
			     struct mlxreg_core_platform_data *pdata)
{
	struct mlxreg_core_data *data = pdata->data;
	bool configured = false;
	int tacho_num = 0, i;

	fan->samples = MLXREG_FAN_TACHO_SAMPLES_PER_PULSE_DEF;
	fan->divider = MLXREG_FAN_TACHO_DIVIDER_DEF;
	for (i = 0; i < pdata->counter; i++, data++) {
		if (strnstr(data->label, "tacho", sizeof(data->label))) {
			if (tacho_num == MLXREG_FAN_MAX_TACHO) {
				dev_err(fan->dev, "too many tacho entries: %s\n",
					data->label);
				return -EINVAL;
			}
			fan->tacho[tacho_num].reg = data->reg;
			fan->tacho[tacho_num].mask = data->mask;
			fan->tacho[tacho_num++].connected = true;
		} else if (strnstr(data->label, "pwm", sizeof(data->label))) {
			if (fan->pwm.connected) {
				dev_err(fan->dev, "duplicate pwm entry: %s\n",
					data->label);
				return -EINVAL;
			}
			fan->pwm.reg = data->reg;
			fan->pwm.connected = true;
		} else if (strnstr(data->label, "conf", sizeof(data->label))) {
			if (configured) {
				dev_err(fan->dev, "duplicate conf entry: %s\n",
					data->label);
				return -EINVAL;
			}
			/* Validate that conf parameters are not zeros. */
			if (!data->mask || !data->bit) {
				dev_err(fan->dev, "invalid conf entry params: %s\n",
					data->label);
				return -EINVAL;
			}
			fan->samples = data->mask;
			fan->divider = data->bit;
			configured = true;
		} else {
			dev_err(fan->dev, "invalid label: %s\n", data->label);
			return -EINVAL;
		}
	}

	/* Init cooling levels per PWM state. */
	for (i = 0; i < MLXREG_FAN_SPEED_MIN_LEVEL; i++)
		fan->cooling_levels[i] = MLXREG_FAN_SPEED_MIN_LEVEL;
	for (i = MLXREG_FAN_SPEED_MIN_LEVEL; i <= MLXREG_FAN_MAX_STATE; i++)
		fan->cooling_levels[i] = i;

	return 0;
}

static int mlxreg_fan_probe(struct platform_device *pdev)
{
	struct mlxreg_core_platform_data *pdata;
	struct mlxreg_fan *fan;
	struct device *hwm;
	int err;

	pdata = dev_get_platdata(&pdev->dev);
	if (!pdata) {
		dev_err(&pdev->dev, "Failed to get platform data.\n");
		return -EINVAL;
	}

	fan = devm_kzalloc(&pdev->dev, sizeof(*fan), GFP_KERNEL);
	if (!fan)
		return -ENOMEM;

	fan->dev = &pdev->dev;
	fan->regmap = pdata->regmap;
	platform_set_drvdata(pdev, fan);

	err = mlxreg_fan_config(fan, pdata);
	if (err)
		return err;

	hwm = devm_hwmon_device_register_with_info(&pdev->dev, "mlxreg_fan",
						   fan,
						   &mlxreg_fan_hwmon_chip_info,
						   NULL);
	if (IS_ERR(hwm)) {
		dev_err(&pdev->dev, "Failed to register hwmon device\n");
		return PTR_ERR(hwm);
	}

	if (IS_REACHABLE(CONFIG_THERMAL)) {
		fan->cdev = thermal_cooling_device_register("mlxreg_fan", fan,
						&mlxreg_fan_cooling_ops);
		if (IS_ERR(fan->cdev)) {
			dev_err(&pdev->dev, "Failed to register cooling device\n");
			return PTR_ERR(fan->cdev);
		}
	}

	return 0;
}

static int mlxreg_fan_remove(struct platform_device *pdev)
{
	struct mlxreg_fan *fan = platform_get_drvdata(pdev);

	if (IS_REACHABLE(CONFIG_THERMAL))
		thermal_cooling_device_unregister(fan->cdev);

	return 0;
}

static struct platform_driver mlxreg_fan_driver = {
	.driver = {
	    .name = "mlxreg-fan",
	},
	.probe = mlxreg_fan_probe,
	.remove = mlxreg_fan_remove,
};

module_platform_driver(mlxreg_fan_driver);

MODULE_AUTHOR("Vadim Pasternak <vadimp@mellanox.com>");
MODULE_DESCRIPTION("Mellanox FAN driver");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:mlxreg-fan");
