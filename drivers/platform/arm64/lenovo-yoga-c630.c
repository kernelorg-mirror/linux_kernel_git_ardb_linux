// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2022-2024, Linaro Ltd
 * Authors:
 *    Bjorn Andersson
 *    Dmitry Baryshkov
 */
#include <linux/auxiliary_bus.h>
#include <linux/bits.h>
#include <linux/cleanup.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/i2c.h>
#include <linux/interrupt.h>
#include <linux/irqreturn.h>
#include <linux/leds.h>
#include <linux/lockdep.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/notifier.h>
#include <linux/pm.h>
#include <linux/slab.h>
#include <linux/platform_data/lenovo-yoga-c630.h>

#define LENOVO_EC_RESPONSE_REG		0x01
#define LENOVO_EC_REQUEST_REG		0x02

#define LENOVO_EC_UCSI_WRITE		0x20
#define LENOVO_EC_UCSI_READ		0x21

#define LENOVO_EC_READ_REG		0xb0
#define LENOVO_EC_WRITE_REG		0xb1
#define LENOVO_EC_REQUEST_NEXT_EVENT	0x84

#define LENOVO_EC_UCSI_VERSION		0x20

#define LENOVO_EC_KBD_BACKLIGHT_REG	0x03
#define LENOVO_EC_KBD_BACKLIGHT_ON	BIT(0)

struct yoga_c630_ec {
	struct i2c_client *client;
	struct mutex lock;
	struct blocking_notifier_head notifier_list;
	struct led_classdev kbd_backlight;
	enum led_brightness kbd_backlight_brightness;
};

static int yoga_c630_ec_request(struct yoga_c630_ec *ec, u8 *req, size_t req_len,
				u8 *resp, size_t resp_len)
{
	int ret;

	lockdep_assert_held(&ec->lock);

	ret = i2c_smbus_write_i2c_block_data(ec->client, LENOVO_EC_REQUEST_REG,
					     req_len, req);
	if (ret < 0)
		return ret;

	return i2c_smbus_read_i2c_block_data(ec->client, LENOVO_EC_RESPONSE_REG,
					     resp_len, resp);
}

static int __yoga_c630_ec_read8(struct yoga_c630_ec *ec, u8 addr)
{
	u8 req[2] = { LENOVO_EC_READ_REG, addr };
	int ret;
	u8 val;

	lockdep_assert_held(&ec->lock);

	ret = yoga_c630_ec_request(ec, req, sizeof(req), &val, 1);
	if (ret < 0)
		return ret;

	return val;
}

int yoga_c630_ec_read8(struct yoga_c630_ec *ec, u8 addr)
{
	guard(mutex)(&ec->lock);

	return __yoga_c630_ec_read8(ec, addr);
}
EXPORT_SYMBOL_GPL(yoga_c630_ec_read8);

int yoga_c630_ec_read16(struct yoga_c630_ec *ec, u8 addr)
{
	u8 req[2] = { LENOVO_EC_READ_REG, };
	int ret;
	u8 msb;
	u8 lsb;

	/* don't overflow the address */
	if (addr == 0xff)
		return -EINVAL;

	guard(mutex)(&ec->lock);

	req[1] = addr;
	ret = yoga_c630_ec_request(ec, req, sizeof(req), &lsb, 1);
	if (ret < 0)
		return ret;

	req[1] = addr + 1;
	ret = yoga_c630_ec_request(ec, req, sizeof(req), &msb, 1);
	if (ret < 0)
		return ret;

	return msb << 8 | lsb;
}
EXPORT_SYMBOL_GPL(yoga_c630_ec_read16);

/*
 * Update the bits in @mask of EC register @addr to those in @val. Return the
 * previous value of the register, or a negative error code.
 */
static int yoga_c630_ec_update_bits(struct yoga_c630_ec *ec, u8 addr, u8 mask,
				    u8 val)
{
	u8 req[3] = { LENOVO_EC_WRITE_REG, addr, };
	int old, ret;

	guard(mutex)(&ec->lock);

	old = __yoga_c630_ec_read8(ec, addr);
	if (old < 0 || (old & mask) == (val & mask))
		return old;

	req[2] = (old & ~mask) | (val & mask);
	ret = i2c_smbus_write_i2c_block_data(ec->client, LENOVO_EC_REQUEST_REG,
					     sizeof(req), req);
	if (ret < 0)
		return ret;

	return old;
}

u16 yoga_c630_ec_ucsi_get_version(struct yoga_c630_ec *ec)
{
	u8 req[3] = { 0xb3, 0xf2, };
	int ret;
	u8 msb;
	u8 lsb;

	guard(mutex)(&ec->lock);

	req[2] = LENOVO_EC_UCSI_VERSION;
	ret = yoga_c630_ec_request(ec, req, sizeof(req), &lsb, 1);
	if (ret < 0)
		return ret;

	req[2] = LENOVO_EC_UCSI_VERSION + 1;
	ret = yoga_c630_ec_request(ec, req, sizeof(req), &msb, 1);
	if (ret < 0)
		return ret;

	return msb << 8 | lsb;
}
EXPORT_SYMBOL_GPL(yoga_c630_ec_ucsi_get_version);

int yoga_c630_ec_ucsi_write(struct yoga_c630_ec *ec,
			    const u8 req[YOGA_C630_UCSI_WRITE_SIZE])
{
	int ret;

	mutex_lock(&ec->lock);
	ret = i2c_smbus_write_i2c_block_data(ec->client, LENOVO_EC_UCSI_WRITE,
					     YOGA_C630_UCSI_WRITE_SIZE, req);
	mutex_unlock(&ec->lock);

	return ret < 0 ? ret : 0;
}
EXPORT_SYMBOL_GPL(yoga_c630_ec_ucsi_write);

int yoga_c630_ec_ucsi_read(struct yoga_c630_ec *ec,
			   u8 resp[YOGA_C630_UCSI_READ_SIZE])
{
	int ret;

	mutex_lock(&ec->lock);
	ret = i2c_smbus_read_i2c_block_data(ec->client, LENOVO_EC_UCSI_READ,
					    YOGA_C630_UCSI_READ_SIZE, resp);
	mutex_unlock(&ec->lock);

	return ret < 0 ? ret : 0;
}
EXPORT_SYMBOL_GPL(yoga_c630_ec_ucsi_read);

static enum led_brightness
yoga_c630_ec_kbd_backlight_get(struct led_classdev *led_cdev)
{
	struct yoga_c630_ec *ec = container_of(led_cdev, struct yoga_c630_ec,
					       kbd_backlight);
	int val;

	val = yoga_c630_ec_read8(ec, LENOVO_EC_KBD_BACKLIGHT_REG);
	if (val < 0)
		return val;

	return val & LENOVO_EC_KBD_BACKLIGHT_ON ? LED_ON : LED_OFF;
}

static int yoga_c630_ec_kbd_backlight_set(struct led_classdev *led_cdev,
					  enum led_brightness brightness)
{
	struct yoga_c630_ec *ec = container_of(led_cdev, struct yoga_c630_ec,
					       kbd_backlight);
	int old;

	old = yoga_c630_ec_update_bits(ec, LENOVO_EC_KBD_BACKLIGHT_REG,
				       LENOVO_EC_KBD_BACKLIGHT_ON,
				       brightness ? LENOVO_EC_KBD_BACKLIGHT_ON : 0);
	if (old < 0)
		return old;

	WRITE_ONCE(ec->kbd_backlight_brightness, brightness ? LED_ON : LED_OFF);

	return 0;
}

/* Report changes made by the EC itself, i.e., when Fn+Space is pressed */
static void yoga_c630_ec_kbd_backlight_update(struct yoga_c630_ec *ec)
{
	int brightness;

	brightness = yoga_c630_ec_kbd_backlight_get(&ec->kbd_backlight);
	if (brightness < 0 ||
	    brightness == READ_ONCE(ec->kbd_backlight_brightness))
		return;

	WRITE_ONCE(ec->kbd_backlight_brightness, brightness);
	led_classdev_notify_brightness_hw_changed(&ec->kbd_backlight,
						  brightness);
}

static int yoga_c630_ec_kbd_backlight_init(struct yoga_c630_ec *ec)
{
	struct led_classdev *led_cdev = &ec->kbd_backlight;
	int brightness;

	brightness = yoga_c630_ec_kbd_backlight_get(led_cdev);
	if (brightness < 0)
		return brightness;

	ec->kbd_backlight_brightness = brightness;

	led_cdev->name = "platform::kbd_backlight";
	led_cdev->flags = LED_BRIGHT_HW_CHANGED;
	led_cdev->max_brightness = LED_ON;
	led_cdev->brightness_get = yoga_c630_ec_kbd_backlight_get;
	led_cdev->brightness_set_blocking = yoga_c630_ec_kbd_backlight_set;

	return devm_led_classdev_register(&ec->client->dev, led_cdev);
}

static irqreturn_t yoga_c630_ec_thread_intr(int irq, void *data)
{
	u8 req[] = { LENOVO_EC_REQUEST_NEXT_EVENT };
	struct yoga_c630_ec *ec = data;
	u8 event;
	int ret;

	mutex_lock(&ec->lock);
	ret = yoga_c630_ec_request(ec, req, sizeof(req), &event, 1);
	mutex_unlock(&ec->lock);
	if (ret < 0)
		return IRQ_HANDLED;

	blocking_notifier_call_chain(&ec->notifier_list, event, ec);

	yoga_c630_ec_kbd_backlight_update(ec);

	return IRQ_HANDLED;
}

/**
 * yoga_c630_ec_register_notify - Register a notifier callback for EC events.
 * @ec: Yoga C630 EC
 * @nb: Notifier block pointer to register
 *
 * Return: 0 on success or negative error code.
 */
int yoga_c630_ec_register_notify(struct yoga_c630_ec *ec, struct notifier_block *nb)
{
	return blocking_notifier_chain_register(&ec->notifier_list, nb);
}
EXPORT_SYMBOL_GPL(yoga_c630_ec_register_notify);

/**
 * yoga_c630_ec_unregister_notify - Unregister notifier callback for EC events.
 * @ec: Yoga C630 EC
 * @nb: Notifier block pointer to unregister
 *
 * Unregister a notifier callback that was previously registered with
 * yoga_c630_ec_register_notify().
 */
void yoga_c630_ec_unregister_notify(struct yoga_c630_ec *ec, struct notifier_block *nb)
{
	blocking_notifier_chain_unregister(&ec->notifier_list, nb);
}
EXPORT_SYMBOL_GPL(yoga_c630_ec_unregister_notify);

static int yoga_c630_aux_init(struct device *parent, const char *name,
			      struct yoga_c630_ec *ec)
{
	struct auxiliary_device *adev;

	adev = devm_auxiliary_device_create(parent, name, ec);
	if (!adev)
		return -ENODEV;

	return 0;
}

static int yoga_c630_ec_probe(struct i2c_client *client)
{
	struct device *dev = &client->dev;
	struct yoga_c630_ec *ec;
	int ret;

	ec = devm_kzalloc(dev, sizeof(*ec), GFP_KERNEL);
	if (!ec)
		return -ENOMEM;

	mutex_init(&ec->lock);
	ec->client = client;
	BLOCKING_INIT_NOTIFIER_HEAD(&ec->notifier_list);
	i2c_set_clientdata(client, ec);

	ret = yoga_c630_ec_kbd_backlight_init(ec);
	if (ret)
		return dev_err_probe(dev, ret,
				     "failed to register keyboard backlight\n");

	ret = devm_request_threaded_irq(dev, client->irq,
					NULL, yoga_c630_ec_thread_intr,
					IRQF_ONESHOT, "yoga_c630_ec", ec);
	if (ret < 0)
		return ret;

	ret = yoga_c630_aux_init(dev, YOGA_C630_DEV_PSY, ec);
	if (ret)
		return ret;

	return yoga_c630_aux_init(dev, YOGA_C630_DEV_UCSI, ec);
}

/*
 * Keep the EC interrupt disabled until the system has resumed. Its
 * handler reads the pending event over I2C, which fails between the late
 * suspend and early resume phases of the I2C controller, and as the
 * interrupt is level triggered, it would fire over and over again until the
 * handler gets to read the event.
 */
static int yoga_c630_ec_suspend(struct device *dev)
{
	struct yoga_c630_ec *ec = dev_get_drvdata(dev);

	disable_irq(ec->client->irq);

	return 0;
}

static int yoga_c630_ec_resume(struct device *dev)
{
	struct yoga_c630_ec *ec = dev_get_drvdata(dev);

	enable_irq(ec->client->irq);

	return 0;
}

static DEFINE_SIMPLE_DEV_PM_OPS(yoga_c630_ec_pm_ops, yoga_c630_ec_suspend,
				yoga_c630_ec_resume);


static const struct of_device_id yoga_c630_ec_of_match[] = {
	{ .compatible = "lenovo,yoga-c630-ec" },
	{}
};
MODULE_DEVICE_TABLE(of, yoga_c630_ec_of_match);

static const struct i2c_device_id yoga_c630_ec_i2c_id_table[] = {
	{ .name = "yoga-c630-ec" },
	{ }
};
MODULE_DEVICE_TABLE(i2c, yoga_c630_ec_i2c_id_table);

static struct i2c_driver yoga_c630_ec_i2c_driver = {
	.driver = {
		.name = "yoga-c630-ec",
		.of_match_table = yoga_c630_ec_of_match,
		.pm = pm_sleep_ptr(&yoga_c630_ec_pm_ops),
	},
	.probe = yoga_c630_ec_probe,
	.id_table = yoga_c630_ec_i2c_id_table,
};
module_i2c_driver(yoga_c630_ec_i2c_driver);

MODULE_DESCRIPTION("Lenovo Yoga C630 Embedded Controller");
MODULE_LICENSE("GPL");
