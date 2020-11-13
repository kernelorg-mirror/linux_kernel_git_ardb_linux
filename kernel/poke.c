// SPDX-License-Identifier: GPL-2.0

#include <linux/kobject.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/module.h>
#include <linux/init.h>

static unsigned long *virt;

static ssize_t val_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "0x%lx\n", *virt);
}

static ssize_t val_store(struct kobject *kobj, struct kobj_attribute *attr,
			 const char *buf, size_t count)
{
	unsigned long val;
	int ret;

	ret = kstrtoul(buf, 0, &val);
	if (ret < 0)
		return ret;

	*virt = val;

	return count;
}
static struct kobj_attribute val_attribute = __ATTR(val, 0664, val_show, val_store);

static ssize_t virt_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "0x%llx\n", (u64)virt);
}

static ssize_t virt_store(struct kobject *kobj, struct kobj_attribute *attr,
			  const char *buf, size_t count)
{
	unsigned long val;
	int ret;

	ret = kstrtoul(buf, 0, &val);
	if (ret < 0)
		return ret;

	virt = (unsigned long *) val;

	return count;
}
static struct kobj_attribute virt_attribute = __ATTR(virt, 0664, virt_show, virt_store);

static struct attribute *attrs[] = {
	&val_attribute.attr,
	&virt_attribute.attr,
	NULL,
};
static struct attribute_group attr_group = {
	.attrs = attrs,
};
static struct kobject *poke_kobj;

static int __init poke_init(void)
{
	int retval;

	poke_kobj = kobject_create_and_add("poke", kernel_kobj);
	if (!poke_kobj)
		return -ENOMEM;

	retval = sysfs_create_group(poke_kobj, &attr_group);
	if (retval)
		kobject_put(poke_kobj);
	else
		pr_info("poke: available under /sys/kernel/poke/\n");

	return retval;
}
late_initcall(poke_init);
MODULE_LICENSE("GPL v2");
