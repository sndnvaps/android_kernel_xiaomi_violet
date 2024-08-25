/* drivers/android/ram_console.c
 *
 * Copyright (C) 2007-2008 Google, Inc.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/console.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/pstore_ram.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/compiler.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include "internal.h"

static unsigned long long mem_address;
module_param_hw(mem_address, ullong, other, 0400);
MODULE_PARM_DESC(mem_address,
		"start of reserved RAM used to store the last bootinfo -> /proc/last_kmsg logs");

static ulong mem_size;
module_param(mem_size, ulong, 0400);
MODULE_PARM_DESC(mem_size,
		"size of reserved RAM used to store the last bootinfo -> /proc/last_kmsg logs");


static struct platform_device *dummy;
static struct ram_console_platform_data *dummy_data;

struct ram_console_platform_data {
    //mem_address for the ram_console, Reserved in device tree
    phys_addr_t mem_address; 
    //size of the memory
    unsigned long mem_size;
    struct persistent_ram_ecc_info ecc_info;
};

struct ram_console_context {
	struct persistent_ram_zone *prz;	/* RAM_CONSOLE zones */
	//mem_address for the ram_console, Reserved in device tree
    phys_addr_t mem_address; 
    //size of the memory
    unsigned long mem_size;
    struct persistent_ram_ecc_info ecc_info;
	const char *bootinfo;
	size_t bootinfo_size;
	struct console console;
};

//static struct persistent_ram_zone *ram_console_zone;
//static const char *bootinfo;
//static size_t bootinfo_size;
static void ram_console_write(struct console *console, const char *s, unsigned int count);

static struct ram_console_context ram_console_cxt = {
	.console = {
		.name	= "ram_console",
		.write	= ram_console_write,
		.flags	= CON_PRINTBUFFER | CON_ENABLED | CON_ANYTIME,
		.index	= -1,
	},
};

static void
ram_console_write(struct console *console, const char *s, unsigned int count)
{
	struct ram_console_context *cxt = &ram_console_cxt;
	cxt->prz = console->data;
	persistent_ram_write(cxt->prz, s, count);
}


void ram_console_enable_console(int enabled)
{
	if (enabled)
		ram_console_cxt.console.flags |= CON_ENABLED;
	else
		ram_console_cxt.console.flags &= ~CON_ENABLED;
}


static int ram_console_parse_dt(struct platform_device *pdev,
			    struct ram_console_platform_data *pdata)
{
	struct resource *res;

	dev_dbg(&pdev->dev, "using Device Tree\n");

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res) {
		dev_err(&pdev->dev,
			"failed to locate DT /reserved-memory resource\n");
		return -EINVAL;
	}

	pdata->mem_size = resource_size(res);
	pdata->mem_address = res->start;
	/*
	 * For backwards compatibility ramoops.ecc=1 means 16 bytes ECC
	 * (using 1 byte for ECC isn't much of use anyway).
	 */
	//set default to '1'
    pdata->ecc_info.ecc_size = 1;

	return 0;
}

static int ram_console_init_prz(const char *name,
			    struct device *dev, struct ram_console_context *cxt,
				struct persistent_ram_ecc_info ecc_info,
			    struct persistent_ram_zone **prz,
			    phys_addr_t *paddr, size_t sz, u32 sig)
{
	if (!sz)
		return 0;

	*prz = persistent_ram_new(*paddr, sz, sig, &cxt->ecc_info,
				  0, 0);
	if (IS_ERR(*prz)) {
		int err = PTR_ERR(*prz);

		dev_err(dev, "failed to request %s mem region (0x%zx@0x%llx): %d\n",
			name, sz, (unsigned long long)*paddr, err);
		return err;
	}

	return 0;
}

static int ram_console_probe(struct platform_device *pdev)
{
	struct ram_console_platform_data *pdata = pdev->dev.platform_data;
	struct ram_console_context *cxt = &ram_console_cxt;
	struct persistent_ram_zone *prz = cxt->prz;
	struct device *dev = &pdev->dev;
	phys_addr_t paddr;
    struct persistent_ram_ecc_info ecc_info;
    unsigned long mem_size;
    int err = -EINVAL;

	if (dev_of_node(dev) && !pdata) {
		pdata = devm_kzalloc(&pdev->dev, sizeof(*pdata), GFP_KERNEL);
		if (!pdata) {
			pr_err("cannot allocate platform data buffer\n");
			err = -ENOMEM;
			goto fail_out;
		}
        err = ram_console_parse_dt(pdev, pdata);
        if (err < 0) {
            goto fail_out;
        }
    }

    /* Make sure we didn't get bogus platform data pointer. */
	if (!pdata) {
		pr_err("NULL platform data\n");
		goto fail_out;
	}

    paddr = pdata->mem_address;
    mem_size = pdata->mem_size;
    ecc_info = pdata->ecc_info;

	err = ram_console_init_prz("ram_console", dev, cxt, cxt->ecc_info, &prz, &paddr, mem_size, 0);
	if (err) {
		pr_err("ram_console: fail to init prz\n");
		goto fail_out;
	}

	if (pdata) {
		cxt->bootinfo = kstrdup(cxt->bootinfo, GFP_KERNEL);
		if (cxt->bootinfo) {
			ram_console_cxt.bootinfo = cxt->bootinfo;
			cxt->bootinfo_size = strlen(cxt->bootinfo);
			ram_console_cxt.bootinfo_size = cxt->bootinfo_size;
		}
	}

	ram_console_cxt.prz = prz;
	ram_console_cxt.console.data = prz;

	register_console(&ram_console_cxt.console);

	return 0;

fail_out:
	return err;
}


static int ram_console_remove(struct platform_device *pdev) 
{
	struct ram_console_context *cxt = &ram_console_cxt;
	unregister_console(&cxt->console);
	kfree(cxt->console.data);

	persistent_ram_free(cxt->prz);

	return 0;

}
static const struct of_device_id dt_match[] = {
	{ .compatible = "ram_console" },
	{}
};


static struct platform_driver ram_console_driver = {
	.probe = ram_console_probe,
	.remove = ram_console_remove,
	.driver		= {
		.name	= "ram_console",
        .of_match_table	= dt_match,
	},
};

static void ram_console_register_dummy(void)
{
	if (!mem_size)
		return;

	pr_info("using module parameters\n");

	dummy_data = kzalloc(sizeof(*dummy_data), GFP_KERNEL);
	if (!dummy_data) {
		pr_info("could not allocate pdata\n");
		return;
	}

	dummy_data->mem_size = mem_size;
	dummy_data->mem_address = mem_address;

	/*
	 * For backwards compatibility ram_console.ecc=1 means 16 bytes ECC
	 * (using 1 byte for ECC isn't much of use anyway).
	 */
	dummy_data->ecc_info.ecc_size = 1;

	dummy = platform_device_register_data(NULL, "ram_console", -1,
			dummy_data, sizeof(struct ram_console_platform_data));
	if (IS_ERR(dummy)) {
		pr_info("could not create platform device: %ld\n",
			PTR_ERR(dummy));
	}
}


#ifndef CONFIG_PRINTK
#define dmesg_restrict	0
#endif

static ssize_t ram_console_read_old(struct file *file, char __user *buf,
				    size_t len, loff_t *offset)
{
	loff_t pos = *offset;
	ssize_t count;
	struct ram_console_context *cxt = &ram_console_cxt;
	struct persistent_ram_zone *prz = cxt->prz;
	size_t old_log_size = persistent_ram_old_size(prz);
	const char *old_log = persistent_ram_old(prz);
	char *str;
	int ret;

	if (dmesg_restrict && !capable(CAP_SYSLOG))
		return -EPERM;

	/* Main last_kmsg log */
	if (pos < old_log_size) {
		count = min(len, (size_t)(old_log_size - pos));
		if (copy_to_user(buf, old_log + pos, count))
			return -EFAULT;
		goto out;
	}

	/* ECC correction notice */
	pos -= old_log_size;
	count = persistent_ram_ecc_string(prz, NULL, 0);
	if (pos < count) {
		str = kmalloc(count, GFP_KERNEL);
		if (!str)
			return -ENOMEM;
		persistent_ram_ecc_string(prz, str, count + 1);
		count = min(len, (size_t)(count - pos));
		ret = copy_to_user(buf, str + pos, count);
		kfree(str);
		if (ret)
			return -EFAULT;
		goto out;
	}

	/* Boot info passed through pdata */
	pos -= count;
	if (pos < cxt->bootinfo_size) {
		count = min(len, (size_t)(cxt->bootinfo_size - pos));
		if (copy_to_user(buf, cxt->bootinfo + pos, count))
			return -EFAULT;
		goto out;
	}

	/* EOF */
	return 0;

out:
	*offset += count;
	return count;
}

static const struct file_operations ram_console_file_ops = {
	.read = ram_console_read_old,
};

static int __init ram_console_late_init(void)
{
	struct proc_dir_entry *entry;
	struct ram_console_context *cxt = &ram_console_cxt;
	struct persistent_ram_zone *prz = cxt->prz;
	size_t temp_var = 0;

	if (!prz)
		return 0;

	if (persistent_ram_old_size(prz) == 0)
		return 0;

	entry = proc_create("last_kmsg", S_IFREG | S_IRUGO, NULL,&ram_console_file_ops);
	if (!entry) {
		printk(KERN_ERR "ram_console: failed to create proc entry\n");
		persistent_ram_free_old(prz);
		return 0;
	}
	temp_var = persistent_ram_old_size(prz) +
		persistent_ram_ecc_string(prz, NULL, 0) +
		cxt->bootinfo_size;
	entry->size = (loff_t)(temp_var);

	return 0;
}

late_initcall(ram_console_late_init);

static int __init ram_console_init(void)
{
	ram_console_register_dummy();
	ram_console_enable_console(1);
	return platform_driver_register(&ram_console_driver);
}
postcore_initcall(ram_console_init);

static void __exit ram_console_exit(void)
{
	platform_driver_unregister(&ram_console_driver);
	platform_device_unregister(dummy);
	kfree(dummy_data);
}

module_exit(ram_console_exit);

