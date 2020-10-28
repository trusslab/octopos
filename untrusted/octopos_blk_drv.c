// SPDX-License-Identifier: GPL-2.0-only
/*
 * OctopOS block driver.
 *
 * Based on:
 *
 * Ram backed block device driver.
 *
 * Copyright (C) 2007 Nick Piggin
 * Copyright (C) 2007 Novell Inc.
 *
 * Parts derived from drivers/block/rd.c, and drivers/block/loop.c, copyright
 * of their respective owners.
 */

#include <linux/init.h>
#include <linux/initrd.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/major.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/fs.h>
#include <linux/backing-dev.h>

#include <linux/uaccess.h>
#include <octopos/storage.h>
#include "storage_client.h" 

struct request_queue	*obd_queue = NULL;
struct gendisk		*obd_disk = NULL;

/*
 * Process a single bvec of a bio.
 */
static int obd_do_bvec(struct page *page, unsigned int len, unsigned int off,
		       unsigned int op, sector_t sector)
{
	void *mem;
	int ret;

	if (len % 512)
		BUG();
	printk("%s [1]\n", __func__);

	ret = request_secure_storage_access(200, STORAGE_UNTRUSTED_ROOT_FS_PARTITION_SIZE);
	if (ret) {
		printk("Error (%s): Failed to get secure access to storage.\n", __func__);
		return ret;
	}
	printk("%s [2]\n", __func__);

	mem = kmap_atomic(page);
	if (!op_is_write(op)) {
		read_secure_storage_blocks(mem + off, sector, len / 512);
		flush_dcache_page(page);
	} else {
		flush_dcache_page(page);
		write_secure_storage_blocks(mem + off, sector, len / 512);
	}
	kunmap_atomic(mem);

	printk("%s [3]\n", __func__);
	yield_secure_storage_access();
	printk("%s [4]\n", __func__);

	return 0;
}

static blk_qc_t obd_make_request(struct request_queue *q, struct bio *bio)
{
	struct bio_vec bvec;
	sector_t sector;
	struct bvec_iter iter;

	sector = bio->bi_iter.bi_sector;
	if (bio_end_sector(bio) > get_capacity(bio->bi_disk))
		goto io_error;

	bio_for_each_segment(bvec, bio, iter) {
		unsigned int len = bvec.bv_len;
		int err;

		/* Don't support un-aligned buffer */
		WARN_ON_ONCE((bvec.bv_offset & (SECTOR_SIZE - 1)) ||
				(len & (SECTOR_SIZE - 1)));

		err = obd_do_bvec(bvec.bv_page, len, bvec.bv_offset,
				  bio_op(bio), sector);
		if (err)
			goto io_error;
		sector += len >> SECTOR_SHIFT;
	}

	bio_endio(bio);
	return BLK_QC_T_NONE;
io_error:
	bio_io_error(bio);
	return BLK_QC_T_NONE;
}

static int obd_rw_page(struct block_device *bdev, sector_t sector,
		       struct page *page, unsigned int op)
{
	int err;

	if (PageTransHuge(page))
		return -ENOTSUPP;
	err = obd_do_bvec(page, PAGE_SIZE, 0, op, sector);
	page_endio(page, op_is_write(op), err);
	return err;
}

static const struct block_device_operations obd_fops = {
	.owner =		THIS_MODULE,
	.rw_page =		obd_rw_page,
};

/*
 * And now the modules code and kernel interface.
 */
unsigned long obd_size =
	(STORAGE_UNTRUSTED_ROOT_FS_PARTITION_SIZE * STORAGE_BLOCK_SIZE) / 1024;
module_param(obd_size, ulong, 0444);
MODULE_PARM_DESC(obd_size, "Size of the partition (in kB) requested from the "
		 "OctopOS storage service.");

MODULE_LICENSE("GPL");
MODULE_ALIAS_BLOCKDEV_MAJOR(OCTOPOS_BLK_MAJOR);
MODULE_ALIAS("obd");

static void obd_free(void)
{
	put_disk(obd_disk);
	blk_cleanup_queue(obd_queue);
}

static struct kobject *obd_probe(dev_t dev, int *part, void *data)
{
	struct kobject *kobj;

	add_disk(obd_disk);
	kobj = get_disk_and_module(obd_disk);

	return kobj;
}

static int obd_init_disk(void)
{
	obd_queue = blk_alloc_queue(obd_make_request, NUMA_NO_NODE);
	if (!obd_queue)
		goto out;

	/* This is so fdisk will align partitions on 4k, because of
	 * direct_access API needing 4k alignment, returning a PFN
	 * (This is only a problem on very small devices <= 4M,
	 *  otherwise fdisk will align on 1M. Regardless this call
	 *  is harmless)
	 */
	blk_queue_physical_block_size(obd_queue, PAGE_SIZE);
	obd_disk = alloc_disk(1);
	if (!obd_disk)
		goto out_free_queue;
	obd_disk->major		= OCTOPOS_BLK_MAJOR;
	obd_disk->first_minor	= 0;
	obd_disk->fops		= &obd_fops;
	obd_disk->private_data	= NULL;
	obd_disk->flags		= GENHD_FL_EXT_DEVT;
	sprintf(obd_disk->disk_name, "octopos_blk");
	set_capacity(obd_disk, obd_size * 2);
	obd_queue->backing_dev_info->capabilities |= BDI_CAP_SYNCHRONOUS_IO;

	/* Tell the block layer that this is not a rotational device */
	blk_queue_flag_set(QUEUE_FLAG_NONROT, obd_queue);
	blk_queue_flag_clear(QUEUE_FLAG_ADD_RANDOM, obd_queue);

	return 0;

out_free_queue:
	blk_cleanup_queue(obd_queue);
out:
	return -ENOMEM;
}

static int __init obd_init(void)
{
	uint8_t secure_storage_key[STORAGE_KEY_SIZE];
	int i;

	for (i = 0; i < STORAGE_KEY_SIZE; i++)
		secure_storage_key[i] = i + 2;

	set_up_secure_storage_key(secure_storage_key);

	if (register_blkdev(OCTOPOS_BLK_MAJOR, "octopos_blk"))
		return -EIO;

	if (obd_init_disk())
		goto out_free;

	/*
	 * associate with queue just before adding disk for
	 * avoiding to mess up failure path
	 */
	obd_disk->queue = obd_queue;
	add_disk(obd_disk);

	blk_register_region(MKDEV(OCTOPOS_BLK_MAJOR, 0), 1UL << MINORBITS,
				  THIS_MODULE, obd_probe, NULL, NULL);

	pr_info("obd: module loaded\n");

	return 0;

out_free:
	obd_free();
	unregister_blkdev(OCTOPOS_BLK_MAJOR, "octopos_blk");

	pr_info("obd: module NOT loaded !!!\n");
	return -ENOMEM;
}

static void __exit obd_exit(void)
{
	obd_free();

	blk_unregister_region(MKDEV(OCTOPOS_BLK_MAJOR, 0), 1UL << MINORBITS);
	unregister_blkdev(OCTOPOS_BLK_MAJOR, "octopos_blk");

	pr_info("obd: module unloaded\n");
}

module_init(obd_init);
module_exit(obd_exit);
