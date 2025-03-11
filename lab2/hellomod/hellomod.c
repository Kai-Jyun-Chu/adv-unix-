/*
 * Lab problem set for UNIX programming course
 * by Chun-Ying Huang <chuang@cs.nctu.edu.tw>
 * License: GPLv2
 */
#include <linux/module.h>	// included for all kernel modules
#include <linux/kernel.h>	// included for KERN_INFO
#include <linux/init.h>		// included for __init and __exit macros
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/errno.h>
#include <linux/sched.h>	// task_struct requried for current_uid()
#include <linux/cred.h>		// for current_uid();
#include <linux/slab.h>		// for kmalloc/kfree
#include <linux/uaccess.h>	// copy_to_user
#include <linux/string.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/printk.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>
#include "cryptomod.h"
#include <linux/mutex.h>
#include <linux/crypto.h>

DEFINE_MUTEX(buffer_lock);
static dev_t devnum;
static struct cdev c_dev;
static struct class *clazz;

static struct CryptoSetup crypto_config;
static bool finalized = false;  // Tracks if CM_IOC_FINALIZE was called
static bool setup_done = false; // Tracks if CM_IOC_SETUP was called
static size_t buffer_size = 0;  // Tracks buffer usage
static unsigned long total_read = 0, total_written = 0;
static unsigned long byte_freq[256] = {0}; // Byte frequency tracking
static char *buffer = NULL;  // Data buffer
static size_t cap = 1024;

static int cryptomod_dev_open(struct inode *i, struct file *f) {
	printk(KERN_INFO "cryptomod: device opened.\n");
	if (!buffer) {  
        
        buffer = kmalloc(cap, GFP_KERNEL);
        if (!buffer) {
            printk(KERN_ERR "Failed to allocate buffer.\n");
            return -ENOMEM;
        }
        memset(buffer, 0, cap);  // Zero initialize
    }
	return 0;
}

static int cryptomod_dev_close(struct inode *i, struct file *f) {
	printk(KERN_INFO "cryptomod: device closed.\n");
	if (buffer) {
        kfree(buffer);
        buffer = NULL;
        
    }
	return 0;
}

static ssize_t cryptomod_dev_read(struct file *f, char __user *buf, size_t len, loff_t *off)
{
	//mutex_lock(&buffer_lock);
    size_t to_copy;
	
    // 1) If the device is not set up yet, return -EINVAL
    if (!setup_done)
        return -EINVAL;

    // 2) If no data in the buffer
	if (!buffer)
		return -ENOMEM;
    if (buffer_size == 0) {
        // 2a) If not finalized, no data is ready, return -EAGAIN
        if (!finalized)
            return -EAGAIN;
        // 2b) If finalized, we're at EOF, return 0
        return 0;
    }


    to_copy = (len > buffer_size) ? buffer_size : len;

    // 4) Copy data to user space
    if (copy_to_user(buf, buffer, to_copy)){
		return -EBUSY;
	}
          
	for (int i = 0; i < to_copy; i++) {
        byte_freq[(unsigned char)buffer[i]]++;
    }	
    if (to_copy < buffer_size) {
        memmove(buffer, buffer + to_copy, buffer_size - to_copy);
    }
	printk(KERN_INFO "cryptomod: read %zu bytes @ %llu.\n", to_copy, *off);
    buffer_size -= to_copy;
	printk(KERN_INFO "buffer_size: %zu.\n", buffer_size);

    total_read += to_copy;
	
    return to_copy;  
}

static ssize_t cryptomod_dev_write(struct file *f, const char __user *buf, size_t len, loff_t *off) {
	
    size_t space_left, bytes_to_copy;

	if(finalized){
		return -EINVAL;
	}
    
    
    if (!buffer)
    	return -ENOMEM;
    if (buffer_size >= cap)
        return -EAGAIN;  

    space_left = cap - buffer_size;
    bytes_to_copy = (len > space_left) ? space_left : len;

    
    if (copy_from_user(buffer + buffer_size, buf, bytes_to_copy))
        return -EBUSY;  

    printk(KERN_INFO "cryptomod: write %zu bytes @ %llu.\n", bytes_to_copy, *off);
    buffer_size += bytes_to_copy;
	total_written += bytes_to_copy;
    // Update the byte frequency counters for the newly copied data
    
	
    return bytes_to_copy;  // Return the number of bytes successfully written
}


static long cryptomod_dev_ioctl(struct file *fp, unsigned int cmd, unsigned long arg) {
	printk(KERN_INFO "cryptomod: ioctl cmd=%u arg=%lu.\n", cmd, arg);
	
	//memset(byte_freq, 0, sizeof(byte_freq)); 
	//buffer_size = 0;  // Clear buffer
	//encrypted = false;  // Reset encryption flag
	
	switch (cmd) {

        case CM_IOC_SETUP: {
			
            if (arg == 0)
                return -EINVAL;  

            if (copy_from_user(&crypto_config, (struct CryptoSetup __user *)arg, sizeof(struct CryptoSetup)))
                return -EBUSY;  // Failed to copy data

            // Validate key length
            if (crypto_config.key_len != 16 && crypto_config.key_len != 24 && crypto_config.key_len != 32)
                return -EINVAL;  

            // Reset buffers and state
            setup_done = true;
            finalized = false;
            //buffer_size = 0;
            //memset(byte_freq, 0, sizeof(byte_freq));

            printk(KERN_INFO "cryptomod: Setup complete - Mode: %s, Key Length: %d, I/O Mode: %s\n",
                   crypto_config.c_mode == ENC ? "Encrypt" : "Decrypt",
                   crypto_config.key_len,
                   crypto_config.io_mode == BASIC ? "Basic" : "Advanced");
            return 0;
        }

        case CM_IOC_FINALIZE: {
			if (!setup_done)
				return -EINVAL;  // Device not set up
			struct crypto_skcipher *tfm = NULL;
			struct skcipher_request *req = NULL;
			struct scatterlist sg;
			DECLARE_CRYPTO_WAIT(wait);
			int err;
		
			
		
			
			if (crypto_config.c_mode == ENC) {
				
				size_t padding = CM_BLOCK_SIZE - (buffer_size % CM_BLOCK_SIZE);
				if (buffer_size + padding > cap)
					return -EINVAL;  // Buffer overflow
		
				for (size_t i = 0; i < padding; i++){
					buffer[buffer_size + i] = padding;
				}
					
				buffer_size += padding;
				//for (size_t i = 0; i < buffer_size; i++)
				//	printk(KERN_INFO "%zu,", i );
				

				
				tfm = crypto_alloc_skcipher("ecb(aes)", 0, 0);
				if (IS_ERR(tfm)) {
					printk(KERN_ERR "cryptomod: Error allocating AES-ECB handle: %ld\n", PTR_ERR(tfm));
					return PTR_ERR(tfm);
				}
		
				err = crypto_skcipher_setkey(tfm, crypto_config.key, crypto_config.key_len);
				if (err) {
					printk(KERN_ERR "cryptomod: Error setting AES key: %d\n", err);
					goto out_free_tfm;
				}
		
				req = skcipher_request_alloc(tfm, GFP_KERNEL);
				if (!req) {
					err = -ENOMEM;
					goto out_free_tfm;
				}
				printk(KERN_INFO "✅✅ready to Encrypt %zu bytes.\n", buffer_size);
				//u8 *encrypt_buf = (u8 *)buffer;
				sg_init_one(&sg, buffer, buffer_size);
				skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
                                       CRYPTO_TFM_REQ_MAY_SLEEP,
                                  crypto_req_done, &wait);
				skcipher_request_set_crypt(req, &sg, &sg, buffer_size, NULL);
					
				err = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
				if (err) {
					printk(KERN_ERR "cryptomod: AES encryption failed: %d\n", err);
					goto out_free_req;
				}
				printk(KERN_INFO "cryptomod: Successfully encrypted %zu bytes.\n", buffer_size);
			}
			finalized = true;

			out_free_req:
				skcipher_request_free(req);
			out_free_tfm:
				crypto_free_skcipher(tfm);
				return err;
		}
		

        case CM_IOC_CLEANUP:
			total_read = 0;
			total_written = 0;
			if (!setup_done)
				return -EINVAL;  // Device not set up

			// Reset all buffers
			buffer_size = 0;
			finalized = false;

			

			printk(KERN_INFO "cryptomod: Cleanup completed (buffer zeroed).\n");
			return 0;

        case CM_IOC_CNT_RST:
            // Reset counters and byte frequency tracking
            total_read = 0;
            total_written = 0;
            memset(byte_freq, 0, sizeof(byte_freq));

            printk(KERN_INFO "cryptomod: Counters reset.\n");
            return 0;

        default:
            return -EINVAL;  // Invalid ioctl command
    }
}

static const struct file_operations cryptomod_dev_fops = {
	.owner = THIS_MODULE,
	.open = cryptomod_dev_open,
	.read = cryptomod_dev_read,
	.write = cryptomod_dev_write,
	.unlocked_ioctl = cryptomod_dev_ioctl,
	.release = cryptomod_dev_close
};

static int cryptomod_proc_read(struct seq_file *m, void *v) {
	int i, j;
	seq_printf(m, "%lu %lu\n", total_read, total_written);

	// Print 16x16 Byte Frequency Matrix
	for (i = 0; i < 16; i++) {
		for (j = 0; j < 16; j++) {
			seq_printf(m, "%lu ", byte_freq[i * 16 + j]);
		}
		seq_printf(m, "\n");
	}
	return 0;
}

static int cryptomod_proc_open(struct inode *inode, struct file *file) {
	return single_open(file, cryptomod_proc_read, NULL);
}

static const struct proc_ops cryptomod_proc_fops = {
	.proc_open = cryptomod_proc_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static char *cryptomod_devnode(const struct device *dev, umode_t *mode) {
	if(mode == NULL) return NULL;
	*mode = 0666;
	return NULL;
}

static int __init cryptomod_init(void)
{
	// create char dev
	if(alloc_chrdev_region(&devnum, 0, 1, "updev") < 0)
		return -1;
	if((clazz = class_create("upclass")) == NULL)
		goto release_region;
	clazz->devnode = cryptomod_devnode;
	if(device_create(clazz, NULL, devnum, NULL, "cryptodev") == NULL)
		goto release_class;
	cdev_init(&c_dev, &cryptomod_dev_fops);
	if(cdev_add(&c_dev, devnum, 1) == -1)
		goto release_device;

	// create proc
	proc_create("cryptomod", 0, NULL, &cryptomod_proc_fops);

	printk(KERN_INFO "cryptomod: initialized.\n");
	return 0;    // Non-zero return means that the module couldn't be loaded.

release_device:
	device_destroy(clazz, devnum);
release_class:
	class_destroy(clazz);
release_region:
	unregister_chrdev_region(devnum, 1);
	return -1;
}

static void __exit cryptomod_cleanup(void)
{
	remove_proc_entry("cryptomod", NULL);

	cdev_del(&c_dev);
	device_destroy(clazz, devnum);
	class_destroy(clazz);
	unregister_chrdev_region(devnum, 1);

	printk(KERN_INFO "cryptomod: cleaned up.\n");
}

module_init(cryptomod_init);
module_exit(cryptomod_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Chun-Ying Huang");
MODULE_DESCRIPTION("The unix programming course demo kernel module.");
