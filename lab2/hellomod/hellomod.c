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

DEFINE_MUTEX(glob_lock);
static dev_t devnum;
static struct cdev c_dev;
static struct class *clazz;

struct cryptomod_priv {

    //struct mutex lock;

    bool setup_done;
    bool finalized;

    char *buffer;
    char *buffer_o;
    size_t buffer_size;
    size_t out_size;
    struct CryptoSetup crypto_config;
};
static unsigned long total_read;
static unsigned long total_written;
static unsigned long byte_freq[256];

static size_t cap = 26000;


int AES(char *buffer, size_t* buffer_size,  struct CryptoSetup *crypto_config, bool finalized){
	struct crypto_skcipher *tfm = NULL;
	struct skcipher_request *req = NULL;
	struct scatterlist sg;
	DECLARE_CRYPTO_WAIT(wait);
	int err;

	if (crypto_config->c_mode == ENC) {
				
		tfm = crypto_alloc_skcipher("ecb(aes)", 0, 0);
		if (IS_ERR(tfm)) {
			printk(KERN_ERR "cryptomod: Error allocating AES-ECB handle: %ld\n", PTR_ERR(tfm));
			return PTR_ERR(tfm);
		}

		err = crypto_skcipher_setkey(tfm, crypto_config->key, crypto_config->key_len);
		if (err) {
			printk(KERN_ERR "cryptomod: Error setting AES key: %d\n", err);
			goto out_free_tfm;
		}

		req = skcipher_request_alloc(tfm, GFP_KERNEL);
		if (!req) {
			err = -ENOMEM;
			goto out_free_tfm;
		}
		//printk(KERN_INFO "✅ready to Encrypt %zu bytes.\n", *buffer_size);
		//u8 *encrypt_buf = (u8 *)buffer;
		sg_init_one(&sg, buffer, *buffer_size);
		skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
								CRYPTO_TFM_REQ_MAY_SLEEP,
							crypto_req_done, &wait);
		skcipher_request_set_crypt(req, &sg, &sg, *buffer_size, NULL);
			
		err = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
		if (err) {
			printk(KERN_ERR "cryptomod: AES encryption failed: %d\n", err);
			goto out_free_req;
		}
		//printk(KERN_INFO "cryptomod: Successfully encrypted %zu bytes.\n", *buffer_size);
	}else if(crypto_config->c_mode == DEC){
		
		tfm = crypto_alloc_skcipher("ecb(aes)", 0, 0);
		if (IS_ERR(tfm)) {
			printk(KERN_ERR "cryptomod: Error allocating AES-ECB handle: %ld\n", PTR_ERR(tfm));
			return PTR_ERR(tfm);
		}

		err = crypto_skcipher_setkey(tfm, crypto_config->key, crypto_config->key_len);
		if (err) {
			printk(KERN_ERR "cryptomod: Error setting AES key: %d\n", err);
			goto out_free_tfm;
		}

		req = skcipher_request_alloc(tfm, GFP_KERNEL);
		if (!req) {
			err = -ENOMEM;
			goto out_free_tfm;
		}
		//printk(KERN_INFO "✅ready to Decrypt %zu bytes.\n", *buffer_size);
		//u8 *encrypt_buf = (u8 *)buffer;
		sg_init_one(&sg, buffer, *buffer_size);
		skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
								CRYPTO_TFM_REQ_MAY_SLEEP,
							crypto_req_done, &wait);
		skcipher_request_set_crypt(req, &sg, &sg, *buffer_size, NULL);
			
		err = crypto_wait_req(crypto_skcipher_decrypt(req), &wait);
		if (err) {
			printk(KERN_ERR "cryptomod: AES decryption failed: %d\n", err);
			//return -EINVAL;
			goto out_free_req;
		}
		//printk(KERN_INFO "cryptomod: Successfully decrypted %zu bytes.\n", *buffer_size);

		if(finalized){
			u8 padding_len = buffer[*buffer_size - 1];
			// Validate padding length
			if (padding_len < 1 || padding_len > CM_BLOCK_SIZE) {
				printk(KERN_ERR "cryptomod: Invalid padding length: %u\n", padding_len);
				return -EINVAL;
			}
			// Validate padding bytes
			for (size_t i = 0; i < padding_len; i++) {
				if (buffer[*buffer_size - 1 - i] != padding_len) {
					printk(KERN_ERR "cryptomod: Padding validation failed at byte %zu\n", *buffer_size - 1 - i);
					return -EINVAL;
				}
			}
			// Remove padding
			*buffer_size -= padding_len;
			printk(KERN_INFO "cryptomod: Successfully removed padding, new size: %zu\n", *buffer_size);
			
		}
		
	}
	
	
	out_free_req:
		skcipher_request_free(req);
	out_free_tfm:
		crypto_free_skcipher(tfm);
	return err;
}

static int cryptomod_dev_open(struct inode *i, struct file *f) {
	//printk(KERN_INFO "cryptomod: device opened.\n");
	struct cryptomod_priv *priv;
    priv = kzalloc(sizeof(*priv), GFP_KERNEL);
    if (!priv)
        return -ENOMEM;

    /* Optionally, set up any defaults here */
    priv->setup_done = false;
    priv->finalized  = false;
    priv->buffer     = kzalloc(cap, GFP_KERNEL);
    priv->buffer_o   = kzalloc(cap, GFP_KERNEL);
    if (!priv->buffer || !priv->buffer_o) {
        kfree(priv->buffer);
        kfree(priv->buffer_o);
        kfree(priv);
        pr_err("cryptomod: Failed to allocate buffers.\n");
        return -ENOMEM;
    }

    /* Save pointer in file->private_data */
    f->private_data = priv;

    pr_info("cryptomod: device opened.\n");
    return 0;
}

static int cryptomod_dev_close(struct inode *i, struct file *f) {
	//printk(KERN_INFO "cryptomod: device closed.\n");
	struct cryptomod_priv *priv = f->private_data;

    if (priv) {
        mutex_lock(&glob_lock);
        kfree(priv->buffer);
        kfree(priv->buffer_o);
        mutex_unlock(&glob_lock);

        kfree(priv); /* final free */
        f->private_data = NULL;
    }

    pr_info("cryptomod: device closed.\n");
    return 0;
}

static ssize_t cryptomod_dev_read(struct file *f, char __user *buf, size_t len, loff_t *off)
{
    struct cryptomod_priv *priv = f->private_data;
    ssize_t to_copy;

    mutex_lock(&glob_lock);

    //pr_info("cryptomod: read request %zu bytes, out_size=%zu\n", len, priv->out_size);

    if (!priv->setup_done) {
        mutex_unlock(&glob_lock);
        return -EINVAL;
    }

    if (priv->out_size == 0) {
        if (!priv->finalized) {
            mutex_unlock(&glob_lock);
            return -EAGAIN;
        }
        mutex_unlock(&glob_lock);
        return 0;
    }

    /* Read up to the smaller of user request or out_size */
    to_copy = min(len, priv->out_size);
    if (copy_to_user(buf, priv->buffer_o, to_copy)) {
        mutex_unlock(&glob_lock);
        return -EFAULT;
    }

    if (priv->crypto_config.c_mode == ENC) {
        for (size_t i = 0; i < to_copy; i++) {
            byte_freq[(unsigned char)priv->buffer_o[i]]++;
        }
    }

    /* Shift remaining data in buffer_o */
    if (to_copy < priv->out_size) {
        memmove(priv->buffer_o, priv->buffer_o + to_copy, priv->out_size - to_copy);
    }
    priv->out_size -= to_copy;
    total_read += to_copy;

    //pr_info("cryptomod: read %zu bytes, out_size now %zu\n", to_copy, priv->out_size);
    mutex_unlock(&glob_lock);
    return to_copy;
}

static ssize_t cryptomod_dev_write(struct file *f, const char __user *buf, size_t len, loff_t *off)
{
	struct cryptomod_priv *priv = f->private_data;
	mutex_lock(&glob_lock);
	if(!priv->setup_done){
		mutex_unlock(&glob_lock);
		return -EINVAL;
	}



    if(priv->finalized){
		mutex_unlock(&glob_lock);
		return -EINVAL;
	}
	//printk(KERN_INFO "cryptomod: write %zu bytes @ %llu.\n", len, *off);
	//printk(KERN_INFO "✅cryptomod: Check bufout:%zu, buf:%zu.\n",priv->out_size, priv->buffer_size);
	if (copy_from_user(priv->buffer + priv->buffer_size, buf , len)){
		mutex_unlock(&glob_lock);
		return -EBUSY;
	}

		
	priv->buffer_size += len;
	size_t process_chunk;
	while(priv->buffer_size>CM_BLOCK_SIZE){
		process_chunk =0;
		size_t left_chunk =0;
		if(priv->crypto_config.c_mode == ENC){
			process_chunk = priv->buffer_size - (priv->buffer_size%CM_BLOCK_SIZE);

			AES(priv->buffer,&process_chunk, &priv->crypto_config, false);  
			memcpy(priv->buffer_o + priv->out_size, priv->buffer, process_chunk);
			memmove(priv->buffer, priv->buffer + process_chunk, (priv->buffer_size%CM_BLOCK_SIZE));
			priv->out_size+=process_chunk;
			//total_written += process_chunk;
			priv->buffer_size -= process_chunk;
			
		}else{
			
			if(priv->buffer_size%CM_BLOCK_SIZE){
				left_chunk = (priv->buffer_size%CM_BLOCK_SIZE);
			}else{
				left_chunk = CM_BLOCK_SIZE;
			}
			
			process_chunk = priv->buffer_size - left_chunk;
			if(process_chunk % CM_BLOCK_SIZE){
				mutex_unlock(&glob_lock);
				return -EINVAL;
			}
			int err = AES(priv->buffer,&process_chunk, &priv->crypto_config, false); 
			if(err){
				mutex_unlock(&glob_lock);
				return -EINVAL;
			} 
			memcpy(priv->buffer_o + priv->out_size, priv->buffer, process_chunk);
			memmove(priv->buffer, priv->buffer + process_chunk, left_chunk);
			priv->out_size+=process_chunk;
			
			priv->buffer_size -= process_chunk; 
			//total_written += process_chunk;
		}
	}
	total_written+=len;
	mutex_unlock(&glob_lock);
	return len;
}

static long cryptomod_dev_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    struct cryptomod_priv *priv = f->private_data;
    mutex_lock(&glob_lock);
    pr_info("cryptomod: ioctl cmd=%u arg=%lu\n", cmd, arg);
    switch (cmd) {
    case CM_IOC_SETUP: {
        if (arg == 0) {
            mutex_unlock(&glob_lock);
			return -EINVAL;
            
        }
        if (copy_from_user(&priv->crypto_config, 
                           (struct CryptoSetup __user *)arg, 
                           sizeof(struct CryptoSetup)))
        {
            mutex_unlock(&glob_lock);
			return -EFAULT;
            
        }
        if (priv->crypto_config.c_mode != ENC && priv->crypto_config.c_mode != DEC) {
            mutex_unlock(&glob_lock);
			return -EINVAL;
            
        }
        if (priv->crypto_config.io_mode != BASIC && priv->crypto_config.io_mode != ADV) {
            mutex_unlock(&glob_lock);
			return -EINVAL;
            
        }
        if (priv->crypto_config.key_len != 16 && 
            priv->crypto_config.key_len != 24 && 
            priv->crypto_config.key_len != 32)
        {
			mutex_unlock(&glob_lock);
            return -EINVAL;
            
        }

        /* Reset state for new setup */
        priv->setup_done = true;
        priv->finalized  = false;
        priv->buffer_size = 0;
        priv->out_size = 0;
        //memset(byte_freq, 0, sizeof(byte_freq));

        pr_info("cryptomod: Setup complete - Mode: %s, Key Len: %d, I/O Mode: %s\n",
                (priv->crypto_config.c_mode == ENC) ? "Encrypt" : "Decrypt",
                priv->crypto_config.key_len,
                (priv->crypto_config.io_mode == BASIC) ? "Basic" : "Advanced");
		mutex_unlock(&glob_lock);
        return 0;
    }
    case CM_IOC_FINALIZE: {
		//printk(KERN_INFO "Arrive finale✅✅✅✅cryptomod: Check bufout:%zu, buf:%zu.\n",out_size, buffer_size);
		if (!priv->setup_done){
			mutex_unlock(&glob_lock);
			return -EINVAL; 
		}
			 
		int err;
		priv->finalized = true;
		if (priv->crypto_config.c_mode == ENC) {
			// Compute padding size (PKCS#7)
			size_t padding = (priv->buffer_size % CM_BLOCK_SIZE == 0) ? CM_BLOCK_SIZE 
																: (CM_BLOCK_SIZE - (priv->buffer_size % CM_BLOCK_SIZE));
	
			if (priv->buffer_size + padding > cap){
				mutex_unlock(&glob_lock);
				return -EINVAL;  
			}	
			// Apply padding directly in buffer
			memset(priv->buffer + priv->buffer_size, padding, padding);
			priv->buffer_size += padding;
			// Ensure buffer_o has enough space
			if (priv->out_size + priv->buffer_size > cap){
				mutex_unlock(&glob_lock);
				return -EINVAL;
			}  
			// Copy buffer content into buffer_o for final encryption
			memcpy(priv->buffer_o + priv->out_size, priv->buffer, priv->buffer_size);
	
			// Encrypt buffer_o in place
			err = AES(priv->buffer_o + priv->out_size, &priv->buffer_size, &priv->crypto_config,true);
			// Update output size
			priv->out_size += priv->buffer_size;
	
		}else{////////////DEC
			printk(KERN_INFO "Finalize Dec Check, b_out: %zu, buf:%zu.\n",priv->out_size, priv->buffer_size);
			/*if(priv->buffer_size%16!=0){
				mutex_unlock(&glob_lock);
				return -EINVAL;
			}*/
			err = AES(priv->buffer, &priv->buffer_size, &priv->crypto_config, true);
			/*if(err){
				printk(KERN_INFO "==============There is an error.================\n");
				//err = -EINVAL;
				mutex_unlock(&glob_lock);
				return -EINVAL;
			}*/
			memcpy(priv->buffer_o + priv->out_size, priv->buffer, priv->buffer_size);
			priv->out_size+=priv->buffer_size;
			
			priv->buffer_size = 0;   
		}
		mutex_unlock(&glob_lock);
		
		pr_info("ERR = %d\n",err);
		return err;
	}
    case CM_IOC_CLEANUP: {
        if (!priv->setup_done) {
			mutex_unlock(&glob_lock);
            return -EINVAL;
        }
        /* Reset everything */
        priv->buffer_size = 0;
        priv->out_size = 0;
        priv->finalized  = false;
        memset(priv->buffer, 0, cap);
        memset(priv->buffer_o, 0, cap);
        //memset(byte_freq, 0, sizeof(byte_freq));
        total_read = 0;
        total_written = 0;

        pr_info("cryptomod: Cleanup complete (zeroed buffers).\n");
		mutex_unlock(&glob_lock);
        return 0;
    }
    case CM_IOC_CNT_RST:{
            // Reset counters and byte frequency tracking
            total_read = 0;
            total_written = 0;
            memset(byte_freq, 0, sizeof(byte_freq));

            printk(KERN_INFO "cryptomod: Counters reset.\n");
			mutex_unlock(&glob_lock);
            return 0;
	}
    default:{
		mutex_unlock(&glob_lock);
        return -EINVAL;  // Invalid ioctl command
	}
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
	//struct cryptomod_priv *priv = m->private;
	int i, j;
	//if (!priv) return -EINVAL;
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
