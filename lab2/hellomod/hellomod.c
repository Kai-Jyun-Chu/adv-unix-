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
static size_t out_size=0;
static unsigned long total_read = 0, total_written = 0;
static unsigned long byte_freq[256] = {0}; // Byte frequency tracking
static char *buffer = NULL;  // Data buffer
static char *buffer_o = NULL;
//static char *buffer_out = NULL;
static size_t cap = 4096;
//static size_t count_byte =0;

int AES(char *buffer, size_t* buffer_size,  struct CryptoSetup crypto_config){
	struct crypto_skcipher *tfm = NULL;
	struct skcipher_request *req = NULL;
	struct scatterlist sg;
	DECLARE_CRYPTO_WAIT(wait);
	int err;

	if (crypto_config.c_mode == ENC) {
				
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
			}else if(crypto_config.c_mode == DEC){
				
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
				printk(KERN_INFO "✅ready to Decrypt %zu bytes.\n", *buffer_size);
				//u8 *encrypt_buf = (u8 *)buffer;
				sg_init_one(&sg, buffer, *buffer_size);
				skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG |
                                       CRYPTO_TFM_REQ_MAY_SLEEP,
                                  crypto_req_done, &wait);
				skcipher_request_set_crypt(req, &sg, &sg, *buffer_size, NULL);
					
				err = crypto_wait_req(crypto_skcipher_decrypt(req), &wait);
				if (err) {
					printk(KERN_ERR "cryptomod: AES decryption failed: %d\n", err);
					goto out_free_req;
				}
				printk(KERN_INFO "cryptomod: Successfully decrypted %zu bytes.\n", *buffer_size);

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
	printk(KERN_INFO "cryptomod: device opened.\n");
	setup_done = false;
	if (!buffer) {  
        
        buffer = kmalloc(cap, GFP_KERNEL);
		
        if (!buffer) {
            printk(KERN_ERR "Failed to allocate buffer.\n");
            return -ENOMEM;
        }
        memset(buffer, 0, cap);  // Zero initialize
    }
	if (!buffer_o) {  
        
        buffer_o = kmalloc(cap, GFP_KERNEL);
		
        if (!buffer_o) {
            printk(KERN_ERR "Failed to allocate buffer_o.\n");
            return -ENOMEM;
        }
        
    }
	
	return 0;
}

static int cryptomod_dev_close(struct inode *i, struct file *f) {
	printk(KERN_INFO "cryptomod: device closed.\n");
	if (buffer) {
        kfree(buffer);
        buffer = NULL;   
    }
	if (buffer_o) {
        kfree(buffer_o);
        buffer_o = NULL;   
    }

	return 0;
}

static ssize_t cryptomod_dev_read(struct file *f, char __user *buf, size_t len, loff_t *off)
{
    printk(KERN_INFO "✅cryptomod: Check bufout:%zu, request:%zu \n", out_size, len);

    // 1) Ensure the device is set up
    if (!setup_done)
        return -EINVAL;

    // 2) If no output data is available, either return -EAGAIN or 0 if finalized
    if (out_size == 0) {
        if (!finalized)
            return -EAGAIN;
        return 0;
    }

    // 3) Read only the available data or the requested size, whichever is smaller
    size_t to_copy = (len < out_size) ? len : out_size;

    if (copy_to_user(buf, buffer_o, to_copy))
        return -EBUSY;

    // 4) Update byte frequency if in encryption mode
    if (crypto_config.c_mode == ENC) {
        for (size_t i = 0; i < to_copy; i++) {
            byte_freq[(unsigned char)buffer_o[i]]++;
        }
    }

    // 5) Shift the remaining data in buffer_o
    if (to_copy < out_size) {
        memmove(buffer_o, buffer_o + to_copy, out_size - to_copy);
    }

    // 6) Update out_size and total_read
    out_size -= to_copy;
    total_read += to_copy;

    printk(KERN_INFO "cryptomod: read %zu bytes, remaining out_size: %zu\n", to_copy, out_size);
    return to_copy;
}

static ssize_t cryptomod_dev_write(struct file *f, const char __user *buf, size_t len, loff_t *off) {
	
    //size_t space_left, bytes_to_copy;

	if(finalized){
		return -EINVAL;
	}
	printk(KERN_INFO "cryptomod: write %zu bytes @ %llu.\n", len, *off);
	printk(KERN_INFO "✅cryptomod: Check bufout:%zu, buf:%zu.\n",out_size, buffer_size);
	if (copy_from_user(buffer + buffer_size, buf , len))
		return -EBUSY;
	buffer_size += len;
	size_t process_chunk;
	while(buffer_size>CM_BLOCK_SIZE){
		process_chunk =0;
		size_t left_chunk =0;
		if(crypto_config.c_mode == ENC){
			process_chunk = buffer_size - (buffer_size%CM_BLOCK_SIZE);

			AES(buffer,&process_chunk, crypto_config);  
			memcpy(buffer_o + out_size, buffer, process_chunk);
			memmove(buffer, buffer + process_chunk, (buffer_size%CM_BLOCK_SIZE));
			out_size+=process_chunk;
			//total_written += process_chunk;
			buffer_size -= process_chunk;
			
		}else{
			
			if(buffer_size%CM_BLOCK_SIZE){
				left_chunk = (buffer_size%CM_BLOCK_SIZE);
			}else{
				left_chunk = CM_BLOCK_SIZE;
			}
			process_chunk = buffer_size - left_chunk;
			AES(buffer,&process_chunk, crypto_config);  
			memcpy(buffer_o + out_size, buffer, process_chunk);
			memmove(buffer, buffer + process_chunk, left_chunk);
			out_size+=process_chunk;
			
			buffer_size -= process_chunk; 
			//total_written += process_chunk;
		}
	}
	total_written+=len;
	return len;

    /*
    if(crypto_config.io_mode == ADV){
		size_t remaining = len;
		printk(KERN_INFO "cryptomod: write %zu bytes @ %llu.\n", len, *off);
		
        while (remaining > 0) {
			
			size_t chunk_size;
			//printk(KERN_INFO "✅cryptomod: Check bufout:%zu, buf:%zu.\n",out_size, buffer_size);
			if(crypto_config.c_mode == DEC ){
				chunk_size = min(remaining, 2*(size_t)CM_BLOCK_SIZE - buffer_size);
			}else{
				chunk_size = min(remaining, (size_t)CM_BLOCK_SIZE - buffer_size);
			}
            
			printk(KERN_INFO "chunk size: %zu, buffer_size %zu.\n", chunk_size, buffer_size);
            if (copy_from_user(buffer + buffer_size, buf + (len - remaining), chunk_size))
                return -EBUSY;

            buffer_size += chunk_size;
            remaining -= chunk_size;
			//count_byte+=chunk_size;
			//printk(KERN_INFO "remaining: %zu, deal  %zu bytes.\n", remaining, count_byte);
            // Encrypt full blocks immediately 
            if ( buffer_size == CM_BLOCK_SIZE&& crypto_config.c_mode == ENC) {
				
                AES(buffer,&buffer_size, crypto_config);  
				memcpy(buffer_o + out_size, buffer, CM_BLOCK_SIZE);
				out_size+=CM_BLOCK_SIZE;
				
                buffer_size = 0;   
            }
			size_t block =CM_BLOCK_SIZE;
			if ( buffer_size > CM_BLOCK_SIZE && crypto_config.c_mode == DEC) {
				
                AES(buffer,&block, crypto_config);  
				memcpy(buffer_o + out_size, buffer, CM_BLOCK_SIZE);
				memmove(buffer, buffer + CM_BLOCK_SIZE, buffer_size - CM_BLOCK_SIZE);
				out_size+=CM_BLOCK_SIZE;
				
                buffer_size -= CM_BLOCK_SIZE;   
            }

			//printk(KERN_INFO "✅cryptomod: Check bufout:%zu, buf:%zu.\n",out_size, buffer_size);
        }
		total_written += len;
		return len;
	}
	else{
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
	}*/
    
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

            
			if (crypto_config.c_mode != ENC && crypto_config.c_mode != DEC)
				return -EINVAL;  
		
			
			if (crypto_config.io_mode != BASIC && crypto_config.io_mode != ADV)
				return -EINVAL;  	
            if (crypto_config.key_len != 16 && crypto_config.key_len != 24 && crypto_config.key_len != 32)
                return -EINVAL;  

            // Reset buffers and state
            setup_done = true;
            finalized = false;
            buffer_size = 0;
            //memset(byte_freq, 0, sizeof(byte_freq));

            printk(KERN_INFO "cryptomod: Setup complete - Mode: %s, Key Length: %d, I/O Mode: %s\n",
                   crypto_config.c_mode == ENC ? "Encrypt" : "Decrypt",
                   crypto_config.key_len,
                   crypto_config.io_mode == BASIC ? "Basic" : "Advanced");
            return 0;
        }
		////////////////////////////////////////////////////////////////////
		///																////
		///																////
		////////////////////////////////////////////////////////////////////
        case CM_IOC_FINALIZE: {
			//printk(KERN_INFO "Arrive finale✅✅✅✅cryptomod: Check bufout:%zu, buf:%zu.\n",out_size, buffer_size);
			if (!setup_done)
				return -EINVAL;  
			int err;
			finalized = true;
			if (crypto_config.c_mode == ENC) {
				// Compute padding size (PKCS#7)
				size_t padding = (buffer_size % CM_BLOCK_SIZE == 0) ? CM_BLOCK_SIZE 
																	: (CM_BLOCK_SIZE - (buffer_size % CM_BLOCK_SIZE));
		
				if (buffer_size + padding > cap)
					return -EINVAL;  
		
				// Apply padding directly in buffer
				memset(buffer + buffer_size, padding, padding);
				buffer_size += padding;
		
				// Ensure buffer_o has enough space
				if (out_size + buffer_size > cap)
					return -EINVAL;  
		
				// Copy buffer content into buffer_o for final encryption
				memcpy(buffer_o + out_size, buffer, buffer_size);
		
				// Encrypt buffer_o in place
				err = AES(buffer_o + out_size, &buffer_size, crypto_config);
		
				// Update output size
				out_size += buffer_size;
		
			}else{////////////DEC
				printk(KERN_INFO "Finalize Dec Check, b_out: %zu, buf:%zu.\n",out_size, buffer_size);
				err = AES(buffer, &buffer_size, crypto_config);
				memcpy(buffer_o + out_size, buffer, buffer_size);
				out_size+=buffer_size;
				
                buffer_size = 0;   
			}
			//AES
			
			
			
			return err;
		}
		

        case CM_IOC_CLEANUP:
			total_read = 0;
			total_written = 0;
			if (!setup_done)
				return -EINVAL;  // Device not set up

			// Reset all buffers
			buffer_size = 0;
			out_size =0;
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
