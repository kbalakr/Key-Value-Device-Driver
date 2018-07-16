///////////////////////////////////////////////////////////////////////
//                             North Carolina State University
//
//
//
//                             Copyright 2016
//
////////////////////////////////////////////////////////////////////////
//
// This program is free software; you can redistribute it and/or modify it
// under the terms and conditions of the GNU General Public License,
// version 2, as published by the Free Software Foundation.
//
// This program is distributed in the hope it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
//
////////////////////////////////////////////////////////////////////////
//
//   Author:  Hung-Wei Tseng
//
//   Description:
//     Skeleton of KeyValue Pseudo Device
//
////////////////////////////////////////////////////////////////////////

#include "keyvalue.h"

#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/poll.h>
#include <linux/list.h>
#include <linux/uaccess.h>
#include <linux/semaphore.h>

unsigned transaction_id;
/*static void free_callback(void *data)
{
}*/

struct semaphore mutex;
extern static int mutex_init_check = 0;
//mutex variable in sem needs to be initialized


struct list_node
{
	__u64 key;
	__u64 size;
	void *data;
	struct list_head list;
};

struct list_node *head = NULL;

static long keyvalue_get(struct keyvalue_get __user *ukv)
{ 	
	
	struct keyvalue_get * kv;								// Pointer to store get value
	unsigned long e,m;
	struct list_head * temp;								// Pointer to kernel linked list
	struct list_node * node;								// Pointer to node
	int flag = 0;											// Check for presence of key
	if(mutex_init_check == 0)
	{
		sema_init(&mutex,1);								// Initializing uninitialized semaphore
		mutex_init_check = 1;
	}
	if(head == NULL)										// If no key-value pair is present
		return -1;
    kv = kmalloc(sizeof(struct keyvalue_get),GFP_KERNEL);	// Allocate memory in kernel space
	m = copy_from_user(kv,ukv,sizeof(struct keyvalue_get));	// Copy from user to kernel space
	if(m != 0)												// If not copied
		return -1;
	down(&mutex);											// sem_wait - Acquire lock

	list_for_each(temp, &head->list)						// Loop over all keyvalues

	{
		node = list_entry(temp, struct list_node, list);
		if(node->key == kv->key)							// Check if required key is matched in linked list
		{
			flag = 1;
			kv->size = &node->size;							// Assign key's value
			kv->data = node->data;
			e = copy_to_user(ukv,kv,sizeof(keyvalue_get));	// Copy to user space
			if(e != 0)
				return -1;
			break;
		}
	}
	up(&mutex);												// sem_post - Release lock
	if(flag == 0)
		return -1;
    return transaction_id++;
}

static long keyvalue_set(struct keyvalue_set __user *ukv)
{
	
	struct keyvalue_set * kv;								// Pointer to store set value
	struct list_node * new;									// Pointer to node
	unsigned long m;
	if(mutex_init_check == 0)
	{
		sema_init(&mutex,1);								// Initializing uninitialized semaphore
		mutex_init_check = 1;
	}
	if(ukv->size > sizeof(int)*1024)						// If size is greater than 4 KB
		return -1;
	if(head == NULL)										// Create head of linked list if it is empty
	{
		head = kmalloc(sizeof(struct list_node),GFP_KERNEL);
		//LIST_HEAD_INIT(&head->list);
	}
    kv = kmalloc(sizeof(struct keyvalue_set),GFP_KERNEL);	// Allocate kernel space
	m = copy_from_user(kv,ukv,sizeof(keyvalue_set));		// Copy from user to kernel space
	if(m != 0)
		return -1;
	new = kmalloc(sizeof(struct list_node),GFP_KERNEL);
	down(&mutex);											// sem_wait - Acquire lock
	new->key = kv->key;										// Set new key-value pair
	new->size = kv->size;
	new->data = kv->data;
	list_add(&new->list,&head->list);						// Add to linked list
	up(&mutex);												// sem_post - Release lock
    return transaction_id++;
}

static long keyvalue_delete(struct keyvalue_delete __user *ukv)
{
	
	unsigned long e,m;
	struct keyvalue_delete * kv;							// Pointer to store set value
	struct list_head * temp;								// Pointer to kernel linked list
	struct list_node * node;								// Pointer to node
	int flag = 0;											// Check for presence of key
	if(mutex_init_check == 0)
	{
		sema_init(&mutex,1);								// Initializing uninitialized semaphore
		mutex_init_check = 1;
	}
    if(head == NULL)										// If no key-value is present
		return -1;
    kv = kmalloc(sizeof(struct keyvalue_get),GFP_KERNEL);	// Allocate kernel memory
	m = copy_from_user(kv,ukv,sizeof(struct keyvalue_delete));	// Copy from user to kernel space
	if(m != 0)
		return -1;
	down(&mutex);												// sem_wait - Acquire lock
	list_for_each(temp, &head->list)							// Iterate over linked list
	{
		node = list_entry(temp, struct list_node, list);
		if(node->key == kv->key)								// Find matching key in list
		{
			flag = 1;
			e = copy_to_user(ukv,kv,sizeof(struct keyvalue_delete));	// Copy to user space
			if(e != 0)
				return -1;
			list_del(&node->list);										// Delete matched key value from linked list
			kfree(node);												// Free space for deleted node
			break;
		}
	}
	up(&mutex);															// sem_post - Release lock	
	if(flag == 0)
		return -1;
    return transaction_id++;
}

//Added by Hung-Wei

unsigned int keyvalue_poll(struct file *filp, struct poll_table_struct *wait)
{
    unsigned int mask = 0;
    printk("keyvalue_poll called. Process queued\n");
    return mask;
}

static long keyvalue_ioctl(struct file *filp, unsigned int cmd,
                                unsigned long arg)
{
    switch (cmd) {
    case KEYVALUE_IOCTL_GET:
        return keyvalue_get((void __user *) arg);
    case KEYVALUE_IOCTL_SET:
        return keyvalue_set((void __user *) arg);
    case KEYVALUE_IOCTL_DELETE:
        return keyvalue_delete((void __user *) arg);
    default:
        return -ENOTTY;
    }
}

static int keyvalue_mmap(struct file *filp, struct vm_area_struct *vma)
{
    return 0;
}

static const struct file_operations keyvalue_fops = {
    .owner                = THIS_MODULE,
    .unlocked_ioctl       = keyvalue_ioctl,
    .mmap                 = keyvalue_mmap,
//    .poll		  = keyvalue_poll,
};

static struct miscdevice keyvalue_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "keyvalue",
    .fops = &keyvalue_fops,
};

static int __init keyvalue_init(void)
{
    int ret;

    if ((ret = misc_register(&keyvalue_dev)))
        printk(KERN_ERR "Unable to register \"keyvalue\" misc device\n");
    return ret;
}

static void __exit keyvalue_exit(void)
{
    misc_deregister(&keyvalue_dev);
}

MODULE_AUTHOR("Hung-Wei Tseng <htseng3@ncsu.edu>");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");
module_init(keyvalue_init);
module_exit(keyvalue_exit);
