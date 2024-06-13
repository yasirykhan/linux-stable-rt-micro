/*
 * linux/ipc/channel.c
 * Copyright (C) 2024 Yasir Khan
 */

#include <linux/spinlock.h>
#include <linux/init.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/ipc.h>
#include <linux/msg.h>
#include <linux/ipc_namespace.h>
#include <linux/utsname.h>
#include <linux/proc_ns.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>

#include "util.h"

#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/channel.h>

/* Initialize the channel array */
int init_channels(struct task_struct *task, int initial_size)
{
    task->channels = NULL;
    task->channels = kmalloc_array(initial_size, sizeof(struct channel *), GFP_KERNEL);
    if (!task->channels) {
        printk(KERN_INFO "init_channel kernel function failed\n");
        return -ENOMEM;
    }

    task->max_channels = initial_size;
    task->num_channels = 0;

    /* Initialize channel slots */
    for (int i = 0; i < initial_size; ++i) {
        task->channels[i] = NULL;
    }

    return 0;
}

/* Resize the channel array */
int resize_channels(struct task_struct *task, int new_size)
{
    struct channel **new_channels;

    if (new_size <= task->max_channels) {
        return 0;
    }

    new_channels = krealloc(task->channels, new_size * sizeof(struct channel *), GFP_KERNEL);
    if (!new_channels) {
        return -ENOMEM;
    }

    /* Initialize new channel slots */
    for (int i = task->max_channels; i < new_size; ++i) {
        new_channels[i] = NULL;
    }

    task->channels = new_channels;
    task->max_channels = new_size;

    return 0;
}

/* Find a free channel slot */
int find_free_channel_slot(struct task_struct *task)
{
    printk(KERN_INFO "find_free_channel_slot kernel function called\n");

    for (int i = 0; i < task->max_channels; ++i) {
        if (task->channels[i] == NULL || !task->channels[i]->in_use) {
            return i;
        }
    }
    return -1; /* No free slot found */
}

/* Add a new channel */
int add_channel(struct task_struct *task, struct channel *ch)
{
    int slot;
    printk(KERN_INFO "add_channel kernel function called\n");

    if (task->num_channels >= task->max_channels) {
        int ret = resize_channels(task, task->max_channels * 2);
        if (ret) {
            return ret;
        }
    }

    slot = find_free_channel_slot(task);
    if (slot < 0) {
        return -ENOMEM; /* No free slot found */
    }

    INIT_LIST_HEAD(&ch->send_queue.head);
    INIT_LIST_HEAD(&ch->recv_queue.head);
    INIT_LIST_HEAD(&ch->reply_queue.head);
    init_waitqueue_head(&ch->send_queue.wait);
    init_waitqueue_head(&ch->recv_queue.wait);
    init_waitqueue_head(&ch->reply_queue.wait);
    ch->in_use = true;
    task->channels[slot] = ch;
    task->num_channels++;

    return slot;
}

/* Add a task to the send queue (priority queue) */
int add_to_send_queue(struct channel *ch, struct task_struct *task, int priority)
{
    struct send_queue_item *item = kmalloc(sizeof(struct send_queue_item), GFP_KERNEL);
    if (!item) {
        return -ENOMEM;
    }

    item->task = task;
    item->priority = priority;

    struct list_head *pos;
    list_for_each(pos, &ch->send_queue.head) {
        struct send_queue_item *curr = list_entry(pos, struct send_queue_item, list);
        if (priority > curr->priority) {
            list_add_tail(&item->list, pos);
            return 0;
        }
    }
    list_add_tail(&item->list, &ch->send_queue.head);

    return 0;
}

/* Add a task to a normal queue */
int add_to_normal_queue(struct list_head *queue, struct task_struct *task)
{
    struct normal_queue_item *item = kmalloc(sizeof(struct normal_queue_item), GFP_KERNEL);
    if (!item) {
        return -ENOMEM;
    }

    item->task = task;
    list_add_tail(&item->list, queue);

    return 0;
}

/* Add a task to the recv queue */
int add_to_recv_queue(struct channel *ch, struct task_struct *task)
{
    return add_to_normal_queue(&ch->recv_queue.head, task);
}

/* Add a task to the reply queue */
int add_to_reply_queue(struct channel *ch, struct task_struct *task)
{
    return add_to_normal_queue(&ch->reply_queue.head, task);
}

/* Clean up the channel array */
void cleanup_channels(struct task_struct *task)
{
    for (int i = 0; i < task->max_channels; ++i) {
        if (task->channels[i] != NULL) {
            struct list_head *pos, *q;
            struct send_queue_item *send_item;
            struct normal_queue_item *recv_item, *reply_item;

            /* Clean up send queue */
            list_for_each_safe(pos, q, &task->channels[i]->send_queue.head) {
                send_item = list_entry(pos, struct send_queue_item, list);
                kfree(send_item);
            }
            /* Clean up recv queue */
            list_for_each_safe(pos, q, &task->channels[i]->recv_queue.head) {
                recv_item = list_entry(pos, struct normal_queue_item, list);
                kfree(recv_item);
            }
            /* Clean up reply queue */
            list_for_each_safe(pos, q, &task->channels[i]->reply_queue.head) {
                reply_item = list_entry(pos, struct normal_queue_item, list);
                kfree(reply_item);
            }
            kfree(task->channels[i]);
        }
    }

    if (task && task->channels) {
        kfree(task->channels);
        task->channels = NULL;
    }
}

long get_current_task(pid_t pid, struct task_struct **task_ret)
{
    struct pid *pid_struct;
    struct task_struct *task;

    if (pid < 0) {
        printk(KERN_INFO "Invalid PID\n");
        return -EINVAL;
    }

    pid_struct = find_get_pid(pid);
    if (!pid_struct) {
        printk(KERN_INFO "PID not found\n");
        return -ESRCH;
    }

    task = get_pid_task(pid_struct, PIDTYPE_PID);
    if (!task) {
        printk(KERN_INFO "Task not found\n");
        put_pid(pid_struct);
        return -ESRCH;
    }

    *task_ret = task;

    return 0;
}

/* System call for creating a channel */
long ksys_channel_create(pid_t pid)
{
    long ret = 0;
    printk(KERN_INFO "channel create system call\n");
    struct channel *new_channel;

    struct task_struct* task;
    ret = get_current_task(pid, &task);
    if (ret < 0) {
        return ret;
    }

    /* Allocate memory for the new channel */
    new_channel = kmalloc(sizeof(struct channel), GFP_KERNEL);
    if (!new_channel) {
        return -ENOMEM; /* Return error code if allocation fails */
    }

    /* Add the new channel to the task_struct */
    ret = add_channel(task, new_channel);

    if (ret < 0) {
        kfree(new_channel);
        return ret;
    }

    return ret;
}

SYSCALL_DEFINE1(channel_create, pid_t, pid)
{
    return ksys_channel_create(pid);
}

/* System call for destroying a channel */
long ksys_channel_destroy(pid_t pid, int channel_id)
{
    printk(KERN_INFO "channel destroy system call\n");
    struct task_struct *task;
    struct pid *pid_struct;
    if (pid < 0) {
        printk(KERN_INFO "Invalid PID\n");
        return -EINVAL;
    }

    pid_struct = find_get_pid(pid);
    if (!pid_struct) {
        printk(KERN_INFO "PID not found\n");
        return -ESRCH;
    }

    task = get_pid_task(pid_struct, PIDTYPE_PID);
    if (!task) {
        printk(KERN_INFO "Task not found\n");
        put_pid(pid_struct);
        return -ESRCH;
    }

    struct task_struct *current_task = task; /* Current task */
    struct channel *ch;
    struct normal_queue_item *recv_item, *recv_tmp;
    struct normal_queue_item *reply_item, *reply_tmp;
    struct send_queue_item *send_item, *send_tmp;

    /* Validate the channel_id */
    if (channel_id < 0 || channel_id >= current_task->max_channels) {
        return -EINVAL; /* Invalid channel ID */
    }

    ch = current_task->channels[channel_id];
    if (!ch || !ch->in_use) {
        return -EINVAL; /* Channel not in use or invalid */
    }

    /* Lock the channel for safe access */
    spin_lock(&ch->lock);

    /* Clean up the send queue */
    list_for_each_entry_safe(send_item, send_tmp, &ch->send_queue.head, list) {
        list_del(&send_item->list);
        kfree(send_item);
    }

    /* Clean up the recv queue */
    list_for_each_entry_safe(recv_item, recv_tmp, &ch->recv_queue.head, list) {
        list_del(&recv_item->list);
        kfree(recv_item);
    }

    /* Clean up the reply queue */
    list_for_each_entry_safe(reply_item, reply_tmp, &ch->reply_queue.head, list) {
        list_del(&reply_item->list);
        kfree(reply_item);
    }

    /* Mark the channel as not in use */
    ch->in_use = false;

    /* Deallocate the channel structure */
    kfree(ch);
    current_task->channels[channel_id] = NULL;

    spin_unlock(&ch->lock);

    return 0;
}

SYSCALL_DEFINE2(channel_destroy, pid_t, pid, int, channel_id)
{
    return ksys_channel_destroy(pid, channel_id);
}
