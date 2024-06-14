/*
 * linux/ipc/fast_msg.c
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

#include <linux/channel.h>
#include <linux/connection.h>

/* Function to send a message via a connection */
long ksys_msg_send(pid_t pid, int connection_id, const char __user *buf, size_t size,
                   char __user *reply_buf, size_t reply_size)
{
    long ret = 0;
    struct task_struct* process_task;
    ret = get_current_task(pid, &process_task);
    if (ret < 0) {
        return ret;
    }

    if (connection_id < 0 || connection_id >= process_task->max_connections 
            || process_task->connections[connection_id] == NULL) {
        return -EINVAL; /* Invalid channel ID */
    }

    struct task_struct *current_task = current; /* Current task */
    struct conn_ipc *conn;
    struct channel_ipc *ch;
    struct task_struct *recv_task;
    struct normal_queue_item *recv_item;
    struct normal_queue_item *reply_item;
    struct send_queue_item *send_item;
    char short_msg_buffer[SHORT_MSG_SIZE];

    /* Validate the buffer pointer */
    if (NULL == buf || !access_ok(buf, size)) {
        return -EFAULT; /* Invalid user pointer */
    }

    printk(KERN_INFO "msg_send Buffer %p, %p, %d OK\n", process_task->connections, 
    process_task->connections[0], connection_id);

    /* Find the connection object using the connection_id */
    rcu_read_lock();
    conn = rcu_dereference(process_task->connections[connection_id]);
    //conn = process_task->connections[connection_id];
    if (!conn) {
        rcu_read_unlock();
        return -EINVAL; /* Invalid connection ID */
    }
    ch = conn->chan;
    rcu_read_unlock();

    /* Check the size against the short message buffer size */
    if (size > SHORT_MSG_SIZE) {
        return -EMSGSIZE; /* Message too big */
    }

    if (copy_from_user(short_msg_buffer, buf, size)) {
        return -EFAULT; /* Copy from user failed */
    }


    /* Lock the channel for safe access */
    spin_lock(&ch->lock);

    printk(KERN_INFO "msg_send  check for queue\n");

    /* Check if there is an item in the recv_queue */
    if (!list_empty(&ch->recv_queue.head)) {

        printk(KERN_INFO "msg_send  recv_queue item processing\n");

        /* Get the first item from the recv_queue */
        recv_item = list_first_entry(&ch->recv_queue.head, struct normal_queue_item, list);
        recv_task = recv_item->task;

        /* Remove the item from the recv_queue */
        list_del(&recv_item->list);
        kfree(recv_item);

        /* Unlock the channel */
        spin_unlock(&ch->lock);

        /* Copy the message from buf to the task's short_msg_buffer */
        printk(KERN_INFO "the buffer = %s, size = %lud\n", short_msg_buffer, size);
        memcpy(recv_task->short_msg_buffer, short_msg_buffer, size);
        printk(KERN_INFO "recv_task = %p, msg = %s\n", recv_task, 
                recv_task->short_msg_buffer);

        recv_task->msg_size = size;
        recv_task->sender = current_task;

        /* Add the current task to the reply_queue */
        reply_item = kmalloc(sizeof(*reply_item), GFP_KERNEL);
        if (!reply_item) {
            return -ENOMEM; /* Memory allocation failure */
        }

        reply_item->task = current_task;

        /* Lock the channel for safe access */
        spin_lock(&ch->lock);
        list_add_tail(&reply_item->list, &ch->reply_queue.head);

        printk(KERN_INFO "msg_send  wake_up recv\n");

        wake_up_process(recv_task);
    } else {

        printk(KERN_INFO "msg_send no recv_queue copy buffer\n");

        /* Copy the message from buf to the current task's short_msg_buffer */
        memcpy(current_task->short_msg_buffer, short_msg_buffer, size);
        current_task->msg_size = size;

        /* Add the current task to the send_queue */
        send_item = kmalloc(sizeof(*send_item), GFP_KERNEL);
        if (!send_item) {
            spin_unlock(&ch->lock);
            return -ENOMEM; /* Memory allocation failure */
        }
        send_item->task = current_task;
        send_item->priority = 0; /* Example priority, can be adjusted as needed */

        /* Insert send_item in the send_queue based on priority */
        struct list_head *pos;
        list_for_each(pos, &ch->send_queue.head) {
            struct send_queue_item *curr = list_entry(pos, struct send_queue_item, list);
            if (send_item->priority > curr->priority) {
                list_add_tail(&send_item->list, pos);
                break;
            }
        }
        if (pos == &ch->send_queue.head) {
            list_add_tail(&send_item->list, &ch->send_queue.head);
        }
    }

    printk(KERN_INFO "msg_send go to sleep, %p\n", current_task);

    /* Put the current task to sleep */
    DEFINE_WAIT(wait);
    prepare_to_wait(&ch->send_queue.wait, &wait, TASK_INTERRUPTIBLE);
    spin_unlock(&ch->lock);
    schedule();
    finish_wait(&ch->send_queue.wait, &wait);


    printk(KERN_INFO "msg_send wake from sleep, %p\n", current_task);

    /* Validate the reply buffer and size pointer */
    if (!access_ok(reply_buf, size)) {
        return -EFAULT; /* Invalid user pointer */
    }

    memcpy(short_msg_buffer, current_task->short_msg_buffer, 
            current_task->msg_size);

    /* Copy the buffer from the current task's short_msg_buffer to reply_buf */
    if (copy_to_user(reply_buf, short_msg_buffer, current_task->msg_size)) {
        return -EFAULT; /* Copy to user failed */
    }

    printk(KERN_INFO "msg_send all done ret = %ld, %p\n", ret, current_task);
    return current_task->msg_size;
}

SYSCALL_DEFINE6(msg_send, pid_t, pid, int, connection_id, const char __user*, buf, size_t, buf_size,
                char __user*, reply_buf, size_t, reply_size)
{
    return ksys_msg_send(pid, connection_id, buf, buf_size, reply_buf, reply_size);
}


/* Function to receive a message via a channel */
long ksys_msg_recv(pid_t pid, int channel_id, const char __user *buf, size_t size)
{
    long ret = 0;
    struct task_struct* process_task;
    ret = get_current_task(pid, &process_task);
    if (ret < 0) {
        return ret;
    }

    struct task_struct *current_task = current; /* Current task */
    struct channel_ipc *ch;
    struct task_struct *send_task;
    struct send_queue_item *send_item;
    struct normal_queue_item *reply_item;
    struct normal_queue_item *recv_item;
    char short_msg_buffer[SHORT_MSG_SIZE];

    long recv_id = 0;

    printk(KERN_INFO "msg_recv system call OK %p, %p\n", current_task, process_task->channels);

    /* Validate the channel_id */
    if (channel_id < 0 || channel_id >= process_task->max_channels) {
        return -EINVAL; /* Invalid channel ID */
    }

    ch = process_task->channels[channel_id];
    if (!ch || !ch->in_use) {
        return -EINVAL; /* Channel not in use or invalid */
    }

    /* Validate the buffer pointer */
    if (NULL == buf || !access_ok(buf, size)) {
        return -EFAULT; /* Invalid user pointer */
    }

    printk(KERN_INFO "msg_recv Buffer %p OK\n", buf);

    /* Lock the channel for safe access */
    spin_lock(&ch->lock);

    /* Check if there is an item in the send_queue */
    if (!list_empty(&ch->send_queue.head)) {
        printk(KERN_INFO "msg_recv send_queue item\n");

        /* Get the first item from the send_queue */
        send_item = list_first_entry(&ch->send_queue.head, struct send_queue_item, list);
        send_task = send_item->task;

        /* Remove the item from the send_queue */
        list_del(&send_item->list);
        kfree(send_item);

        /* Unlock the channel */
        spin_unlock(&ch->lock);

        /* Check the size against the short message buffer size */
        if (send_task->msg_size > SHORT_MSG_SIZE) {
            return -EMSGSIZE; /* Message too big */
        }

        memcpy(short_msg_buffer, send_task->short_msg_buffer, 
                            send_task->msg_size);
        size = send_task->msg_size;
        if (copy_to_user((char* __user)buf, short_msg_buffer, size)) {
            return -EFAULT; /* Copy from user failed */
        }
        

        /* Add the send_task to the reply_queue */
        reply_item = kmalloc(sizeof(*reply_item), GFP_KERNEL);
        if (!reply_item) {
            return -ENOMEM; /* Memory allocation failure */
        }
        reply_item->task = send_task;
        list_add_tail(&reply_item->list, &ch->reply_queue.head);
        /*recv_id = (long)(((long)send_task & 0xFFFF) << 16) | 
        (channel_id & 0xFFFF);*/
        recv_id = (long)send_task;
    } else {

        /* Add the current task to the recv_queue */
        recv_item = kmalloc(sizeof(*recv_item), GFP_KERNEL);
        if (!recv_item) {
            spin_unlock(&ch->lock);
            return -ENOMEM; /* Memory allocation failure */
        }

        recv_item->task = current_task;
        printk(KERN_INFO "msg_recv recv_item =%p recv_item->task %p\n", 
                            recv_item, recv_item->task);

        list_add_tail(&recv_item->list, &ch->recv_queue.head);
        /* Put the current task to sleep */
        DEFINE_WAIT(wait);
        prepare_to_wait(&ch->recv_queue.wait, &wait, TASK_INTERRUPTIBLE);
        spin_unlock(&ch->lock);
        schedule();
        finish_wait(&ch->recv_queue.wait, &wait);

        spin_lock(&ch->lock);

        /*recv_id = (long)(((long)current_task->sender & 0xFFFF) << 16) 
                    | (channel_id & 0xFFFF);*/
        recv_id = (long)(current_task->sender);
        printk(KERN_INFO "msg_recv recv_task =%p recv_id %p, sender=%p, recv_id==sender=%d\n", 
        current_task, recv_id, current_task->sender, 
        recv_id == (long)current_task->sender);
                                    /* Check the size against the short message buffer size */
        if (current_task->msg_size > SHORT_MSG_SIZE) {
            spin_unlock(&ch->lock);
            return -EMSGSIZE; /* Message too big */
        }

        memcpy(short_msg_buffer, current_task->short_msg_buffer,
                current_task->msg_size);
        //*read_bytes = current_task->msg_size;
        printk(KERN_INFO "msg_recv short_buf =%s buffer_p %p, size =%lud\n", short_msg_buffer, buf,
                         size);
        if (copy_to_user((char __user*)buf, short_msg_buffer, current_task->msg_size)) {
            spin_unlock(&ch->lock);
            return -EFAULT; /* Copy from user failed */
        }

        spin_unlock(&ch->lock);
    }

    printk(KERN_INFO "msg_recv  after wake %p\n", (void*)recv_id);

    return recv_id;
}

SYSCALL_DEFINE4(msg_recv, pid_t, pid, int, channel_id, const char __user*, buf, size_t, size)
{
    return ksys_msg_recv(pid, channel_id, buf, size);
}

/* Function to reply to a message */
long ksys_msg_reply(pid_t pid, long recv_id, const char __user *buf, size_t size)
{
    long ret = 0;
    struct task_struct* process_task;
    ret = get_current_task(pid, &process_task);
    if (ret < 0) {
        return ret;
    }

     /* Task to reply to */
    struct task_struct *send_task = ((struct task_struct *)recv_id);//(struct task_struct *)(((long)recv_id >> 16) & 0xFFFF);
    int channel_id = 0;//(int)((recv_id) & 0xFFFF);
    struct channel_ipc* ch;
    struct normal_queue_item *item;
    int found = 0;

    /* Validate the buffer pointer */
    if (NULL == buf || !access_ok(buf, size)) {
        return -EFAULT; /* Invalid user pointer */
    }

    /* Validate the buffer size */
    if (size > SHORT_MSG_SIZE) {
        return -EMSGSIZE; /* Message too big */
    }

    /* Validate the channel_id */
    if (channel_id < 0 || channel_id >= process_task->max_channels) {
        return -EINVAL; /* Invalid channel ID */
    }

    ch = process_task->channels[channel_id];
    if (!ch || !ch->in_use) {
        return -EINVAL; /* Channel not in use or invalid */
    }


    printk(KERN_INFO "msg_reply  iterate reply_queue %p\n", send_task);

    /* Iterate over all channels to find the reply_task in reply_queue */
    spin_lock(&ch->lock);

    list_for_each_entry(item, &ch->reply_queue.head, list) {
        printk(KERN_INFO "msg_reply  item %p:%p\n", (long)item->task, send_task);
        if ((long)item->task == recv_id) {
            found = 1;
            send_task = item->task;
            list_del(&item->list);
            kfree(item);
            break;
        }
    }

    spin_unlock(&ch->lock);

    if (!found) {
        return -ESRCH; /* No such process */
    }

    char short_msg_buffer[SHORT_MSG_SIZE];

    /* Check the size against the short message buffer size */
    if (size > SHORT_MSG_SIZE) {
        return -EMSGSIZE; /* Message too big */
    }

    /* Copy the message from buf to the task's short_msg_buffer */
    if (copy_from_user(short_msg_buffer, buf, size)) {
        return -EFAULT; /* Copy from user failed */
    }

    printk(KERN_INFO "msg_reply  copying into send_task buffer\n");

    memcpy(send_task->short_msg_buffer, short_msg_buffer, size);
    send_task->msg_size = size;

    printk(KERN_INFO "msg_reply wakeup %p\n", send_task);

    /* Wake up the task */
    wake_up_process(send_task);

    return 0;
}

SYSCALL_DEFINE4(msg_reply, pid_t, pid, long, recv_id, const char __user*, buf, size_t, size)
{
    return ksys_msg_reply(pid, recv_id, buf, size);
}
