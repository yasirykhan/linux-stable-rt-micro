/*
 * linux/ipc/connection.c
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

#include <linux/connection.h>

/* Initialize the connection array */
int init_connections(struct task_struct *task, int initial_size)
{
    task->connections = kmalloc_array(initial_size, sizeof(struct connection *), GFP_KERNEL);
    if (!task->connections) {
        return -ENOMEM;
    }

    task->max_connections = initial_size;
    task->num_connections = 0;

    /* Initialize connection slots */
    for (int i = 0; i < initial_size; ++i) {
        task->connections[i] = NULL;
    }

    return 0;
}

/* Resize the connection array */
int resize_connections(struct task_struct *task, int new_size)
{
    struct connection **new_connections;

    if (new_size <= task->max_connections) {
        return 0;
    }

    new_connections = krealloc(task->connections, new_size * sizeof(struct connection *), GFP_KERNEL);
    if (!new_connections) {
        return -ENOMEM;
    }

    /* Initialize new connection slots */
    for (int i = task->max_connections; i < new_size; ++i) {
        new_connections[i] = NULL;
    }

    task->connections = new_connections;
    task->max_connections = new_size;

    return 0;
}

/* Find a free connection slot */
int find_free_connection_slot(struct task_struct *task)
{
    for (int i = 0; i < task->max_connections; ++i) {
        if (task->connections[i] == NULL) {
            return i;
        }
    }
    return -1; /* No free slot found */
}

/* Attach a connection to a channel */
int connection_attach(struct task_struct *task, int channel_id)
{
    if (channel_id < 0 || channel_id >= task->max_channels || task->channels[channel_id] == NULL) {
        return -EINVAL; /* Invalid channel ID */
    }

    struct connection *conn;
    int slot;

    /* Allocate memory for the new connection */
    conn = kmalloc(sizeof(struct connection), GFP_KERNEL);
    if (!conn) {
        return -ENOMEM; /* Return error code if allocation fails */
    }

    /* Set the connection fields */
    conn->chan = task->channels[channel_id];

    /* Add the new connection to the current task_struct */
    if (current->num_connections >= current->max_connections) {
        int ret = resize_connections(current, current->max_connections * 2);
        if (ret) {
            kfree(conn);
            return ret;
        }
    }

    slot = find_free_connection_slot(current);
    printk(KERN_INFO "connection attach system call: find_free_slot %d\n", slot);

    if (slot < 0) {
        kfree(conn);
        return -ENOMEM; /* No free slot found */
    }

    current->connections[slot] = conn;
    conn->connection_id = slot;

    current->num_connections++;

    printk(KERN_INFO "connection attach %p, %p and %d", task->connections, task->connections[slot], slot);

    /* Return the connection ID */
    return conn->connection_id;
}

/* Clean up the connection array */
void cleanup_connections(struct task_struct *task)
{
    for (int i = 0; i < task->max_connections; ++i) {
        if (task->connections[i] != NULL) {
            kfree(task->connections[i]);
        }
    }

    if (NULL != task && NULL != task->connections) 
        kfree(task->connections);
}

/* System call for attaching a connection */
long ksys_connection_attach(pid_t pid, int channel_id)
{
    long ret = 0;
    struct task_struct* task;
    ret = get_current_task(pid, &task);
    if (ret < 0) {
        return ret;
    }
    printk(KERN_INFO "connection_attach: task = %p", task);

    return connection_attach(task, channel_id);
}

SYSCALL_DEFINE2(connection_attach, pid_t, pid, int, channel_id)
{
    return ksys_connection_attach(pid, channel_id);
}

/* System call for closing a connection */
long ksys_connection_close(pid_t pid, int connection_id)
{
    printk(KERN_INFO "connection close system call: connection %d\n", connection_id);
    return 0;
}

SYSCALL_DEFINE2(connection_close, pid_t, pid, int, connection_id)
{
    return ksys_connection_close(pid, connection_id);
}
