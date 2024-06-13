/*
 * include/linux/channel.h
 */

#ifndef _LINUX_CHANNEL_H
#define _LINUX_CHANNEL_H

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/sched.h>

#define INITIAL_CHANNEL_SIZE 10 /* Define the initial channel array size */

/**
 * struct wait_queue - Represents a combined list and wait queue
 * @head: List head for the queue
 * @wait: Wait queue head for the queue
 */
struct wait_queue {
    struct list_head head;
    wait_queue_head_t wait;
};

/**
 * struct channel - Represents a communication channel
 * @send_queue: Priority queue for sending messages
 * @recv_queue: Normal queue for receiving messages
 * @reply_queue: Normal queue for reply messages
 * @in_use: Flag to indicate if the channel is in use
 * @lock: Spinlock for synchronizing access to the channel
 */
struct channel {
    struct wait_queue send_queue;  /* Priority queue */
    struct wait_queue recv_queue;  /* Normal queue */
    struct wait_queue reply_queue; /* Normal queue */
    bool in_use;                   /* Flag to indicate if the channel is in use */
    spinlock_t lock;               /* Spinlock for synchronizing access */
};

/**
 * struct send_queue_item - Represents an item in the send queue
 * @list: List head for the send queue
 * @task: Pointer to the task associated with this item
 * @priority: Priority of the item in the send queue
 */
struct send_queue_item {
    struct list_head list;
    struct task_struct *task;
    int priority; /* Priority for the priority queue */
};

/**
 * struct normal_queue_item - Represents an item in a normal queue
 * @list: List head for the normal queue
 * @task: Pointer to the task associated with this item
 */
struct normal_queue_item {
    struct list_head list;
    struct task_struct *task;
    struct task_struct *sender;
};

/* Function prototypes */

/**
 * init_channels - Initializes the channel array for a task
 * @task: The task for which to initialize the channels
 * @initial_size: The initial size of the channel array
 *
 * Returns 0 on success, -ENOMEM on memory allocation failure.
 */
int init_channels(struct task_struct *task, int initial_size);

/**
 * resize_channels - Resizes the channel array for a task
 * @task: The task for which to resize the channels
 * @new_size: The new size of the channel array
 *
 * Returns 0 on success, -ENOMEM on memory allocation failure.
 */
int resize_channels(struct task_struct *task, int new_size);

/**
 * find_free_channel_slot - Finds a free slot in the channel array
 * @task: The task for which to find a free channel slot
 *
 * Returns the index of a free slot, or -1 if no free slot is found.
 */
int find_free_channel_slot(struct task_struct *task);

/**
 * add_channel - Adds a new channel to the task's channel array
 * @task: The task to which to add the channel
 * @ch: The channel to add
 *
 * Returns the index of the added channel on success, or an error code on failure.
 */
int add_channel(struct task_struct *task, struct channel *ch);

/**
 * add_to_send_queue - Adds a task to the send queue of a channel
 * @ch: The channel to which to add the task
 * @task: The task to add to the send queue
 * @priority: The priority of the task in the send queue
 *
 * Returns 0 on success, or an error code on failure.
 */
int add_to_send_queue(struct channel *ch, struct task_struct *task, int priority);

/**
 * add_to_recv_queue - Adds a task to the receive queue of a channel
 * @ch: The channel to which to add the task
 * @task: The task to add to the receive queue
 *
 * Returns 0 on success, or an error code on failure.
 */
int add_to_recv_queue(struct channel *ch, struct task_struct *task);

/**
 * add_to_reply_queue - Adds a task to the reply queue of a channel
 * @ch: The channel to which to add the task
 * @task: The task to add to the reply queue
 *
 * Returns 0 on success, or an error code on failure.
 */
int add_to_reply_queue(struct channel *ch, struct task_struct *task);

/**
 * cleanup_channels - Cleans up the channel array for a task
 * @task: The task for which to clean up the channels
 */
void cleanup_channels(struct task_struct *task);

/**
 * create_channel - Creates a new channel
 *
 * Returns the index of the created channel on success, or an error code on failure.
 */
long create_channel(pid_t pid);

long get_current_task(pid_t pid, struct task_struct **task_ret);


#endif /* _LINUX_CHANNEL_H */
