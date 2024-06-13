#ifndef _LINUX_CONNECTION_H
#define _LINUX_CONNECTION_H

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/channel.h>

#define INITIAL_CONNECTION_SIZE 10

struct connection {
    struct channel *chan; // Pointer to the associated channel
    int connection_id;    // Connection ID
};

// Function prototypes for connection management

/**
 * Initializes the connection array for a task.
 * @param task The task struct for which the connections are initialized.
 * @param initial_size The initial size of the connection array.
 * @return 0 on success, -ENOMEM on memory allocation failure.
 */
int init_connections(struct task_struct *task, int initial_size);

/**
 * Resizes the connection array for a task.
 * @param task The task struct for which the connections are resized.
 * @param new_size The new size of the connection array. 
 * @return 0 on success, -ENOMEM on memory allocation failure.
 */
int resize_connections(struct task_struct *task, int new_size);

/**
 * Finds a free slot in the connection array.
 * @param task The task struct to search for a free connection slot.
 * @return The index of a free slot, or -1 if no free slot is found.
 */
int find_free_connection_slot(struct task_struct *task);

/**
 * Attaches a connection to a channel.
 * @param task The task struct for which the connection is attached.
 * @param channel_id The ID of the channel to which the connection is attached.
 * @return The connection ID on success, -EINVAL for invalid channel ID, -ENOMEM on memory allocation failure.
 */
int connection_attach(struct task_struct *task, int channel_id);

/**
 * Cleans up the connection array for a task.
 * @param task The task struct for which the connections are cleaned up.
 */
void cleanup_connections(struct task_struct *task);

#endif /* _LINUX_CONNECTION_H */
