#ifndef __FT_H__
#define __FT_H__

#include <ctype.h>
#include <sys/uio.h>

#include "glusterfs.h"
#include "xlator.h"
#include "logging.h"
#include "defaults.h"
#include "iatt.h"
#include "ft-mem-types.h"


/* Translator Private Data */
typedef struct {
        FILE *file;
} ft_private_t;

typedef struct _ft_local_create{
        char *file_path;
        int op_ret;
        int op_errno;
        fd_t *fd;
        inode_t *inode;
        struct iatt *stbuf;
        struct iatt *preparent;
        struct iatt *postparent;
} ft_local_create_t;

#endif
