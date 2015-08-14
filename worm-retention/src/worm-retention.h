#ifndef __WR_H__
#define __WR_H__

#include <ctype.h>
#include <sys/uio.h>

#include "glusterfs.h"
#include "xlator.h"
#include "logging.h"
#include "defaults.h"
#include "iatt.h"
#include "wr-mem-types.h"
#include "syncop.h"

/* Translator Private Data */
typedef struct {
        FILE *file;
} wr_private_t;

typedef struct _wr_in_create {
        int crt_flag;
} wr_in_create_t;

typedef struct _wr_local_create{
        int op_ret;
        int op_errno;
        fd_t *fd;
        inode_t *inode;
        struct iatt *stbuf;
        struct iatt *preparent;
        struct iatt *postparent;
} wr_local_create_t;

typedef struct _wr_local_writev{
        fd_t *fd;
        struct iovec *vector;
        int32_t count;
        off_t off;
        uint32_t flags;
        struct iobref *iobref;
} wr_local_writev_t;

#endif
