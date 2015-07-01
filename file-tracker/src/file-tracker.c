/*
   Copyright (c) 2006-2012 Red Hat, Inc. <http://www.redhat.com>
   This file is part of GlusterFS.

   This file is licensed to you under your choice of the GNU Lesser
   General Public License, version 3 or any later version (LGPLv3 or
   later), or the GNU General Public License, version 2 (GPLv2), in all
   cases as published by the Free Software Foundation.
*/
#include <ctype.h>
#include <sys/uio.h>

#include "glusterfs.h"
#include "xlator.h"
#include "logging.h"

#include "file-tracker.h"


int32_t
ft_create_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
                int op_ret, int op_errno,
                fd_t *fd, inode_t *inode, struct iatt *stbuf,
                struct iatt *preparent, struct iatt *postparent,
                dict_t *xdata) {
        
        ft_private_t *priv = NULL;
        priv = this->private;

        if (op_ret != -1) {
                char **f_loc = (char **) frame->local;
                fprintf (priv->file , "%s\n" , f_loc[0]);
                GF_FREE (frame->local);
        }
        gf_log ("file-tracker", GF_LOG_ERROR,
                        "\n\n---------\nHello In Create Back\n-----------\n\n");
        STACK_UNWIND_STRICT (create, frame, op_ret, op_errno, fd, inode,
                             stbuf,preparent, postparent, xdata);
        
        return 0;
}

int32_t
ft_create(call_frame_t *frame, xlator_t *this,
            loc_t *loc, int32_t flags, mode_t mode,
            mode_t umask, fd_t *fd, dict_t *xdata) {
        gf_log ("file-tracker", GF_LOG_ERROR,
                        "\n\n------------\n\nHello In Create\n\n--------------\n\n");
        char **f_loc = NULL;

        gf_asprintf (f_loc , loc->path);
        frame->local = f_loc;

        STACK_WIND (frame, ft_create_cbk, FIRST_CHILD (this),
                    FIRST_CHILD (this)->fops->create,
                    loc, flags, mode, umask, fd, xdata);
        return 0;
}

int32_t
init (xlator_t *this)
{
        ft_private_t *priv = NULL;

        FILE *fptr = fopen ("/file_track_log.txt" , "a");
        priv = GF_CALLOC (sizeof (ft_private_t), 1, 0);
        priv->file = fptr;
        this->private = priv;
        gf_log ("file-tracker", GF_LOG_ERROR,
                "\n------------------\n\nInitializing\n\n------------------\n");

        if (!this->children || this->children->next) {
                gf_log ("file-tracker", GF_LOG_ERROR,
                        "FATAL: file-tracker should have exactly one child");
                return -1;
        }

        if (!this->parents) {
                gf_log (this->name, GF_LOG_WARNING,
                        "dangling volume. check volfile ");
        }

        priv = GF_CALLOC (sizeof (ft_private_t), 1, 0);
        if (!priv)
                return -1;

        this->private = priv;
        gf_log ("file-tracker", GF_LOG_DEBUG, "file-tracker xlator loaded");
        return 0;
}

void
fini (xlator_t *this)
{
        ft_private_t *priv = this->private;

        if (!priv)
                return;
        fclose (priv->file);
        gf_log ("file-tracker", GF_LOG_ERROR,
                        "\n\n------------\n\nFile Closed\n\n-------------\n\n");
        this->private = NULL;
        GF_FREE (priv);

        return;
}

struct xlator_fops fops = {
        .create       = ft_create
};

struct xlator_cbks cbks;

struct volume_options options[] = {
        { .key  = {NULL} },
};
