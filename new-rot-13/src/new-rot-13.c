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

#include "new-rot-13.h"

/*
 * This is a rot13 ``encryption'' xlator. It rot13's data when
 * writing to disk and rot13's it back when reading it.
 * This xlator is meant as an example, NOT FOR PRODUCTION
 * USE ;) (hence no error-checking)
 */

void
rot13 (char *buf, int len)
{
        int i;
        for (i = 0; i < len; i++) {
                if (buf[i] >= 'a' && buf[i] <= 'z')
                        buf[i] = 'a' + ((buf[i] - 'a' + 13) % 26);
                else if (buf[i] >= 'A' && buf[i] <= 'Z')
                        buf[i] = 'A' + ((buf[i] - 'A' + 13) % 26);
        }
}

void
rot13_iovec (struct iovec *vector, int count)
{
        int i;
        for (i = 0; i < count; i++) {
                rot13 (vector[i].iov_base, vector[i].iov_len);
        }
}

int32_t
rot13_readv_cbk (call_frame_t *frame,
                 void *cookie,
                 xlator_t *this,
                 int32_t op_ret,
                 int32_t op_errno,
                 struct iovec *vector,
                 int32_t count,
                 struct iatt *stbuf,
                 struct iobref *iobref, dict_t *xdata)
{
        gf_log ("new-rot13", GF_LOG_ERROR,
                        "\n\n---------\n\nHello In Read Back\n\n--------\n\n");
        rot_13_private_t *priv = (rot_13_private_t *)this->private;
        if (priv->decrypt_read)
                rot13_iovec (vector, count);

        
        STACK_UNWIND_STRICT (readv, frame, op_ret, op_errno, vector, count,
                             stbuf, iobref, xdata);
        return 0;
}

int32_t
rot13_readv (call_frame_t *frame,
             xlator_t *this,
             fd_t *fd,
             size_t size,
             off_t offset, uint32_t flags, dict_t *xdata)
{
        gf_log ("new-rot13", GF_LOG_ERROR,
                        "\n\n----------\n\nHello In Read\n\n------------\n\n");
        STACK_WIND (frame,
                    rot13_readv_cbk,
                    FIRST_CHILD (this),
                    FIRST_CHILD (this)->fops->readv,
                    fd, size, offset, flags, xdata);
        return 0;
}

int32_t
rot13_writev_cbk (call_frame_t *frame,
                  void *cookie,
                  xlator_t *this,
                  int32_t op_ret,
                  int32_t op_errno,
                  struct iatt *prebuf,
                  struct iatt *postbuf, dict_t *xdata)
{
        gf_log ("new-rot13", GF_LOG_ERROR,
                        "\n\n---------\n\nHello In Write Back\n\n-----------\n\n");
        STACK_UNWIND_STRICT (writev, frame, op_ret, op_errno, prebuf, postbuf,
                             xdata);
        return 0;
}

int32_t
rot13_writev (call_frame_t *frame,
              xlator_t *this,
              fd_t *fd,
              struct iovec *vector,
              int32_t count,
              off_t offset, uint32_t flags,
              struct iobref *iobref, dict_t *xdata)
{
        gf_log ("new-rot13", GF_LOG_ERROR,
                        "\n\n------------\n\nHello In Write\n\n--------------\n\n");
        rot_13_private_t *priv = (rot_13_private_t *)this->private;

        if (priv->encrypt_write)
                rot13_iovec (vector, count);

        
        STACK_WIND (frame,
                        rot13_writev_cbk,
                        FIRST_CHILD (this),
                        FIRST_CHILD (this)->fops->writev,
                        fd, vector, count, offset, flags,
                        iobref, xdata);
        return 0;
}

int32_t
rot13_create_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
                int op_ret, int op_errno,
                fd_t *fd, inode_t *inode, struct iatt *stbuf,
                struct iatt *preparent, struct iatt *postparent,
                dict_t *xdata) {
        gf_log ("new-rot13", GF_LOG_ERROR,
                        "\n\n---------\n\nHello In Create Back\n\n-----------\n\n");
        STACK_UNWIND_STRICT (create, frame, op_ret, op_errno, fd, inode,
                             stbuf,
                        preparent, postparent, xdata);
        return 0;
}

int32_t
rot13_create(call_frame_t *frame, xlator_t *this,
            loc_t *loc, int32_t flags, mode_t mode,
            mode_t umask, fd_t *fd, dict_t *xdata) {
        gf_log ("new-rot13", GF_LOG_ERROR,
                        "\n\n------------\n\nHello In Create\n\n--------------\n\n");
        rot_13_private_t *priv = NULL;

        priv = this->private;
        fprintf (priv->file,"%s\n",loc->path);
        STACK_WIND (frame, rot13_create_cbk, FIRST_CHILD (this),
                    FIRST_CHILD (this)->fops->create,
                    loc, flags, mode, umask, fd, xdata);
        return 0;
}

int32_t
init (xlator_t *this)
{
        data_t *data = NULL;
        rot_13_private_t *priv = NULL;

        gf_log ("new-rot13", GF_LOG_ERROR,
                        "\n---------------------\n\nGetting Initializing>>>>\n\n---------------------\n");

        if (!this->children || this->children->next) {
                gf_log ("new-rot13", GF_LOG_ERROR,
                        "FATAL: new-rot13 should have exactly one child");
                return -1;
        }

        if (!this->parents) {
                gf_log (this->name, GF_LOG_WARNING,
                        "dangling volume. check volfile ");
        }

        priv = GF_CALLOC (sizeof (rot_13_private_t), 1, 0);
        if (!priv)
                return -1;

        FILE *p_fd = fopen ("/home/sathyendra/file_list.txt" , "a");

        gf_log ("new-rot13", GF_LOG_ERROR,"Created FD");

        priv->decrypt_read = 1;
        priv->encrypt_write = 1;
        priv->file = p_fd;

        data = dict_get (this->options, "encrypt-write");
        if (data) {
                if (gf_string2boolean (data->data, &priv->encrypt_write) == -1) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "encrypt-write takes only boolean options");
                        GF_FREE (priv);
                        return -1;
                }
        }

        data = dict_get (this->options, "decrypt-read");
        if (data) {
                if (gf_string2boolean (data->data, &priv->decrypt_read) == -1) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "decrypt-read takes only boolean options");
                        GF_FREE (priv);
                        return -1;
                }
        }

        this->private = priv;
        gf_log ("new-rot13", GF_LOG_DEBUG, "new-rot13 xlator loaded");
        return 0;
}

void
fini (xlator_t *this)
{
        rot_13_private_t *priv = this->private;

        if (!priv)
                return;
        this->private = NULL;
        GF_FREE (priv);

        return;
}

struct xlator_fops fops = {
        .create       = rot13_create,
        .readv        = rot13_readv,
        .writev       = rot13_writev
};

struct xlator_cbks cbks;

struct volume_options options[] = {
        { .key  = {"encrypt-write"},
          .type = GF_OPTION_TYPE_BOOL
        },
        { .key  = {"decrypt-read"},
          .type = GF_OPTION_TYPE_BOOL
        },
        { .key  = {NULL} },
};
