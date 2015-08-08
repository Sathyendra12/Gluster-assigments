#include "worm-retention.h"

int32_t
wr_writev_getxattr_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                      int32_t op_ret, int32_t op_errno, dict_t *dict,
                      dict_t *xdata)
{
        int ret = -1;
        char *name;
        uint8_t worm_state = 0;
        wr_local_writev_t *wr_local_writev = NULL;

        ret = gf_asprintf(&name, "trusted.worm_state");
        if (ret <= 0) {
               gf_log (this->name , GF_LOG_ERROR , "Failed setting worm_state key!");
               goto error;
        }

        int8_t worm_state_signed = 0;
        ret = dict_get_int8 (dict , name , &worm_state_signed);
        worm_state = (uint8_t) worm_state_signed;

        if ((worm_state>>7) & 1) 
                gf_log (this->name , GF_LOG_ERROR , "Write Failed. File is Worm-Retained!");
        else if ((worm_state>>6) & 1) 
                gf_log (this->name , GF_LOG_ERROR , "Write Failed. File is a Worm!");
        else if ((worm_state>>7) & 1) 
                gf_log (this->name , GF_LOG_ERROR , "Write Failed. File is Worm-Held!");
        else
                ret = 0;

        if (ret != 0) {
                op_errno = -30;
                goto error;
        }

        wr_local_writev = (wr_local_writev_t *) frame->local;
        STACK_WIND (frame,
                            default_writev_cbk,
                            FIRST_CHILD(this),
                            FIRST_CHILD(this)->fops->writev,
                             wr_local_writev->fd,
                             wr_local_writev->vector,
                             wr_local_writev->count,
                             wr_local_writev->off,
                             wr_local_writev->flags,
                             wr_local_writev->iobref,
                             xdata);
error:
        STACK_UNWIND_STRICT (writev, frame, -1, op_errno, NULL, NULL,
                                     NULL);
        return ret;
}


int32_t
wr_writev (call_frame_t *frame, xlator_t *this, fd_t *fd, struct iovec *vector,
           int32_t count, off_t off, uint32_t flags, struct iobref *iobref,
           dict_t *xdata)
{
        gf_log (this->name , GF_LOG_ERROR , "\n\n--\nIN WR WRITEV\n--\n\n");
        int ret = -1;
        wr_local_writev_t *wr_local_writev = NULL;

        wr_local_writev = GF_CALLOC (1, sizeof (wr_local_writev_t), gf_wr_mt_local_create_t);
        if (!wr_local_writev) {

               gf_log (this->name , GF_LOG_ERROR ,
                                        "failed init of local of writev fop!");
               goto error;
        }

        char *name;

        ret = gf_asprintf(&name, "trusted.worm_state");
        if (ret <= 0) {
               gf_log (this->name , GF_LOG_ERROR ,
                                        "Failed setting worm_state key!");
               goto error;
        }

        wr_local_writev->fd = fd;
        wr_local_writev->vector = vector;
        wr_local_writev->count = count;
        wr_local_writev->off = off;
        wr_local_writev->flags = flags;
        wr_local_writev->iobref = iobref;

        ret = 0;
        goto out;

error:
        if (wr_local_writev)
                GF_FREE (wr_local_writev);
        wr_local_writev = NULL;

out:
        frame->local = wr_local_writev;

        STACK_WIND (frame, wr_writev_getxattr_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->fgetxattr, fd, name, xdata);
        return ret;
}

int32_t
wr_getxattr_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                      int32_t op_ret, int32_t op_errno, dict_t *dict,
                      dict_t *xdata)
{
        int ret = -1;
        uint8_t worm_state = 0;
        wr_local_create_t *wr_local_create = NULL;
        char *name;

        wr_local_create = (wr_local_create_t*) frame->local;
        ret = gf_asprintf(&name, "trusted.worm_state");
        if (ret <= 0) {
               gf_log (this->name , GF_LOG_ERROR , "Failed setting worm_state key!");
               goto error;
        }

        int8_t worm_state_signed = 0;

        ret = dict_get_int8 (dict , name , &worm_state_signed);
        worm_state = (uint8_t) worm_state_signed;
        gf_log (this->name , GF_LOG_ERROR ,
                        "\n\n---\nWORM STATE: %" PRId8 "\n---\n\n", worm_state);
        ret = 0;
error:
        STACK_UNWIND_STRICT (create, frame,
                             wr_local_create->op_ret,
                             wr_local_create->op_errno,
                             wr_local_create->fd,
                             wr_local_create->inode,
                             wr_local_create->stbuf,
                             wr_local_create->preparent,
                             wr_local_create->postparent,
                             xdata);

       return ret;
}

int32_t
wr_setxattr_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                  int32_t op_ret, int32_t op_errno, dict_t *xdata)
{
        int ret = -1;
        wr_local_create_t *wr_local_create = NULL;

        wr_local_create = (wr_local_create_t*) frame->local;
        GF_ASSERT (frame);
        GF_ASSERT (frame->local);

        char *name;

        ret = gf_asprintf(&name, "trusted.worm_state");
        if (ret <= 0) {
               gf_log (this->name , GF_LOG_ERROR , "Failed setting worm_state key!");
               goto error;
        }

        STACK_WIND (frame, wr_getxattr_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->fgetxattr, wr_local_create->fd, name, xdata);
        ret = 0;
        goto out;
error:
        STACK_UNWIND_STRICT (create, frame,
                             wr_local_create->op_ret,
                             wr_local_create->op_errno,
                             wr_local_create->fd,
                             wr_local_create->inode,
                             wr_local_create->stbuf,
                             wr_local_create->preparent,
                             wr_local_create->postparent,
                             xdata);
out:
       return ret;
}

/* Function to add worm state attribute */
int32_t
wr_create_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
                int op_ret, int op_errno,
                fd_t *fd, inode_t *inode, struct iatt *stbuf,
                struct iatt *preparent, struct iatt *postparent,
                dict_t *xdata) {

        int ret = -1;
        uint8_t worm_state = 4;
        dict_t *dict = NULL;
        wr_local_create_t *wr_local_create = NULL;

        GF_ASSERT (frame);
        GF_ASSERT (this);
        GF_ASSERT (stbuf);

        /* If frame->local is null do nothing*/
        if (!frame->local) {
               goto error;
        }

        /*If create has failed then nothing to do*/
        if (op_ret == -1) {
               goto error;
        }
        wr_local_create = (wr_local_create_t*) frame->local;

        /*Saving current create fop's context on to frame->local*/
        wr_local_create->op_ret = op_ret;
        wr_local_create->op_errno = op_errno;
        wr_local_create->fd = fd;
        wr_local_create->inode = inode;
        wr_local_create->stbuf = stbuf;
        wr_local_create->preparent = preparent;
        wr_local_create->postparent = postparent;

        /*Setting atime of the file to xattr*/
        dict = dict_new ();
        if (!dict) {
              goto error;
        }

        ret = dict_set_int8 (dict, "trusted.worm_state", worm_state);

        if (ret) {
               gf_log (this->name , GF_LOG_ERROR , "Failed setting worm_state!");
               goto error;
        }

        STACK_WIND (frame, wr_setxattr_cbk,
                    FIRST_CHILD (this), FIRST_CHILD (this)->fops->fsetxattr, fd,
                    dict, 0, xdata);
        ret = 0;
        goto out;
error:
        STACK_UNWIND_STRICT (create, frame, op_ret, op_errno, fd, inode,
                        stbuf, preparent, postparent, xdata);
out:
        if (dict)
            dict_unref (dict); 

        if (wr_local_create) {
                GF_FREE (wr_local_create);
        }

        frame->local = NULL;
        return ret;
}

int32_t
wr_create(call_frame_t *frame, xlator_t *this,
            loc_t *loc, int32_t flags, mode_t mode,
            mode_t umask, fd_t *fd, dict_t *xdata) {

        int ret = -1;
        wr_local_create_t *wr_local_create = NULL;
        wr_local_create = GF_CALLOC (1, sizeof (wr_local_create_t), gf_wr_mt_local_create_t);

        if (!wr_local_create) {

               gf_log (this->name , GF_LOG_ERROR , "failed init of local of create fop!");
               goto error;
        }

        ret = 0;
        goto out;

error:
        if (wr_local_create)
                GF_FREE (wr_local_create);
        wr_local_create = NULL;

out:
        frame->local = wr_local_create;

        STACK_WIND (frame, wr_create_cbk, FIRST_CHILD (this),
                    FIRST_CHILD (this)->fops->create,
                    loc, flags, mode, umask, fd, xdata);
        return ret;
}

int32_t
init (xlator_t *this)
{
        gf_log (this->name , GF_LOG_ERROR ,
                "\n---------------\nIn Init\n---------------\n");

        if (!this->children || this->children->next) {
                gf_log (this->name , GF_LOG_ERROR ,
                        "FATAL: worm-retention should have exactly one child");
                return -1;
        }

        if (!this->parents) {
                gf_log (this->name , GF_LOG_WARNING ,
                        "Dangling volume. check volfile ");
        }

        gf_log (this->name , GF_LOG_DEBUG , "worm-retention xlator loaded");
        return 0;
}


int32_t
mem_acct_init (xlator_t *this)
{
        int     ret = -1;

        GF_VALIDATE_OR_GOTO ("ctr", this, out);

        ret = xlator_mem_acct_init (this, gf_wr_mt_end + 1);

        if (ret != 0) {
                gf_log (this->name , GF_LOG_ERROR , "Memory accounting init failed");
                return ret;
        }
out:
        return ret;
}


void
fini (xlator_t *this)
{
        wr_private_t *priv = NULL;

        priv = this->private ;
        if (!priv)
                return;
        this->private = NULL;
        GF_FREE (priv);

        return;
}

struct xlator_fops fops = {
        .create       = wr_create,
        .writev       = wr_writev
};

struct xlator_cbks cbks;

struct volume_options options[] = {
        { .key  = {NULL} },
};
