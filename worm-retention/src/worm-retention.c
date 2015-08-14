#include "worm-retention.h"

int32_t
wr_setattr (call_frame_t *frame, xlator_t *this, loc_t *loc,
            struct iatt *stbuf, int32_t valid, dict_t *xdata)
{
        gf_log (this->name , GF_LOG_ERROR , "\n\n\nIN SETATTR\n\n\n");
        int ret = -1;
        char *name;
        int32_t op_ret = -1, op_errno = -1;
        uint8_t worm_state = 0;
        dict_t *dict = dict_new();
        wr_in_create_t *crt_st = (wr_in_create_t *) frame->local;

        if (crt_st->crt_flag == 1)
                goto out;

        ret = gf_asprintf(&name, "trusted.worm_state");
        if (ret <= 0) {
               gf_log (this->name , GF_LOG_ERROR , "Failed setting worm_state key!");
               goto error;
        }
        ret = syncop_getxattr (this, loc, &dict,
                                       name, NULL, NULL);
        gf_log (this->name , GF_LOG_ERROR , "\n\nRET: %d\n\n",ret);
        if (ret) {
                        gf_msg (this->name, GF_LOG_ERROR, 0, 0, "ERROR"
                                " in determining xattr of the file\n\n");
                        ret = -1;
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

        goto out;
error:
        STACK_UNWIND_STRICT (setattr, frame, op_ret, op_errno, NULL,
                             NULL, xdata);
        goto ret_out;
out:
        STACK_WIND (frame,
                            default_setattr_cbk,
                            FIRST_CHILD (this),
                            FIRST_CHILD (this)->fops->setattr,
                            loc, stbuf, valid, xdata);
ret_out:
        return ret;
}

int32_t
wr_fsetxattr (call_frame_t *frame, xlator_t *this, fd_t *fd, dict_t *dict,
              int32_t flags, dict_t *xdata)
{
        gf_log (this->name , GF_LOG_ERROR , "\n\n\nIN F SETXATTR\n\n\n");
        int ret = -1;
        char *name;
        int32_t op_ret = -1, op_errno = -1;
        uint8_t worm_state = 0;
        wr_in_create_t *crt_st = (wr_in_create_t *) frame->local;

        if (crt_st->crt_flag == 1)
                goto out;
        ret = gf_asprintf(&name, "trusted.worm_state");
        if (ret <= 0) {
               gf_log (this->name , GF_LOG_ERROR , "Failed setting worm_state key!");
               goto error;
        }
        ret = syncop_fgetxattr (this, fd, &dict,
                                       name, NULL, NULL);
        if (ret) {
                        gf_msg (this->name, GF_LOG_ERROR, 0, 0, "ERROR"
                                "in determining xattr of the file\n\n");
                        ret = -1;
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

        goto out;
error:
        STACK_UNWIND_STRICT (fsetxattr, frame, op_ret, op_errno, xdata);
        goto ret_out;
out:
        STACK_WIND (frame, default_fsetxattr_cbk,
                    FIRST_CHILD (this), FIRST_CHILD (this)->fops->fsetxattr, fd,
                    dict, 0, xdata);
ret_out:
        return ret;
}


int32_t
wr_setxattr (call_frame_t *frame, xlator_t *this, loc_t *loc, dict_t *dict,
             int32_t flags, dict_t *xdata)
{
        gf_log (this->name , GF_LOG_ERROR , "\n\nIN SETXATTR\n\n");
        int ret = -1;
        char *name;
        int32_t op_ret = -1, op_errno = -1;
        uint8_t worm_state = 0;
        wr_in_create_t *crt_st = (wr_in_create_t *) frame->local;

        if (crt_st->crt_flag == 1)
                goto out;

        ret = gf_asprintf(&name, "trusted.worm_state");
        if (ret <= 0) {
               gf_log (this->name , GF_LOG_ERROR , "Failed setting worm_state key!");
               goto error;
        }
        ret = syncop_getxattr (this, loc, &dict,
                                       name, NULL, NULL);
        if (ret) {
                        gf_msg (this->name, GF_LOG_ERROR, 0, 0, "ERROR"
                                "in determining xattr of the file\n\n");
                        ret = -1;
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

        goto out;

error:
        STACK_UNWIND_STRICT (setxattr, frame, op_ret, op_errno, xdata);
        goto ret_out;
out:
        STACK_WIND (frame,
                        default_setxattr_cbk,
                        FIRST_CHILD(this),
                        FIRST_CHILD(this)->fops->setxattr,
                        loc, dict, flags, xdata);
ret_out:
        return ret;
}


int32_t
wr_writev (call_frame_t *frame, xlator_t *this, fd_t *fd, struct iovec *vector,
           int32_t count, off_t off, uint32_t flags, struct iobref *iobref,
           dict_t *xdata)
{
        gf_log (this->name , GF_LOG_ERROR , "\n\n--\nIN WR WRITEV\n--\n\n");
        int ret = -1;
        char *name;
        int32_t op_ret = -1, op_errno = -1;
        uint8_t worm_state = 0;
        dict_t *dict = dict_new ();
        wr_in_create_t *crt_st = (wr_in_create_t *) frame->local;

        if (crt_st->crt_flag == 1)
                goto out;
        ret = gf_asprintf(&name, "trusted.worm_state");
        if (ret <= 0) {
               gf_log (this->name , GF_LOG_ERROR , "Failed setting worm_state key!");
               goto error;
        }
        ret = syncop_fgetxattr (this, fd, &dict,
                                       name, NULL, NULL);
        if (ret) {
                        gf_msg (this->name, GF_LOG_ERROR, 0, 0, "ERROR"
                                "in determining xattr of the file\n\n");
                        ret = -1;
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

        goto out;
error:
        STACK_UNWIND_STRICT (writev, frame, op_ret, op_errno, NULL, NULL, xdata);
        goto ret_out;
out:
        STACK_WIND (frame, default_writev_cbk,
                        FIRST_CHILD(this),
                        FIRST_CHILD(this)->fops->writev, fd, vector,
                        count, off, flags, iobref, xdata);
ret_out:
        return ret;
}

int32_t
wr_create_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
                int op_ret, int op_errno,
                fd_t *fd, inode_t *inode, struct iatt *stbuf,
                struct iatt *preparent, struct iatt *postparent,
                dict_t *xdata) {

        int ret = -1;
        uint8_t worm_state = 0;
        dict_t *dict = NULL;

        GF_ASSERT (this);
        GF_ASSERT (stbuf);

        /*If create has failed then nothing to do*/
        if (op_ret == -1) {
               goto out;
        }

        dict = dict_new ();
        if (!dict) {
              goto out;
        }

        ret = dict_set_int8 (dict, "trusted.worm_state", worm_state);
        if (ret) {
               gf_log (this->name , GF_LOG_ERROR , "Failed setting worm_state!");
               goto out;
        }

        ret = syncop_fsetxattr (this, fd, dict, 0, NULL, NULL);
        if (ret) {
                gf_log (this->name, GF_LOG_ERROR, "fsetxattr failed to set worm-state\n");
                goto out;
        }

        ret = 0;
out:
        if (dict)
            dict_unref (dict);

        STACK_UNWIND_STRICT (create, frame, op_ret, op_errno, fd, inode,
                        stbuf, preparent, postparent, xdata);
        return ret;
}



int32_t
wr_create(call_frame_t *frame, xlator_t *this,
            loc_t *loc, int32_t flags, mode_t mode,
            mode_t umask, fd_t *fd, dict_t *xdata) {

        int ret = -1;
        wr_in_create_t *st_crt;

        st_crt = GF_CALLOC (1, sizeof (wr_in_create_t), 0);
        st_crt->crt_flag = 1;
        frame->local = st_crt;

        STACK_WIND (frame, wr_create_cbk, FIRST_CHILD (this),
                    FIRST_CHILD (this)->fops->create,
                    loc, flags, mode, umask, fd, xdata);
        ret = 0;
        st_crt->crt_flag = 0;
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
        .writev       = wr_writev,
        .setxattr     = wr_setxattr,
        .fsetxattr    = wr_fsetxattr
        .setattr      = wr_setattr,
};

struct xlator_cbks cbks;

struct volume_options options[] = {
        { .key  = {NULL} },
};
