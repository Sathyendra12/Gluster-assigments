#include <ctype.h>
#include <sys/uio.h>

#include "glusterfs.h"
#include "xlator.h"
#include "logging.h"
#include "defaults.h"
#include "iatt.h"

#include "file-tracker.h"

int32_t
ft_setxattr (call_frame_t *frame, xlator_t *this,
                         fd_t *fd, dict_t *dict, int flags, dict_t *xdata)
{
        STACK_WIND (frame, default_setxattr_cbk,
                    FIRST_CHILD (this), FIRST_CHILD (this)->fops->fsetxattr, fd,
                    dict, flags, xdata);

        dict_unref (xdata);
        return 0;
}

/* Function to track file creation */
int32_t
ft_create_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
                int op_ret, int op_errno,
                fd_t *fd, inode_t *inode, struct iatt *stbuf,
                struct iatt *preparent, struct iatt *postparent,
                dict_t *xdata) {

        int ret = -1;
        uint64_t atime = stbuf->ia_atime;
        uint64_t mtime = stbuf->ia_mtime;
        uint64_t ctime = stbuf->ia_ctime;
        dict_t *dict = NULL;

        gf_log ("file-tracker" , GF_LOG_ERROR ,
                "\n\n---------\nIn Create Cbk\n-----------\n\n");

        ft_private_t *priv = NULL;
        char *file_entry = NULL;

        priv = this->private;
        if(op_ret != -1) {
                file_entry = (char *)frame->local;
                gf_log ("file-tracker" , GF_LOG_ERROR,
                        "\nFile Entry = %s\n" , file_entry);
                fprintf (priv->file , "%s\n" , file_entry);
                fflush (priv->file);

                if (!xdata) 
                        xdata = dict_new ();
                        if (!xdata)
                                goto cont_op;
                /*} else {
                        dict_ref (xdata);
                }*/
                gf_log ("file-tracker" , GF_LOG_ERROR ,
                        "\n\n---------PRE ATIME: \n-----------\n\n");
                ret = dict_set_int64 (xdata, "trusted.gf_atime", atime);
                /*gf_log ("file-tracker" , GF_LOG_ERROR ,
                "\n\n---------ATIME: %" PRIu64 "\n-----------\n\n",atime);*/
                if (ret)
                        goto unref_dict;
                ret = dict_set_int64 (xdata, "trusted.gf_mtime", mtime);
                if (ret)
                        goto unref_dict;
                ret = dict_set_int64 (xdata, "trusted.gf_ctime", ctime);
                if (ret)
                        goto unref_dict;

                ret = ft_setxattr (frame, this,
                        fd, dict, 0, xdata);
                if (ret)
                        gf_log ("file-tracker" , GF_LOG_ERROR ,
                                "\n\nError in creating xattr\n\n");

                goto cont_op;
        }

unref_dict:
        dict_unref (xdata);

cont_op:
        STACK_UNWIND_STRICT (create, frame, op_ret, op_errno, fd, inode,
                        stbuf, preparent, postparent, xdata);
        __gf_free (file_entry);

        return 0;
}

int32_t
ft_create(call_frame_t *frame, xlator_t *this,
            loc_t *loc, int32_t flags, mode_t mode,
            mode_t umask, fd_t *fd, dict_t *xdata) {

        char *file_entry = NULL;

        gf_log ("file-tracker" , GF_LOG_ERROR,
                "\n\n------------\n\nIn Create\n\n--------------\n\n");

        gf_asprintf(&file_entry , loc->path);
        gf_log ("file-tracker" , GF_LOG_ERROR , "\nf_loc = %s\n\n" , file_entry);

        frame->local = file_entry;

        STACK_WIND (frame, ft_create_cbk, FIRST_CHILD (this),
                    FIRST_CHILD (this)->fops->create,
                    loc, flags, mode, umask, fd, xdata);
        return 0;
}

int32_t
init (xlator_t *this)
{
        ft_private_t *priv = NULL;

        gf_log ("file-tracker" , GF_LOG_ERROR ,
                "\n---------------\nIn Init\n---------------\n");

        if (!this->children || this->children->next) {
                gf_log ("file-tracker" , GF_LOG_ERROR ,
                        "FATAL: file-tracker should have exactly one child");
                return -1;
        }

        if (!this->parents) {
                gf_log (this->name , GF_LOG_WARNING ,
                        "dangling volume. check volfile ");
        }

        priv = __gf_calloc (sizeof (ft_private_t) , 1 , 0 , "0");
        if (!priv)
                return -1;

        FILE *log_fptr = fopen ("/file_track_log.txt" , "a");

        priv->file = log_fptr;
        this->private = priv;

        gf_log ("file-tracker" , GF_LOG_DEBUG , "file-tracker xlator loaded");
        return 0;
}

void
fini (xlator_t *this)
{
        ft_private_t *priv = NULL;

        priv = this->private ;

        gf_log ("file-tracker" , GF_LOG_ERROR ,
                        "\n\n------------\nFile Closed\n--------------\n\n");

        if (!priv)
                return;
        fclose (priv->file);
        this->private = NULL;
        __gf_free (priv);

        return;
}

struct xlator_fops fops = {
        .create       = ft_create
};

struct xlator_cbks cbks;

struct volume_options options[] = {
        { .key  = {NULL} },
};
