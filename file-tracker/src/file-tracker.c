#include <ctype.h>
#include <sys/uio.h>

#include "glusterfs.h"
#include "xlator.h"
#include "logging.h"

#include "file-tracker.h"

/* Function to track file creation */
int32_t
ft_create_cbk(call_frame_t *frame, void *cookie, xlator_t *this,
                int op_ret, int op_errno,
                fd_t *fd, inode_t *inode, struct iatt *stbuf,
                struct iatt *preparent, struct iatt *postparent,
                dict_t *xdata) {

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
        }

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
