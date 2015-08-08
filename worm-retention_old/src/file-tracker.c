#include "file-tracker.h"


int32_t
ft_setxattr_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                  int32_t op_ret, int32_t op_errno, dict_t *xdata)
{

       ft_local_create_t *ft_local_create = NULL;
       
       GF_ASSERT (frame);
       GF_ASSERT (frame->local);
       
       gf_log (this->name , GF_LOG_ERROR , "\n\n---- \nInside xattr\n---\n\n");

       ft_local_create = (ft_local_create_t*) frame->local;

       STACK_UNWIND_STRICT (create, frame,
                             ft_local_create->op_ret,
                             ft_local_create->op_errno,
                             ft_local_create->fd,
                             ft_local_create->inode,
                             ft_local_create->stbuf,
                             ft_local_create->preparent,
                             ft_local_create->postparent,
                             xdata);

       frame->local = NULL;

       return 0;
}

int32_t
ft_setattr_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                  int32_t op_ret, int32_t op_errno, dict_t *xdata)
{

       ft_local_create_t *ft_local_create = NULL;
       
       GF_ASSERT (frame);
       GF_ASSERT (frame->local);
       
       gf_log (this->name , GF_LOG_ERROR , "\n\n---- \nInside xattr\n---\n\n");

       ft_local_create = (ft_local_create_t*) frame->local;

       STACK_UNWIND_STRICT (create, frame,
                             ft_local_create->op_ret,
                             ft_local_create->op_errno,
                             ft_local_create->fd,
                             ft_local_create->inode,
                             ft_local_create->stbuf,
                             ft_local_create->preparent,
                             ft_local_create->postparent,
                             xdata);

       frame->local = NULL;

       return 0;
}

int32_t
ft_setattr (call_frame_t *frame, xlator_t *this, loc_t *loc,
            struct iatt *stbuf, int32_t valid, dict_t *xdata)
{
        int ret = -1;
        uint64_t wrm_state = 0;
        dict_t *dict = NULL;

        STACK_WIND_TAIL (frame, FIRST_CHILD (this),
                                 FIRST_CHILD(this)->fops->setattr, loc, stbuf,
                                 valid, xdata);
        struct stat buf;
        stat(loc->path, &buf);

        int read =( (buf.st_mode & S_IRUSR) ? 1 : 0 );
        int write =( (buf.st_mode & S_IWUSR) ? 1 : 0 );
        int execute =( (buf.st_mode & S_IXUSR) ? 1 : 0 );

        gf_log (this->name, GF_LOG_WARNING,
                "\n\n read = %d \n write = %d \n execute = %d \n\n" , read, write, execute);

        dict = dict_new ();
        if(write == 0)
        {
                wrm_state = 0x010000000;
                ret = dict_set_int64 (dict, "trusted.worm_state", wrm_state);
                if (ret) {
                        gf_log (this->name , GF_LOG_ERROR , "Failed setting worm_state!");
                }

                gf_log (this->name, GF_LOG_WARNING,"\n\n ft_setattr \n\n");
        }
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
        uint64_t atime = 0;
        dict_t *dict = NULL;
        ft_private_t *priv = NULL;
        ft_local_create_t *ft_local_create = NULL;

        GF_ASSERT (frame);
        GF_ASSERT (this);
        GF_ASSERT (this->private);
        GF_ASSERT (stbuf);

        /* If frame->local is null do nothing*/
        if (!frame->local) {
               goto error;		
        }

        /*If create has failed then nothing to do*/
        if (op_ret == -1) {
               goto error;
        }


        ft_local_create = (ft_local_create_t*) frame->local;

        /*Copy atime of the inode */
        atime = stbuf->ia_atime;

       /*writing file name to db file*/
        priv = this->private;        
        if (!ft_local_create->file_path) {
                goto error;
        }
        fprintf (priv->file , "%s\n" , ft_local_create->file_path);
        fflush (priv->file);


        /*Saving current create fop's context on to frame->local*/
        ft_local_create->op_ret = op_ret;
        ft_local_create->op_errno = op_errno;
        ft_local_create->fd = fd;
        ft_local_create->inode = inode;
        ft_local_create->stbuf = stbuf;
        ft_local_create->preparent = preparent;
        ft_local_create->postparent = postparent;


        /*Setting atime of the file to xattr*/
        dict = dict_new ();
        if (!dict) {
              goto error;
        }
        
        ret = dict_set_int64 (dict, "trusted.gf_atime", atime);
        if (ret) {
               gf_log (this->name , GF_LOG_ERROR , "Failed setting atime!");
               goto error;
        }

        STACK_WIND (frame, ft_setxattr_cbk,
                    FIRST_CHILD (this), FIRST_CHILD (this)->fops->fsetxattr, fd,
                    dict, 0, xdata);

        goto out;
error:
        STACK_UNWIND_STRICT (create, frame, op_ret, op_errno, fd, inode,
                        stbuf, preparent, postparent, xdata);
out:

        if (dict)
            dict_unref (dict); 

        if (ft_local_create) {
                GF_FREE (ft_local_create->file_path);
                GF_FREE (ft_local_create);
        }

        frame->local = NULL;

        return 0;
}

int32_t
ft_create(call_frame_t *frame, xlator_t *this,
            loc_t *loc, int32_t flags, mode_t mode,
            mode_t umask, fd_t *fd, dict_t *xdata) {

        int ret = -1;
        ft_local_create_t *ft_local_create = NULL;

        ft_local_create = GF_CALLOC (1, sizeof (ft_local_create_t), gf_ft_mt_local_create_t);
        if (!ft_local_create) {

               gf_log (this->name , GF_LOG_ERROR , "failed init of local of create fop!");
               goto error;

        }

        ret = gf_asprintf(&ft_local_create->file_path, loc->path);
        if (ret == -1) {
                 gf_log (this->name , GF_LOG_ERROR , "failed init of file path");
                 goto error;        
        }


        ret = 0;
        goto out;

error:
        if (ft_local_create)
                GF_FREE (ft_local_create->file_path);
        GF_FREE (ft_local_create);
out:
        frame->local = ft_local_create;

        STACK_WIND (frame, ft_create_cbk, FIRST_CHILD (this),
                    FIRST_CHILD (this)->fops->create,
                    loc, flags, mode, umask, fd, xdata);
        return 0;
}

int32_t
init (xlator_t *this)
{
        ft_private_t *priv = NULL;

        gf_log (this->name , GF_LOG_ERROR ,
                "\n---------------\nIn Init\n---------------\n");

        if (!this->children || this->children->next) {
                gf_log (this->name , GF_LOG_ERROR ,
                        "FATAL: file-tracker should have exactly one child");
                return -1;
        }

        if (!this->parents) {
                gf_log (this->name , GF_LOG_WARNING ,
                        "dangling volume. check volfile ");
        }

        priv =  GF_CALLOC (1, sizeof (ft_private_t), gf_ft_mt_private_t);
        if (!priv)
                return -1;

        FILE *log_fptr = fopen ("/file_track_log.txt" , "a");

        priv->file = log_fptr;
        this->private = priv;

        gf_log (this->name , GF_LOG_DEBUG , "file-tracker xlator loaded");
        return 0;
}


int32_t
mem_acct_init (xlator_t *this)
{
        int     ret = -1;

        GF_VALIDATE_OR_GOTO ("ctr", this, out);

        ret = xlator_mem_acct_init (this, gf_ft_mt_end + 1);

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
        ft_private_t *priv = NULL;

        priv = this->private ;

        gf_log (this->name, GF_LOG_ERROR ,
                      "\n\n------------\nFile Closed\n--------------\n\n");

        if (!priv)
                return;
        fclose (priv->file);
        
        this->private = NULL;
        GF_FREE (priv);

        return;
}

struct xlator_fops fops = {
        .create      = ft_create,
        .setattr     = ft_setattr,
};

struct xlator_cbks cbks;

struct volume_options options[] = {
        { .key  = {NULL} },
};
