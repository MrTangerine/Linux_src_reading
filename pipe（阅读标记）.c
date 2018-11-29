/*
 *  linux/fs/pipe.c
 *
 *  Copyright (C) 1991, 1992, 1999  Linus Torvalds
 */

#include <linux/mm.h>
#include <linux/file.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/init.h>

#include <asm/uaccess.h>
#include <asm/ioctls.h>

/*
 * We use a start+len construction, which provides full use of the 
 * allocated memory.
 * -- Florian Coosmann (FGC)
 * 
 * Reads with count = 0 should always return 0.
 * -- Julian Bradfield 1999-06-07.
 */

/* Drop the inode semaphore and wait for a pipe event, atomically */
void pipe_wait(struct inode * inode)                                        //inode:VFS(virtual file system)的索引节点 用来存储档案及目录的基本信息的一种数据结构
{
	DECLARE_WAITQUEUE(wait, current);                                       //等待队列初始化
	current->state = TASK_INTERRUPTIBLE;                                    //如果状态被置为TASK_INTERRUPTIBLE ，则信号唤醒进程。即为伪唤醒（唤醒不是因为事件的发生），因此检查并处理信号。
	add_wait_queue(PIPE_WAIT(*inode), &wait);                               //把自己加入到等待队列中。该队列会在进程等待的条件满足时唤醒它。在其他地方写相关代码，在事件发生时，对等的队列执行wake_up()操作。
	up(PIPE_SEM(*inode));                                                   //信号量控制
	schedule();                                                             //检查condition是否为真，否则调用schedule()
	remove_wait_queue(PIPE_WAIT(*inode), &wait);                            //从等待队列中移除
	current->state = TASK_RUNNING;                                          //状态设为running
	down(PIPE_SEM(*inode));                                                 //信号量控制
}

static ssize_t
pipe_read(struct file *filp, char *buf, size_t count, loff_t *ppos)         //从管道中读取count个字节，loff_t *ppos为当前文件的偏移量 size_t:unsigned int
{
	struct inode *inode = filp->f_dentry->d_inode;                          //通过文件路径找到inode
	ssize_t size, read, ret;                                                //而ssize_t这个数据类型用来表示可以被执行读写操作的数据块的大小.它和size_t类似,但必需是signed
                                                                            //使用读文件描述符fd[0]作为参数，调用read()系统调用，内核将此调用指向pipe_read()函数
	/* Seeks are not allowed on pipes.  */
	ret = -ESPIPE;
	read = 0;
	if (ppos != &filp->f_pos)                                               //f_pos为读写位置
		goto out_nolock;

	/* Always return 0 on null read.  */
	ret = 0;
	if (count == 0)
		goto out_nolock;

	/* Get the pipe semaphore */
	ret = -ERESTARTSYS;
	if (down_interruptible(PIPE_SEM(*inode)))
		goto out_nolock;

	if (PIPE_EMPTY(*inode)) {                                                //若管道为空
do_more_read:
		ret = 0;
		if (!PIPE_WRITERS(*inode))                                           //如果没有写进程则退出
			goto out;

		ret = -EAGAIN;
		if (filp->f_flags & O_NONBLOCK)                                      //如果读管道的操作类型是非阻塞读，则检查管道是否上锁，若上锁则退出
			goto out;

		for (;;) {
			PIPE_WAITING_READERS(*inode)++;                                  //????????
			pipe_wait(inode);
			PIPE_WAITING_READERS(*inode)--;
			ret = -ERESTARTSYS;
			if (signal_pending(current))
				goto out;
			ret = 0;
			if (!PIPE_EMPTY(*inode))
				break;
			if (!PIPE_WRITERS(*inode))
				goto out;
		}
	}

	/* Read what data is available.  */                                                     //读进程
	ret = -EFAULT;
	while (count > 0 && (size = PIPE_LEN(*inode))) {                                        //长度大于零且管道长度大于零？
		char *pipebuf = PIPE_BASE(*inode) + PIPE_START(*inode);                             //计算出当前读取内存缓冲区的偏移量
		ssize_t chars = PIPE_MAX_RCHUNK(*inode);

		if (chars > count)
			chars = count;
		if (chars > size)
			chars = size;

		if (copy_to_user(buf, pipebuf, chars))                                              //按照读请求的字节数把管道缓冲区的内容拷贝到用户地址空间
			goto out;

		read += chars;
		PIPE_START(*inode) += chars;
		PIPE_START(*inode) &= (PIPE_SIZE - 1);
		PIPE_LEN(*inode) -= chars;
		count -= chars;
		buf += chars;
	}

	/* Cache behaviour optimization */
	if (!PIPE_LEN(*inode))
		PIPE_START(*inode) = 0;

	if (count && PIPE_WAITING_WRITERS(*inode) && !(filp->f_flags & O_NONBLOCK)) {               //如果是阻塞读，该管道为空或已加锁，说明有其他进程正在访问这个管道
		/*
		 * We know that we are going to sleep: signal
		 * writers synchronously that there is more
		 * room.
		 */
		wake_up_interruptible_sync(PIPE_WAIT(*inode));                                          //唤醒队列中睡眠的其他进程
		if (!PIPE_EMPTY(*inode))                                                                //如果此时管道不为空则证明发生错误
			BUG();
		goto do_more_read;                                                                      //继续进行do_more_read检查
	}
	/* Signal writers asynchronously that there is more room.  */
	wake_up_interruptible(PIPE_WAIT(*inode));                                                   //唤醒这个管道中的等待队列中睡眠的所有进程

	ret = read;
out:
	up(PIPE_SEM(*inode));
out_nolock:
	if (read)
		ret = read;
	return ret;                                                                                  //返回拷贝到用户地址空间的字节数
}

static ssize_t
pipe_write(struct file *filp, const char *buf, size_t count, loff_t *ppos)                       //调用情况同理
{
	struct inode *inode = filp->f_dentry->d_inode;
	ssize_t free, written, ret;

	/* Seeks are not allowed on pipes.  */
	ret = -ESPIPE;
	written = 0;
	if (ppos != &filp->f_pos)
		goto out_nolock;

	/* Null write succeeds.  */
	ret = 0;
	if (count == 0)
		goto out_nolock;

	ret = -ERESTARTSYS;
	if (down_interruptible(PIPE_SEM(*inode)))
		goto out_nolock;

	/* No readers yields SIGPIPE.  */                                                              //如果这个管道没有读进程的标志，就向当前进程发送sigpipe信号并返回-EIPIPE错误
	if (!PIPE_READERS(*inode))
		goto sigpipe;

	/* If count <= PIPE_BUF, we have to make it atomic.  */                                       //检查写入内容长度是否小于管道缓冲区长度
	free = (count <= PIPE_BUF ? count : 1);

	/* Wait, or check for, available space.  */
	if (filp->f_flags & O_NONBLOCK) {                                                             //是否为非阻塞 
		ret = -EAGAIN;
		if (PIPE_FREE(*inode) < free)                                                             //检查写入长度是否小于管道长度？
			goto out;
	} else {
		while (PIPE_FREE(*inode) < free) {
			PIPE_WAITING_WRITERS(*inode)++;                                                       //如果缓冲区没有足够的空间，并且这个管道已加锁，就把当前进程加入到管道的等待队列中
			pipe_wait(inode);                                                                     //并将其挂起，等待读进程从管道把数据读走为止
			PIPE_WAITING_WRITERS(*inode)--;
			ret = -ERESTARTSYS;
			if (signal_pending(current))
				goto out;

			if (!PIPE_READERS(*inode))
				goto sigpipe;
		}
	}

	/* Copy into available space.  */
	ret = -EFAULT;
	while (count > 0) {
		int space;
		char *pipebuf = PIPE_BASE(*inode) + PIPE_END(*inode);                           //计算出当前写入的偏移量
		ssize_t chars = PIPE_MAX_WCHUNK(*inode);

		if ((space = PIPE_FREE(*inode)) != 0) {
			if (chars > count)
				chars = count;
			if (chars > space)
				chars = space;

			if (copy_from_user(pipebuf, buf, chars))                                    //将请求写的字节数从用户空间拷贝到管道的内存缓冲区中
				goto out;

			written += chars;
			PIPE_LEN(*inode) += chars;
			count -= chars;
			buf += chars;
			space = PIPE_FREE(*inode);
			continue;                                                                   //如果一次没有写完，就继续重新写入
		}

		ret = written;
		if (filp->f_flags & O_NONBLOCK)
			break;

		do {                                                                            //个人认为 如果管道已被写入，强制把当前程序加入到管道的等待队列中并将其挂起，
			/*                                                                          //等待读进程从管道把数据读走为止
			 * Synchronous wake-up: it knows that this process
			 * is going to give up this CPU, so it doesnt have
			 * to do idle reschedules.
			 */
			wake_up_interruptible_sync(PIPE_WAIT(*inode));
			PIPE_WAITING_WRITERS(*inode)++;
			pipe_wait(inode);
			PIPE_WAITING_WRITERS(*inode)--;
			if (signal_pending(current))
				goto out;
			if (!PIPE_READERS(*inode))
				goto sigpipe;
		} while (!PIPE_FREE(*inode));
		ret = -EFAULT;
	}

	/* Signal readers asynchronously that there is more data.  */
	wake_up_interruptible(PIPE_WAIT(*inode));                                          //唤醒这个管道中的等待队列中睡眠的所有进程

	inode->i_ctime = inode->i_mtime = CURRENT_TIME;
	mark_inode_dirty(inode);

out:
	up(PIPE_SEM(*inode));
out_nolock:
	if (written)
		ret = written;
	return ret;

sigpipe:
	if (written)
		goto out;
	up(PIPE_SEM(*inode));
	send_sig(SIGPIPE, current, 0);
	return -EPIPE;
}

static loff_t
pipe_lseek(struct file *file, loff_t offset, int orig)
{
	return -ESPIPE;
}

static ssize_t
bad_pipe_r(struct file *filp, char *buf, size_t count, loff_t *ppos)
{
	return -EBADF;
}

static ssize_t
bad_pipe_w(struct file *filp, const char *buf, size_t count, loff_t *ppos)
{
	return -EBADF;
}

static int
pipe_ioctl(struct inode *pino, struct file *filp,
	   unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
		case FIONREAD:
			return put_user(PIPE_LEN(*pino), (int *)arg);
		default:
			return -EINVAL;
	}
}

/* No kernel lock held - fine */
static unsigned int
pipe_poll(struct file *filp, poll_table *wait)
{
	unsigned int mask;
	struct inode *inode = filp->f_dentry->d_inode;

	poll_wait(filp, PIPE_WAIT(*inode), wait);

	/* Reading only -- no need for acquiring the semaphore.  */
	mask = POLLIN | POLLRDNORM;
	if (PIPE_EMPTY(*inode))
		mask = POLLOUT | POLLWRNORM;
	if (!PIPE_WRITERS(*inode) && filp->f_version != PIPE_WCOUNTER(*inode))
		mask |= POLLHUP;
	if (!PIPE_READERS(*inode))
		mask |= POLLERR;

	return mask;
}

/* FIXME: most Unices do not set POLLERR for fifos */
#define fifo_poll pipe_poll

static int
pipe_release(struct inode *inode, int decr, int decw)                                         //释放管道
{
	down(PIPE_SEM(*inode));
	PIPE_READERS(*inode) -= decr;
	PIPE_WRITERS(*inode) -= decw;
	if (!PIPE_READERS(*inode) && !PIPE_WRITERS(*inode)) {
		struct pipe_inode_info *info = inode->i_pipe;
		inode->i_pipe = NULL;
		free_page((unsigned long) info->base);
		kfree(info);
	} else {
		wake_up_interruptible(PIPE_WAIT(*inode));
	}
	up(PIPE_SEM(*inode));

	return 0;
}

static int
pipe_read_release(struct inode *inode, struct file *filp)
{
	return pipe_release(inode, 1, 0);
}

static int
pipe_write_release(struct inode *inode, struct file *filp)
{
	return pipe_release(inode, 0, 1);
}

static int
pipe_rdwr_release(struct inode *inode, struct file *filp)
{
	int decr, decw;

	decr = (filp->f_mode & FMODE_READ) != 0;
	decw = (filp->f_mode & FMODE_WRITE) != 0;
	return pipe_release(inode, decr, decw);
}

static int
pipe_read_open(struct inode *inode, struct file *filp)
{
	/* We could have perhaps used atomic_t, but this and friends
	   below are the only places.  So it doesn't seem worthwhile.  */
	down(PIPE_SEM(*inode));
	PIPE_READERS(*inode)++;
	up(PIPE_SEM(*inode));

	return 0;
}

static int
pipe_write_open(struct inode *inode, struct file *filp)
{
	down(PIPE_SEM(*inode));
	PIPE_WRITERS(*inode)++;
	up(PIPE_SEM(*inode));

	return 0;
}

static int
pipe_rdwr_open(struct inode *inode, struct file *filp)
{
	down(PIPE_SEM(*inode));
	if (filp->f_mode & FMODE_READ)
		PIPE_READERS(*inode)++;
	if (filp->f_mode & FMODE_WRITE)
		PIPE_WRITERS(*inode)++;
	up(PIPE_SEM(*inode));

	return 0;
}

/*
 * The file_operations structs are not static because they
 * are also used in linux/fs/fifo.c to do operations on FIFOs.
 */
struct file_operations read_fifo_fops = {                                        //定义结构体方便在在不同文件和包中引用
	llseek:		pipe_lseek,
	read:		pipe_read,
	write:		bad_pipe_w,
	poll:		fifo_poll,
	ioctl:		pipe_ioctl,
	open:		pipe_read_open,
	release:	pipe_read_release,
};

struct file_operations write_fifo_fops = {
	llseek:		pipe_lseek,
	read:		bad_pipe_r,
	write:		pipe_write,
	poll:		fifo_poll,
	ioctl:		pipe_ioctl,
	open:		pipe_write_open,
	release:	pipe_write_release,
};

struct file_operations rdwr_fifo_fops = {
	llseek:		pipe_lseek,
	read:		pipe_read,
	write:		pipe_write,
	poll:		fifo_poll,
	ioctl:		pipe_ioctl,
	open:		pipe_rdwr_open,
	release:	pipe_rdwr_release,
};

struct file_operations read_pipe_fops = {
	llseek:		pipe_lseek,
	read:		pipe_read,
	write:		bad_pipe_w,
	poll:		pipe_poll,
	ioctl:		pipe_ioctl,
	open:		pipe_read_open,
	release:	pipe_read_release,
};

struct file_operations write_pipe_fops = {
	llseek:		pipe_lseek,
	read:		bad_pipe_r,
	write:		pipe_write,
	poll:		pipe_poll,
	ioctl:		pipe_ioctl,
	open:		pipe_write_open,
	release:	pipe_write_release,
};

struct file_operations rdwr_pipe_fops = {
	llseek:		pipe_lseek,
	read:		pipe_read,
	write:		pipe_write,
	poll:		pipe_poll,
	ioctl:		pipe_ioctl,
	open:		pipe_rdwr_open,
	release:	pipe_rdwr_release,
};

struct inode* pipe_new(struct inode* inode)
{
	unsigned long page;

	page = __get_free_page(GFP_USER);
	if (!page)
		return NULL;

	inode->i_pipe = kmalloc(sizeof(struct pipe_inode_info), GFP_KERNEL);
	if (!inode->i_pipe)
		goto fail_page;

	init_waitqueue_head(PIPE_WAIT(*inode));
	PIPE_BASE(*inode) = (char*) page;
	PIPE_START(*inode) = PIPE_LEN(*inode) = 0;
	PIPE_READERS(*inode) = PIPE_WRITERS(*inode) = 0;
	PIPE_WAITING_READERS(*inode) = PIPE_WAITING_WRITERS(*inode) = 0;
	PIPE_RCOUNTER(*inode) = PIPE_WCOUNTER(*inode) = 1;

	return inode;
fail_page:
	free_page(page);
	return NULL;
}

static struct vfsmount *pipe_mnt;
static int pipefs_delete_dentry(struct dentry *dentry)
{
	return 1;
}
static struct dentry_operations pipefs_dentry_operations = {
	d_delete:	pipefs_delete_dentry,
};

static struct inode * get_pipe_inode(void)
{
	struct inode *inode = new_inode(pipe_mnt->mnt_sb);

	if (!inode)
		goto fail_inode;

	if(!pipe_new(inode))
		goto fail_iput;
	PIPE_READERS(*inode) = PIPE_WRITERS(*inode) = 1;
	inode->i_fop = &rdwr_pipe_fops;

	/*
	 * Mark the inode dirty from the very beginning,
	 * that way it will never be moved to the dirty
	 * list because "mark_inode_dirty()" will think
	 * that it already _is_ on the dirty list.
	 */
	inode->i_state = I_DIRTY;
	inode->i_mode = S_IFIFO | S_IRUSR | S_IWUSR;
	inode->i_uid = current->fsuid;
	inode->i_gid = current->fsgid;
	inode->i_atime = inode->i_mtime = inode->i_ctime = CURRENT_TIME;
	inode->i_blksize = PAGE_SIZE;
	return inode;

fail_iput:
	iput(inode);
fail_inode:
	return NULL;
}

int do_pipe(int *fd)                                //pipe()通过sys_pipe内核函数间接调用do_pipe()函数
{
	struct qstr this;
	char name[32];
	struct dentry *dentry;
	struct inode * inode;
	struct file *f1, *f2;
	int error;
	int i,j;

	error = -ENFILE;
	f1 = get_empty_filp();                          //一次为读通道分配一个文件表项
	if (!f1)
		goto no_files;

	f2 = get_empty_filp();                          //一次为写通道分配一个文件表项
	if (!f2)
		goto close_f1;

	inode = get_pipe_inode();                       //在用户空间分配一个用做管道的内存缓冲区页帧
	if (!inode)                                     //分配一个大小为struct pipe_inode_info的内存空间
		goto close_f12;                             //

	error = get_unused_fd();
	if (error < 0)
		goto close_f12_inode;
	i = error;

	error = get_unused_fd();
	if (error < 0)
		goto close_f12_inode_i;
	j = error;

	error = -ENOMEM;
	sprintf(name, "[%lu]", inode->i_ino);
	this.name = name;
	this.len = strlen(name);
	this.hash = inode->i_ino; /* will go */
	dentry = d_alloc(pipe_mnt->mnt_sb->s_root, &this);          //申请一个目录项对象，把两个文件对象和两个索引节点对象链接到一起
	if (!dentry)                                               
		goto close_f12_inode_i_j;
	dentry->d_op = &pipefs_dentry_operations;
	d_add(dentry, inode);
	f1->f_vfsmnt = f2->f_vfsmnt = mntget(mntget(pipe_mnt));
	f1->f_dentry = f2->f_dentry = dget(dentry);

	/* read file */                                             //对一开始分配的两个文件对象进行初始化
	f1->f_pos = f2->f_pos = 0;
	f1->f_flags = O_RDONLY;
	f1->f_op = &read_pipe_fops;
	f1->f_mode = 1;
	f1->f_version = 0;

	/* write file */
	f2->f_flags = O_WRONLY;
	f2->f_op = &write_pipe_fops;
	f2->f_mode = 2;
	f2->f_version = 0;

	fd_install(i, f1);
	fd_install(j, f2);
	fd[0] = i;                                             //返回两个struct file的文件描述符，一个用于读一个用于写
	fd[1] = j;                                             //其中的f_inode域均指向同一个inode其中就包含了pipe_inode_info结果
	return 0;                                              //此结构中有指向用于通信的内存缓冲区的地址

close_f12_inode_i_j:
	put_unused_fd(j);
close_f12_inode_i:
	put_unused_fd(i);
close_f12_inode:
	free_page((unsigned long) PIPE_BASE(*inode));
	kfree(inode->i_pipe);
	inode->i_pipe = NULL;
	iput(inode);
close_f12:
	put_filp(f2);
close_f1:
	put_filp(f1);
no_files:
	return error;	
}

/*
 * pipefs should _never_ be mounted by userland - too much of security hassle,
 * no real gain from having the whole whorehouse mounted. So we don't need
 * any operations on the root directory. However, we need a non-trivial
 * d_name - pipe: will go nicely and kill the special-casing in procfs.
 */
static int pipefs_statfs(struct super_block *sb, struct statfs *buf)
{
	buf->f_type = PIPEFS_MAGIC;
	buf->f_bsize = 1024;
	buf->f_namelen = 255;
	return 0;
}

static struct super_operations pipefs_ops = {
	statfs:		pipefs_statfs,
};

static struct super_block * pipefs_read_super(struct super_block *sb, void *data, int silent)
{
	struct inode *root = new_inode(sb);
	if (!root)
		return NULL;
	root->i_mode = S_IFDIR | S_IRUSR | S_IWUSR;
	root->i_uid = root->i_gid = 0;
	root->i_atime = root->i_mtime = root->i_ctime = CURRENT_TIME;
	sb->s_blocksize = 1024;
	sb->s_blocksize_bits = 10;
	sb->s_magic = PIPEFS_MAGIC;
	sb->s_op	= &pipefs_ops;
	sb->s_root = d_alloc(NULL, &(const struct qstr) { "pipe:", 5, 0 });
	if (!sb->s_root) {
		iput(root);
		return NULL;
	}
	sb->s_root->d_sb = sb;
	sb->s_root->d_parent = sb->s_root;
	d_instantiate(sb->s_root, root);
	return sb;
}

static DECLARE_FSTYPE(pipe_fs_type, "pipefs", pipefs_read_super, FS_NOMOUNT);

static int __init init_pipe_fs(void)
{
	int err = register_filesystem(&pipe_fs_type);
	if (!err) {
		pipe_mnt = kern_mount(&pipe_fs_type);
		err = PTR_ERR(pipe_mnt);
		if (IS_ERR(pipe_mnt))
			unregister_filesystem(&pipe_fs_type);
		else
			err = 0;
	}
	return err;
}

static void __exit exit_pipe_fs(void)
{
	unregister_filesystem(&pipe_fs_type);
	mntput(pipe_mnt);
}

module_init(init_pipe_fs)
module_exit(exit_pipe_fs)
