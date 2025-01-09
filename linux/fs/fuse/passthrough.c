// SPDX-License-Identifier: GPL-2.0
/*
 * FUSE passthrough to backing file.
 *
 * Copyright (c) 2023 CTERA Networks.
 */

#include "fuse_i.h"

#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/backing-file.h>
#include <linux/splice.h>
#include <linux/pagemap.h>
#include <linux/workqueue.h>

static struct workqueue_struct *fuse_passthrough_pages_io_wq;

static void fuse_file_accessed(struct file *file)
{
	struct inode *inode = file_inode(file);

	fuse_invalidate_atime(inode);
}

static void fuse_file_modified(struct file *file)
{
	struct inode *inode = file_inode(file);

	fuse_invalidate_attr_mask(inode, FUSE_STATX_MODSIZE);
}

ssize_t fuse_passthrough_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	struct fuse_file *ff = file->private_data;
	struct file *backing_file = fuse_file_passthrough(ff);
	size_t count = iov_iter_count(iter);
	ssize_t ret;
	struct backing_file_ctx ctx = {
		.cred = ff->cred,
		.user_file = file,
		.accessed = fuse_file_accessed,
	};


	pr_debug("%s: backing_file=0x%p, pos=%lld, len=%zu\n", __func__,
		 backing_file, iocb->ki_pos, count);

	if (!count)
		return 0;

	ret = backing_file_read_iter(backing_file, iter, iocb, iocb->ki_flags,
				     &ctx);

	return ret;
}

ssize_t fuse_passthrough_write_iter(struct kiocb *iocb,
				    struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	struct fuse_file *ff = file->private_data;
	struct file *backing_file = fuse_file_passthrough(ff);
	size_t count = iov_iter_count(iter);
	ssize_t ret;
	struct backing_file_ctx ctx = {
		.cred = ff->cred,
		.user_file = file,
		.end_write = fuse_file_modified,
	};

	pr_debug("%s: backing_file=0x%p, pos=%lld, len=%zu\n", __func__,
		 backing_file, iocb->ki_pos, count);

	if (!count)
		return 0;

	inode_lock(inode);
	ret = backing_file_write_iter(backing_file, iter, iocb, iocb->ki_flags,
				      &ctx);
	inode_unlock(inode);

	return ret;
}

ssize_t fuse_passthrough_splice_read(struct file *in, loff_t *ppos,
				     struct pipe_inode_info *pipe,
				     size_t len, unsigned int flags)
{
	struct fuse_file *ff = in->private_data;
	struct file *backing_file = fuse_file_passthrough(ff);
	struct backing_file_ctx ctx = {
		.cred = ff->cred,
		.user_file = in,
		.accessed = fuse_file_accessed,
	};

	pr_debug("%s: backing_file=0x%p, pos=%lld, len=%zu, flags=0x%x\n", __func__,
		 backing_file, ppos ? *ppos : 0, len, flags);

	return backing_file_splice_read(backing_file, ppos, pipe, len, flags,
					&ctx);
}

ssize_t fuse_passthrough_splice_write(struct pipe_inode_info *pipe,
				      struct file *out, loff_t *ppos,
				      size_t len, unsigned int flags)
{
	struct fuse_file *ff = out->private_data;
	struct file *backing_file = fuse_file_passthrough(ff);
	struct inode *inode = file_inode(out);
	ssize_t ret;
	struct backing_file_ctx ctx = {
		.cred = ff->cred,
		.user_file = out,
		.end_write = fuse_file_modified,
	};

	pr_debug("%s: backing_file=0x%p, pos=%lld, len=%zu, flags=0x%x\n", __func__,
		 backing_file, ppos ? *ppos : 0, len, flags);

	inode_lock(inode);
	ret = backing_file_splice_write(pipe, backing_file, ppos, len, flags,
					&ctx);
	inode_unlock(inode);

	return ret;
}

ssize_t fuse_passthrough_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct fuse_file *ff = file->private_data;
	struct file *backing_file = fuse_file_passthrough(ff);
	struct backing_file_ctx ctx = {
		.cred = ff->cred,
		.user_file = file,
		.accessed = fuse_file_accessed,
	};

	pr_debug("%s: backing_file=0x%p, start=%lu, end=%lu\n", __func__,
		 backing_file, vma->vm_start, vma->vm_end);

	return backing_file_mmap(backing_file, vma, &ctx);
}

struct fuse_backing *fuse_backing_get(struct fuse_backing *fb)
{
	if (fb && refcount_inc_not_zero(&fb->count))
		return fb;
	return NULL;
}

static void fuse_backing_free(struct fuse_backing *fb)
{
	pr_debug("%s: fb=0x%p\n", __func__, fb);

	if (fb->file)
		fput(fb->file);
	put_cred(fb->cred);
	kfree_rcu(fb, rcu);
}

void fuse_backing_put(struct fuse_backing *fb)
{
	if (fb && refcount_dec_and_test(&fb->count))
		fuse_backing_free(fb);
}

void fuse_backing_files_init(struct fuse_conn *fc)
{
	idr_init(&fc->backing_files_map);
}

static int fuse_backing_id_alloc(struct fuse_conn *fc, struct fuse_backing *fb)
{
	int id;

	idr_preload(GFP_KERNEL);
	spin_lock(&fc->lock);
	/* FIXME: xarray might be space inefficient */
	id = idr_alloc_cyclic(&fc->backing_files_map, fb, 1, 0, GFP_ATOMIC);
	spin_unlock(&fc->lock);
	idr_preload_end();

	WARN_ON_ONCE(id == 0);
	return id;
}

static struct fuse_backing *fuse_backing_id_remove(struct fuse_conn *fc,
						   int id)
{
	struct fuse_backing *fb;

	spin_lock(&fc->lock);
	fb = idr_remove(&fc->backing_files_map, id);
	spin_unlock(&fc->lock);

	return fb;
}

static int fuse_backing_id_free(int id, void *p, void *data)
{
	struct fuse_backing *fb = p;

	WARN_ON_ONCE(refcount_read(&fb->count) != 1);
	fuse_backing_free(fb);
	return 0;
}

void fuse_backing_files_free(struct fuse_conn *fc)
{
	idr_for_each(&fc->backing_files_map, fuse_backing_id_free, NULL);
	idr_destroy(&fc->backing_files_map);
}

int fuse_backing_open(struct fuse_conn *fc, struct fuse_backing_map *map)
{
	struct file *file;
	struct super_block *backing_sb;
	struct fuse_backing *fb = NULL;
	int res;

	pr_debug("%s: fd=%d flags=0x%x\n", __func__, map->fd, map->flags);

	/* TODO: relax CAP_SYS_ADMIN once backing files are visible to lsof */
	res = -EPERM;
	if (!fc->passthrough || !capable(CAP_SYS_ADMIN))
		goto out;

	res = -EINVAL;
	if (map->padding)
		goto out;

	file = fget(map->fd);
	res = -EBADF;
	if (!file)
		goto out;

	res = -EOPNOTSUPP;
	if (!file->f_op->read_iter || !file->f_op->write_iter)
		goto out_fput;

	backing_sb = file_inode(file)->i_sb;
	res = -ELOOP;
	if (backing_sb->s_stack_depth >= fc->max_stack_depth)
		goto out_fput;

	fb = kmalloc(sizeof(struct fuse_backing), GFP_KERNEL);
	res = -ENOMEM;
	if (!fb)
		goto out_fput;

	fb->file = file;
	fb->cred = prepare_creds();
	fb->flags = map->flags;
	refcount_set(&fb->count, 1);

	res = fuse_backing_id_alloc(fc, fb);
	if (res < 0) {
		fuse_backing_free(fb);
		fb = NULL;
	}

out:
	pr_debug("%s: fc=0x%p, fb=0x%p, ret=%i\n", __func__, fc, fb, res);

	return res;

out_fput:
	fput(file);
	goto out;
}

int fuse_backing_close(struct fuse_conn *fc, int backing_id)
{
	struct fuse_backing *fb = NULL;
	int err;

	pr_debug("%s: fc=0x%p, backing_id=%d\n", __func__, fc, backing_id);

	/* TODO: relax CAP_SYS_ADMIN once backing files are visible to lsof */
	err = -EPERM;
	if (!fc->passthrough || !capable(CAP_SYS_ADMIN))
		goto out;

	err = -EINVAL;
	if (backing_id <= 0)
		goto out;

	err = -ENOENT;
	fb = fuse_backing_id_remove(fc, backing_id);
	if (!fb)
		goto out;

	fuse_backing_put(fb);
	err = 0;
out:
	pr_debug("%s: fc=0x%p, fb=0x%p, err=%i\n", __func__, fc, fb, err);

	return err;
}

/*
 * Setup passthrough to a backing file.
 *
 * Returns an fb object with elevated refcount to be stored in fuse inode.
 */
struct fuse_backing *fuse_passthrough_open(struct file *file,
					   struct inode *inode,
					   int backing_id)
{
	struct fuse_file *ff = file->private_data;
	struct fuse_conn *fc = ff->fm->fc;
	struct fuse_backing *fb = NULL;
	struct file *backing_file;
	int err;

	err = -EINVAL;
	if (backing_id <= 0)
		goto out;

	rcu_read_lock();
	fb = idr_find(&fc->backing_files_map, backing_id);
	fb = fuse_backing_get(fb);
	rcu_read_unlock();

	err = -ENOENT;
	if (!fb)
		goto out;

	/* Allocate backing file per fuse file to store fuse path */
	backing_file = backing_file_open(&file->f_path, file->f_flags,
					 &fb->file->f_path, fb->cred);
	err = PTR_ERR(backing_file);
	if (IS_ERR(backing_file)) {
		fuse_backing_put(fb);
		goto out;
	}

	err = 0;
	ff->passthrough = backing_file;
	ff->cred = get_cred(fb->cred);
out:
	pr_debug("%s: fc=0x%p, backing_id=%d, fb=0x%p, backing_file=0x%p, err=%i\n", __func__,
		 fc, backing_id, fb, ff->passthrough, err);

	return err ? ERR_PTR(err) : fb;
}

void fuse_passthrough_release(struct fuse_file *ff, struct fuse_backing *fb)
{
	pr_debug("%s: fb=0x%p, ff=0x%p, backing_file=0x%p\n", __func__,
		 fb, ff, ff->passthrough);

	fput(ff->passthrough);
	ff->passthrough = NULL;
	put_cred(ff->cred);
	ff->cred = NULL;
}

bool fuse_to_backing_file(struct fuse_file *ff, unsigned long index)
{
	pr_debug("%s: ff=0x%p, index=%ld\n", __func__, ff, index);

	struct file *backing_file = fuse_file_passthrough(ff);
	const struct cred *cred = ff->cred;
	const struct cred *old_cred;
	loff_t hole_offset;

	if (!backing_file || !cred)
		return false;

	backing_file = get_file(backing_file);
	cred = get_cred(cred);

	old_cred = override_creds(cred);
	hole_offset = vfs_llseek(backing_file, (loff_t)index * PAGE_SIZE, SEEK_HOLE);
	revert_creds(old_cred);

	fput(backing_file);
	put_cred(cred);

	if (hole_offset >= ((loff_t)index + 1) * PAGE_SIZE)
		return true;

	return false;
}

void fuse_backing_span_iter_first(struct fuse_backing_span_iter *state,
				  struct fuse_file *ff,
				  unsigned long first_index,
				  unsigned long last_index)
{
	pr_debug("%s: state=0x%p, ff=0x%p, first_index=%ld, last_index=%ld\n", __func__, state, ff, first_index, last_index);

	struct file *backing_file = fuse_file_passthrough(ff);
	const struct cred *cred = ff->cred;

	memset(state, 0, sizeof(struct fuse_backing_span_iter));
	state->first_index = first_index;
	state->last_index = last_index;

	if (!backing_file || !cred) {
		state->err = -EINVAL;
		state->is_hole = 1;
		state->start_hole = first_index;
		state->last_hole = last_index;
		state->first_index = state->last_hole + 1;
		return;
	}

	state->file = get_file(backing_file);
	state->cred = get_cred(cred);

	fuse_backing_span_iter_next(state);
}

void fuse_backing_span_iter_next(struct fuse_backing_span_iter *state)
{
	pr_debug("%s: state=0x%p, first_index=%ld, last_index=%ld, err=%d\n", __func__, state, state->first_index, state->last_index, state->err);

	const struct cred *old_cred;
	loff_t hole_offset, used_offset;
	unsigned long hole_index, used_index;

	if (state->err || state->first_index > state->last_index) {
		state->is_hole = -1;
		return;
	}

	old_cred = override_creds(state->cred);
	hole_offset = vfs_llseek(state->file, (loff_t)state->first_index * PAGE_SIZE, SEEK_HOLE);
	revert_creds(old_cred);

	if (hole_offset < 0) {
		state->err = hole_offset;
		goto err_out;
	}

	hole_index = hole_offset / PAGE_SIZE;

	if (hole_index > state->first_index) {
		state->is_hole = 0;
		state->start_used = state->first_index;
		state->last_used = min(hole_index - 1, state->last_index);
		state->first_index = state->last_used + 1;
		return;
	}

	old_cred = override_creds(state->cred);
	used_offset = vfs_llseek(state->file, ((loff_t)hole_index + 1) * PAGE_SIZE, SEEK_DATA);
	revert_creds(old_cred);

	if (used_offset < 0) {
		state->err = used_offset;
		goto err_out;
	}

	used_index = used_offset / PAGE_SIZE;

	state->is_hole = 1;
	state->start_hole = state->first_index;
	state->last_hole = min((loff_t)used_index * PAGE_SIZE == used_offset ? used_index-1 : used_index, state->last_index);
	state->first_index = state->last_hole + 1;
	return;

err_out:
	state->is_hole = 1;
	state->start_hole = state->first_index;
	state->last_hole = state->last_index;
	state->first_index = state->last_hole + 1;
	return;
}

bool fuse_backing_span_iter_done(struct fuse_backing_span_iter *state)
{
	if (state->is_hole != -1)
		return false;

	if (state->file)
		fput(state->file);
	if (state->cred)
		put_cred(state->cred);

	return true;
}

struct fuse_passthrough_pages_io {
	struct kiocb iocb;
	struct iov_iter iter;
	struct bio_vec *bio;
	struct fuse_io_args *ia;
	struct work_struct work;
	struct file *backing_file;
	const struct cred *cred;
};

static void fuse_passthrough_pages_io_free(struct fuse_passthrough_pages_io *io)
{
	pr_debug("%s: io=0x%p free fuse_passthrough_pages_io\n", __func__, io);

	fput(io->backing_file);
	put_cred(io->cred);
	kfree(io->bio);
	kfree(io);
}

static void fuse_passthrough_pages_io_complete(struct fuse_passthrough_pages_io *io, long res)
{
	pr_debug("%s: io=0x%p, res=%ld\n", __func__, io, res);

	struct fuse_io_args *ia = io->ia;
	unsigned long size = res >= 0 ? res : 0;

	if (io->iocb.ki_flags & IOCB_WRITE) {
		pr_debug("%s: io=0x%p, res=%ld is write\n", __func__, io, res);

		ia->write.out.size = size;
	} else {
		pr_debug("%s: io=0x%p, res=%ld is read\n", __func__, io, res);

		ia->ap.args.out_args[0].size = size;
	}

	pr_debug("%s: ia=0x%p, ap=0x%p, end=0x%p\n", __func__, ia, &ia->ap, ia->ap.args.end);
	if (ia->ap.args.end) {
		pr_debug("%s: io=0x%p, res=%ld call ia->ap.args.end\n", __func__, io, res);

		ia->ap.args.end(ia->ff->fm, &ia->ap.args, res < 0 ? res : 0);
	}
}

static ssize_t fuse_passthrough_pages_io_rw(struct fuse_passthrough_pages_io *io)
{
	pr_debug("%s: io=0x%p, backing_file=0x%p\n", __func__, io, io->backing_file);

	const struct cred *old_cred;
	ssize_t ret;

	old_cred = override_creds(io->cred);
	if (io->iocb.ki_flags & IOCB_WRITE) {
		ret = vfs_iocb_iter_write(io->backing_file, &io->iocb, &io->iter);
	} else {
		ret = vfs_iocb_iter_read(io->backing_file, &io->iocb, &io->iter);
	}
	revert_creds(old_cred);

	pr_debug("%s: io=0x%p, backing_file=0x%p, vfs_iocb_iter_read/write return %ld\n", __func__, io, io->backing_file, ret);

	fuse_passthrough_pages_io_complete(io, ret);

	return ret;
}

static void fuse_passthrough_pages_aio_work(struct work_struct *work)
{
	pr_debug("%s: work=0x%p\n", __func__, work);

	struct fuse_passthrough_pages_io *io = container_of(work, struct fuse_passthrough_pages_io, work);

	fuse_passthrough_pages_io_rw(io);
	fuse_passthrough_pages_io_free(io);
}

static ssize_t fuse_passthrough_pages_io(struct fuse_io_args *ia, bool write, bool async)
{
	pr_debug("%s: ia=0x%p\n", __func__, ia);

	struct fuse_passthrough_pages_io *io;
	struct bio_vec *bio;
	struct fuse_args_pages *ap = &ia->ap;
	struct fuse_file *ff = ia->ff;
	struct file *backing_file = fuse_file_passthrough(ff);
	const struct cred *cred = ff->cred;
	ssize_t ret;
	int i;

	if (!ia->to_backing_file || !backing_file || !cred || ia->ap.num_pages <= 0)
		return -EINVAL;

	bio = kcalloc(ap->num_pages, sizeof(struct bio_vec), GFP_KERNEL);
	if (unlikely(!bio))
		return -ENOMEM;

	pr_debug("%s: ia=0x%p, num_pages=%d, offset=%lld, size=%d bvec_set_page\n", __func__, ia, ia->ap.num_pages, write ? ia->write.in.offset : ia->read.in.offset, write ? ia->write.in.size : ia->read.in.size);

	for (i = 0; i < ap->num_pages; i++) {
		bvec_set_page(&bio[i], ap->pages[i], ap->descs[i].length, ap->descs[i].offset);
	}

	io = kmalloc(sizeof(struct fuse_passthrough_pages_io), GFP_KERNEL);
	if (!io) {
		kfree(bio);
		return -ENOMEM;
	}

	io->bio = bio;
	io->ia = ia;
	io->backing_file = get_file(backing_file);
	io->cred = get_cred(cred);
	iov_iter_bvec(&io->iter, write ? ITER_SOURCE : ITER_DEST, bio, ap->num_pages, write ? ia->write.in.size : ia->read.in.size);
	init_sync_kiocb(&io->iocb, io->backing_file);
	io->iocb.ki_pos = write ? ia->write.in.offset : ia->read.in.offset;
	if (write) {
		io->iocb.ki_flags |= IOCB_WRITE;
	}

	if (async) {
		pr_debug("%s: ia=0x%p async\n", __func__, ia);

		INIT_WORK(&io->work, fuse_passthrough_pages_aio_work);
		queue_work(fuse_passthrough_pages_io_wq, &io->work);
		return 0;
	}

	ret = fuse_passthrough_pages_io_rw(io);
	fuse_passthrough_pages_io_free(io);

	return ret;
}

ssize_t fuse_passthrough_read_pages(struct fuse_io_args *ia, bool async)
{
	pr_debug("%s: ia=0x%p, async=%s\n", __func__, ia, async?"true":"false");

	return fuse_passthrough_pages_io(ia, false, async);
}

ssize_t fuse_passthrough_write_pages(struct fuse_io_args *ia, bool async)
{
	pr_debug("%s: ia=0x%p, async=%s\n", __func__, ia, async?"true":"false");

	return fuse_passthrough_pages_io(ia, true, async);
}

int __init fuse_passthrough_pages_io_init(void)
{
	fuse_passthrough_pages_io_wq = alloc_workqueue("fuse-passthrough-pages-io", 0, 0);

	if (!fuse_passthrough_pages_io_wq)
		return -ENOMEM;
	return 0;
}

void fuse_passthrough_pages_io_cleanup(void)
{
	flush_workqueue(fuse_passthrough_pages_io_wq);
	destroy_workqueue(fuse_passthrough_pages_io_wq);
}
