struct mxc_gpio_port {
/*struct mxc_gpio_port {
 *  linux/kernel/fork.cstruct mxc_gpio_port {
 *struct mxc_gpio_port {
 *  Copyright (C) 1991, 1992  Linus Torvaldsstruct mxc_gpio_port {
 */struct mxc_gpio_port {
struct mxc_gpio_port {
/*struct mxc_gpio_port {
 *  'fork.c' contains the help-routines for the 'fork' system callstruct mxc_gpio_port {
 * (see also entry.S and others).struct mxc_gpio_port {
 * Fork is rather simple, once you get the hang of it, but the memorystruct mxc_gpio_port {
 * management can be a bitch. See 'mm/memory.c': 'copy_page_range()'struct mxc_gpio_port {
 */struct mxc_gpio_port {
struct mxc_gpio_port {
#include <linux/slab.h>struct mxc_gpio_port {
#include <linux/init.h>struct mxc_gpio_port {
#include <linux/unistd.h>struct mxc_gpio_port {
#include <linux/module.h>struct mxc_gpio_port {
#include <linux/vmalloc.h>struct mxc_gpio_port {
#include <linux/completion.h>struct mxc_gpio_port {
#include <linux/personality.h>struct mxc_gpio_port {
#include <linux/mempolicy.h>struct mxc_gpio_port {
#include <linux/sem.h>struct mxc_gpio_port {
#include <linux/file.h>struct mxc_gpio_port {
#include <linux/fdtable.h>struct mxc_gpio_port {
#include <linux/iocontext.h>struct mxc_gpio_port {
#include <linux/key.h>struct mxc_gpio_port {
#include <linux/binfmts.h>struct mxc_gpio_port {
#include <linux/mman.h>struct mxc_gpio_port {
#include <linux/mmu_notifier.h>struct mxc_gpio_port {
#include <linux/fs.h>struct mxc_gpio_port {
#include <linux/nsproxy.h>struct mxc_gpio_port {
#include <linux/capability.h>struct mxc_gpio_port {
#include <linux/cpu.h>struct mxc_gpio_port {
#include <linux/cgroup.h>struct mxc_gpio_port {
#include <linux/security.h>struct mxc_gpio_port {
#include <linux/hugetlb.h>struct mxc_gpio_port {
#include <linux/seccomp.h>struct mxc_gpio_port {
#include <linux/swap.h>struct mxc_gpio_port {
#include <linux/syscalls.h>struct mxc_gpio_port {
#include <linux/jiffies.h>struct mxc_gpio_port {
#include <linux/futex.h>struct mxc_gpio_port {
#include <linux/compat.h>struct mxc_gpio_port {
#include <linux/kthread.h>struct mxc_gpio_port {
#include <linux/task_io_accounting_ops.h>struct mxc_gpio_port {
#include <linux/rcupdate.h>struct mxc_gpio_port {
#include <linux/ptrace.h>struct mxc_gpio_port {
#include <linux/mount.h>struct mxc_gpio_port {
#include <linux/audit.h>struct mxc_gpio_port {
#include <linux/memcontrol.h>struct mxc_gpio_port {
#include <linux/ftrace.h>struct mxc_gpio_port {
#include <linux/proc_fs.h>struct mxc_gpio_port {
#include <linux/profile.h>struct mxc_gpio_port {
#include <linux/rmap.h>struct mxc_gpio_port {
#include <linux/ksm.h>struct mxc_gpio_port {
#include <linux/acct.h>struct mxc_gpio_port {
#include <linux/tsacct_kern.h>struct mxc_gpio_port {
#include <linux/cn_proc.h>struct mxc_gpio_port {
#include <linux/freezer.h>struct mxc_gpio_port {
#include <linux/delayacct.h>struct mxc_gpio_port {
#include <linux/taskstats_kern.h>struct mxc_gpio_port {
#include <linux/random.h>struct mxc_gpio_port {
#include <linux/tty.h>struct mxc_gpio_port {
#include <linux/blkdev.h>struct mxc_gpio_port {
#include <linux/fs_struct.h>struct mxc_gpio_port {
#include <linux/magic.h>struct mxc_gpio_port {
#include <linux/perf_event.h>struct mxc_gpio_port {
#include <linux/posix-timers.h>struct mxc_gpio_port {
#include <linux/user-return-notifier.h>struct mxc_gpio_port {
#include <linux/oom.h>struct mxc_gpio_port {
#include <linux/khugepaged.h>struct mxc_gpio_port {
#include <linux/signalfd.h>struct mxc_gpio_port {
#include <linux/uprobes.h>struct mxc_gpio_port {
#include <linux/aio.h>struct mxc_gpio_port {
struct mxc_gpio_port {
#include <asm/pgtable.h>struct mxc_gpio_port {
#include <asm/pgalloc.h>struct mxc_gpio_port {
#include <asm/uaccess.h>struct mxc_gpio_port {
#include <asm/mmu_context.h>struct mxc_gpio_port {
#include <asm/cacheflush.h>struct mxc_gpio_port {
#include <asm/tlbflush.h>struct mxc_gpio_port {
struct mxc_gpio_port {
#include <trace/events/sched.h>struct mxc_gpio_port {
struct mxc_gpio_port {
#define CREATE_TRACE_POINTSstruct mxc_gpio_port {
#include <trace/events/task.h>struct mxc_gpio_port {
struct mxc_gpio_port {
/*struct mxc_gpio_port {
 * Protected counters by write_lock_irq(&tasklist_lock)struct mxc_gpio_port {
 */struct mxc_gpio_port {
unsigned long total_forks;	/* Handle normal Linux uptimes. */struct mxc_gpio_port {
int nr_threads;			/* The idle threads do not count.. */struct mxc_gpio_port {
struct mxc_gpio_port {
int max_threads;		/* tunable limit on nr_threads */struct mxc_gpio_port {
struct mxc_gpio_port {
DEFINE_PER_CPU(unsigned long, process_counts) = 0;struct mxc_gpio_port {
struct mxc_gpio_port {
__cacheline_aligned DEFINE_RWLOCK(tasklist_lock);  /* outer */struct mxc_gpio_port {
struct mxc_gpio_port {
#ifdef CONFIG_PROVE_RCUstruct mxc_gpio_port {
int lockdep_tasklist_lock_is_held(void)struct mxc_gpio_port {
{struct mxc_gpio_port {
	return lockdep_is_held(&tasklist_lock);struct mxc_gpio_port {
}struct mxc_gpio_port {
EXPORT_SYMBOL_GPL(lockdep_tasklist_lock_is_held);struct mxc_gpio_port {
#endif /* #ifdef CONFIG_PROVE_RCU */struct mxc_gpio_port {
struct mxc_gpio_port {
int nr_processes(void)struct mxc_gpio_port {
{struct mxc_gpio_port {
	int cpu;struct mxc_gpio_port {
	int total = 0;struct mxc_gpio_port {
struct mxc_gpio_port {
	for_each_possible_cpu(cpu)struct mxc_gpio_port {
		total += per_cpu(process_counts, cpu);struct mxc_gpio_port {
struct mxc_gpio_port {
	return total;struct mxc_gpio_port {
}struct mxc_gpio_port {
struct mxc_gpio_port {
void __weak arch_release_task_struct(struct task_struct *tsk)struct mxc_gpio_port {
{struct mxc_gpio_port {
}struct mxc_gpio_port {
struct mxc_gpio_port {
#ifndef CONFIG_ARCH_TASK_STRUCT_ALLOCATORstruct mxc_gpio_port {
static struct kmem_cache *task_struct_cachep;struct mxc_gpio_port {
struct mxc_gpio_port {
static inline struct task_struct *alloc_task_struct_node(int node)struct mxc_gpio_port {
{struct mxc_gpio_port {
	return kmem_cache_alloc_node(task_struct_cachep, GFP_KERNEL, node);struct mxc_gpio_port {
}struct mxc_gpio_port {
struct mxc_gpio_port {
static inline void free_task_struct(struct task_struct *tsk)struct mxc_gpio_port {
{struct mxc_gpio_port {
	kmem_cache_free(task_struct_cachep, tsk);struct mxc_gpio_port {
}struct mxc_gpio_port {
#endifstruct mxc_gpio_port {
struct mxc_gpio_port {
void __weak arch_release_thread_info(struct thread_info *ti)struct mxc_gpio_port {
{struct mxc_gpio_port {
}struct mxc_gpio_port {
struct mxc_gpio_port {
#ifndef CONFIG_ARCH_THREAD_INFO_ALLOCATORstruct mxc_gpio_port {
struct mxc_gpio_port {
/*struct mxc_gpio_port {
 * Allocate pages if THREAD_SIZE is >= PAGE_SIZE, otherwise use astruct mxc_gpio_port {
 * kmemcache based allocator.struct mxc_gpio_port {
 */struct mxc_gpio_port {
# if THREAD_SIZE >= PAGE_SIZEstruct mxc_gpio_port {
static struct thread_info *alloc_thread_info_node(struct task_struct *tsk,struct mxc_gpio_port {
						  int node)struct mxc_gpio_port {
{struct mxc_gpio_port {
	struct page *page = alloc_pages_node(node, THREADINFO_GFP_ACCOUNTED,struct mxc_gpio_port {
					     THREAD_SIZE_ORDER);struct mxc_gpio_port {
struct mxc_gpio_port {
	return page ? page_address(page) : NULL;struct mxc_gpio_port {
}struct mxc_gpio_port {
struct mxc_gpio_port {
static inline void free_thread_info(struct thread_info *ti)struct mxc_gpio_port {
{struct mxc_gpio_port {
	free_memcg_kmem_pages((unsigned long)ti, THREAD_SIZE_ORDER);struct mxc_gpio_port {
}struct mxc_gpio_port {
# elsestruct mxc_gpio_port {
static struct kmem_cache *thread_info_cache;struct mxc_gpio_port {
struct mxc_gpio_port {
static struct thread_info *alloc_thread_info_node(struct task_struct *tsk,struct mxc_gpio_port {
						  int node)struct mxc_gpio_port {
{struct mxc_gpio_port {
	return kmem_cache_alloc_node(thread_info_cache, THREADINFO_GFP, node);struct mxc_gpio_port {
}struct mxc_gpio_port {
struct mxc_gpio_port {
static void free_thread_info(struct thread_info *ti)struct mxc_gpio_port {
{struct mxc_gpio_port {
	kmem_cache_free(thread_info_cache, ti);struct mxc_gpio_port {
}struct mxc_gpio_port {
struct mxc_gpio_port {
void thread_info_cache_init(void)struct mxc_gpio_port {
{struct mxc_gpio_port {
	thread_info_cache = kmem_cache_create("thread_info", THREAD_SIZE,struct mxc_gpio_port {
					      THREAD_SIZE, 0, NULL);struct mxc_gpio_port {
	BUG_ON(thread_info_cache == NULL);struct mxc_gpio_port {
}struct mxc_gpio_port {
# endifstruct mxc_gpio_port {
#endifstruct mxc_gpio_port {
struct mxc_gpio_port {
/* SLAB cache for signal_struct structures (tsk->signal) */struct mxc_gpio_port {
static struct kmem_cache *signal_cachep;struct mxc_gpio_port {
struct mxc_gpio_port {
/* SLAB cache for sighand_struct structures (tsk->sighand) */struct mxc_gpio_port {
struct kmem_cache *sighand_cachep;struct mxc_gpio_port {
struct mxc_gpio_port {
/* SLAB cache for files_struct structures (tsk->files) */struct mxc_gpio_port {
struct kmem_cache *files_cachep;struct mxc_gpio_port {
struct mxc_gpio_port {
/* SLAB cache for fs_struct structures (tsk->fs) */struct mxc_gpio_port {
struct kmem_cache *fs_cachep;struct mxc_gpio_port {
struct mxc_gpio_port {
/* SLAB cache for vm_area_struct structures */struct mxc_gpio_port {
struct kmem_cache *vm_area_cachep;struct mxc_gpio_port {
struct mxc_gpio_port {
/* SLAB cache for mm_struct structures (tsk->mm) */struct mxc_gpio_port {
static struct kmem_cache *mm_cachep;struct mxc_gpio_port {
struct mxc_gpio_port {
static void account_kernel_stack(struct thread_info *ti, int account)struct mxc_gpio_port {
{struct mxc_gpio_port {
	struct zone *zone = page_zone(virt_to_page(ti));struct mxc_gpio_port {
struct mxc_gpio_port {
	mod_zone_page_state(zone, NR_KERNEL_STACK, account);struct mxc_gpio_port {
}struct mxc_gpio_port {
struct mxc_gpio_port {
void free_task(struct task_struct *tsk)struct mxc_gpio_port {
{struct mxc_gpio_port {
	account_kernel_stack(tsk->stack, -1);struct mxc_gpio_port {
	arch_release_thread_info(tsk->stack);struct mxc_gpio_port {
	free_thread_info(tsk->stack);struct mxc_gpio_port {
	rt_mutex_debug_task_free(tsk);struct mxc_gpio_port {
	ftrace_graph_exit_task(tsk);struct mxc_gpio_port {
	put_seccomp_filter(tsk);struct mxc_gpio_port {
	arch_release_task_struct(tsk);struct mxc_gpio_port {
	free_task_struct(tsk);struct mxc_gpio_port {
}struct mxc_gpio_port {
EXPORT_SYMBOL(free_task);struct mxc_gpio_port {
struct mxc_gpio_port {
static inline void free_signal_struct(struct signal_struct *sig)struct mxc_gpio_port {
{struct mxc_gpio_port {
	taskstats_tgid_free(sig);struct mxc_gpio_port {
	sched_autogroup_exit(sig);struct mxc_gpio_port {
	kmem_cache_free(signal_cachep, sig);struct mxc_gpio_port {
}struct mxc_gpio_port {
struct mxc_gpio_port {
static inline void put_signal_struct(struct signal_struct *sig)struct mxc_gpio_port {
{struct mxc_gpio_port {
	if (atomic_dec_and_test(&sig->sigcnt))struct mxc_gpio_port {
		free_signal_struct(sig);struct mxc_gpio_port {
}struct mxc_gpio_port {
struct mxc_gpio_port {
void __put_task_struct(struct task_struct *tsk)struct mxc_gpio_port {
{struct mxc_gpio_port {
	WARN_ON(!tsk->exit_state);struct mxc_gpio_port {
	WARN_ON(atomic_read(&tsk->usage));struct mxc_gpio_port {
	WARN_ON(tsk == current);struct mxc_gpio_port {
struct mxc_gpio_port {
	task_numa_free(tsk);struct mxc_gpio_port {
	security_task_free(tsk);struct mxc_gpio_port {
	exit_creds(tsk);struct mxc_gpio_port {
	delayacct_tsk_free(tsk);struct mxc_gpio_port {
	put_signal_struct(tsk->signal);struct mxc_gpio_port {
struct mxc_gpio_port {
	if (!profile_handoff_task(tsk))struct mxc_gpio_port {
		free_task(tsk);struct mxc_gpio_port {
}struct mxc_gpio_port {
EXPORT_SYMBOL_GPL(__put_task_struct);struct mxc_gpio_port {
struct mxc_gpio_port {
void __init __weak arch_task_cache_init(void) { }struct mxc_gpio_port {
struct mxc_gpio_port {
void __init fork_init(unsigned long mempages)struct mxc_gpio_port {
{struct mxc_gpio_port {
#ifndef CONFIG_ARCH_TASK_STRUCT_ALLOCATORstruct mxc_gpio_port {
#ifndef ARCH_MIN_TASKALIGNstruct mxc_gpio_port {
#define ARCH_MIN_TASKALIGN	L1_CACHE_BYTESstruct mxc_gpio_port {
#endifstruct mxc_gpio_port {
	/* create a slab on which task_structs can be allocated */struct mxc_gpio_port {
	task_struct_cachep =struct mxc_gpio_port {
		kmem_cache_create("task_struct", sizeof(struct task_struct),struct mxc_gpio_port {
			ARCH_MIN_TASKALIGN, SLAB_PANIC | SLAB_NOTRACK, NULL);struct mxc_gpio_port {
#endifstruct mxc_gpio_port {
struct mxc_gpio_port {
	/* do the arch specific task caches init */struct mxc_gpio_port {
	arch_task_cache_init();struct mxc_gpio_port {
struct mxc_gpio_port {
	/*struct mxc_gpio_port {
	 * The default maximum number of threads is set to a safestruct mxc_gpio_port {
	 * value: the thread structures can take up at most halfstruct mxc_gpio_port {
	 * of memory.struct mxc_gpio_port {
	 */struct mxc_gpio_port {
	max_threads = mempages / (8 * THREAD_SIZE / PAGE_SIZE);struct mxc_gpio_port {
struct mxc_gpio_port {
	/*struct mxc_gpio_port {
	 * we need to allow at least 20 threads to boot a systemstruct mxc_gpio_port {
	 */struct mxc_gpio_port {
	if (max_threads < 20)struct mxc_gpio_port {
		max_threads = 20;struct mxc_gpio_port {
struct mxc_gpio_port {
	init_task.signal->rlim[RLIMIT_NPROC].rlim_cur = max_threads/2;struct mxc_gpio_port {
	init_task.signal->rlim[RLIMIT_NPROC].rlim_max = max_threads/2;struct mxc_gpio_port {
	init_task.signal->rlim[RLIMIT_SIGPENDING] =struct mxc_gpio_port {
		init_task.signal->rlim[RLIMIT_NPROC];struct mxc_gpio_port {
}struct mxc_gpio_port {
struct mxc_gpio_port {
int __attribute__((weak)) arch_dup_task_struct(struct task_struct *dst,struct mxc_gpio_port {
					       struct task_struct *src)struct mxc_gpio_port {
{struct mxc_gpio_port {
	*dst = *src;struct mxc_gpio_port {
	return 0;struct mxc_gpio_port {
}struct mxc_gpio_port {
struct mxc_gpio_port {
static struct task_struct *dup_task_struct(struct task_struct *orig)struct mxc_gpio_port {
{struct mxc_gpio_port {
	struct task_struct *tsk;struct mxc_gpio_port {
	struct thread_info *ti;struct mxc_gpio_port {
	unsigned long *stackend;struct mxc_gpio_port {
	int node = tsk_fork_get_node(orig);struct mxc_gpio_port {
	int err;struct mxc_gpio_port {
struct mxc_gpio_port {
	tsk = alloc_task_struct_node(node);struct mxc_gpio_port {
	if (!tsk)struct mxc_gpio_port {
		return NULL;struct mxc_gpio_port {
struct mxc_gpio_port {
	ti = alloc_thread_info_node(tsk, node);struct mxc_gpio_port {
	if (!ti)struct mxc_gpio_port {
		goto free_tsk;struct mxc_gpio_port {
struct mxc_gpio_port {
	err = arch_dup_task_struct(tsk, orig);struct mxc_gpio_port {
	if (err)struct mxc_gpio_port {
		goto free_ti;struct mxc_gpio_port {
struct mxc_gpio_port {
	tsk->stack = ti;struct mxc_gpio_port {
struct mxc_gpio_port {
	setup_thread_stack(tsk, orig);struct mxc_gpio_port {
	clear_user_return_notifier(tsk);struct mxc_gpio_port {
	clear_tsk_need_resched(tsk);struct mxc_gpio_port {
	stackend = end_of_stack(tsk);struct mxc_gpio_port {
	*stackend = STACK_END_MAGIC;	/* for overflow detection */struct mxc_gpio_port {
struct mxc_gpio_port {
#ifdef CONFIG_CC_STACKPROTECTORstruct mxc_gpio_port {
	tsk->stack_canary = get_random_int();struct mxc_gpio_port {
#endifstruct mxc_gpio_port {
struct mxc_gpio_port {
	/*struct mxc_gpio_port {
	 * One for us, one for whoever does the "release_task()" (usuallystruct mxc_gpio_port {
	 * parent)struct mxc_gpio_port {
	 */struct mxc_gpio_port {
	atomic_set(&tsk->usage, 2);struct mxc_gpio_port {
#ifdef CONFIG_BLK_DEV_IO_TRACEstruct mxc_gpio_port {
	tsk->btrace_seq = 0;struct mxc_gpio_port {
#endifstruct mxc_gpio_port {
	tsk->splice_pipe = NULL;struct mxc_gpio_port {
	tsk->task_frag.page = NULL;struct mxc_gpio_port {
struct mxc_gpio_port {
	account_kernel_stack(ti, 1);struct mxc_gpio_port {
struct mxc_gpio_port {
	return tsk;struct mxc_gpio_port {
struct mxc_gpio_port {
free_ti:struct mxc_gpio_port {
	free_thread_info(ti);struct mxc_gpio_port {
free_tsk:struct mxc_gpio_port {
	free_task_struct(tsk);struct mxc_gpio_port {
	return NULL;struct mxc_gpio_port {
}struct mxc_gpio_port {
struct mxc_gpio_port {
#ifdef CONFIG_MMUstruct mxc_gpio_port {
static int dup_mmap(struct mm_struct *mm, struct mm_struct *oldmm)struct mxc_gpio_port {
{struct mxc_gpio_port {
	struct vm_area_struct *mpnt, *tmp, *prev, **pprev;struct mxc_gpio_port {
	struct rb_node **rb_link, *rb_parent;struct mxc_gpio_port {
	int retval;struct mxc_gpio_port {
	unsigned long charge;struct mxc_gpio_port {
struct mxc_gpio_port {
	uprobe_start_dup_mmap();struct mxc_gpio_port {
	down_write(&oldmm->mmap_sem);struct mxc_gpio_port {
	flush_cache_dup_mm(oldmm);struct mxc_gpio_port {
	uprobe_dup_mmap(oldmm, mm);struct mxc_gpio_port {
	/*struct mxc_gpio_port {
	 * Not linked in yet - no deadlock potential:struct mxc_gpio_port {
	 */struct mxc_gpio_port {
	down_write_nested(&mm->mmap_sem, SINGLE_DEPTH_NESTING);struct mxc_gpio_port {
struct mxc_gpio_port {
	mm->locked_vm = 0;struct mxc_gpio_port {
	mm->mmap = NULL;struct mxc_gpio_port {
	mm->mmap_cache = NULL;struct mxc_gpio_port {
	mm->map_count = 0;struct mxc_gpio_port {
	cpumask_clear(mm_cpumask(mm));struct mxc_gpio_port {
	mm->mm_rb = RB_ROOT;struct mxc_gpio_port {
	rb_link = &mm->mm_rb.rb_node;struct mxc_gpio_port {
	rb_parent = NULL;struct mxc_gpio_port {
	pprev = &mm->mmap;struct mxc_gpio_port {
	retval = ksm_fork(mm, oldmm);struct mxc_gpio_port {
	if (retval)struct mxc_gpio_port {
		goto out;struct mxc_gpio_port {
	retval = khugepaged_fork(mm, oldmm);struct mxc_gpio_port {
	if (retval)struct mxc_gpio_port {
		goto out;struct mxc_gpio_port {
struct mxc_gpio_port {
	prev = NULL;struct mxc_gpio_port {
	for (mpnt = oldmm->mmap; mpnt; mpnt = mpnt->vm_next) {struct mxc_gpio_port {
		struct file *file;struct mxc_gpio_port {
struct mxc_gpio_port {
		if (mpnt->vm_flags & VM_DONTCOPY) {struct mxc_gpio_port {
			vm_stat_account(mm, mpnt->vm_flags, mpnt->vm_file,struct mxc_gpio_port {
							-vma_pages(mpnt));struct mxc_gpio_port {
			continue;struct mxc_gpio_port {
		}struct mxc_gpio_port {
		charge = 0;struct mxc_gpio_port {
		if (mpnt->vm_flags & VM_ACCOUNT) {struct mxc_gpio_port {
			unsigned long len = vma_pages(mpnt);struct mxc_gpio_port {
struct mxc_gpio_port {
			if (security_vm_enough_memory_mm(oldmm, len)) /* sic */struct mxc_gpio_port {
				goto fail_nomem;struct mxc_gpio_port {
			charge = len;struct mxc_gpio_port {
		}struct mxc_gpio_port {
		tmp = kmem_cache_alloc(vm_area_cachep, GFP_KERNEL);struct mxc_gpio_port {
		if (!tmp)struct mxc_gpio_port {
			goto fail_nomem;struct mxc_gpio_port {
		*tmp = *mpnt;struct mxc_gpio_port {
		INIT_LIST_HEAD(&tmp->anon_vma_chain);struct mxc_gpio_port {
		retval = vma_dup_policy(mpnt, tmp);struct mxc_gpio_port {
		if (retval)struct mxc_gpio_port {
			goto fail_nomem_policy;struct mxc_gpio_port {
		tmp->vm_mm = mm;struct mxc_gpio_port {
		if (anon_vma_fork(tmp, mpnt))struct mxc_gpio_port {
			goto fail_nomem_anon_vma_fork;struct mxc_gpio_port {
		tmp->vm_flags &= ~VM_LOCKED;struct mxc_gpio_port {
		tmp->vm_next = tmp->vm_prev = NULL;struct mxc_gpio_port {
		file = tmp->vm_file;struct mxc_gpio_port {
		if (file) {struct mxc_gpio_port {
			struct inode *inode = file_inode(file);struct mxc_gpio_port {
			struct address_space *mapping = file->f_mapping;struct mxc_gpio_port {
struct mxc_gpio_port {
			get_file(file);struct mxc_gpio_port {
			if (tmp->vm_flags & VM_DENYWRITE)struct mxc_gpio_port {
				atomic_dec(&inode->i_writecount);struct mxc_gpio_port {
			mutex_lock(&mapping->i_mmap_mutex);struct mxc_gpio_port {
			if (tmp->vm_flags & VM_SHARED)struct mxc_gpio_port {
				mapping->i_mmap_writable++;struct mxc_gpio_port {
			flush_dcache_mmap_lock(mapping);struct mxc_gpio_port {
			/* insert tmp into the share list, just after mpnt */struct mxc_gpio_port {
			if (unlikely(tmp->vm_flags & VM_NONLINEAR))struct mxc_gpio_port {
				vma_nonlinear_insert(tmp,struct mxc_gpio_port {
						&mapping->i_mmap_nonlinear);struct mxc_gpio_port {
			elsestruct mxc_gpio_port {
				vma_interval_tree_insert_after(tmp, mpnt,struct mxc_gpio_port {
							&mapping->i_mmap);struct mxc_gpio_port {
			flush_dcache_mmap_unlock(mapping);struct mxc_gpio_port {
			mutex_unlock(&mapping->i_mmap_mutex);struct mxc_gpio_port {
		}struct mxc_gpio_port {
struct mxc_gpio_port {
		/*struct mxc_gpio_port {
		 * Clear hugetlb-related page reserves for children. This onlystruct mxc_gpio_port {
		 * affects MAP_PRIVATE mappings. Faults generated by the childstruct mxc_gpio_port {
		 * are not guaranteed to succeed, even if read-onlystruct mxc_gpio_port {
		 */struct mxc_gpio_port {
		if (is_vm_hugetlb_page(tmp))struct mxc_gpio_port {
			reset_vma_resv_huge_pages(tmp);struct mxc_gpio_port {
struct mxc_gpio_port {
		/*struct mxc_gpio_port {
		 * Link in the new vma and copy the page table entries.struct mxc_gpio_port {
		 */struct mxc_gpio_port {
		*pprev = tmp;struct mxc_gpio_port {
		pprev = &tmp->vm_next;struct mxc_gpio_port {
		tmp->vm_prev = prev;struct mxc_gpio_port {
		prev = tmp;struct mxc_gpio_port {
struct mxc_gpio_port {
		__vma_link_rb(mm, tmp, rb_link, rb_parent);struct mxc_gpio_port {
		rb_link = &tmp->vm_rb.rb_right;struct mxc_gpio_port {
		rb_parent = &tmp->vm_rb;struct mxc_gpio_port {
struct mxc_gpio_port {
		mm->map_count++;struct mxc_gpio_port {
		retval = copy_page_range(mm, oldmm, mpnt);struct mxc_gpio_port {
struct mxc_gpio_port {
		if (tmp->vm_ops && tmp->vm_ops->open)struct mxc_gpio_port {
			tmp->vm_ops->open(tmp);struct mxc_gpio_port {
struct mxc_gpio_port {
		if (retval)struct mxc_gpio_port {
			goto out;struct mxc_gpio_port {
	}struct mxc_gpio_port {
	/* a new mm has just been created */struct mxc_gpio_port {
	arch_dup_mmap(oldmm, mm);struct mxc_gpio_port {
	retval = 0;struct mxc_gpio_port {
out:struct mxc_gpio_port {
	up_write(&mm->mmap_sem);struct mxc_gpio_port {
	flush_tlb_mm(oldmm);struct mxc_gpio_port {
	up_write(&oldmm->mmap_sem);struct mxc_gpio_port {
	uprobe_end_dup_mmap();struct mxc_gpio_port {
	return retval;struct mxc_gpio_port {
fail_nomem_anon_vma_fork:struct mxc_gpio_port {
	mpol_put(vma_policy(tmp));struct mxc_gpio_port {
fail_nomem_policy:struct mxc_gpio_port {
	kmem_cache_free(vm_area_cachep, tmp);struct mxc_gpio_port {
fail_nomem:struct mxc_gpio_port {
	retval = -ENOMEM;struct mxc_gpio_port {
	vm_unacct_memory(charge);struct mxc_gpio_port {
	goto out;struct mxc_gpio_port {
}struct mxc_gpio_port {
struct mxc_gpio_port {
static inline int mm_alloc_pgd(struct mm_struct *mm)struct mxc_gpio_port {
{struct mxc_gpio_port {
	mm->pgd = pgd_alloc(mm);struct mxc_gpio_port {
	if (unlikely(!mm->pgd))struct mxc_gpio_port {
		return -ENOMEM;struct mxc_gpio_port {
	return 0;struct mxc_gpio_port {
}struct mxc_gpio_port {
struct mxc_gpio_port {
static inline void mm_free_pgd(struct mm_struct *mm)struct mxc_gpio_port {
{struct mxc_gpio_port {
	pgd_free(mm, mm->pgd);struct mxc_gpio_port {
}struct mxc_gpio_port {
#elsestruct mxc_gpio_port {
#define dup_mmap(mm, oldmm)	(0)struct mxc_gpio_port {
#define mm_alloc_pgd(mm)	(0)struct mxc_gpio_port {
#define mm_free_pgd(mm)struct mxc_gpio_port {
#endif /* CONFIG_MMU */struct mxc_gpio_port {
struct mxc_gpio_port {
__cacheline_aligned_in_smp DEFINE_SPINLOCK(mmlist_lock);struct mxc_gpio_port {
struct mxc_gpio_port {
#define allocate_mm()	(kmem_cache_alloc(mm_cachep, GFP_KERNEL))struct mxc_gpio_port {
#define free_mm(mm)	(kmem_cache_free(mm_cachep, (mm)))struct mxc_gpio_port {
struct mxc_gpio_port {
static unsigned long default_dump_filter = MMF_DUMP_FILTER_DEFAULT;struct mxc_gpio_port {
struct mxc_gpio_port {
static int __init coredump_filter_setup(char *s)struct mxc_gpio_port {
{struct mxc_gpio_port {
	default_dump_filter =struct mxc_gpio_port {
		(simple_strtoul(s, NULL, 0) << MMF_DUMP_FILTER_SHIFT) &struct mxc_gpio_port {
		MMF_DUMP_FILTER_MASK;struct mxc_gpio_port {
	return 1;struct mxc_gpio_port {
}struct mxc_gpio_port {
struct mxc_gpio_port {
__setup("coredump_filter=", coredump_filter_setup);struct mxc_gpio_port {
struct mxc_gpio_port {
#include <linux/init_task.h>struct mxc_gpio_port {
struct mxc_gpio_port {
static void mm_init_aio(struct mm_struct *mm)struct mxc_gpio_port {
{struct mxc_gpio_port {
#ifdef CONFIG_AIOstruct mxc_gpio_port {
	spin_lock_init(&mm->ioctx_lock);struct mxc_gpio_port {
	mm->ioctx_table = NULL;struct mxc_gpio_port {
#endifstruct mxc_gpio_port {
}struct mxc_gpio_port {
struct mxc_gpio_port {
static struct mm_struct *mm_init(struct mm_struct *mm, struct task_struct *p)struct mxc_gpio_port {
{struct mxc_gpio_port {
	atomic_set(&mm->mm_users, 1);struct mxc_gpio_port {
	atomic_set(&mm->mm_count, 1);struct mxc_gpio_port {
	init_rwsem(&mm->mmap_sem);struct mxc_gpio_port {
	INIT_LIST_HEAD(&mm->mmlist);struct mxc_gpio_port {
	mm->flags = (current->mm) ?struct mxc_gpio_port {
		(current->mm->flags & MMF_INIT_MASK) : default_dump_filter;struct mxc_gpio_port {
	mm->core_state = NULL;struct mxc_gpio_port {
	atomic_long_set(&mm->nr_ptes, 0);struct mxc_gpio_port {
	memset(&mm->rss_stat, 0, sizeof(mm->rss_stat));struct mxc_gpio_port {
	spin_lock_init(&mm->page_table_lock);struct mxc_gpio_port {
	mm_init_aio(mm);struct mxc_gpio_port {
	mm_init_owner(mm, p);struct mxc_gpio_port {
	clear_tlb_flush_pending(mm);struct mxc_gpio_port {
struct mxc_gpio_port {
	if (likely(!mm_alloc_pgd(mm))) {struct mxc_gpio_port {
		mm->def_flags = 0;struct mxc_gpio_port {
		mmu_notifier_mm_init(mm);struct mxc_gpio_port {
		return mm;struct mxc_gpio_port {
	}struct mxc_gpio_port {
struct mxc_gpio_port {
	free_mm(mm);struct mxc_gpio_port {
	return NULL;struct mxc_gpio_port {
}struct mxc_gpio_port {
struct mxc_gpio_port {
static void check_mm(struct mm_struct *mm)struct mxc_gpio_port {
{struct mxc_gpio_port {
	int i;struct mxc_gpio_port {
struct mxc_gpio_port {
	for (i = 0; i < NR_MM_COUNTERS; i++) {struct mxc_gpio_port {
		long x = atomic_long_read(&mm->rss_stat.count[i]);struct mxc_gpio_port {
struct mxc_gpio_port {
		if (unlikely(x))struct mxc_gpio_port {
			printk(KERN_ALERT "BUG: Bad rss-counter state "struct mxc_gpio_port {
					  "mm:%p idx:%d val:%ld\n", mm, i, x);struct mxc_gpio_port {
	}struct mxc_gpio_port {
struct mxc_gpio_port {
#if defined(CONFIG_TRANSPARENT_HUGEPAGE) && !USE_SPLIT_PMD_PTLOCKSstruct mxc_gpio_port {
	VM_BUG_ON(mm->pmd_huge_pte);struct mxc_gpio_port {
#endifstruct mxc_gpio_port {
}struct mxc_gpio_port {
struct mxc_gpio_port {
/*struct mxc_gpio_port {
 * Allocate and initialize an mm_struct.struct mxc_gpio_port {
 */struct mxc_gpio_port {
struct mm_struct *mm_alloc(void)struct mxc_gpio_port {
{struct mxc_gpio_port {
	struct mm_struct *mm;struct mxc_gpio_port {
struct mxc_gpio_port {
	mm = allocate_mm();struct mxc_gpio_port {
	if (!mm)struct mxc_gpio_port {
		return NULL;struct mxc_gpio_port {
struct mxc_gpio_port {
	memset(mm, 0, sizeof(*mm));struct mxc_gpio_port {
	mm_init_cpumask(mm);struct mxc_gpio_port {
	return mm_init(mm, current);struct mxc_gpio_port {
}struct mxc_gpio_port {
struct mxc_gpio_port {
/*struct mxc_gpio_port {
 * Called when the last reference to the mmstruct mxc_gpio_port {
 * is dropped: either by a lazy thread or bystruct mxc_gpio_port {
 * mmput. Free the page directory and the mm.struct mxc_gpio_port {
 */struct mxc_gpio_port {
void __mmdrop(struct mm_struct *mm)struct mxc_gpio_port {
{struct mxc_gpio_port {
	BUG_ON(mm == &init_mm);struct mxc_gpio_port {
	mm_free_pgd(mm);struct mxc_gpio_port {
	destroy_context(mm);struct mxc_gpio_port {
	mmu_notifier_mm_destroy(mm);struct mxc_gpio_port {
	check_mm(mm);struct mxc_gpio_port {
	free_mm(mm);struct mxc_gpio_port {
}struct mxc_gpio_port {
EXPORT_SYMBOL_GPL(__mmdrop);struct mxc_gpio_port {
struct mxc_gpio_port {
/*struct mxc_gpio_port {
 * Decrement the use count and release all resources for an mm.struct mxc_gpio_port {
 */struct mxc_gpio_port {
void mmput(struct mm_struct *mm)struct mxc_gpio_port {
{struct mxc_gpio_port {
	might_sleep();struct mxc_gpio_port {
struct mxc_gpio_port {
	if (atomic_dec_and_test(&mm->mm_users)) {struct mxc_gpio_port {
		uprobe_clear_state(mm);struct mxc_gpio_port {
		exit_aio(mm);struct mxc_gpio_port {
		ksm_exit(mm);struct mxc_gpio_port {
		khugepaged_exit(mm); /* must run before exit_mmap */struct mxc_gpio_port {
		exit_mmap(mm);struct mxc_gpio_port {
		set_mm_exe_file(mm, NULL);struct mxc_gpio_port {
		if (!list_empty(&mm->mmlist)) {struct mxc_gpio_port {
			spin_lock(&mmlist_lock);struct mxc_gpio_port {
			list_del(&mm->mmlist);struct mxc_gpio_port {
			spin_unlock(&mmlist_lock);struct mxc_gpio_port {
		}struct mxc_gpio_port {
		if (mm->binfmt)struct mxc_gpio_port {
			module_put(mm->binfmt->module);struct mxc_gpio_port {
		mmdrop(mm);struct mxc_gpio_port {
	}struct mxc_gpio_port {
}struct mxc_gpio_port {
EXPORT_SYMBOL_GPL(mmput);struct mxc_gpio_port {
struct mxc_gpio_port {
void set_mm_exe_file(struct mm_struct *mm, struct file *new_exe_file)struct mxc_gpio_port {
{struct mxc_gpio_port {
	if (new_exe_file)struct mxc_gpio_port {
		get_file(new_exe_file);struct mxc_gpio_port {
	if (mm->exe_file)struct mxc_gpio_port {
		fput(mm->exe_file);struct mxc_gpio_port {
	mm->exe_file = new_exe_file;struct mxc_gpio_port {
}struct mxc_gpio_port {
struct mxc_gpio_port {
struct file *get_mm_exe_file(struct mm_struct *mm)struct mxc_gpio_port {
{struct mxc_gpio_port {
	struct file *exe_file;struct mxc_gpio_port {
struct mxc_gpio_port {
	/* We need mmap_sem to protect against races with removal of exe_file */struct mxc_gpio_port {
	down_read(&mm->mmap_sem);struct mxc_gpio_port {
	exe_file = mm->exe_file;struct mxc_gpio_port {
	if (exe_file)struct mxc_gpio_port {
		get_file(exe_file);struct mxc_gpio_port {
	up_read(&mm->mmap_sem);struct mxc_gpio_port {
	return exe_file;struct mxc_gpio_port {
}struct mxc_gpio_port {
struct mxc_gpio_port {
static void dup_mm_exe_file(struct mm_struct *oldmm, struct mm_struct *newmm)struct mxc_gpio_port {
{struct mxc_gpio_port {
	/* It's safe to write the exe_file pointer without exe_file_lock becausestruct mxc_gpio_port {
	 * this is called during fork when the task is not yet in /proc */struct mxc_gpio_port {
	newmm->exe_file = get_mm_exe_file(oldmm);struct mxc_gpio_port {
}struct mxc_gpio_port {
struct mxc_gpio_port {
/**struct mxc_gpio_port {
 * get_task_mm - acquire a reference to the task's mmstruct mxc_gpio_port {
 *struct mxc_gpio_port {
 * Returns %NULL if the task has no mm.  Checks PF_KTHREAD (meaningstruct mxc_gpio_port {
 * this kernel workthread has transiently adopted a user mm with use_mm,struct mxc_gpio_port {
 * to do its AIO) is not set and if so returns a reference to it, afterstruct mxc_gpio_port {
 * bumping up the use count.  User must release the mm via mmput()struct mxc_gpio_port {
 * after use.  Typically used by /proc and ptrace.struct mxc_gpio_port {
 */struct mxc_gpio_port {
struct mm_struct *get_task_mm(struct task_struct *task)struct mxc_gpio_port {
{struct mxc_gpio_port {
	struct mm_struct *mm;struct mxc_gpio_port {
struct mxc_gpio_port {
	task_lock(task);struct mxc_gpio_port {
	mm = task->mm;struct mxc_gpio_port {
	if (mm) {struct mxc_gpio_port {
		if (task->flags & PF_KTHREAD)struct mxc_gpio_port {
			mm = NULL;struct mxc_gpio_port {
		elsestruct mxc_gpio_port {
			atomic_inc(&mm->mm_users);struct mxc_gpio_port {
	}struct mxc_gpio_port {
	task_unlock(task);struct mxc_gpio_port {
	return mm;struct mxc_gpio_port {
}struct mxc_gpio_port {
EXPORT_SYMBOL_GPL(get_task_mm);struct mxc_gpio_port {
struct mxc_gpio_port {
struct mm_struct *mm_access(struct task_struct *task, unsigned int mode)struct mxc_gpio_port {
{struct mxc_gpio_port {
	struct mm_struct *mm;struct mxc_gpio_port {
	int err;struct mxc_gpio_port {
struct mxc_gpio_port {
	err =  mutex_lock_killable(&task->signal->cred_guard_mutex);struct mxc_gpio_port {
	if (err)struct mxc_gpio_port {
		return ERR_PTR(err);struct mxc_gpio_port {
struct mxc_gpio_port {
	mm = get_task_mm(task);struct mxc_gpio_port {
	if (mm && mm != current->mm &&struct mxc_gpio_port {
			!ptrace_may_access(task, mode)) {struct mxc_gpio_port {
		mmput(mm);struct mxc_gpio_port {
		mm = ERR_PTR(-EACCES);struct mxc_gpio_port {
	}struct mxc_gpio_port {
	mutex_unlock(&task->signal->cred_guard_mutex);struct mxc_gpio_port {
struct mxc_gpio_port {
	return mm;struct mxc_gpio_port {
}struct mxc_gpio_port {
struct mxc_gpio_port {
static void complete_vfork_done(struct task_struct *tsk)struct mxc_gpio_port {
{struct mxc_gpio_port {
	struct completion *vfork;struct mxc_gpio_port {
struct mxc_gpio_port {
	task_lock(tsk);struct mxc_gpio_port {
	vfork = tsk->vfork_done;struct mxc_gpio_port {
	if (likely(vfork)) {struct mxc_gpio_port {
		tsk->vfork_done = NULL;struct mxc_gpio_port {
		complete(vfork);struct mxc_gpio_port {
	}struct mxc_gpio_port {
	task_unlock(tsk);struct mxc_gpio_port {
}struct mxc_gpio_port {
struct mxc_gpio_port {
static int wait_for_vfork_done(struct task_struct *child,struct mxc_gpio_port {
				struct completion *vfork)struct mxc_gpio_port {
{struct mxc_gpio_port {
	int killed;struct mxc_gpio_port {
struct mxc_gpio_port {
	freezer_do_not_count();struct mxc_gpio_port {
	killed = wait_for_completion_killable(vfork);struct mxc_gpio_port {
	freezer_count();struct mxc_gpio_port {
struct mxc_gpio_port {
	if (killed) {struct mxc_gpio_port {
		task_lock(child);struct mxc_gpio_port {
		child->vfork_done = NULL;struct mxc_gpio_port {
		task_unlock(child);struct mxc_gpio_port {
	}struct mxc_gpio_port {
struct mxc_gpio_port {
	put_task_struct(child);struct mxc_gpio_port {
	return killed;struct mxc_gpio_port {
}struct mxc_gpio_port {
struct mxc_gpio_port {
/* Please note the differences between mmput and mm_release.struct mxc_gpio_port {
 * mmput is called whenever we stop holding onto a mm_struct,struct mxc_gpio_port {
 * error success whatever.struct mxc_gpio_port {
 *struct mxc_gpio_port {
 * mm_release is called after a mm_struct has been removedstruct mxc_gpio_port {
 * from the current process.struct mxc_gpio_port {
 *struct mxc_gpio_port {
 * This difference is important for error handling, when westruct mxc_gpio_port {
 * only half set up a mm_struct for a new process and need to restorestruct mxc_gpio_port {
 * the old one.  Because we mmput the new mm_struct beforestruct mxc_gpio_port {
 * restoring the old one. . .struct mxc_gpio_port {
 * Eric Biederman 10 January 1998struct mxc_gpio_port {
 */struct mxc_gpio_port {
void mm_release(struct task_struct *tsk, struct mm_struct *mm)struct mxc_gpio_port {
{struct mxc_gpio_port {
	/* Get rid of any futexes when releasing the mm */struct mxc_gpio_port {
#ifdef CONFIG_FUTEXstruct mxc_gpio_port {
	if (unlikely(tsk->robust_list)) {struct mxc_gpio_port {
		exit_robust_list(tsk);struct mxc_gpio_port {
		tsk->robust_list = NULL;struct mxc_gpio_port {
	}struct mxc_gpio_port {
#ifdef CONFIG_COMPATstruct mxc_gpio_port {
	if (unlikely(tsk->compat_robust_list)) {struct mxc_gpio_port {
		compat_exit_robust_list(tsk);struct mxc_gpio_port {
		tsk->compat_robust_list = NULL;struct mxc_gpio_port {
	}struct mxc_gpio_port {
#endifstruct mxc_gpio_port {
	if (unlikely(!list_empty(&tsk->pi_state_list)))struct mxc_gpio_port {
		exit_pi_state_list(tsk);struct mxc_gpio_port {
#endifstruct mxc_gpio_port {
struct mxc_gpio_port {
	uprobe_free_utask(tsk);struct mxc_gpio_port {
struct mxc_gpio_port {
	/* Get rid of any cached register state */struct mxc_gpio_port {
	deactivate_mm(tsk, mm);struct mxc_gpio_port {
struct mxc_gpio_port {
	/*struct mxc_gpio_port {
	 * If we're exiting normally, clear a user-space tid field ifstruct mxc_gpio_port {
	 * requested.  We leave this alone when dying by signal, to leavestruct mxc_gpio_port {
	 * the value intact in a core dump, and to save the unnecessarystruct mxc_gpio_port {
	 * trouble, say, a killed vfork parent shouldn't touch this mm.struct mxc_gpio_port {
	 * Userland only wants this done for a sys_exit.struct mxc_gpio_port {
	 */struct mxc_gpio_port {
	if (tsk->clear_child_tid) {struct mxc_gpio_port {
		if (!(tsk->flags & PF_SIGNALED) &&struct mxc_gpio_port {
		    atomic_read(&mm->mm_users) > 1) {struct mxc_gpio_port {
			/*struct mxc_gpio_port {
			 * We don't check the error code - if userspace hasstruct mxc_gpio_port {
			 * not set up a proper pointer then tough luck.struct mxc_gpio_port {
			 */struct mxc_gpio_port {
			put_user(0, tsk->clear_child_tid);struct mxc_gpio_port {
			sys_futex(tsk->clear_child_tid, FUTEX_WAKE,struct mxc_gpio_port {
					1, NULL, NULL, 0);struct mxc_gpio_port {
		}struct mxc_gpio_port {
		tsk->clear_child_tid = NULL;struct mxc_gpio_port {
	}struct mxc_gpio_port {
struct mxc_gpio_port {
	/*struct mxc_gpio_port {
	 * All done, finally we can wake up parent and return this mm to him.struct mxc_gpio_port {
	 * Also kthread_stop() uses this completion for synchronization.struct mxc_gpio_port {
	 */struct mxc_gpio_port {
	if (tsk->vfork_done)struct mxc_gpio_port {
		complete_vfork_done(tsk);struct mxc_gpio_port {
}struct mxc_gpio_port {
struct mxc_gpio_port {
/*struct mxc_gpio_port {
 * Allocate a new mm structure and copy contents from thestruct mxc_gpio_port {
 * mm structure of the passed in task structure.struct mxc_gpio_port {
 */struct mxc_gpio_port {
static struct mm_struct *dup_mm(struct task_struct *tsk)struct mxc_gpio_port {
{struct mxc_gpio_port {
	struct mm_struct *mm, *oldmm = current->mm;struct mxc_gpio_port {
	int err;struct mxc_gpio_port {
struct mxc_gpio_port {
	mm = allocate_mm();struct mxc_gpio_port {
	if (!mm)struct mxc_gpio_port {
		goto fail_nomem;struct mxc_gpio_port {
struct mxc_gpio_port {
	memcpy(mm, oldmm, sizeof(*mm));struct mxc_gpio_port {
	mm_init_cpumask(mm);struct mxc_gpio_port {
struct mxc_gpio_port {
#if defined(CONFIG_TRANSPARENT_HUGEPAGE) && !USE_SPLIT_PMD_PTLOCKSstruct mxc_gpio_port {
	mm->pmd_huge_pte = NULL;struct mxc_gpio_port {
#endifstruct mxc_gpio_port {
	if (!mm_init(mm, tsk))struct mxc_gpio_port {
		goto fail_nomem;struct mxc_gpio_port {
struct mxc_gpio_port {
	if (init_new_context(tsk, mm))struct mxc_gpio_port {
		goto fail_nocontext;struct mxc_gpio_port {
struct mxc_gpio_port {
	dup_mm_exe_file(oldmm, mm);struct mxc_gpio_port {
struct mxc_gpio_port {
	err = dup_mmap(mm, oldmm);struct mxc_gpio_port {
	if (err)struct mxc_gpio_port {
		goto free_pt;struct mxc_gpio_port {
struct mxc_gpio_port {
	mm->hiwater_rss = get_mm_rss(mm);struct mxc_gpio_port {
	mm->hiwater_vm = mm->total_vm;struct mxc_gpio_port {
struct mxc_gpio_port {
	if (mm->binfmt && !try_module_get(mm->binfmt->module))struct mxc_gpio_port {
		goto free_pt;struct mxc_gpio_port {
struct mxc_gpio_port {
	return mm;struct mxc_gpio_port {
struct mxc_gpio_port {
free_pt:struct mxc_gpio_port {
	/* don't put binfmt in mmput, we haven't got module yet */struct mxc_gpio_port {
	mm->binfmt = NULL;struct mxc_gpio_port {
	mmput(mm);struct mxc_gpio_port {
struct mxc_gpio_port {
fail_nomem:struct mxc_gpio_port {
	return NULL;struct mxc_gpio_port {
struct mxc_gpio_port {
fail_nocontext:struct mxc_gpio_port {
	/*struct mxc_gpio_port {
	 * If init_new_context() failed, we cannot use mmput() to free the mmstruct mxc_gpio_port {
	 * because it calls destroy_context()struct mxc_gpio_port {
	 */struct mxc_gpio_port {
	mm_free_pgd(mm);struct mxc_gpio_port {
	free_mm(mm);struct mxc_gpio_port {
	return NULL;struct mxc_gpio_port {
}struct mxc_gpio_port {
struct mxc_gpio_port {
static int copy_mm(unsigned long clone_flags, struct task_struct *tsk)struct mxc_gpio_port {
{struct mxc_gpio_port {
	struct mm_struct *mm, *oldmm;struct mxc_gpio_port {
	int retval;struct mxc_gpio_port {
struct mxc_gpio_port {
	tsk->min_flt = tsk->maj_flt = 0;struct mxc_gpio_port {
	tsk->nvcsw = tsk->nivcsw = 0;struct mxc_gpio_port {
#ifdef CONFIG_DETECT_HUNG_TASKstruct mxc_gpio_port {
	tsk->last_switch_count = tsk->nvcsw + tsk->nivcsw;struct mxc_gpio_port {
#endifstruct mxc_gpio_port {
struct mxc_gpio_port {
	tsk->mm = NULL;struct mxc_gpio_port {
	tsk->active_mm = NULL;struct mxc_gpio_port {
struct mxc_gpio_port {
	/*struct mxc_gpio_port {
	 * Are we cloning a kernel thread?struct mxc_gpio_port {
	 *struct mxc_gpio_port {
	 * We need to steal a active VM for that..struct mxc_gpio_port {
	 */struct mxc_gpio_port {
	oldmm = current->mm;struct mxc_gpio_port {
	if (!oldmm)struct mxc_gpio_port {
		return 0;struct mxc_gpio_port {
struct mxc_gpio_port {
	if (clone_flags & CLONE_VM) {struct mxc_gpio_port {
		atomic_inc(&oldmm->mm_users);struct mxc_gpio_port {
		mm = oldmm;struct mxc_gpio_port {
		goto good_mm;struct mxc_gpio_port {
	}struct mxc_gpio_port {
struct mxc_gpio_port {
	retval = -ENOMEM;struct mxc_gpio_port {
	mm = dup_mm(tsk);struct mxc_gpio_port {
	if (!mm)struct mxc_gpio_port {
		goto fail_nomem;struct mxc_gpio_port {
struct mxc_gpio_port {
good_mm:struct mxc_gpio_port {
	tsk->mm = mm;struct mxc_gpio_port {
	tsk->active_mm = mm;struct mxc_gpio_port {
	return 0;struct mxc_gpio_port {
struct mxc_gpio_port {
fail_nomem:struct mxc_gpio_port {
	return retval;struct mxc_gpio_port {
}struct mxc_gpio_port {
struct mxc_gpio_port {
static int copy_fs(unsigned long clone_flags, struct task_struct *tsk)struct mxc_gpio_port {
{struct mxc_gpio_port {
	struct fs_struct *fs = current->fs;struct mxc_gpio_port {
	if (clone_flags & CLONE_FS) {struct mxc_gpio_port {
		/* tsk->fs is already what we want */struct mxc_gpio_port {
		spin_lock(&fs->lock);struct mxc_gpio_port {
		if (fs->in_exec) {struct mxc_gpio_port {
			spin_unlock(&fs->lock);struct mxc_gpio_port {
			return -EAGAIN;struct mxc_gpio_port {
		}struct mxc_gpio_port {
		fs->users++;struct mxc_gpio_port {
		spin_unlock(&fs->lock);struct mxc_gpio_port {
		return 0;struct mxc_gpio_port {
	}struct mxc_gpio_port {
	tsk->fs = copy_fs_struct(fs);struct mxc_gpio_port {
	if (!tsk->fs)struct mxc_gpio_port {
		return -ENOMEM;struct mxc_gpio_port {
	return 0;struct mxc_gpio_port {
}struct mxc_gpio_port {
struct mxc_gpio_port {
static int copy_files(unsigned long clone_flags, struct task_struct *tsk)struct mxc_gpio_port {
{struct mxc_gpio_port {
	struct files_struct *oldf, *newf;struct mxc_gpio_port {
	int error = 0;struct mxc_gpio_port {
struct mxc_gpio_port {
	/*struct mxc_gpio_port {
	 * A background process may not have any files ...struct mxc_gpio_port {
	 */struct mxc_gpio_port {
	oldf = current->files;struct mxc_gpio_port {
	if (!oldf)struct mxc_gpio_port {
		goto out;struct mxc_gpio_port {
struct mxc_gpio_port {
	if (clone_flags & CLONE_FILES) {struct mxc_gpio_port {
		atomic_inc(&oldf->count);struct mxc_gpio_port {
		goto out;struct mxc_gpio_port {
	}struct mxc_gpio_port {
struct mxc_gpio_port {
	newf = dup_fd(oldf, &error);struct mxc_gpio_port {
	if (!newf)struct mxc_gpio_port {
		goto out;struct mxc_gpio_port {
struct mxc_gpio_port {
	tsk->files = newf;struct mxc_gpio_port {
	error = 0;struct mxc_gpio_port {
out:struct mxc_gpio_port {
	return error;struct mxc_gpio_port {
}struct mxc_gpio_port {
struct mxc_gpio_port {
static int copy_io(unsigned long clone_flags, struct task_struct *tsk)struct mxc_gpio_port {
{struct mxc_gpio_port {
#ifdef CONFIG_BLOCKstruct mxc_gpio_port {
	struct io_context *ioc = current->io_context;struct mxc_gpio_port {
	struct io_context *new_ioc;struct mxc_gpio_port {
struct mxc_gpio_port {
	if (!ioc)struct mxc_gpio_port {
		return 0;struct mxc_gpio_port {
	/*struct mxc_gpio_port {
	 * Share io context with parent, if CLONE_IO is setstruct mxc_gpio_port {
	 */struct mxc_gpio_port {
	if (clone_flags & CLONE_IO) {struct mxc_gpio_port {
		ioc_task_link(ioc);struct mxc_gpio_port {
		tsk->io_context = ioc;struct mxc_gpio_port {
	} else if (ioprio_valid(ioc->ioprio)) {struct mxc_gpio_port {
		new_ioc = get_task_io_context(tsk, GFP_KERNEL, NUMA_NO_NODE);struct mxc_gpio_port {
		if (unlikely(!new_ioc))struct mxc_gpio_port {
			return -ENOMEM;struct mxc_gpio_port {
struct mxc_gpio_port {
		new_ioc->ioprio = ioc->ioprio;struct mxc_gpio_port {
		put_io_context(new_ioc);struct mxc_gpio_port {
	}struct mxc_gpio_port {
#endifstruct mxc_gpio_port {
	return 0;struct mxc_gpio_port {
}struct mxc_gpio_port {
struct mxc_gpio_port {
static int copy_sighand(unsigned long clone_flags, struct task_struct *tsk)struct mxc_gpio_port {
{struct mxc_gpio_port {
	struct sighand_struct *sig;struct mxc_gpio_port {
struct mxc_gpio_port {
	if (clone_flags & CLONE_SIGHAND) {struct mxc_gpio_port {
		atomic_inc(&current->sighand->count);struct mxc_gpio_port {
		return 0;struct mxc_gpio_port {
	}struct mxc_gpio_port {
	sig = kmem_cache_alloc(sighand_cachep, GFP_KERNEL);struct mxc_gpio_port {
	rcu_assign_pointer(tsk->sighand, sig);struct mxc_gpio_port {
	if (!sig)struct mxc_gpio_port {
		return -ENOMEM;struct mxc_gpio_port {
	atomic_set(&sig->count, 1);struct mxc_gpio_port {
	memcpy(sig->action, current->sighand->action, sizeof(sig->action));struct mxc_gpio_port {
	return 0;struct mxc_gpio_port {
}struct mxc_gpio_port {
struct mxc_gpio_port {
void __cleanup_sighand(struct sighand_struct *sighand)struct mxc_gpio_port {
{struct mxc_gpio_port {
	if (atomic_dec_and_test(&sighand->count)) {struct mxc_gpio_port {
		signalfd_cleanup(sighand);struct mxc_gpio_port {
		kmem_cache_free(sighand_cachep, sighand);struct mxc_gpio_port {
	}struct mxc_gpio_port {
}struct mxc_gpio_port {
struct mxc_gpio_port {
struct mxc_gpio_port {
/*struct mxc_gpio_port {
 * Initialize POSIX timer handling for a thread group.struct mxc_gpio_port {
 */struct mxc_gpio_port {
static void posix_cpu_timers_init_group(struct signal_struct *sig)struct mxc_gpio_port {
{struct mxc_gpio_port {
	unsigned long cpu_limit;struct mxc_gpio_port {
struct mxc_gpio_port {
	/* Thread group counters. */struct mxc_gpio_port {
	thread_group_cputime_init(sig);struct mxc_gpio_port {
struct mxc_gpio_port {
	cpu_limit = ACCESS_ONCE(sig->rlim[RLIMIT_CPU].rlim_cur);struct mxc_gpio_port {
	if (cpu_limit != RLIM_INFINITY) {struct mxc_gpio_port {
		sig->cputime_expires.prof_exp = secs_to_cputime(cpu_limit);struct mxc_gpio_port {
		sig->cputimer.running = 1;struct mxc_gpio_port {
	}struct mxc_gpio_port {
struct mxc_gpio_port {
	/* The timer lists. */struct mxc_gpio_port {
	INIT_LIST_HEAD(&sig->cpu_timers[0]);struct mxc_gpio_port {
	INIT_LIST_HEAD(&sig->cpu_timers[1]);struct mxc_gpio_port {
	INIT_LIST_HEAD(&sig->cpu_timers[2]);struct mxc_gpio_port {
}struct mxc_gpio_port {
struct mxc_gpio_port {
static int copy_signal(unsigned long clone_flags, struct task_struct *tsk)struct mxc_gpio_port {
{struct mxc_gpio_port {
	struct signal_struct *sig;struct mxc_gpio_port {
struct mxc_gpio_port {
	if (clone_flags & CLONE_THREAD)struct mxc_gpio_port {
		return 0;struct mxc_gpio_port {
struct mxc_gpio_port {
	sig = kmem_cache_zalloc(signal_cachep, GFP_KERNEL);struct mxc_gpio_port {
	tsk->signal = sig;struct mxc_gpio_port {
	if (!sig)struct mxc_gpio_port {
		return -ENOMEM;struct mxc_gpio_port {
struct mxc_gpio_port {
	sig->nr_threads = 1;struct mxc_gpio_port {
	atomic_set(&sig->live, 1);struct mxc_gpio_port {
	atomic_set(&sig->sigcnt, 1);struct mxc_gpio_port {
struct mxc_gpio_port {
	/* list_add(thread_node, thread_head) without INIT_LIST_HEAD() */struct mxc_gpio_port {
	sig->thread_head = (struct list_head)LIST_HEAD_INIT(tsk->thread_node);struct mxc_gpio_port {
	tsk->thread_node = (struct list_head)LIST_HEAD_INIT(sig->thread_head);struct mxc_gpio_port {
struct mxc_gpio_port {
	init_waitqueue_head(&sig->wait_chldexit);struct mxc_gpio_port {
	sig->curr_target = tsk;struct mxc_gpio_port {
	init_sigpending(&sig->shared_pending);struct mxc_gpio_port {
	INIT_LIST_HEAD(&sig->posix_timers);struct mxc_gpio_port {
struct mxc_gpio_port {
	hrtimer_init(&sig->real_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);struct mxc_gpio_port {
	sig->real_timer.function = it_real_fn;struct mxc_gpio_port {
struct mxc_gpio_port {
	task_lock(current->group_leader);struct mxc_gpio_port {
	memcpy(sig->rlim, current->signal->rlim, sizeof sig->rlim);struct mxc_gpio_port {
	task_unlock(current->group_leader);struct mxc_gpio_port {
struct mxc_gpio_port {
	posix_cpu_timers_init_group(sig);struct mxc_gpio_port {
struct mxc_gpio_port {
	tty_audit_fork(sig);struct mxc_gpio_port {
	sched_autogroup_fork(sig);struct mxc_gpio_port {
struct mxc_gpio_port {
#ifdef CONFIG_CGROUPSstruct mxc_gpio_port {
	init_rwsem(&sig->group_rwsem);struct mxc_gpio_port {
#endifstruct mxc_gpio_port {
struct mxc_gpio_port {
	sig->oom_score_adj = current->signal->oom_score_adj;struct mxc_gpio_port {
	sig->oom_score_adj_min = current->signal->oom_score_adj_min;struct mxc_gpio_port {
struct mxc_gpio_port {
	sig->has_child_subreaper = current->signal->has_child_subreaper ||struct mxc_gpio_port {
				   current->signal->is_child_subreaper;struct mxc_gpio_port {
struct mxc_gpio_port {
	mutex_init(&sig->cred_guard_mutex);struct mxc_gpio_port {
struct mxc_gpio_port {
	return 0;struct mxc_gpio_port {
}struct mxc_gpio_port {
struct mxc_gpio_port {
static void copy_flags(unsigned long clone_flags, struct task_struct *p)struct mxc_gpio_port {
{struct mxc_gpio_port {
	unsigned long new_flags = p->flags;struct mxc_gpio_port {
struct mxc_gpio_port {
	new_flags &= ~(PF_SUPERPRIV | PF_WQ_WORKER);struct mxc_gpio_port {
	new_flags |= PF_FORKNOEXEC;struct mxc_gpio_port {
	p->flags = new_flags;struct mxc_gpio_port {
}struct mxc_gpio_port {
struct mxc_gpio_port {
SYSCALL_DEFINE1(set_tid_address, int __user *, tidptr)struct mxc_gpio_port {
{struct mxc_gpio_port {
	current->clear_child_tid = tidptr;struct mxc_gpio_port {
struct mxc_gpio_port {
	return task_pid_vnr(current);struct mxc_gpio_port {
}struct mxc_gpio_port {
struct mxc_gpio_port {
static void rt_mutex_init_task(struct task_struct *p)struct mxc_gpio_port {
{struct mxc_gpio_port {
	raw_spin_lock_init(&p->pi_lock);struct mxc_gpio_port {
#ifdef CONFIG_RT_MUTEXESstruct mxc_gpio_port {
	p->pi_waiters = RB_ROOT;struct mxc_gpio_port {
	p->pi_waiters_leftmost = NULL;struct mxc_gpio_port {
	p->pi_blocked_on = NULL;struct mxc_gpio_port {
	p->pi_top_task = NULL;struct mxc_gpio_port {
#endifstruct mxc_gpio_port {
}struct mxc_gpio_port {
struct mxc_gpio_port {
#ifdef CONFIG_MM_OWNERstruct mxc_gpio_port {
void mm_init_owner(struct mm_struct *mm, struct task_struct *p)struct mxc_gpio_port {
{struct mxc_gpio_port {
	mm->owner = p;struct mxc_gpio_port {
}struct mxc_gpio_port {
#endif /* CONFIG_MM_OWNER */struct mxc_gpio_port {
struct mxc_gpio_port {
/*struct mxc_gpio_port {
 * Initialize POSIX timer handling for a single task.struct mxc_gpio_port {
 */struct mxc_gpio_port {
static void posix_cpu_timers_init(struct task_struct *tsk)struct mxc_gpio_port {
{struct mxc_gpio_port {
	tsk->cputime_expires.prof_exp = 0;struct mxc_gpio_port {
	tsk->cputime_expires.virt_exp = 0;struct mxc_gpio_port {
	tsk->cputime_expires.sched_exp = 0;struct mxc_gpio_port {
	INIT_LIST_HEAD(&tsk->cpu_timers[0]);struct mxc_gpio_port {
	INIT_LIST_HEAD(&tsk->cpu_timers[1]);struct mxc_gpio_port {
	INIT_LIST_HEAD(&tsk->cpu_timers[2]);struct mxc_gpio_port {
}struct mxc_gpio_port {
struct mxc_gpio_port {
static inline voidstruct mxc_gpio_port {
init_task_pid(struct task_struct *task, enum pid_type type, struct pid *pid)struct mxc_gpio_port {
{struct mxc_gpio_port {
	 task->pids[type].pid = pid;struct mxc_gpio_port {
}struct mxc_gpio_port {
struct mxc_gpio_port {
/*struct mxc_gpio_port {
 * This creates a new process as a copy of the old one,struct mxc_gpio_port {
 * but does not actually start it yet.struct mxc_gpio_port {
 *struct mxc_gpio_port {
 * It copies the registers, and all the appropriatestruct mxc_gpio_port {
 * parts of the process environment (as per the clonestruct mxc_gpio_port {
 * flags). The actual kick-off is left to the caller.struct mxc_gpio_port {
 */struct mxc_gpio_port {
static struct task_struct *copy_process(unsigned long clone_flags,struct mxc_gpio_port {
					unsigned long stack_start,struct mxc_gpio_port {
					unsigned long stack_size,struct mxc_gpio_port {
					int __user *child_tidptr,struct mxc_gpio_port {
					struct pid *pid,struct mxc_gpio_port {
					int trace)struct mxc_gpio_port {
{struct mxc_gpio_port {
	int retval;struct mxc_gpio_port {
	struct task_struct *p;struct mxc_gpio_port {
struct mxc_gpio_port {
	if ((clone_flags & (CLONE_NEWNS|CLONE_FS)) == (CLONE_NEWNS|CLONE_FS))struct mxc_gpio_port {
		return ERR_PTR(-EINVAL);struct mxc_gpio_port {
struct mxc_gpio_port {
	if ((clone_flags & (CLONE_NEWUSER|CLONE_FS)) == (CLONE_NEWUSER|CLONE_FS))struct mxc_gpio_port {
		return ERR_PTR(-EINVAL);struct mxc_gpio_port {
struct mxc_gpio_port {
	/*struct mxc_gpio_port {
	 * Thread groups must share signals as well, and detached threadsstruct mxc_gpio_port {
	 * can only be started up within the thread group.struct mxc_gpio_port {
	 */struct mxc_gpio_port {
	if ((clone_flags & CLONE_THREAD) && !(clone_flags & CLONE_SIGHAND))struct mxc_gpio_port {
		return ERR_PTR(-EINVAL);struct mxc_gpio_port {
struct mxc_gpio_port {
	/*struct mxc_gpio_port {
	 * Shared signal handlers imply shared VM. By way of the above,struct mxc_gpio_port {
	 * thread groups also imply shared VM. Blocking this case allowsstruct mxc_gpio_port {
	 * for various simplifications in other code.struct mxc_gpio_port {
	 */struct mxc_gpio_port {
	if ((clone_flags & CLONE_SIGHAND) && !(clone_flags & CLONE_VM))struct mxc_gpio_port {
		return ERR_PTR(-EINVAL);struct mxc_gpio_port {
struct mxc_gpio_port {
	/*struct mxc_gpio_port {
	 * Siblings of global init remain as zombies on exit since they arestruct mxc_gpio_port {
	 * not reaped by their parent (swapper). To solve this and to avoidstruct mxc_gpio_port {
	 * multi-rooted process trees, prevent global and container-initsstruct mxc_gpio_port {
	 * from creating siblings.struct mxc_gpio_port {
	 */struct mxc_gpio_port {
	if ((clone_flags & CLONE_PARENT) &&struct mxc_gpio_port {
				current->signal->flags & SIGNAL_UNKILLABLE)struct mxc_gpio_port {
		return ERR_PTR(-EINVAL);struct mxc_gpio_port {
struct mxc_gpio_port {
	/*struct mxc_gpio_port {
	 * If the new process will be in a different pid or user namespacestruct mxc_gpio_port {
	 * do not allow it to share a thread group or signal handlers orstruct mxc_gpio_port {
	 * parent with the forking task.struct mxc_gpio_port {
	 */struct mxc_gpio_port {
	if (clone_flags & CLONE_SIGHAND) {struct mxc_gpio_port {
		if ((clone_flags & (CLONE_NEWUSER | CLONE_NEWPID)) ||struct mxc_gpio_port {
		    (task_active_pid_ns(current) !=struct mxc_gpio_port {
				current->nsproxy->pid_ns_for_children))struct mxc_gpio_port {
			return ERR_PTR(-EINVAL);struct mxc_gpio_port {
	}struct mxc_gpio_port {
struct mxc_gpio_port {
	retval = security_task_create(clone_flags);struct mxc_gpio_port {
	if (retval)struct mxc_gpio_port {
		goto fork_out;struct mxc_gpio_port {
struct mxc_gpio_port {
	retval = -ENOMEM;struct mxc_gpio_port {
	p = dup_task_struct(current);struct mxc_gpio_port {
	if (!p)struct mxc_gpio_port {
		goto fork_out;struct mxc_gpio_port {
struct mxc_gpio_port {
	ftrace_graph_init_task(p);struct mxc_gpio_port {
	get_seccomp_filter(p);struct mxc_gpio_port {
struct mxc_gpio_port {
	rt_mutex_init_task(p);struct mxc_gpio_port {
struct mxc_gpio_port {
#ifdef CONFIG_PROVE_LOCKINGstruct mxc_gpio_port {
	DEBUG_LOCKS_WARN_ON(!p->hardirqs_enabled);struct mxc_gpio_port {
	DEBUG_LOCKS_WARN_ON(!p->softirqs_enabled);struct mxc_gpio_port {
#endifstruct mxc_gpio_port {
	retval = -EAGAIN;struct mxc_gpio_port {
	if (atomic_read(&p->real_cred->user->processes) >=struct mxc_gpio_port {
			task_rlimit(p, RLIMIT_NPROC)) {struct mxc_gpio_port {
		if (p->real_cred->user != INIT_USER &&struct mxc_gpio_port {
		    !capable(CAP_SYS_RESOURCE) && !capable(CAP_SYS_ADMIN))struct mxc_gpio_port {
			goto bad_fork_free;struct mxc_gpio_port {
	}struct mxc_gpio_port {
	current->flags &= ~PF_NPROC_EXCEEDED;struct mxc_gpio_port {
struct mxc_gpio_port {
	retval = copy_creds(p, clone_flags);struct mxc_gpio_port {
	if (retval < 0)struct mxc_gpio_port {
		goto bad_fork_free;struct mxc_gpio_port {
struct mxc_gpio_port {
	/*struct mxc_gpio_port {
	 * If multiple threads are within copy_process(), then this checkstruct mxc_gpio_port {
	 * triggers too late. This doesn't hurt, the check is only therestruct mxc_gpio_port {
	 * to stop root fork bombs.struct mxc_gpio_port {
	 */struct mxc_gpio_port {
	retval = -EAGAIN;struct mxc_gpio_port {
	if (nr_threads >= max_threads)struct mxc_gpio_port {
		goto bad_fork_cleanup_count;struct mxc_gpio_port {
struct mxc_gpio_port {
	if (!try_module_get(task_thread_info(p)->exec_domain->module))struct mxc_gpio_port {
		goto bad_fork_cleanup_count;struct mxc_gpio_port {
struct mxc_gpio_port {
	delayacct_tsk_init(p);	/* Must remain after dup_task_struct() */struct mxc_gpio_port {
	copy_flags(clone_flags, p);struct mxc_gpio_port {
	INIT_LIST_HEAD(&p->children);struct mxc_gpio_port {
	INIT_LIST_HEAD(&p->sibling);struct mxc_gpio_port {
	rcu_copy_process(p);struct mxc_gpio_port {
	p->vfork_done = NULL;struct mxc_gpio_port {
	spin_lock_init(&p->alloc_lock);struct mxc_gpio_port {
struct mxc_gpio_port {
	init_sigpending(&p->pending);struct mxc_gpio_port {
struct mxc_gpio_port {
	p->utime = p->stime = p->gtime = 0;struct mxc_gpio_port {
	p->utimescaled = p->stimescaled = 0;struct mxc_gpio_port {
#ifndef CONFIG_VIRT_CPU_ACCOUNTING_NATIVEstruct mxc_gpio_port {
	p->prev_cputime.utime = p->prev_cputime.stime = 0;struct mxc_gpio_port {
#endifstruct mxc_gpio_port {
#ifdef CONFIG_VIRT_CPU_ACCOUNTING_GENstruct mxc_gpio_port {
	seqlock_init(&p->vtime_seqlock);struct mxc_gpio_port {
	p->vtime_snap = 0;struct mxc_gpio_port {
	p->vtime_snap_whence = VTIME_SLEEPING;struct mxc_gpio_port {
#endifstruct mxc_gpio_port {
struct mxc_gpio_port {
#if defined(SPLIT_RSS_COUNTING)struct mxc_gpio_port {
	memset(&p->rss_stat, 0, sizeof(p->rss_stat));struct mxc_gpio_port {
#endifstruct mxc_gpio_port {
struct mxc_gpio_port {
	p->default_timer_slack_ns = current->timer_slack_ns;struct mxc_gpio_port {
struct mxc_gpio_port {
	task_io_accounting_init(&p->ioac);struct mxc_gpio_port {
	acct_clear_integrals(p);struct mxc_gpio_port {
struct mxc_gpio_port {
	posix_cpu_timers_init(p);struct mxc_gpio_port {
struct mxc_gpio_port {
	do_posix_clock_monotonic_gettime(&p->start_time);struct mxc_gpio_port {
	p->real_start_time = p->start_time;struct mxc_gpio_port {
	monotonic_to_bootbased(&p->real_start_time);struct mxc_gpio_port {
	p->io_context = NULL;struct mxc_gpio_port {
	p->audit_context = NULL;struct mxc_gpio_port {
	if (clone_flags & CLONE_THREAD)struct mxc_gpio_port {
		threadgroup_change_begin(current);struct mxc_gpio_port {
	cgroup_fork(p);struct mxc_gpio_port {
#ifdef CONFIG_NUMAstruct mxc_gpio_port {
	p->mempolicy = mpol_dup(p->mempolicy);struct mxc_gpio_port {
	if (IS_ERR(p->mempolicy)) {struct mxc_gpio_port {
		retval = PTR_ERR(p->mempolicy);struct mxc_gpio_port {
		p->mempolicy = NULL;struct mxc_gpio_port {
		goto bad_fork_cleanup_cgroup;struct mxc_gpio_port {
	}struct mxc_gpio_port {
	mpol_fix_fork_child_flag(p);struct mxc_gpio_port {
#endifstruct mxc_gpio_port {
#ifdef CONFIG_CPUSETSstruct mxc_gpio_port {
	p->cpuset_mem_spread_rotor = NUMA_NO_NODE;struct mxc_gpio_port {
	p->cpuset_slab_spread_rotor = NUMA_NO_NODE;struct mxc_gpio_port {
	seqcount_init(&p->mems_allowed_seq);struct mxc_gpio_port {
#endifstruct mxc_gpio_port {
#ifdef CONFIG_TRACE_IRQFLAGSstruct mxc_gpio_port {
	p->irq_events = 0;struct mxc_gpio_port {
	p->hardirqs_enabled = 0;struct mxc_gpio_port {
	p->hardirq_enable_ip = 0;struct mxc_gpio_port {
	p->hardirq_enable_event = 0;struct mxc_gpio_port {
	p->hardirq_disable_ip = _THIS_IP_;struct mxc_gpio_port {
	p->hardirq_disable_event = 0;struct mxc_gpio_port {
	p->softirqs_enabled = 1;struct mxc_gpio_port {
	p->softirq_enable_ip = _THIS_IP_;struct mxc_gpio_port {
	p->softirq_enable_event = 0;struct mxc_gpio_port {
	p->softirq_disable_ip = 0;struct mxc_gpio_port {
	p->softirq_disable_event = 0;struct mxc_gpio_port {
	p->hardirq_context = 0;struct mxc_gpio_port {
	p->softirq_context = 0;struct mxc_gpio_port {
#endifstruct mxc_gpio_port {
#ifdef CONFIG_LOCKDEPstruct mxc_gpio_port {
	p->lockdep_depth = 0; /* no locks held yet */struct mxc_gpio_port {
	p->curr_chain_key = 0;struct mxc_gpio_port {
	p->lockdep_recursion = 0;struct mxc_gpio_port {
#endifstruct mxc_gpio_port {
struct mxc_gpio_port {
#ifdef CONFIG_DEBUG_MUTEXESstruct mxc_gpio_port {
	p->blocked_on = NULL; /* not blocked yet */struct mxc_gpio_port {
#endifstruct mxc_gpio_port {
#ifdef CONFIG_MEMCGstruct mxc_gpio_port {
	p->memcg_batch.do_batch = 0;struct mxc_gpio_port {
	p->memcg_batch.memcg = NULL;struct mxc_gpio_port {
#endifstruct mxc_gpio_port {
#ifdef CONFIG_BCACHEstruct mxc_gpio_port {
	p->sequential_io	= 0;struct mxc_gpio_port {
	p->sequential_io_avg	= 0;struct mxc_gpio_port {
#endifstruct mxc_gpio_port {
struct mxc_gpio_port {
	/* Perform scheduler related setup. Assign this task to a CPU. */struct mxc_gpio_port {
	retval = sched_fork(clone_flags, p);struct mxc_gpio_port {
	if (retval)struct mxc_gpio_port {
		goto bad_fork_cleanup_policy;struct mxc_gpio_port {
struct mxc_gpio_port {
	retval = perf_event_init_task(p);struct mxc_gpio_port {
	if (retval)struct mxc_gpio_port {
		goto bad_fork_cleanup_policy;struct mxc_gpio_port {
	retval = audit_alloc(p);struct mxc_gpio_port {
	if (retval)struct mxc_gpio_port {
		goto bad_fork_cleanup_policy;struct mxc_gpio_port {
	/* copy all the process information */struct mxc_gpio_port {
	retval = copy_semundo(clone_flags, p);struct mxc_gpio_port {
	if (retval)struct mxc_gpio_port {
		goto bad_fork_cleanup_audit;struct mxc_gpio_port {
	retval = copy_files(clone_flags, p);struct mxc_gpio_port {
	if (retval)struct mxc_gpio_port {
		goto bad_fork_cleanup_semundo;struct mxc_gpio_port {
	retval = copy_fs(clone_flags, p);struct mxc_gpio_port {
	if (retval)struct mxc_gpio_port {
		goto bad_fork_cleanup_files;struct mxc_gpio_port {
	retval = copy_sighand(clone_flags, p);struct mxc_gpio_port {
	if (retval)struct mxc_gpio_port {
		goto bad_fork_cleanup_fs;struct mxc_gpio_port {
	retval = copy_signal(clone_flags, p);struct mxc_gpio_port {
	if (retval)struct mxc_gpio_port {
		goto bad_fork_cleanup_sighand;struct mxc_gpio_port {
	retval = copy_mm(clone_flags, p);struct mxc_gpio_port {
	if (retval)struct mxc_gpio_port {
		goto bad_fork_cleanup_signal;struct mxc_gpio_port {
	retval = copy_namespaces(clone_flags, p);struct mxc_gpio_port {
	if (retval)struct mxc_gpio_port {
		goto bad_fork_cleanup_mm;struct mxc_gpio_port {
	retval = copy_io(clone_flags, p);struct mxc_gpio_port {
	if (retval)struct mxc_gpio_port {
		goto bad_fork_cleanup_namespaces;struct mxc_gpio_port {
	retval = copy_thread(clone_flags, stack_start, stack_size, p);struct mxc_gpio_port {
	if (retval)struct mxc_gpio_port {
		goto bad_fork_cleanup_io;struct mxc_gpio_port {
struct mxc_gpio_port {
	if (pid != &init_struct_pid) {struct mxc_gpio_port {
		retval = -ENOMEM;struct mxc_gpio_port {
		pid = alloc_pid(p->nsproxy->pid_ns_for_children);struct mxc_gpio_port {
		if (!pid)struct mxc_gpio_port {
			goto bad_fork_cleanup_io;struct mxc_gpio_port {
	}struct mxc_gpio_port {
struct mxc_gpio_port {
	p->set_child_tid = (clone_flags & CLONE_CHILD_SETTID) ? child_tidptr : NULL;struct mxc_gpio_port {
	/*struct mxc_gpio_port {
	 * Clear TID on mm_release()?struct mxc_gpio_port {
	 */struct mxc_gpio_port {
	p->clear_child_tid = (clone_flags & CLONE_CHILD_CLEARTID) ? child_tidptr : NULL;struct mxc_gpio_port {
#ifdef CONFIG_BLOCKstruct mxc_gpio_port {
	p->plug = NULL;struct mxc_gpio_port {
#endifstruct mxc_gpio_port {
#ifdef CONFIG_FUTEXstruct mxc_gpio_port {
	p->robust_list = NULL;struct mxc_gpio_port {
#ifdef CONFIG_COMPATstruct mxc_gpio_port {
	p->compat_robust_list = NULL;struct mxc_gpio_port {
#endifstruct mxc_gpio_port {
	INIT_LIST_HEAD(&p->pi_state_list);struct mxc_gpio_port {
	p->pi_state_cache = NULL;struct mxc_gpio_port {
#endifstruct mxc_gpio_port {
	/*struct mxc_gpio_port {
	 * sigaltstack should be cleared when sharing the same VMstruct mxc_gpio_port {
	 */struct mxc_gpio_port {
	if ((clone_flags & (CLONE_VM|CLONE_VFORK)) == CLONE_VM)struct mxc_gpio_port {
		p->sas_ss_sp = p->sas_ss_size = 0;struct mxc_gpio_port {
struct mxc_gpio_port {
	/*struct mxc_gpio_port {
	 * Syscall tracing and stepping should be turned off in thestruct mxc_gpio_port {
	 * child regardless of CLONE_PTRACE.struct mxc_gpio_port {
	 */struct mxc_gpio_port {
	user_disable_single_step(p);struct mxc_gpio_port {
	clear_tsk_thread_flag(p, TIF_SYSCALL_TRACE);struct mxc_gpio_port {
#ifdef TIF_SYSCALL_EMUstruct mxc_gpio_port {
	clear_tsk_thread_flag(p, TIF_SYSCALL_EMU);struct mxc_gpio_port {
#endifstruct mxc_gpio_port {
	clear_all_latency_tracing(p);struct mxc_gpio_port {
struct mxc_gpio_port {
	/* ok, now we should be set up.. */struct mxc_gpio_port {
	p->pid = pid_nr(pid);struct mxc_gpio_port {
	if (clone_flags & CLONE_THREAD) {struct mxc_gpio_port {
		p->exit_signal = -1;struct mxc_gpio_port {
		p->group_leader = current->group_leader;struct mxc_gpio_port {
		p->tgid = current->tgid;struct mxc_gpio_port {
	} else {struct mxc_gpio_port {
		if (clone_flags & CLONE_PARENT)struct mxc_gpio_port {
			p->exit_signal = current->group_leader->exit_signal;struct mxc_gpio_port {
		elsestruct mxc_gpio_port {
			p->exit_signal = (clone_flags & CSIGNAL);struct mxc_gpio_port {
		p->group_leader = p;struct mxc_gpio_port {
		p->tgid = p->pid;struct mxc_gpio_port {
	}struct mxc_gpio_port {
struct mxc_gpio_port {
	p->nr_dirtied = 0;struct mxc_gpio_port {
	p->nr_dirtied_pause = 128 >> (PAGE_SHIFT - 10);struct mxc_gpio_port {
	p->dirty_paused_when = 0;struct mxc_gpio_port {
struct mxc_gpio_port {
	p->pdeath_signal = 0;struct mxc_gpio_port {
	INIT_LIST_HEAD(&p->thread_group);struct mxc_gpio_port {
	p->task_works = NULL;struct mxc_gpio_port {
struct mxc_gpio_port {
	/*struct mxc_gpio_port {
	 * Make it visible to the rest of the system, but dont wake it up yet.struct mxc_gpio_port {
	 * Need tasklist lock for parent etc handling!struct mxc_gpio_port {
	 */struct mxc_gpio_port {
	write_lock_irq(&tasklist_lock);struct mxc_gpio_port {
struct mxc_gpio_port {
	/* CLONE_PARENT re-uses the old parent */struct mxc_gpio_port {
	if (clone_flags & (CLONE_PARENT|CLONE_THREAD)) {struct mxc_gpio_port {
		p->real_parent = current->real_parent;struct mxc_gpio_port {
		p->parent_exec_id = current->parent_exec_id;struct mxc_gpio_port {
	} else {struct mxc_gpio_port {
		p->real_parent = current;struct mxc_gpio_port {
		p->parent_exec_id = current->self_exec_id;struct mxc_gpio_port {
	}struct mxc_gpio_port {
struct mxc_gpio_port {
	spin_lock(&current->sighand->siglock);struct mxc_gpio_port {
struct mxc_gpio_port {
	/*struct mxc_gpio_port {
	 * Process group and session signals need to be delivered to just thestruct mxc_gpio_port {
	 * parent before the fork or both the parent and the child after thestruct mxc_gpio_port {
	 * fork. Restart if a signal comes in before we add the new process tostruct mxc_gpio_port {
	 * it's process group.struct mxc_gpio_port {
	 * A fatal signal pending means that current will exit, so the newstruct mxc_gpio_port {
	 * thread can't slip out of an OOM kill (or normal SIGKILL).struct mxc_gpio_port {
	*/struct mxc_gpio_port {
	recalc_sigpending();struct mxc_gpio_port {
	if (signal_pending(current)) {struct mxc_gpio_port {
		spin_unlock(&current->sighand->siglock);struct mxc_gpio_port {
		write_unlock_irq(&tasklist_lock);struct mxc_gpio_port {
		retval = -ERESTARTNOINTR;struct mxc_gpio_port {
		goto bad_fork_free_pid;struct mxc_gpio_port {
	}struct mxc_gpio_port {
struct mxc_gpio_port {
	if (likely(p->pid)) {struct mxc_gpio_port {
		ptrace_init_task(p, (clone_flags & CLONE_PTRACE) || trace);struct mxc_gpio_port {
struct mxc_gpio_port {
		init_task_pid(p, PIDTYPE_PID, pid);struct mxc_gpio_port {
		if (thread_group_leader(p)) {struct mxc_gpio_port {
			init_task_pid(p, PIDTYPE_PGID, task_pgrp(current));struct mxc_gpio_port {
			init_task_pid(p, PIDTYPE_SID, task_session(current));struct mxc_gpio_port {
struct mxc_gpio_port {
			if (is_child_reaper(pid)) {struct mxc_gpio_port {
				ns_of_pid(pid)->child_reaper = p;struct mxc_gpio_port {
				p->signal->flags |= SIGNAL_UNKILLABLE;struct mxc_gpio_port {
			}struct mxc_gpio_port {
struct mxc_gpio_port {
			p->signal->leader_pid = pid;struct mxc_gpio_port {
			p->signal->tty = tty_kref_get(current->signal->tty);struct mxc_gpio_port {
			list_add_tail(&p->sibling, &p->real_parent->children);struct mxc_gpio_port {
			list_add_tail_rcu(&p->tasks, &init_task.tasks);struct mxc_gpio_port {
			attach_pid(p, PIDTYPE_PGID);struct mxc_gpio_port {
			attach_pid(p, PIDTYPE_SID);struct mxc_gpio_port {
			__this_cpu_inc(process_counts);struct mxc_gpio_port {
		} else {struct mxc_gpio_port {
			current->signal->nr_threads++;struct mxc_gpio_port {
			atomic_inc(&current->signal->live);struct mxc_gpio_port {
			atomic_inc(&current->signal->sigcnt);struct mxc_gpio_port {
			list_add_tail_rcu(&p->thread_group,struct mxc_gpio_port {
					  &p->group_leader->thread_group);struct mxc_gpio_port {
			list_add_tail_rcu(&p->thread_node,struct mxc_gpio_port {
					  &p->signal->thread_head);struct mxc_gpio_port {
		}struct mxc_gpio_port {
		attach_pid(p, PIDTYPE_PID);struct mxc_gpio_port {
		nr_threads++;struct mxc_gpio_port {
	}struct mxc_gpio_port {
struct mxc_gpio_port {
	total_forks++;struct mxc_gpio_port {
	spin_unlock(&current->sighand->siglock);struct mxc_gpio_port {
	write_unlock_irq(&tasklist_lock);struct mxc_gpio_port {
	proc_fork_connector(p);struct mxc_gpio_port {
	cgroup_post_fork(p);struct mxc_gpio_port {
	if (clone_flags & CLONE_THREAD)struct mxc_gpio_port {
		threadgroup_change_end(current);struct mxc_gpio_port {
	perf_event_fork(p);struct mxc_gpio_port {
struct mxc_gpio_port {
	trace_task_newtask(p, clone_flags);struct mxc_gpio_port {
	uprobe_copy_process(p, clone_flags);struct mxc_gpio_port {
struct mxc_gpio_port {
	return p;struct mxc_gpio_port {
struct mxc_gpio_port {
bad_fork_free_pid:struct mxc_gpio_port {
	if (pid != &init_struct_pid)struct mxc_gpio_port {
		free_pid(pid);struct mxc_gpio_port {
bad_fork_cleanup_io:struct mxc_gpio_port {
	if (p->io_context)struct mxc_gpio_port {
		exit_io_context(p);struct mxc_gpio_port {
bad_fork_cleanup_namespaces:struct mxc_gpio_port {
	exit_task_namespaces(p);struct mxc_gpio_port {
bad_fork_cleanup_mm:struct mxc_gpio_port {
	if (p->mm)struct mxc_gpio_port {
		mmput(p->mm);struct mxc_gpio_port {
bad_fork_cleanup_signal:struct mxc_gpio_port {
	if (!(clone_flags & CLONE_THREAD))struct mxc_gpio_port {
		free_signal_struct(p->signal);struct mxc_gpio_port {
bad_fork_cleanup_sighand:struct mxc_gpio_port {
	__cleanup_sighand(p->sighand);struct mxc_gpio_port {
bad_fork_cleanup_fs:struct mxc_gpio_port {
	exit_fs(p); /* blocking */struct mxc_gpio_port {
bad_fork_cleanup_files:struct mxc_gpio_port {
	exit_files(p); /* blocking */struct mxc_gpio_port {
bad_fork_cleanup_semundo:struct mxc_gpio_port {
	exit_sem(p);struct mxc_gpio_port {
bad_fork_cleanup_audit:struct mxc_gpio_port {
	audit_free(p);struct mxc_gpio_port {
bad_fork_cleanup_policy:struct mxc_gpio_port {
	perf_event_free_task(p);struct mxc_gpio_port {
#ifdef CONFIG_NUMAstruct mxc_gpio_port {
	mpol_put(p->mempolicy);struct mxc_gpio_port {
bad_fork_cleanup_cgroup:struct mxc_gpio_port {
#endifstruct mxc_gpio_port {
	if (clone_flags & CLONE_THREAD)struct mxc_gpio_port {
		threadgroup_change_end(current);struct mxc_gpio_port {
	cgroup_exit(p, 0);struct mxc_gpio_port {
	delayacct_tsk_free(p);struct mxc_gpio_port {
	module_put(task_thread_info(p)->exec_domain->module);struct mxc_gpio_port {
bad_fork_cleanup_count:struct mxc_gpio_port {
	atomic_dec(&p->cred->user->processes);struct mxc_gpio_port {
	exit_creds(p);struct mxc_gpio_port {
bad_fork_free:struct mxc_gpio_port {
	free_task(p);struct mxc_gpio_port {
fork_out:struct mxc_gpio_port {
	return ERR_PTR(retval);struct mxc_gpio_port {
}struct mxc_gpio_port {
struct mxc_gpio_port {
static inline void init_idle_pids(struct pid_link *links)struct mxc_gpio_port {
{struct mxc_gpio_port {
	enum pid_type type;struct mxc_gpio_port {
struct mxc_gpio_port {
	for (type = PIDTYPE_PID; type < PIDTYPE_MAX; ++type) {struct mxc_gpio_port {
		INIT_HLIST_NODE(&links[type].node); /* not really needed */struct mxc_gpio_port {
		links[type].pid = &init_struct_pid;struct mxc_gpio_port {
	}struct mxc_gpio_port {
}struct mxc_gpio_port {
struct mxc_gpio_port {
struct task_struct *fork_idle(int cpu)struct mxc_gpio_port {
{struct mxc_gpio_port {
	struct task_struct *task;struct mxc_gpio_port {
	task = copy_process(CLONE_VM, 0, 0, NULL, &init_struct_pid, 0);struct mxc_gpio_port {
	if (!IS_ERR(task)) {struct mxc_gpio_port {
		init_idle_pids(task->pids);struct mxc_gpio_port {
		init_idle(task, cpu);struct mxc_gpio_port {
	}struct mxc_gpio_port {
struct mxc_gpio_port {
	return task;struct mxc_gpio_port {
}struct mxc_gpio_port {
struct mxc_gpio_port {
/*struct mxc_gpio_port {
 *  Ok, this is the main fork-routine.struct mxc_gpio_port {
 *struct mxc_gpio_port {
 * It copies the process, and if successful kick-startsstruct mxc_gpio_port {
 * it and waits for it to finish using the VM if required.struct mxc_gpio_port {
 */struct mxc_gpio_port {
long do_fork(unsigned long clone_flags,struct mxc_gpio_port {
	      unsigned long stack_start,struct mxc_gpio_port {
	      unsigned long stack_size,struct mxc_gpio_port {
	      int __user *parent_tidptr,struct mxc_gpio_port {
	      int __user *child_tidptr)struct mxc_gpio_port {
{struct mxc_gpio_port {
	struct task_struct *p;struct mxc_gpio_port {
	int trace = 0;struct mxc_gpio_port {
	long nr;struct mxc_gpio_port {
struct mxc_gpio_port {
	/*struct mxc_gpio_port {
	 * Determine whether and which event to report to ptracer.  Whenstruct mxc_gpio_port {
	 * called from kernel_thread or CLONE_UNTRACED is explicitlystruct mxc_gpio_port {
	 * requested, no event is reported; otherwise, report if the eventstruct mxc_gpio_port {
	 * for the type of forking is enabled.struct mxc_gpio_port {
	 */struct mxc_gpio_port {
	if (!(clone_flags & CLONE_UNTRACED)) {struct mxc_gpio_port {
		if (clone_flags & CLONE_VFORK)struct mxc_gpio_port {
			trace = PTRACE_EVENT_VFORK;struct mxc_gpio_port {
		else if ((clone_flags & CSIGNAL) != SIGCHLD)struct mxc_gpio_port {
			trace = PTRACE_EVENT_CLONE;struct mxc_gpio_port {
		elsestruct mxc_gpio_port {
			trace = PTRACE_EVENT_FORK;struct mxc_gpio_port {
struct mxc_gpio_port {
		if (likely(!ptrace_event_enabled(current, trace)))struct mxc_gpio_port {
			trace = 0;struct mxc_gpio_port {
	}struct mxc_gpio_port {
struct mxc_gpio_port {
	p = copy_process(clone_flags, stack_start, stack_size,struct mxc_gpio_port {
			 child_tidptr, NULL, trace);struct mxc_gpio_port {
	/*struct mxc_gpio_port {
	 * Do this prior waking up the new thread - the thread pointerstruct mxc_gpio_port {
	 * might get invalid after that point, if the thread exits quickly.struct mxc_gpio_port {
	 */struct mxc_gpio_port {
	if (!IS_ERR(p)) {struct mxc_gpio_port {
		struct completion vfork;struct mxc_gpio_port {
struct mxc_gpio_port {
		trace_sched_process_fork(current, p);struct mxc_gpio_port {
struct mxc_gpio_port {
		nr = task_pid_vnr(p);struct mxc_gpio_port {
struct mxc_gpio_port {
		if (clone_flags & CLONE_PARENT_SETTID)struct mxc_gpio_port {
			put_user(nr, parent_tidptr);struct mxc_gpio_port {
struct mxc_gpio_port {
		if (clone_flags & CLONE_VFORK) {struct mxc_gpio_port {
			p->vfork_done = &vfork;struct mxc_gpio_port {
			init_completion(&vfork);struct mxc_gpio_port {
			get_task_struct(p);struct mxc_gpio_port {
		}struct mxc_gpio_port {
struct mxc_gpio_port {
		wake_up_new_task(p);struct mxc_gpio_port {
struct mxc_gpio_port {
		/* forking complete and child started to run, tell ptracer */struct mxc_gpio_port {
		if (unlikely(trace))struct mxc_gpio_port {
			ptrace_event(trace, nr);struct mxc_gpio_port {
struct mxc_gpio_port {
		if (clone_flags & CLONE_VFORK) {struct mxc_gpio_port {
			if (!wait_for_vfork_done(p, &vfork))struct mxc_gpio_port {
				ptrace_event(PTRACE_EVENT_VFORK_DONE, nr);struct mxc_gpio_port {
		}struct mxc_gpio_port {
	} else {struct mxc_gpio_port {
		nr = PTR_ERR(p);struct mxc_gpio_port {
	}struct mxc_gpio_port {
	return nr;struct mxc_gpio_port {
}struct mxc_gpio_port {
struct mxc_gpio_port {
/*struct mxc_gpio_port {
 * Create a kernel thread.struct mxc_gpio_port {
 */struct mxc_gpio_port {
pid_t kernel_thread(int (*fn)(void *), void *arg, unsigned long flags)struct mxc_gpio_port {
{struct mxc_gpio_port {
	return do_fork(flags|CLONE_VM|CLONE_UNTRACED, (unsigned long)fn,struct mxc_gpio_port {
		(unsigned long)arg, NULL, NULL);struct mxc_gpio_port {
}struct mxc_gpio_port {
struct mxc_gpio_port {
#ifdef __ARCH_WANT_SYS_FORKstruct mxc_gpio_port {
SYSCALL_DEFINE0(fork)struct mxc_gpio_port {
{struct mxc_gpio_port {
#ifdef CONFIG_MMUstruct mxc_gpio_port {
	return do_fork(SIGCHLD, 0, 0, NULL, NULL);struct mxc_gpio_port {
#elsestruct mxc_gpio_port {
	/* can not support in nommu mode */struct mxc_gpio_port {
	return -EINVAL;struct mxc_gpio_port {
#endifstruct mxc_gpio_port {
}struct mxc_gpio_port {
#endifstruct mxc_gpio_port {
struct mxc_gpio_port {
#ifdef __ARCH_WANT_SYS_VFORKstruct mxc_gpio_port {
SYSCALL_DEFINE0(vfork)struct mxc_gpio_port {
{struct mxc_gpio_port {
	return do_fork(CLONE_VFORK | CLONE_VM | SIGCHLD, 0,struct mxc_gpio_port {
			0, NULL, NULL);struct mxc_gpio_port {
}struct mxc_gpio_port {
#endifstruct mxc_gpio_port {
struct mxc_gpio_port {
#ifdef __ARCH_WANT_SYS_CLONEstruct mxc_gpio_port {
#ifdef CONFIG_CLONE_BACKWARDSstruct mxc_gpio_port {
SYSCALL_DEFINE5(clone, unsigned long, clone_flags, unsigned long, newsp,struct mxc_gpio_port {
		 int __user *, parent_tidptr,struct mxc_gpio_port {
		 int, tls_val,struct mxc_gpio_port {
		 int __user *, child_tidptr)struct mxc_gpio_port {
#elif defined(CONFIG_CLONE_BACKWARDS2)struct mxc_gpio_port {
SYSCALL_DEFINE5(clone, unsigned long, newsp, unsigned long, clone_flags,struct mxc_gpio_port {
		 int __user *, parent_tidptr,struct mxc_gpio_port {
		 int __user *, child_tidptr,struct mxc_gpio_port {
		 int, tls_val)struct mxc_gpio_port {
#elif defined(CONFIG_CLONE_BACKWARDS3)struct mxc_gpio_port {
SYSCALL_DEFINE6(clone, unsigned long, clone_flags, unsigned long, newsp,struct mxc_gpio_port {
		int, stack_size,struct mxc_gpio_port {
		int __user *, parent_tidptr,struct mxc_gpio_port {
		int __user *, child_tidptr,struct mxc_gpio_port {
		int, tls_val)struct mxc_gpio_port {
#elsestruct mxc_gpio_port {
SYSCALL_DEFINE5(clone, unsigned long, clone_flags, unsigned long, newsp,struct mxc_gpio_port {
		 int __user *, parent_tidptr,struct mxc_gpio_port {
		 int __user *, child_tidptr,struct mxc_gpio_port {
		 int, tls_val)struct mxc_gpio_port {
#endifstruct mxc_gpio_port {
{struct mxc_gpio_port {
	return do_fork(clone_flags, newsp, 0, parent_tidptr, child_tidptr);struct mxc_gpio_port {
}struct mxc_gpio_port {
#endifstruct mxc_gpio_port {
struct mxc_gpio_port {
#ifndef ARCH_MIN_MMSTRUCT_ALIGNstruct mxc_gpio_port {
#define ARCH_MIN_MMSTRUCT_ALIGN 0struct mxc_gpio_port {
#endifstruct mxc_gpio_port {
struct mxc_gpio_port {
static void sighand_ctor(void *data)struct mxc_gpio_port {
{struct mxc_gpio_port {
	struct sighand_struct *sighand = data;struct mxc_gpio_port {
struct mxc_gpio_port {
	spin_lock_init(&sighand->siglock);struct mxc_gpio_port {
	init_waitqueue_head(&sighand->signalfd_wqh);struct mxc_gpio_port {
}struct mxc_gpio_port {
struct mxc_gpio_port {
void __init proc_caches_init(void)struct mxc_gpio_port {
{struct mxc_gpio_port {
	sighand_cachep = kmem_cache_create("sighand_cache",struct mxc_gpio_port {
			sizeof(struct sighand_struct), 0,struct mxc_gpio_port {
			SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_DESTROY_BY_RCU|struct mxc_gpio_port {
			SLAB_NOTRACK, sighand_ctor);struct mxc_gpio_port {
	signal_cachep = kmem_cache_create("signal_cache",struct mxc_gpio_port {
			sizeof(struct signal_struct), 0,struct mxc_gpio_port {
			SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_NOTRACK, NULL);struct mxc_gpio_port {
	files_cachep = kmem_cache_create("files_cache",struct mxc_gpio_port {
			sizeof(struct files_struct), 0,struct mxc_gpio_port {
			SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_NOTRACK, NULL);struct mxc_gpio_port {
	fs_cachep = kmem_cache_create("fs_cache",struct mxc_gpio_port {
			sizeof(struct fs_struct), 0,struct mxc_gpio_port {
			SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_NOTRACK, NULL);struct mxc_gpio_port {
	/*struct mxc_gpio_port {
	 * FIXME! The "sizeof(struct mm_struct)" currently includes thestruct mxc_gpio_port {
	 * whole struct cpumask for the OFFSTACK case. We could changestruct mxc_gpio_port {
	 * this to *only* allocate as much of it as required by thestruct mxc_gpio_port {
	 * maximum number of CPU's we can ever have.  The cpumask_allocationstruct mxc_gpio_port {
	 * is at the end of the structure, exactly for that reason.struct mxc_gpio_port {
	 */struct mxc_gpio_port {
	mm_cachep = kmem_cache_create("mm_struct",struct mxc_gpio_port {
			sizeof(struct mm_struct), ARCH_MIN_MMSTRUCT_ALIGN,struct mxc_gpio_port {
			SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_NOTRACK, NULL);struct mxc_gpio_port {
	vm_area_cachep = KMEM_CACHE(vm_area_struct, SLAB_PANIC);struct mxc_gpio_port {
	mmap_init();struct mxc_gpio_port {
	nsproxy_cache_init();struct mxc_gpio_port {
}struct mxc_gpio_port {
struct mxc_gpio_port {
/*struct mxc_gpio_port {
 * Check constraints on flags passed to the unshare system call.struct mxc_gpio_port {
 */struct mxc_gpio_port {
static int check_unshare_flags(unsigned long unshare_flags)struct mxc_gpio_port {
{struct mxc_gpio_port {
	if (unshare_flags & ~(CLONE_THREAD|CLONE_FS|CLONE_NEWNS|CLONE_SIGHAND|struct mxc_gpio_port {
				CLONE_VM|CLONE_FILES|CLONE_SYSVSEM|struct mxc_gpio_port {
				CLONE_NEWUTS|CLONE_NEWIPC|CLONE_NEWNET|struct mxc_gpio_port {
				CLONE_NEWUSER|CLONE_NEWPID))struct mxc_gpio_port {
		return -EINVAL;struct mxc_gpio_port {
	/*struct mxc_gpio_port {
	 * Not implemented, but pretend it works if there is nothing tostruct mxc_gpio_port {
	 * unshare. Note that unsharing CLONE_THREAD or CLONE_SIGHANDstruct mxc_gpio_port {
	 * needs to unshare vm.struct mxc_gpio_port {
	 */struct mxc_gpio_port {
	if (unshare_flags & (CLONE_THREAD | CLONE_SIGHAND | CLONE_VM)) {struct mxc_gpio_port {
		/* FIXME: get_task_mm() increments ->mm_users */struct mxc_gpio_port {
		if (atomic_read(&current->mm->mm_users) > 1)struct mxc_gpio_port {
			return -EINVAL;struct mxc_gpio_port {
	}struct mxc_gpio_port {
struct mxc_gpio_port {
	return 0;struct mxc_gpio_port {
}struct mxc_gpio_port {
struct mxc_gpio_port {
/*struct mxc_gpio_port {
 * Unshare the filesystem structure if it is being sharedstruct mxc_gpio_port {
 */struct mxc_gpio_port {
static int unshare_fs(unsigned long unshare_flags, struct fs_struct **new_fsp)struct mxc_gpio_port {
{struct mxc_gpio_port {
	struct fs_struct *fs = current->fs;struct mxc_gpio_port {
struct mxc_gpio_port {
	if (!(unshare_flags & CLONE_FS) || !fs)struct mxc_gpio_port {
		return 0;struct mxc_gpio_port {
struct mxc_gpio_port {
	/* don't need lock here; in the worst case we'll do useless copy */struct mxc_gpio_port {
	if (fs->users == 1)struct mxc_gpio_port {
		return 0;struct mxc_gpio_port {
struct mxc_gpio_port {
	*new_fsp = copy_fs_struct(fs);struct mxc_gpio_port {
	if (!*new_fsp)struct mxc_gpio_port {
		return -ENOMEM;struct mxc_gpio_port {
struct mxc_gpio_port {
	return 0;struct mxc_gpio_port {
}struct mxc_gpio_port {
struct mxc_gpio_port {
/*struct mxc_gpio_port {
 * Unshare file descriptor table if it is being sharedstruct mxc_gpio_port {
 */struct mxc_gpio_port {
static int unshare_fd(unsigned long unshare_flags, struct files_struct **new_fdp)struct mxc_gpio_port {
{struct mxc_gpio_port {
	struct files_struct *fd = current->files;struct mxc_gpio_port {
	int error = 0;struct mxc_gpio_port {
struct mxc_gpio_port {
	if ((unshare_flags & CLONE_FILES) &&struct mxc_gpio_port {
	    (fd && atomic_read(&fd->count) > 1)) {struct mxc_gpio_port {
		*new_fdp = dup_fd(fd, &error);struct mxc_gpio_port {
		if (!*new_fdp)struct mxc_gpio_port {
			return error;struct mxc_gpio_port {
	}struct mxc_gpio_port {
struct mxc_gpio_port {
	return 0;struct mxc_gpio_port {
}struct mxc_gpio_port {
struct mxc_gpio_port {
/*struct mxc_gpio_port {
 * unshare allows a process to 'unshare' part of the processstruct mxc_gpio_port {
 * context which was originally shared using clone.  copy_*struct mxc_gpio_port {
 * functions used by do_fork() cannot be used here directlystruct mxc_gpio_port {
 * because they modify an inactive task_struct that is beingstruct mxc_gpio_port {
 * constructed. Here we are modifying the current, active,struct mxc_gpio_port {
 * task_struct.struct mxc_gpio_port {
 */struct mxc_gpio_port {
SYSCALL_DEFINE1(unshare, unsigned long, unshare_flags)struct mxc_gpio_port {
{struct mxc_gpio_port {
	struct fs_struct *fs, *new_fs = NULL;struct mxc_gpio_port {
	struct files_struct *fd, *new_fd = NULL;struct mxc_gpio_port {
	struct cred *new_cred = NULL;struct mxc_gpio_port {
	struct nsproxy *new_nsproxy = NULL;struct mxc_gpio_port {
	int do_sysvsem = 0;struct mxc_gpio_port {
	int err;struct mxc_gpio_port {
struct mxc_gpio_port {
	/*struct mxc_gpio_port {
	 * If unsharing a user namespace must also unshare the thread.struct mxc_gpio_port {
	 */struct mxc_gpio_port {
	if (unshare_flags & CLONE_NEWUSER)struct mxc_gpio_port {
		unshare_flags |= CLONE_THREAD | CLONE_FS;struct mxc_gpio_port {
	/*struct mxc_gpio_port {
	 * If unsharing a thread from a thread group, must also unshare vm.struct mxc_gpio_port {
	 */struct mxc_gpio_port {
	if (unshare_flags & CLONE_THREAD)struct mxc_gpio_port {
		unshare_flags |= CLONE_VM;struct mxc_gpio_port {
	/*struct mxc_gpio_port {
	 * If unsharing vm, must also unshare signal handlers.struct mxc_gpio_port {
	 */struct mxc_gpio_port {
	if (unshare_flags & CLONE_VM)struct mxc_gpio_port {
		unshare_flags |= CLONE_SIGHAND;struct mxc_gpio_port {
	/*struct mxc_gpio_port {
	 * If unsharing namespace, must also unshare filesystem information.struct mxc_gpio_port {
	 */struct mxc_gpio_port {
	if (unshare_flags & CLONE_NEWNS)struct mxc_gpio_port {
		unshare_flags |= CLONE_FS;struct mxc_gpio_port {
struct mxc_gpio_port {
	err = check_unshare_flags(unshare_flags);struct mxc_gpio_port {
	if (err)struct mxc_gpio_port {
		goto bad_unshare_out;struct mxc_gpio_port {
	/*struct mxc_gpio_port {
	 * CLONE_NEWIPC must also detach from the undolist: after switchingstruct mxc_gpio_port {
	 * to a new ipc namespace, the semaphore arrays from the oldstruct mxc_gpio_port {
	 * namespace are unreachable.struct mxc_gpio_port {
	 */struct mxc_gpio_port {
	if (unshare_flags & (CLONE_NEWIPC|CLONE_SYSVSEM))struct mxc_gpio_port {
		do_sysvsem = 1;struct mxc_gpio_port {
	err = unshare_fs(unshare_flags, &new_fs);struct mxc_gpio_port {
	if (err)struct mxc_gpio_port {
		goto bad_unshare_out;struct mxc_gpio_port {
	err = unshare_fd(unshare_flags, &new_fd);struct mxc_gpio_port {
	if (err)struct mxc_gpio_port {
		goto bad_unshare_cleanup_fs;struct mxc_gpio_port {
	err = unshare_userns(unshare_flags, &new_cred);struct mxc_gpio_port {
	if (err)struct mxc_gpio_port {
		goto bad_unshare_cleanup_fd;struct mxc_gpio_port {
	err = unshare_nsproxy_namespaces(unshare_flags, &new_nsproxy,struct mxc_gpio_port {
					 new_cred, new_fs);struct mxc_gpio_port {
	if (err)struct mxc_gpio_port {
		goto bad_unshare_cleanup_cred;struct mxc_gpio_port {
struct mxc_gpio_port {
	if (new_fs || new_fd || do_sysvsem || new_cred || new_nsproxy) {struct mxc_gpio_port {
		if (do_sysvsem) {struct mxc_gpio_port {
			/*struct mxc_gpio_port {
			 * CLONE_SYSVSEM is equivalent to sys_exit().struct mxc_gpio_port {
			 */struct mxc_gpio_port {
			exit_sem(current);struct mxc_gpio_port {
		}struct mxc_gpio_port {
struct mxc_gpio_port {
		if (new_nsproxy)struct mxc_gpio_port {
			switch_task_namespaces(current, new_nsproxy);struct mxc_gpio_port {
struct mxc_gpio_port {
		task_lock(current);struct mxc_gpio_port {
struct mxc_gpio_port {
		if (new_fs) {struct mxc_gpio_port {
			fs = current->fs;struct mxc_gpio_port {
			spin_lock(&fs->lock);struct mxc_gpio_port {
			current->fs = new_fs;struct mxc_gpio_port {
			if (--fs->users)struct mxc_gpio_port {
				new_fs = NULL;struct mxc_gpio_port {
			elsestruct mxc_gpio_port {
				new_fs = fs;struct mxc_gpio_port {
			spin_unlock(&fs->lock);struct mxc_gpio_port {
		}struct mxc_gpio_port {
struct mxc_gpio_port {
		if (new_fd) {struct mxc_gpio_port {
			fd = current->files;struct mxc_gpio_port {
			current->files = new_fd;struct mxc_gpio_port {
			new_fd = fd;struct mxc_gpio_port {
		}struct mxc_gpio_port {
struct mxc_gpio_port {
		task_unlock(current);struct mxc_gpio_port {
struct mxc_gpio_port {
		if (new_cred) {struct mxc_gpio_port {
			/* Install the new user namespace */struct mxc_gpio_port {
			commit_creds(new_cred);struct mxc_gpio_port {
			new_cred = NULL;struct mxc_gpio_port {
		}struct mxc_gpio_port {
	}struct mxc_gpio_port {
struct mxc_gpio_port {
bad_unshare_cleanup_cred:struct mxc_gpio_port {
	if (new_cred)struct mxc_gpio_port {
		put_cred(new_cred);struct mxc_gpio_port {
bad_unshare_cleanup_fd:struct mxc_gpio_port {
	if (new_fd)struct mxc_gpio_port {
		put_files_struct(new_fd);struct mxc_gpio_port {
struct mxc_gpio_port {
bad_unshare_cleanup_fs:struct mxc_gpio_port {
	if (new_fs)struct mxc_gpio_port {
		free_fs_struct(new_fs);struct mxc_gpio_port {
struct mxc_gpio_port {
bad_unshare_out:struct mxc_gpio_port {
	return err;struct mxc_gpio_port {
}struct mxc_gpio_port {
struct mxc_gpio_port {
/*struct mxc_gpio_port {
 *	Helper to unshare the files of the current task.struct mxc_gpio_port {
 *	We don't want to expose copy_files internals tostruct mxc_gpio_port {
 *	the exec layer of the kernel.struct mxc_gpio_port {
 */struct mxc_gpio_port {
struct mxc_gpio_port {
int unshare_files(struct files_struct **displaced)struct mxc_gpio_port {
{struct mxc_gpio_port {
	struct task_struct *task = current;struct mxc_gpio_port {
	struct files_struct *copy = NULL;struct mxc_gpio_port {
	int error;struct mxc_gpio_port {
struct mxc_gpio_port {
	error = unshare_fd(CLONE_FILES, &copy);struct mxc_gpio_port {
	if (error || !copy) {struct mxc_gpio_port {
		*displaced = NULL;struct mxc_gpio_port {
		return error;struct mxc_gpio_port {
	}struct mxc_gpio_port {
	*displaced = task->files;struct mxc_gpio_port {
	task_lock(task);struct mxc_gpio_port {
	task->files = copy;struct mxc_gpio_port {
	task_unlock(task);struct mxc_gpio_port {
	return 0;struct mxc_gpio_port {
}