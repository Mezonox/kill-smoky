	case IRQ_TYPE_EDGE_RISING:
/*	case IRQ_TYPE_EDGE_RISING:
 *  linux/kernel/fork.c	case IRQ_TYPE_EDGE_RISING:
 *	case IRQ_TYPE_EDGE_RISING:
 *  Copyright (C) 1991, 1992  Linus Torvalds	case IRQ_TYPE_EDGE_RISING:
 */	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
/*	case IRQ_TYPE_EDGE_RISING:
 *  'fork.c' contains the help-routines for the 'fork' system call	case IRQ_TYPE_EDGE_RISING:
 * (see also entry.S and others).	case IRQ_TYPE_EDGE_RISING:
 * Fork is rather simple, once you get the hang of it, but the memory	case IRQ_TYPE_EDGE_RISING:
 * management can be a bitch. See 'mm/memory.c': 'copy_page_range()'	case IRQ_TYPE_EDGE_RISING:
 */	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
#include <linux/slab.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/init.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/unistd.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/module.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/vmalloc.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/completion.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/personality.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/mempolicy.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/sem.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/file.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/fdtable.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/iocontext.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/key.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/binfmts.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/mman.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/mmu_notifier.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/fs.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/nsproxy.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/capability.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/cpu.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/cgroup.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/security.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/hugetlb.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/seccomp.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/swap.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/syscalls.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/jiffies.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/futex.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/compat.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/kthread.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/task_io_accounting_ops.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/rcupdate.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/ptrace.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/mount.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/audit.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/memcontrol.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/ftrace.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/proc_fs.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/profile.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/rmap.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/ksm.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/acct.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/tsacct_kern.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/cn_proc.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/freezer.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/delayacct.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/taskstats_kern.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/random.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/tty.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/blkdev.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/fs_struct.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/magic.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/perf_event.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/posix-timers.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/user-return-notifier.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/oom.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/khugepaged.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/signalfd.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/uprobes.h>	case IRQ_TYPE_EDGE_RISING:
#include <linux/aio.h>	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
#include <asm/pgtable.h>	case IRQ_TYPE_EDGE_RISING:
#include <asm/pgalloc.h>	case IRQ_TYPE_EDGE_RISING:
#include <asm/uaccess.h>	case IRQ_TYPE_EDGE_RISING:
#include <asm/mmu_context.h>	case IRQ_TYPE_EDGE_RISING:
#include <asm/cacheflush.h>	case IRQ_TYPE_EDGE_RISING:
#include <asm/tlbflush.h>	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
#include <trace/events/sched.h>	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
#define CREATE_TRACE_POINTS	case IRQ_TYPE_EDGE_RISING:
#include <trace/events/task.h>	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
/*	case IRQ_TYPE_EDGE_RISING:
 * Protected counters by write_lock_irq(&tasklist_lock)	case IRQ_TYPE_EDGE_RISING:
 */	case IRQ_TYPE_EDGE_RISING:
unsigned long total_forks;	/* Handle normal Linux uptimes. */	case IRQ_TYPE_EDGE_RISING:
int nr_threads;			/* The idle threads do not count.. */	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
int max_threads;		/* tunable limit on nr_threads */	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
DEFINE_PER_CPU(unsigned long, process_counts) = 0;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
__cacheline_aligned DEFINE_RWLOCK(tasklist_lock);  /* outer */	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
#ifdef CONFIG_PROVE_RCU	case IRQ_TYPE_EDGE_RISING:
int lockdep_tasklist_lock_is_held(void)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	return lockdep_is_held(&tasklist_lock);	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
EXPORT_SYMBOL_GPL(lockdep_tasklist_lock_is_held);	case IRQ_TYPE_EDGE_RISING:
#endif /* #ifdef CONFIG_PROVE_RCU */	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
int nr_processes(void)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	int cpu;	case IRQ_TYPE_EDGE_RISING:
	int total = 0;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	for_each_possible_cpu(cpu)	case IRQ_TYPE_EDGE_RISING:
		total += per_cpu(process_counts, cpu);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	return total;	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
void __weak arch_release_task_struct(struct task_struct *tsk)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
#ifndef CONFIG_ARCH_TASK_STRUCT_ALLOCATOR	case IRQ_TYPE_EDGE_RISING:
static struct kmem_cache *task_struct_cachep;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
static inline struct task_struct *alloc_task_struct_node(int node)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	return kmem_cache_alloc_node(task_struct_cachep, GFP_KERNEL, node);	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
static inline void free_task_struct(struct task_struct *tsk)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	kmem_cache_free(task_struct_cachep, tsk);	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
#endif	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
void __weak arch_release_thread_info(struct thread_info *ti)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
#ifndef CONFIG_ARCH_THREAD_INFO_ALLOCATOR	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
/*	case IRQ_TYPE_EDGE_RISING:
 * Allocate pages if THREAD_SIZE is >= PAGE_SIZE, otherwise use a	case IRQ_TYPE_EDGE_RISING:
 * kmemcache based allocator.	case IRQ_TYPE_EDGE_RISING:
 */	case IRQ_TYPE_EDGE_RISING:
# if THREAD_SIZE >= PAGE_SIZE	case IRQ_TYPE_EDGE_RISING:
static struct thread_info *alloc_thread_info_node(struct task_struct *tsk,	case IRQ_TYPE_EDGE_RISING:
						  int node)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	struct page *page = alloc_pages_node(node, THREADINFO_GFP_ACCOUNTED,	case IRQ_TYPE_EDGE_RISING:
					     THREAD_SIZE_ORDER);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	return page ? page_address(page) : NULL;	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
static inline void free_thread_info(struct thread_info *ti)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	free_memcg_kmem_pages((unsigned long)ti, THREAD_SIZE_ORDER);	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
# else	case IRQ_TYPE_EDGE_RISING:
static struct kmem_cache *thread_info_cache;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
static struct thread_info *alloc_thread_info_node(struct task_struct *tsk,	case IRQ_TYPE_EDGE_RISING:
						  int node)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	return kmem_cache_alloc_node(thread_info_cache, THREADINFO_GFP, node);	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
static void free_thread_info(struct thread_info *ti)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	kmem_cache_free(thread_info_cache, ti);	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
void thread_info_cache_init(void)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	thread_info_cache = kmem_cache_create("thread_info", THREAD_SIZE,	case IRQ_TYPE_EDGE_RISING:
					      THREAD_SIZE, 0, NULL);	case IRQ_TYPE_EDGE_RISING:
	BUG_ON(thread_info_cache == NULL);	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
# endif	case IRQ_TYPE_EDGE_RISING:
#endif	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
/* SLAB cache for signal_struct structures (tsk->signal) */	case IRQ_TYPE_EDGE_RISING:
static struct kmem_cache *signal_cachep;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
/* SLAB cache for sighand_struct structures (tsk->sighand) */	case IRQ_TYPE_EDGE_RISING:
struct kmem_cache *sighand_cachep;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
/* SLAB cache for files_struct structures (tsk->files) */	case IRQ_TYPE_EDGE_RISING:
struct kmem_cache *files_cachep;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
/* SLAB cache for fs_struct structures (tsk->fs) */	case IRQ_TYPE_EDGE_RISING:
struct kmem_cache *fs_cachep;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
/* SLAB cache for vm_area_struct structures */	case IRQ_TYPE_EDGE_RISING:
struct kmem_cache *vm_area_cachep;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
/* SLAB cache for mm_struct structures (tsk->mm) */	case IRQ_TYPE_EDGE_RISING:
static struct kmem_cache *mm_cachep;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
static void account_kernel_stack(struct thread_info *ti, int account)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	struct zone *zone = page_zone(virt_to_page(ti));	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	mod_zone_page_state(zone, NR_KERNEL_STACK, account);	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
void free_task(struct task_struct *tsk)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	account_kernel_stack(tsk->stack, -1);	case IRQ_TYPE_EDGE_RISING:
	arch_release_thread_info(tsk->stack);	case IRQ_TYPE_EDGE_RISING:
	free_thread_info(tsk->stack);	case IRQ_TYPE_EDGE_RISING:
	rt_mutex_debug_task_free(tsk);	case IRQ_TYPE_EDGE_RISING:
	ftrace_graph_exit_task(tsk);	case IRQ_TYPE_EDGE_RISING:
	put_seccomp_filter(tsk);	case IRQ_TYPE_EDGE_RISING:
	arch_release_task_struct(tsk);	case IRQ_TYPE_EDGE_RISING:
	free_task_struct(tsk);	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
EXPORT_SYMBOL(free_task);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
static inline void free_signal_struct(struct signal_struct *sig)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	taskstats_tgid_free(sig);	case IRQ_TYPE_EDGE_RISING:
	sched_autogroup_exit(sig);	case IRQ_TYPE_EDGE_RISING:
	kmem_cache_free(signal_cachep, sig);	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
static inline void put_signal_struct(struct signal_struct *sig)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	if (atomic_dec_and_test(&sig->sigcnt))	case IRQ_TYPE_EDGE_RISING:
		free_signal_struct(sig);	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
void __put_task_struct(struct task_struct *tsk)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	WARN_ON(!tsk->exit_state);	case IRQ_TYPE_EDGE_RISING:
	WARN_ON(atomic_read(&tsk->usage));	case IRQ_TYPE_EDGE_RISING:
	WARN_ON(tsk == current);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	task_numa_free(tsk);	case IRQ_TYPE_EDGE_RISING:
	security_task_free(tsk);	case IRQ_TYPE_EDGE_RISING:
	exit_creds(tsk);	case IRQ_TYPE_EDGE_RISING:
	delayacct_tsk_free(tsk);	case IRQ_TYPE_EDGE_RISING:
	put_signal_struct(tsk->signal);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	if (!profile_handoff_task(tsk))	case IRQ_TYPE_EDGE_RISING:
		free_task(tsk);	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
EXPORT_SYMBOL_GPL(__put_task_struct);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
void __init __weak arch_task_cache_init(void) { }	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
void __init fork_init(unsigned long mempages)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
#ifndef CONFIG_ARCH_TASK_STRUCT_ALLOCATOR	case IRQ_TYPE_EDGE_RISING:
#ifndef ARCH_MIN_TASKALIGN	case IRQ_TYPE_EDGE_RISING:
#define ARCH_MIN_TASKALIGN	L1_CACHE_BYTES	case IRQ_TYPE_EDGE_RISING:
#endif	case IRQ_TYPE_EDGE_RISING:
	/* create a slab on which task_structs can be allocated */	case IRQ_TYPE_EDGE_RISING:
	task_struct_cachep =	case IRQ_TYPE_EDGE_RISING:
		kmem_cache_create("task_struct", sizeof(struct task_struct),	case IRQ_TYPE_EDGE_RISING:
			ARCH_MIN_TASKALIGN, SLAB_PANIC | SLAB_NOTRACK, NULL);	case IRQ_TYPE_EDGE_RISING:
#endif	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	/* do the arch specific task caches init */	case IRQ_TYPE_EDGE_RISING:
	arch_task_cache_init();	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	/*	case IRQ_TYPE_EDGE_RISING:
	 * The default maximum number of threads is set to a safe	case IRQ_TYPE_EDGE_RISING:
	 * value: the thread structures can take up at most half	case IRQ_TYPE_EDGE_RISING:
	 * of memory.	case IRQ_TYPE_EDGE_RISING:
	 */	case IRQ_TYPE_EDGE_RISING:
	max_threads = mempages / (8 * THREAD_SIZE / PAGE_SIZE);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	/*	case IRQ_TYPE_EDGE_RISING:
	 * we need to allow at least 20 threads to boot a system	case IRQ_TYPE_EDGE_RISING:
	 */	case IRQ_TYPE_EDGE_RISING:
	if (max_threads < 20)	case IRQ_TYPE_EDGE_RISING:
		max_threads = 20;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	init_task.signal->rlim[RLIMIT_NPROC].rlim_cur = max_threads/2;	case IRQ_TYPE_EDGE_RISING:
	init_task.signal->rlim[RLIMIT_NPROC].rlim_max = max_threads/2;	case IRQ_TYPE_EDGE_RISING:
	init_task.signal->rlim[RLIMIT_SIGPENDING] =	case IRQ_TYPE_EDGE_RISING:
		init_task.signal->rlim[RLIMIT_NPROC];	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
int __attribute__((weak)) arch_dup_task_struct(struct task_struct *dst,	case IRQ_TYPE_EDGE_RISING:
					       struct task_struct *src)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	*dst = *src;	case IRQ_TYPE_EDGE_RISING:
	return 0;	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
static struct task_struct *dup_task_struct(struct task_struct *orig)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	struct task_struct *tsk;	case IRQ_TYPE_EDGE_RISING:
	struct thread_info *ti;	case IRQ_TYPE_EDGE_RISING:
	unsigned long *stackend;	case IRQ_TYPE_EDGE_RISING:
	int node = tsk_fork_get_node(orig);	case IRQ_TYPE_EDGE_RISING:
	int err;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	tsk = alloc_task_struct_node(node);	case IRQ_TYPE_EDGE_RISING:
	if (!tsk)	case IRQ_TYPE_EDGE_RISING:
		return NULL;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	ti = alloc_thread_info_node(tsk, node);	case IRQ_TYPE_EDGE_RISING:
	if (!ti)	case IRQ_TYPE_EDGE_RISING:
		goto free_tsk;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	err = arch_dup_task_struct(tsk, orig);	case IRQ_TYPE_EDGE_RISING:
	if (err)	case IRQ_TYPE_EDGE_RISING:
		goto free_ti;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	tsk->stack = ti;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	setup_thread_stack(tsk, orig);	case IRQ_TYPE_EDGE_RISING:
	clear_user_return_notifier(tsk);	case IRQ_TYPE_EDGE_RISING:
	clear_tsk_need_resched(tsk);	case IRQ_TYPE_EDGE_RISING:
	stackend = end_of_stack(tsk);	case IRQ_TYPE_EDGE_RISING:
	*stackend = STACK_END_MAGIC;	/* for overflow detection */	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
#ifdef CONFIG_CC_STACKPROTECTOR	case IRQ_TYPE_EDGE_RISING:
	tsk->stack_canary = get_random_int();	case IRQ_TYPE_EDGE_RISING:
#endif	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	/*	case IRQ_TYPE_EDGE_RISING:
	 * One for us, one for whoever does the "release_task()" (usually	case IRQ_TYPE_EDGE_RISING:
	 * parent)	case IRQ_TYPE_EDGE_RISING:
	 */	case IRQ_TYPE_EDGE_RISING:
	atomic_set(&tsk->usage, 2);	case IRQ_TYPE_EDGE_RISING:
#ifdef CONFIG_BLK_DEV_IO_TRACE	case IRQ_TYPE_EDGE_RISING:
	tsk->btrace_seq = 0;	case IRQ_TYPE_EDGE_RISING:
#endif	case IRQ_TYPE_EDGE_RISING:
	tsk->splice_pipe = NULL;	case IRQ_TYPE_EDGE_RISING:
	tsk->task_frag.page = NULL;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	account_kernel_stack(ti, 1);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	return tsk;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
free_ti:	case IRQ_TYPE_EDGE_RISING:
	free_thread_info(ti);	case IRQ_TYPE_EDGE_RISING:
free_tsk:	case IRQ_TYPE_EDGE_RISING:
	free_task_struct(tsk);	case IRQ_TYPE_EDGE_RISING:
	return NULL;	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
#ifdef CONFIG_MMU	case IRQ_TYPE_EDGE_RISING:
static int dup_mmap(struct mm_struct *mm, struct mm_struct *oldmm)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	struct vm_area_struct *mpnt, *tmp, *prev, **pprev;	case IRQ_TYPE_EDGE_RISING:
	struct rb_node **rb_link, *rb_parent;	case IRQ_TYPE_EDGE_RISING:
	int retval;	case IRQ_TYPE_EDGE_RISING:
	unsigned long charge;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	uprobe_start_dup_mmap();	case IRQ_TYPE_EDGE_RISING:
	down_write(&oldmm->mmap_sem);	case IRQ_TYPE_EDGE_RISING:
	flush_cache_dup_mm(oldmm);	case IRQ_TYPE_EDGE_RISING:
	uprobe_dup_mmap(oldmm, mm);	case IRQ_TYPE_EDGE_RISING:
	/*	case IRQ_TYPE_EDGE_RISING:
	 * Not linked in yet - no deadlock potential:	case IRQ_TYPE_EDGE_RISING:
	 */	case IRQ_TYPE_EDGE_RISING:
	down_write_nested(&mm->mmap_sem, SINGLE_DEPTH_NESTING);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	mm->locked_vm = 0;	case IRQ_TYPE_EDGE_RISING:
	mm->mmap = NULL;	case IRQ_TYPE_EDGE_RISING:
	mm->mmap_cache = NULL;	case IRQ_TYPE_EDGE_RISING:
	mm->map_count = 0;	case IRQ_TYPE_EDGE_RISING:
	cpumask_clear(mm_cpumask(mm));	case IRQ_TYPE_EDGE_RISING:
	mm->mm_rb = RB_ROOT;	case IRQ_TYPE_EDGE_RISING:
	rb_link = &mm->mm_rb.rb_node;	case IRQ_TYPE_EDGE_RISING:
	rb_parent = NULL;	case IRQ_TYPE_EDGE_RISING:
	pprev = &mm->mmap;	case IRQ_TYPE_EDGE_RISING:
	retval = ksm_fork(mm, oldmm);	case IRQ_TYPE_EDGE_RISING:
	if (retval)	case IRQ_TYPE_EDGE_RISING:
		goto out;	case IRQ_TYPE_EDGE_RISING:
	retval = khugepaged_fork(mm, oldmm);	case IRQ_TYPE_EDGE_RISING:
	if (retval)	case IRQ_TYPE_EDGE_RISING:
		goto out;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	prev = NULL;	case IRQ_TYPE_EDGE_RISING:
	for (mpnt = oldmm->mmap; mpnt; mpnt = mpnt->vm_next) {	case IRQ_TYPE_EDGE_RISING:
		struct file *file;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
		if (mpnt->vm_flags & VM_DONTCOPY) {	case IRQ_TYPE_EDGE_RISING:
			vm_stat_account(mm, mpnt->vm_flags, mpnt->vm_file,	case IRQ_TYPE_EDGE_RISING:
							-vma_pages(mpnt));	case IRQ_TYPE_EDGE_RISING:
			continue;	case IRQ_TYPE_EDGE_RISING:
		}	case IRQ_TYPE_EDGE_RISING:
		charge = 0;	case IRQ_TYPE_EDGE_RISING:
		if (mpnt->vm_flags & VM_ACCOUNT) {	case IRQ_TYPE_EDGE_RISING:
			unsigned long len = vma_pages(mpnt);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
			if (security_vm_enough_memory_mm(oldmm, len)) /* sic */	case IRQ_TYPE_EDGE_RISING:
				goto fail_nomem;	case IRQ_TYPE_EDGE_RISING:
			charge = len;	case IRQ_TYPE_EDGE_RISING:
		}	case IRQ_TYPE_EDGE_RISING:
		tmp = kmem_cache_alloc(vm_area_cachep, GFP_KERNEL);	case IRQ_TYPE_EDGE_RISING:
		if (!tmp)	case IRQ_TYPE_EDGE_RISING:
			goto fail_nomem;	case IRQ_TYPE_EDGE_RISING:
		*tmp = *mpnt;	case IRQ_TYPE_EDGE_RISING:
		INIT_LIST_HEAD(&tmp->anon_vma_chain);	case IRQ_TYPE_EDGE_RISING:
		retval = vma_dup_policy(mpnt, tmp);	case IRQ_TYPE_EDGE_RISING:
		if (retval)	case IRQ_TYPE_EDGE_RISING:
			goto fail_nomem_policy;	case IRQ_TYPE_EDGE_RISING:
		tmp->vm_mm = mm;	case IRQ_TYPE_EDGE_RISING:
		if (anon_vma_fork(tmp, mpnt))	case IRQ_TYPE_EDGE_RISING:
			goto fail_nomem_anon_vma_fork;	case IRQ_TYPE_EDGE_RISING:
		tmp->vm_flags &= ~VM_LOCKED;	case IRQ_TYPE_EDGE_RISING:
		tmp->vm_next = tmp->vm_prev = NULL;	case IRQ_TYPE_EDGE_RISING:
		file = tmp->vm_file;	case IRQ_TYPE_EDGE_RISING:
		if (file) {	case IRQ_TYPE_EDGE_RISING:
			struct inode *inode = file_inode(file);	case IRQ_TYPE_EDGE_RISING:
			struct address_space *mapping = file->f_mapping;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
			get_file(file);	case IRQ_TYPE_EDGE_RISING:
			if (tmp->vm_flags & VM_DENYWRITE)	case IRQ_TYPE_EDGE_RISING:
				atomic_dec(&inode->i_writecount);	case IRQ_TYPE_EDGE_RISING:
			mutex_lock(&mapping->i_mmap_mutex);	case IRQ_TYPE_EDGE_RISING:
			if (tmp->vm_flags & VM_SHARED)	case IRQ_TYPE_EDGE_RISING:
				mapping->i_mmap_writable++;	case IRQ_TYPE_EDGE_RISING:
			flush_dcache_mmap_lock(mapping);	case IRQ_TYPE_EDGE_RISING:
			/* insert tmp into the share list, just after mpnt */	case IRQ_TYPE_EDGE_RISING:
			if (unlikely(tmp->vm_flags & VM_NONLINEAR))	case IRQ_TYPE_EDGE_RISING:
				vma_nonlinear_insert(tmp,	case IRQ_TYPE_EDGE_RISING:
						&mapping->i_mmap_nonlinear);	case IRQ_TYPE_EDGE_RISING:
			else	case IRQ_TYPE_EDGE_RISING:
				vma_interval_tree_insert_after(tmp, mpnt,	case IRQ_TYPE_EDGE_RISING:
							&mapping->i_mmap);	case IRQ_TYPE_EDGE_RISING:
			flush_dcache_mmap_unlock(mapping);	case IRQ_TYPE_EDGE_RISING:
			mutex_unlock(&mapping->i_mmap_mutex);	case IRQ_TYPE_EDGE_RISING:
		}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
		/*	case IRQ_TYPE_EDGE_RISING:
		 * Clear hugetlb-related page reserves for children. This only	case IRQ_TYPE_EDGE_RISING:
		 * affects MAP_PRIVATE mappings. Faults generated by the child	case IRQ_TYPE_EDGE_RISING:
		 * are not guaranteed to succeed, even if read-only	case IRQ_TYPE_EDGE_RISING:
		 */	case IRQ_TYPE_EDGE_RISING:
		if (is_vm_hugetlb_page(tmp))	case IRQ_TYPE_EDGE_RISING:
			reset_vma_resv_huge_pages(tmp);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
		/*	case IRQ_TYPE_EDGE_RISING:
		 * Link in the new vma and copy the page table entries.	case IRQ_TYPE_EDGE_RISING:
		 */	case IRQ_TYPE_EDGE_RISING:
		*pprev = tmp;	case IRQ_TYPE_EDGE_RISING:
		pprev = &tmp->vm_next;	case IRQ_TYPE_EDGE_RISING:
		tmp->vm_prev = prev;	case IRQ_TYPE_EDGE_RISING:
		prev = tmp;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
		__vma_link_rb(mm, tmp, rb_link, rb_parent);	case IRQ_TYPE_EDGE_RISING:
		rb_link = &tmp->vm_rb.rb_right;	case IRQ_TYPE_EDGE_RISING:
		rb_parent = &tmp->vm_rb;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
		mm->map_count++;	case IRQ_TYPE_EDGE_RISING:
		retval = copy_page_range(mm, oldmm, mpnt);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
		if (tmp->vm_ops && tmp->vm_ops->open)	case IRQ_TYPE_EDGE_RISING:
			tmp->vm_ops->open(tmp);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
		if (retval)	case IRQ_TYPE_EDGE_RISING:
			goto out;	case IRQ_TYPE_EDGE_RISING:
	}	case IRQ_TYPE_EDGE_RISING:
	/* a new mm has just been created */	case IRQ_TYPE_EDGE_RISING:
	arch_dup_mmap(oldmm, mm);	case IRQ_TYPE_EDGE_RISING:
	retval = 0;	case IRQ_TYPE_EDGE_RISING:
out:	case IRQ_TYPE_EDGE_RISING:
	up_write(&mm->mmap_sem);	case IRQ_TYPE_EDGE_RISING:
	flush_tlb_mm(oldmm);	case IRQ_TYPE_EDGE_RISING:
	up_write(&oldmm->mmap_sem);	case IRQ_TYPE_EDGE_RISING:
	uprobe_end_dup_mmap();	case IRQ_TYPE_EDGE_RISING:
	return retval;	case IRQ_TYPE_EDGE_RISING:
fail_nomem_anon_vma_fork:	case IRQ_TYPE_EDGE_RISING:
	mpol_put(vma_policy(tmp));	case IRQ_TYPE_EDGE_RISING:
fail_nomem_policy:	case IRQ_TYPE_EDGE_RISING:
	kmem_cache_free(vm_area_cachep, tmp);	case IRQ_TYPE_EDGE_RISING:
fail_nomem:	case IRQ_TYPE_EDGE_RISING:
	retval = -ENOMEM;	case IRQ_TYPE_EDGE_RISING:
	vm_unacct_memory(charge);	case IRQ_TYPE_EDGE_RISING:
	goto out;	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
static inline int mm_alloc_pgd(struct mm_struct *mm)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	mm->pgd = pgd_alloc(mm);	case IRQ_TYPE_EDGE_RISING:
	if (unlikely(!mm->pgd))	case IRQ_TYPE_EDGE_RISING:
		return -ENOMEM;	case IRQ_TYPE_EDGE_RISING:
	return 0;	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
static inline void mm_free_pgd(struct mm_struct *mm)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	pgd_free(mm, mm->pgd);	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
#else	case IRQ_TYPE_EDGE_RISING:
#define dup_mmap(mm, oldmm)	(0)	case IRQ_TYPE_EDGE_RISING:
#define mm_alloc_pgd(mm)	(0)	case IRQ_TYPE_EDGE_RISING:
#define mm_free_pgd(mm)	case IRQ_TYPE_EDGE_RISING:
#endif /* CONFIG_MMU */	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
__cacheline_aligned_in_smp DEFINE_SPINLOCK(mmlist_lock);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
#define allocate_mm()	(kmem_cache_alloc(mm_cachep, GFP_KERNEL))	case IRQ_TYPE_EDGE_RISING:
#define free_mm(mm)	(kmem_cache_free(mm_cachep, (mm)))	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
static unsigned long default_dump_filter = MMF_DUMP_FILTER_DEFAULT;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
static int __init coredump_filter_setup(char *s)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	default_dump_filter =	case IRQ_TYPE_EDGE_RISING:
		(simple_strtoul(s, NULL, 0) << MMF_DUMP_FILTER_SHIFT) &	case IRQ_TYPE_EDGE_RISING:
		MMF_DUMP_FILTER_MASK;	case IRQ_TYPE_EDGE_RISING:
	return 1;	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
__setup("coredump_filter=", coredump_filter_setup);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
#include <linux/init_task.h>	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
static void mm_init_aio(struct mm_struct *mm)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
#ifdef CONFIG_AIO	case IRQ_TYPE_EDGE_RISING:
	spin_lock_init(&mm->ioctx_lock);	case IRQ_TYPE_EDGE_RISING:
	mm->ioctx_table = NULL;	case IRQ_TYPE_EDGE_RISING:
#endif	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
static struct mm_struct *mm_init(struct mm_struct *mm, struct task_struct *p)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	atomic_set(&mm->mm_users, 1);	case IRQ_TYPE_EDGE_RISING:
	atomic_set(&mm->mm_count, 1);	case IRQ_TYPE_EDGE_RISING:
	init_rwsem(&mm->mmap_sem);	case IRQ_TYPE_EDGE_RISING:
	INIT_LIST_HEAD(&mm->mmlist);	case IRQ_TYPE_EDGE_RISING:
	mm->flags = (current->mm) ?	case IRQ_TYPE_EDGE_RISING:
		(current->mm->flags & MMF_INIT_MASK) : default_dump_filter;	case IRQ_TYPE_EDGE_RISING:
	mm->core_state = NULL;	case IRQ_TYPE_EDGE_RISING:
	atomic_long_set(&mm->nr_ptes, 0);	case IRQ_TYPE_EDGE_RISING:
	memset(&mm->rss_stat, 0, sizeof(mm->rss_stat));	case IRQ_TYPE_EDGE_RISING:
	spin_lock_init(&mm->page_table_lock);	case IRQ_TYPE_EDGE_RISING:
	mm_init_aio(mm);	case IRQ_TYPE_EDGE_RISING:
	mm_init_owner(mm, p);	case IRQ_TYPE_EDGE_RISING:
	clear_tlb_flush_pending(mm);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	if (likely(!mm_alloc_pgd(mm))) {	case IRQ_TYPE_EDGE_RISING:
		mm->def_flags = 0;	case IRQ_TYPE_EDGE_RISING:
		mmu_notifier_mm_init(mm);	case IRQ_TYPE_EDGE_RISING:
		return mm;	case IRQ_TYPE_EDGE_RISING:
	}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	free_mm(mm);	case IRQ_TYPE_EDGE_RISING:
	return NULL;	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
static void check_mm(struct mm_struct *mm)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	int i;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	for (i = 0; i < NR_MM_COUNTERS; i++) {	case IRQ_TYPE_EDGE_RISING:
		long x = atomic_long_read(&mm->rss_stat.count[i]);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
		if (unlikely(x))	case IRQ_TYPE_EDGE_RISING:
			printk(KERN_ALERT "BUG: Bad rss-counter state "	case IRQ_TYPE_EDGE_RISING:
					  "mm:%p idx:%d val:%ld\n", mm, i, x);	case IRQ_TYPE_EDGE_RISING:
	}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
#if defined(CONFIG_TRANSPARENT_HUGEPAGE) && !USE_SPLIT_PMD_PTLOCKS	case IRQ_TYPE_EDGE_RISING:
	VM_BUG_ON(mm->pmd_huge_pte);	case IRQ_TYPE_EDGE_RISING:
#endif	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
/*	case IRQ_TYPE_EDGE_RISING:
 * Allocate and initialize an mm_struct.	case IRQ_TYPE_EDGE_RISING:
 */	case IRQ_TYPE_EDGE_RISING:
struct mm_struct *mm_alloc(void)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	struct mm_struct *mm;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	mm = allocate_mm();	case IRQ_TYPE_EDGE_RISING:
	if (!mm)	case IRQ_TYPE_EDGE_RISING:
		return NULL;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	memset(mm, 0, sizeof(*mm));	case IRQ_TYPE_EDGE_RISING:
	mm_init_cpumask(mm);	case IRQ_TYPE_EDGE_RISING:
	return mm_init(mm, current);	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
/*	case IRQ_TYPE_EDGE_RISING:
 * Called when the last reference to the mm	case IRQ_TYPE_EDGE_RISING:
 * is dropped: either by a lazy thread or by	case IRQ_TYPE_EDGE_RISING:
 * mmput. Free the page directory and the mm.	case IRQ_TYPE_EDGE_RISING:
 */	case IRQ_TYPE_EDGE_RISING:
void __mmdrop(struct mm_struct *mm)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	BUG_ON(mm == &init_mm);	case IRQ_TYPE_EDGE_RISING:
	mm_free_pgd(mm);	case IRQ_TYPE_EDGE_RISING:
	destroy_context(mm);	case IRQ_TYPE_EDGE_RISING:
	mmu_notifier_mm_destroy(mm);	case IRQ_TYPE_EDGE_RISING:
	check_mm(mm);	case IRQ_TYPE_EDGE_RISING:
	free_mm(mm);	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
EXPORT_SYMBOL_GPL(__mmdrop);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
/*	case IRQ_TYPE_EDGE_RISING:
 * Decrement the use count and release all resources for an mm.	case IRQ_TYPE_EDGE_RISING:
 */	case IRQ_TYPE_EDGE_RISING:
void mmput(struct mm_struct *mm)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	might_sleep();	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	if (atomic_dec_and_test(&mm->mm_users)) {	case IRQ_TYPE_EDGE_RISING:
		uprobe_clear_state(mm);	case IRQ_TYPE_EDGE_RISING:
		exit_aio(mm);	case IRQ_TYPE_EDGE_RISING:
		ksm_exit(mm);	case IRQ_TYPE_EDGE_RISING:
		khugepaged_exit(mm); /* must run before exit_mmap */	case IRQ_TYPE_EDGE_RISING:
		exit_mmap(mm);	case IRQ_TYPE_EDGE_RISING:
		set_mm_exe_file(mm, NULL);	case IRQ_TYPE_EDGE_RISING:
		if (!list_empty(&mm->mmlist)) {	case IRQ_TYPE_EDGE_RISING:
			spin_lock(&mmlist_lock);	case IRQ_TYPE_EDGE_RISING:
			list_del(&mm->mmlist);	case IRQ_TYPE_EDGE_RISING:
			spin_unlock(&mmlist_lock);	case IRQ_TYPE_EDGE_RISING:
		}	case IRQ_TYPE_EDGE_RISING:
		if (mm->binfmt)	case IRQ_TYPE_EDGE_RISING:
			module_put(mm->binfmt->module);	case IRQ_TYPE_EDGE_RISING:
		mmdrop(mm);	case IRQ_TYPE_EDGE_RISING:
	}	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
EXPORT_SYMBOL_GPL(mmput);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
void set_mm_exe_file(struct mm_struct *mm, struct file *new_exe_file)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	if (new_exe_file)	case IRQ_TYPE_EDGE_RISING:
		get_file(new_exe_file);	case IRQ_TYPE_EDGE_RISING:
	if (mm->exe_file)	case IRQ_TYPE_EDGE_RISING:
		fput(mm->exe_file);	case IRQ_TYPE_EDGE_RISING:
	mm->exe_file = new_exe_file;	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
struct file *get_mm_exe_file(struct mm_struct *mm)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	struct file *exe_file;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	/* We need mmap_sem to protect against races with removal of exe_file */	case IRQ_TYPE_EDGE_RISING:
	down_read(&mm->mmap_sem);	case IRQ_TYPE_EDGE_RISING:
	exe_file = mm->exe_file;	case IRQ_TYPE_EDGE_RISING:
	if (exe_file)	case IRQ_TYPE_EDGE_RISING:
		get_file(exe_file);	case IRQ_TYPE_EDGE_RISING:
	up_read(&mm->mmap_sem);	case IRQ_TYPE_EDGE_RISING:
	return exe_file;	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
static void dup_mm_exe_file(struct mm_struct *oldmm, struct mm_struct *newmm)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	/* It's safe to write the exe_file pointer without exe_file_lock because	case IRQ_TYPE_EDGE_RISING:
	 * this is called during fork when the task is not yet in /proc */	case IRQ_TYPE_EDGE_RISING:
	newmm->exe_file = get_mm_exe_file(oldmm);	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
/**	case IRQ_TYPE_EDGE_RISING:
 * get_task_mm - acquire a reference to the task's mm	case IRQ_TYPE_EDGE_RISING:
 *	case IRQ_TYPE_EDGE_RISING:
 * Returns %NULL if the task has no mm.  Checks PF_KTHREAD (meaning	case IRQ_TYPE_EDGE_RISING:
 * this kernel workthread has transiently adopted a user mm with use_mm,	case IRQ_TYPE_EDGE_RISING:
 * to do its AIO) is not set and if so returns a reference to it, after	case IRQ_TYPE_EDGE_RISING:
 * bumping up the use count.  User must release the mm via mmput()	case IRQ_TYPE_EDGE_RISING:
 * after use.  Typically used by /proc and ptrace.	case IRQ_TYPE_EDGE_RISING:
 */	case IRQ_TYPE_EDGE_RISING:
struct mm_struct *get_task_mm(struct task_struct *task)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	struct mm_struct *mm;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	task_lock(task);	case IRQ_TYPE_EDGE_RISING:
	mm = task->mm;	case IRQ_TYPE_EDGE_RISING:
	if (mm) {	case IRQ_TYPE_EDGE_RISING:
		if (task->flags & PF_KTHREAD)	case IRQ_TYPE_EDGE_RISING:
			mm = NULL;	case IRQ_TYPE_EDGE_RISING:
		else	case IRQ_TYPE_EDGE_RISING:
			atomic_inc(&mm->mm_users);	case IRQ_TYPE_EDGE_RISING:
	}	case IRQ_TYPE_EDGE_RISING:
	task_unlock(task);	case IRQ_TYPE_EDGE_RISING:
	return mm;	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
EXPORT_SYMBOL_GPL(get_task_mm);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
struct mm_struct *mm_access(struct task_struct *task, unsigned int mode)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	struct mm_struct *mm;	case IRQ_TYPE_EDGE_RISING:
	int err;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	err =  mutex_lock_killable(&task->signal->cred_guard_mutex);	case IRQ_TYPE_EDGE_RISING:
	if (err)	case IRQ_TYPE_EDGE_RISING:
		return ERR_PTR(err);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	mm = get_task_mm(task);	case IRQ_TYPE_EDGE_RISING:
	if (mm && mm != current->mm &&	case IRQ_TYPE_EDGE_RISING:
			!ptrace_may_access(task, mode)) {	case IRQ_TYPE_EDGE_RISING:
		mmput(mm);	case IRQ_TYPE_EDGE_RISING:
		mm = ERR_PTR(-EACCES);	case IRQ_TYPE_EDGE_RISING:
	}	case IRQ_TYPE_EDGE_RISING:
	mutex_unlock(&task->signal->cred_guard_mutex);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	return mm;	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
static void complete_vfork_done(struct task_struct *tsk)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	struct completion *vfork;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	task_lock(tsk);	case IRQ_TYPE_EDGE_RISING:
	vfork = tsk->vfork_done;	case IRQ_TYPE_EDGE_RISING:
	if (likely(vfork)) {	case IRQ_TYPE_EDGE_RISING:
		tsk->vfork_done = NULL;	case IRQ_TYPE_EDGE_RISING:
		complete(vfork);	case IRQ_TYPE_EDGE_RISING:
	}	case IRQ_TYPE_EDGE_RISING:
	task_unlock(tsk);	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
static int wait_for_vfork_done(struct task_struct *child,	case IRQ_TYPE_EDGE_RISING:
				struct completion *vfork)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	int killed;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	freezer_do_not_count();	case IRQ_TYPE_EDGE_RISING:
	killed = wait_for_completion_killable(vfork);	case IRQ_TYPE_EDGE_RISING:
	freezer_count();	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	if (killed) {	case IRQ_TYPE_EDGE_RISING:
		task_lock(child);	case IRQ_TYPE_EDGE_RISING:
		child->vfork_done = NULL;	case IRQ_TYPE_EDGE_RISING:
		task_unlock(child);	case IRQ_TYPE_EDGE_RISING:
	}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	put_task_struct(child);	case IRQ_TYPE_EDGE_RISING:
	return killed;	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
/* Please note the differences between mmput and mm_release.	case IRQ_TYPE_EDGE_RISING:
 * mmput is called whenever we stop holding onto a mm_struct,	case IRQ_TYPE_EDGE_RISING:
 * error success whatever.	case IRQ_TYPE_EDGE_RISING:
 *	case IRQ_TYPE_EDGE_RISING:
 * mm_release is called after a mm_struct has been removed	case IRQ_TYPE_EDGE_RISING:
 * from the current process.	case IRQ_TYPE_EDGE_RISING:
 *	case IRQ_TYPE_EDGE_RISING:
 * This difference is important for error handling, when we	case IRQ_TYPE_EDGE_RISING:
 * only half set up a mm_struct for a new process and need to restore	case IRQ_TYPE_EDGE_RISING:
 * the old one.  Because we mmput the new mm_struct before	case IRQ_TYPE_EDGE_RISING:
 * restoring the old one. . .	case IRQ_TYPE_EDGE_RISING:
 * Eric Biederman 10 January 1998	case IRQ_TYPE_EDGE_RISING:
 */	case IRQ_TYPE_EDGE_RISING:
void mm_release(struct task_struct *tsk, struct mm_struct *mm)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	/* Get rid of any futexes when releasing the mm */	case IRQ_TYPE_EDGE_RISING:
#ifdef CONFIG_FUTEX	case IRQ_TYPE_EDGE_RISING:
	if (unlikely(tsk->robust_list)) {	case IRQ_TYPE_EDGE_RISING:
		exit_robust_list(tsk);	case IRQ_TYPE_EDGE_RISING:
		tsk->robust_list = NULL;	case IRQ_TYPE_EDGE_RISING:
	}	case IRQ_TYPE_EDGE_RISING:
#ifdef CONFIG_COMPAT	case IRQ_TYPE_EDGE_RISING:
	if (unlikely(tsk->compat_robust_list)) {	case IRQ_TYPE_EDGE_RISING:
		compat_exit_robust_list(tsk);	case IRQ_TYPE_EDGE_RISING:
		tsk->compat_robust_list = NULL;	case IRQ_TYPE_EDGE_RISING:
	}	case IRQ_TYPE_EDGE_RISING:
#endif	case IRQ_TYPE_EDGE_RISING:
	if (unlikely(!list_empty(&tsk->pi_state_list)))	case IRQ_TYPE_EDGE_RISING:
		exit_pi_state_list(tsk);	case IRQ_TYPE_EDGE_RISING:
#endif	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	uprobe_free_utask(tsk);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	/* Get rid of any cached register state */	case IRQ_TYPE_EDGE_RISING:
	deactivate_mm(tsk, mm);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	/*	case IRQ_TYPE_EDGE_RISING:
	 * If we're exiting normally, clear a user-space tid field if	case IRQ_TYPE_EDGE_RISING:
	 * requested.  We leave this alone when dying by signal, to leave	case IRQ_TYPE_EDGE_RISING:
	 * the value intact in a core dump, and to save the unnecessary	case IRQ_TYPE_EDGE_RISING:
	 * trouble, say, a killed vfork parent shouldn't touch this mm.	case IRQ_TYPE_EDGE_RISING:
	 * Userland only wants this done for a sys_exit.	case IRQ_TYPE_EDGE_RISING:
	 */	case IRQ_TYPE_EDGE_RISING:
	if (tsk->clear_child_tid) {	case IRQ_TYPE_EDGE_RISING:
		if (!(tsk->flags & PF_SIGNALED) &&	case IRQ_TYPE_EDGE_RISING:
		    atomic_read(&mm->mm_users) > 1) {	case IRQ_TYPE_EDGE_RISING:
			/*	case IRQ_TYPE_EDGE_RISING:
			 * We don't check the error code - if userspace has	case IRQ_TYPE_EDGE_RISING:
			 * not set up a proper pointer then tough luck.	case IRQ_TYPE_EDGE_RISING:
			 */	case IRQ_TYPE_EDGE_RISING:
			put_user(0, tsk->clear_child_tid);	case IRQ_TYPE_EDGE_RISING:
			sys_futex(tsk->clear_child_tid, FUTEX_WAKE,	case IRQ_TYPE_EDGE_RISING:
					1, NULL, NULL, 0);	case IRQ_TYPE_EDGE_RISING:
		}	case IRQ_TYPE_EDGE_RISING:
		tsk->clear_child_tid = NULL;	case IRQ_TYPE_EDGE_RISING:
	}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	/*	case IRQ_TYPE_EDGE_RISING:
	 * All done, finally we can wake up parent and return this mm to him.	case IRQ_TYPE_EDGE_RISING:
	 * Also kthread_stop() uses this completion for synchronization.	case IRQ_TYPE_EDGE_RISING:
	 */	case IRQ_TYPE_EDGE_RISING:
	if (tsk->vfork_done)	case IRQ_TYPE_EDGE_RISING:
		complete_vfork_done(tsk);	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
/*	case IRQ_TYPE_EDGE_RISING:
 * Allocate a new mm structure and copy contents from the	case IRQ_TYPE_EDGE_RISING:
 * mm structure of the passed in task structure.	case IRQ_TYPE_EDGE_RISING:
 */	case IRQ_TYPE_EDGE_RISING:
static struct mm_struct *dup_mm(struct task_struct *tsk)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	struct mm_struct *mm, *oldmm = current->mm;	case IRQ_TYPE_EDGE_RISING:
	int err;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	mm = allocate_mm();	case IRQ_TYPE_EDGE_RISING:
	if (!mm)	case IRQ_TYPE_EDGE_RISING:
		goto fail_nomem;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	memcpy(mm, oldmm, sizeof(*mm));	case IRQ_TYPE_EDGE_RISING:
	mm_init_cpumask(mm);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
#if defined(CONFIG_TRANSPARENT_HUGEPAGE) && !USE_SPLIT_PMD_PTLOCKS	case IRQ_TYPE_EDGE_RISING:
	mm->pmd_huge_pte = NULL;	case IRQ_TYPE_EDGE_RISING:
#endif	case IRQ_TYPE_EDGE_RISING:
	if (!mm_init(mm, tsk))	case IRQ_TYPE_EDGE_RISING:
		goto fail_nomem;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	if (init_new_context(tsk, mm))	case IRQ_TYPE_EDGE_RISING:
		goto fail_nocontext;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	dup_mm_exe_file(oldmm, mm);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	err = dup_mmap(mm, oldmm);	case IRQ_TYPE_EDGE_RISING:
	if (err)	case IRQ_TYPE_EDGE_RISING:
		goto free_pt;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	mm->hiwater_rss = get_mm_rss(mm);	case IRQ_TYPE_EDGE_RISING:
	mm->hiwater_vm = mm->total_vm;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	if (mm->binfmt && !try_module_get(mm->binfmt->module))	case IRQ_TYPE_EDGE_RISING:
		goto free_pt;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	return mm;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
free_pt:	case IRQ_TYPE_EDGE_RISING:
	/* don't put binfmt in mmput, we haven't got module yet */	case IRQ_TYPE_EDGE_RISING:
	mm->binfmt = NULL;	case IRQ_TYPE_EDGE_RISING:
	mmput(mm);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
fail_nomem:	case IRQ_TYPE_EDGE_RISING:
	return NULL;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
fail_nocontext:	case IRQ_TYPE_EDGE_RISING:
	/*	case IRQ_TYPE_EDGE_RISING:
	 * If init_new_context() failed, we cannot use mmput() to free the mm	case IRQ_TYPE_EDGE_RISING:
	 * because it calls destroy_context()	case IRQ_TYPE_EDGE_RISING:
	 */	case IRQ_TYPE_EDGE_RISING:
	mm_free_pgd(mm);	case IRQ_TYPE_EDGE_RISING:
	free_mm(mm);	case IRQ_TYPE_EDGE_RISING:
	return NULL;	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
static int copy_mm(unsigned long clone_flags, struct task_struct *tsk)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	struct mm_struct *mm, *oldmm;	case IRQ_TYPE_EDGE_RISING:
	int retval;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	tsk->min_flt = tsk->maj_flt = 0;	case IRQ_TYPE_EDGE_RISING:
	tsk->nvcsw = tsk->nivcsw = 0;	case IRQ_TYPE_EDGE_RISING:
#ifdef CONFIG_DETECT_HUNG_TASK	case IRQ_TYPE_EDGE_RISING:
	tsk->last_switch_count = tsk->nvcsw + tsk->nivcsw;	case IRQ_TYPE_EDGE_RISING:
#endif	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	tsk->mm = NULL;	case IRQ_TYPE_EDGE_RISING:
	tsk->active_mm = NULL;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	/*	case IRQ_TYPE_EDGE_RISING:
	 * Are we cloning a kernel thread?	case IRQ_TYPE_EDGE_RISING:
	 *	case IRQ_TYPE_EDGE_RISING:
	 * We need to steal a active VM for that..	case IRQ_TYPE_EDGE_RISING:
	 */	case IRQ_TYPE_EDGE_RISING:
	oldmm = current->mm;	case IRQ_TYPE_EDGE_RISING:
	if (!oldmm)	case IRQ_TYPE_EDGE_RISING:
		return 0;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	if (clone_flags & CLONE_VM) {	case IRQ_TYPE_EDGE_RISING:
		atomic_inc(&oldmm->mm_users);	case IRQ_TYPE_EDGE_RISING:
		mm = oldmm;	case IRQ_TYPE_EDGE_RISING:
		goto good_mm;	case IRQ_TYPE_EDGE_RISING:
	}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	retval = -ENOMEM;	case IRQ_TYPE_EDGE_RISING:
	mm = dup_mm(tsk);	case IRQ_TYPE_EDGE_RISING:
	if (!mm)	case IRQ_TYPE_EDGE_RISING:
		goto fail_nomem;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
good_mm:	case IRQ_TYPE_EDGE_RISING:
	tsk->mm = mm;	case IRQ_TYPE_EDGE_RISING:
	tsk->active_mm = mm;	case IRQ_TYPE_EDGE_RISING:
	return 0;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
fail_nomem:	case IRQ_TYPE_EDGE_RISING:
	return retval;	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
static int copy_fs(unsigned long clone_flags, struct task_struct *tsk)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	struct fs_struct *fs = current->fs;	case IRQ_TYPE_EDGE_RISING:
	if (clone_flags & CLONE_FS) {	case IRQ_TYPE_EDGE_RISING:
		/* tsk->fs is already what we want */	case IRQ_TYPE_EDGE_RISING:
		spin_lock(&fs->lock);	case IRQ_TYPE_EDGE_RISING:
		if (fs->in_exec) {	case IRQ_TYPE_EDGE_RISING:
			spin_unlock(&fs->lock);	case IRQ_TYPE_EDGE_RISING:
			return -EAGAIN;	case IRQ_TYPE_EDGE_RISING:
		}	case IRQ_TYPE_EDGE_RISING:
		fs->users++;	case IRQ_TYPE_EDGE_RISING:
		spin_unlock(&fs->lock);	case IRQ_TYPE_EDGE_RISING:
		return 0;	case IRQ_TYPE_EDGE_RISING:
	}	case IRQ_TYPE_EDGE_RISING:
	tsk->fs = copy_fs_struct(fs);	case IRQ_TYPE_EDGE_RISING:
	if (!tsk->fs)	case IRQ_TYPE_EDGE_RISING:
		return -ENOMEM;	case IRQ_TYPE_EDGE_RISING:
	return 0;	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
static int copy_files(unsigned long clone_flags, struct task_struct *tsk)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	struct files_struct *oldf, *newf;	case IRQ_TYPE_EDGE_RISING:
	int error = 0;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	/*	case IRQ_TYPE_EDGE_RISING:
	 * A background process may not have any files ...	case IRQ_TYPE_EDGE_RISING:
	 */	case IRQ_TYPE_EDGE_RISING:
	oldf = current->files;	case IRQ_TYPE_EDGE_RISING:
	if (!oldf)	case IRQ_TYPE_EDGE_RISING:
		goto out;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	if (clone_flags & CLONE_FILES) {	case IRQ_TYPE_EDGE_RISING:
		atomic_inc(&oldf->count);	case IRQ_TYPE_EDGE_RISING:
		goto out;	case IRQ_TYPE_EDGE_RISING:
	}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	newf = dup_fd(oldf, &error);	case IRQ_TYPE_EDGE_RISING:
	if (!newf)	case IRQ_TYPE_EDGE_RISING:
		goto out;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	tsk->files = newf;	case IRQ_TYPE_EDGE_RISING:
	error = 0;	case IRQ_TYPE_EDGE_RISING:
out:	case IRQ_TYPE_EDGE_RISING:
	return error;	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
static int copy_io(unsigned long clone_flags, struct task_struct *tsk)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
#ifdef CONFIG_BLOCK	case IRQ_TYPE_EDGE_RISING:
	struct io_context *ioc = current->io_context;	case IRQ_TYPE_EDGE_RISING:
	struct io_context *new_ioc;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	if (!ioc)	case IRQ_TYPE_EDGE_RISING:
		return 0;	case IRQ_TYPE_EDGE_RISING:
	/*	case IRQ_TYPE_EDGE_RISING:
	 * Share io context with parent, if CLONE_IO is set	case IRQ_TYPE_EDGE_RISING:
	 */	case IRQ_TYPE_EDGE_RISING:
	if (clone_flags & CLONE_IO) {	case IRQ_TYPE_EDGE_RISING:
		ioc_task_link(ioc);	case IRQ_TYPE_EDGE_RISING:
		tsk->io_context = ioc;	case IRQ_TYPE_EDGE_RISING:
	} else if (ioprio_valid(ioc->ioprio)) {	case IRQ_TYPE_EDGE_RISING:
		new_ioc = get_task_io_context(tsk, GFP_KERNEL, NUMA_NO_NODE);	case IRQ_TYPE_EDGE_RISING:
		if (unlikely(!new_ioc))	case IRQ_TYPE_EDGE_RISING:
			return -ENOMEM;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
		new_ioc->ioprio = ioc->ioprio;	case IRQ_TYPE_EDGE_RISING:
		put_io_context(new_ioc);	case IRQ_TYPE_EDGE_RISING:
	}	case IRQ_TYPE_EDGE_RISING:
#endif	case IRQ_TYPE_EDGE_RISING:
	return 0;	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
static int copy_sighand(unsigned long clone_flags, struct task_struct *tsk)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	struct sighand_struct *sig;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	if (clone_flags & CLONE_SIGHAND) {	case IRQ_TYPE_EDGE_RISING:
		atomic_inc(&current->sighand->count);	case IRQ_TYPE_EDGE_RISING:
		return 0;	case IRQ_TYPE_EDGE_RISING:
	}	case IRQ_TYPE_EDGE_RISING:
	sig = kmem_cache_alloc(sighand_cachep, GFP_KERNEL);	case IRQ_TYPE_EDGE_RISING:
	rcu_assign_pointer(tsk->sighand, sig);	case IRQ_TYPE_EDGE_RISING:
	if (!sig)	case IRQ_TYPE_EDGE_RISING:
		return -ENOMEM;	case IRQ_TYPE_EDGE_RISING:
	atomic_set(&sig->count, 1);	case IRQ_TYPE_EDGE_RISING:
	memcpy(sig->action, current->sighand->action, sizeof(sig->action));	case IRQ_TYPE_EDGE_RISING:
	return 0;	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
void __cleanup_sighand(struct sighand_struct *sighand)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	if (atomic_dec_and_test(&sighand->count)) {	case IRQ_TYPE_EDGE_RISING:
		signalfd_cleanup(sighand);	case IRQ_TYPE_EDGE_RISING:
		kmem_cache_free(sighand_cachep, sighand);	case IRQ_TYPE_EDGE_RISING:
	}	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
/*	case IRQ_TYPE_EDGE_RISING:
 * Initialize POSIX timer handling for a thread group.	case IRQ_TYPE_EDGE_RISING:
 */	case IRQ_TYPE_EDGE_RISING:
static void posix_cpu_timers_init_group(struct signal_struct *sig)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	unsigned long cpu_limit;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	/* Thread group counters. */	case IRQ_TYPE_EDGE_RISING:
	thread_group_cputime_init(sig);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	cpu_limit = ACCESS_ONCE(sig->rlim[RLIMIT_CPU].rlim_cur);	case IRQ_TYPE_EDGE_RISING:
	if (cpu_limit != RLIM_INFINITY) {	case IRQ_TYPE_EDGE_RISING:
		sig->cputime_expires.prof_exp = secs_to_cputime(cpu_limit);	case IRQ_TYPE_EDGE_RISING:
		sig->cputimer.running = 1;	case IRQ_TYPE_EDGE_RISING:
	}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	/* The timer lists. */	case IRQ_TYPE_EDGE_RISING:
	INIT_LIST_HEAD(&sig->cpu_timers[0]);	case IRQ_TYPE_EDGE_RISING:
	INIT_LIST_HEAD(&sig->cpu_timers[1]);	case IRQ_TYPE_EDGE_RISING:
	INIT_LIST_HEAD(&sig->cpu_timers[2]);	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
static int copy_signal(unsigned long clone_flags, struct task_struct *tsk)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	struct signal_struct *sig;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	if (clone_flags & CLONE_THREAD)	case IRQ_TYPE_EDGE_RISING:
		return 0;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	sig = kmem_cache_zalloc(signal_cachep, GFP_KERNEL);	case IRQ_TYPE_EDGE_RISING:
	tsk->signal = sig;	case IRQ_TYPE_EDGE_RISING:
	if (!sig)	case IRQ_TYPE_EDGE_RISING:
		return -ENOMEM;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	sig->nr_threads = 1;	case IRQ_TYPE_EDGE_RISING:
	atomic_set(&sig->live, 1);	case IRQ_TYPE_EDGE_RISING:
	atomic_set(&sig->sigcnt, 1);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	/* list_add(thread_node, thread_head) without INIT_LIST_HEAD() */	case IRQ_TYPE_EDGE_RISING:
	sig->thread_head = (struct list_head)LIST_HEAD_INIT(tsk->thread_node);	case IRQ_TYPE_EDGE_RISING:
	tsk->thread_node = (struct list_head)LIST_HEAD_INIT(sig->thread_head);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	init_waitqueue_head(&sig->wait_chldexit);	case IRQ_TYPE_EDGE_RISING:
	sig->curr_target = tsk;	case IRQ_TYPE_EDGE_RISING:
	init_sigpending(&sig->shared_pending);	case IRQ_TYPE_EDGE_RISING:
	INIT_LIST_HEAD(&sig->posix_timers);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	hrtimer_init(&sig->real_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);	case IRQ_TYPE_EDGE_RISING:
	sig->real_timer.function = it_real_fn;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	task_lock(current->group_leader);	case IRQ_TYPE_EDGE_RISING:
	memcpy(sig->rlim, current->signal->rlim, sizeof sig->rlim);	case IRQ_TYPE_EDGE_RISING:
	task_unlock(current->group_leader);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	posix_cpu_timers_init_group(sig);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	tty_audit_fork(sig);	case IRQ_TYPE_EDGE_RISING:
	sched_autogroup_fork(sig);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
#ifdef CONFIG_CGROUPS	case IRQ_TYPE_EDGE_RISING:
	init_rwsem(&sig->group_rwsem);	case IRQ_TYPE_EDGE_RISING:
#endif	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	sig->oom_score_adj = current->signal->oom_score_adj;	case IRQ_TYPE_EDGE_RISING:
	sig->oom_score_adj_min = current->signal->oom_score_adj_min;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	sig->has_child_subreaper = current->signal->has_child_subreaper ||	case IRQ_TYPE_EDGE_RISING:
				   current->signal->is_child_subreaper;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	mutex_init(&sig->cred_guard_mutex);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	return 0;	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
static void copy_flags(unsigned long clone_flags, struct task_struct *p)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	unsigned long new_flags = p->flags;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	new_flags &= ~(PF_SUPERPRIV | PF_WQ_WORKER);	case IRQ_TYPE_EDGE_RISING:
	new_flags |= PF_FORKNOEXEC;	case IRQ_TYPE_EDGE_RISING:
	p->flags = new_flags;	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
SYSCALL_DEFINE1(set_tid_address, int __user *, tidptr)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	current->clear_child_tid = tidptr;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	return task_pid_vnr(current);	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
static void rt_mutex_init_task(struct task_struct *p)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	raw_spin_lock_init(&p->pi_lock);	case IRQ_TYPE_EDGE_RISING:
#ifdef CONFIG_RT_MUTEXES	case IRQ_TYPE_EDGE_RISING:
	p->pi_waiters = RB_ROOT;	case IRQ_TYPE_EDGE_RISING:
	p->pi_waiters_leftmost = NULL;	case IRQ_TYPE_EDGE_RISING:
	p->pi_blocked_on = NULL;	case IRQ_TYPE_EDGE_RISING:
	p->pi_top_task = NULL;	case IRQ_TYPE_EDGE_RISING:
#endif	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
#ifdef CONFIG_MM_OWNER	case IRQ_TYPE_EDGE_RISING:
void mm_init_owner(struct mm_struct *mm, struct task_struct *p)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	mm->owner = p;	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
#endif /* CONFIG_MM_OWNER */	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
/*	case IRQ_TYPE_EDGE_RISING:
 * Initialize POSIX timer handling for a single task.	case IRQ_TYPE_EDGE_RISING:
 */	case IRQ_TYPE_EDGE_RISING:
static void posix_cpu_timers_init(struct task_struct *tsk)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	tsk->cputime_expires.prof_exp = 0;	case IRQ_TYPE_EDGE_RISING:
	tsk->cputime_expires.virt_exp = 0;	case IRQ_TYPE_EDGE_RISING:
	tsk->cputime_expires.sched_exp = 0;	case IRQ_TYPE_EDGE_RISING:
	INIT_LIST_HEAD(&tsk->cpu_timers[0]);	case IRQ_TYPE_EDGE_RISING:
	INIT_LIST_HEAD(&tsk->cpu_timers[1]);	case IRQ_TYPE_EDGE_RISING:
	INIT_LIST_HEAD(&tsk->cpu_timers[2]);	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
static inline void	case IRQ_TYPE_EDGE_RISING:
init_task_pid(struct task_struct *task, enum pid_type type, struct pid *pid)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	 task->pids[type].pid = pid;	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
/*	case IRQ_TYPE_EDGE_RISING:
 * This creates a new process as a copy of the old one,	case IRQ_TYPE_EDGE_RISING:
 * but does not actually start it yet.	case IRQ_TYPE_EDGE_RISING:
 *	case IRQ_TYPE_EDGE_RISING:
 * It copies the registers, and all the appropriate	case IRQ_TYPE_EDGE_RISING:
 * parts of the process environment (as per the clone	case IRQ_TYPE_EDGE_RISING:
 * flags). The actual kick-off is left to the caller.	case IRQ_TYPE_EDGE_RISING:
 */	case IRQ_TYPE_EDGE_RISING:
static struct task_struct *copy_process(unsigned long clone_flags,	case IRQ_TYPE_EDGE_RISING:
					unsigned long stack_start,	case IRQ_TYPE_EDGE_RISING:
					unsigned long stack_size,	case IRQ_TYPE_EDGE_RISING:
					int __user *child_tidptr,	case IRQ_TYPE_EDGE_RISING:
					struct pid *pid,	case IRQ_TYPE_EDGE_RISING:
					int trace)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	int retval;	case IRQ_TYPE_EDGE_RISING:
	struct task_struct *p;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	if ((clone_flags & (CLONE_NEWNS|CLONE_FS)) == (CLONE_NEWNS|CLONE_FS))	case IRQ_TYPE_EDGE_RISING:
		return ERR_PTR(-EINVAL);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	if ((clone_flags & (CLONE_NEWUSER|CLONE_FS)) == (CLONE_NEWUSER|CLONE_FS))	case IRQ_TYPE_EDGE_RISING:
		return ERR_PTR(-EINVAL);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	/*	case IRQ_TYPE_EDGE_RISING:
	 * Thread groups must share signals as well, and detached threads	case IRQ_TYPE_EDGE_RISING:
	 * can only be started up within the thread group.	case IRQ_TYPE_EDGE_RISING:
	 */	case IRQ_TYPE_EDGE_RISING:
	if ((clone_flags & CLONE_THREAD) && !(clone_flags & CLONE_SIGHAND))	case IRQ_TYPE_EDGE_RISING:
		return ERR_PTR(-EINVAL);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	/*	case IRQ_TYPE_EDGE_RISING:
	 * Shared signal handlers imply shared VM. By way of the above,	case IRQ_TYPE_EDGE_RISING:
	 * thread groups also imply shared VM. Blocking this case allows	case IRQ_TYPE_EDGE_RISING:
	 * for various simplifications in other code.	case IRQ_TYPE_EDGE_RISING:
	 */	case IRQ_TYPE_EDGE_RISING:
	if ((clone_flags & CLONE_SIGHAND) && !(clone_flags & CLONE_VM))	case IRQ_TYPE_EDGE_RISING:
		return ERR_PTR(-EINVAL);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	/*	case IRQ_TYPE_EDGE_RISING:
	 * Siblings of global init remain as zombies on exit since they are	case IRQ_TYPE_EDGE_RISING:
	 * not reaped by their parent (swapper). To solve this and to avoid	case IRQ_TYPE_EDGE_RISING:
	 * multi-rooted process trees, prevent global and container-inits	case IRQ_TYPE_EDGE_RISING:
	 * from creating siblings.	case IRQ_TYPE_EDGE_RISING:
	 */	case IRQ_TYPE_EDGE_RISING:
	if ((clone_flags & CLONE_PARENT) &&	case IRQ_TYPE_EDGE_RISING:
				current->signal->flags & SIGNAL_UNKILLABLE)	case IRQ_TYPE_EDGE_RISING:
		return ERR_PTR(-EINVAL);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	/*	case IRQ_TYPE_EDGE_RISING:
	 * If the new process will be in a different pid or user namespace	case IRQ_TYPE_EDGE_RISING:
	 * do not allow it to share a thread group or signal handlers or	case IRQ_TYPE_EDGE_RISING:
	 * parent with the forking task.	case IRQ_TYPE_EDGE_RISING:
	 */	case IRQ_TYPE_EDGE_RISING:
	if (clone_flags & CLONE_SIGHAND) {	case IRQ_TYPE_EDGE_RISING:
		if ((clone_flags & (CLONE_NEWUSER | CLONE_NEWPID)) ||	case IRQ_TYPE_EDGE_RISING:
		    (task_active_pid_ns(current) !=	case IRQ_TYPE_EDGE_RISING:
				current->nsproxy->pid_ns_for_children))	case IRQ_TYPE_EDGE_RISING:
			return ERR_PTR(-EINVAL);	case IRQ_TYPE_EDGE_RISING:
	}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	retval = security_task_create(clone_flags);	case IRQ_TYPE_EDGE_RISING:
	if (retval)	case IRQ_TYPE_EDGE_RISING:
		goto fork_out;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	retval = -ENOMEM;	case IRQ_TYPE_EDGE_RISING:
	p = dup_task_struct(current);	case IRQ_TYPE_EDGE_RISING:
	if (!p)	case IRQ_TYPE_EDGE_RISING:
		goto fork_out;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	ftrace_graph_init_task(p);	case IRQ_TYPE_EDGE_RISING:
	get_seccomp_filter(p);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	rt_mutex_init_task(p);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
#ifdef CONFIG_PROVE_LOCKING	case IRQ_TYPE_EDGE_RISING:
	DEBUG_LOCKS_WARN_ON(!p->hardirqs_enabled);	case IRQ_TYPE_EDGE_RISING:
	DEBUG_LOCKS_WARN_ON(!p->softirqs_enabled);	case IRQ_TYPE_EDGE_RISING:
#endif	case IRQ_TYPE_EDGE_RISING:
	retval = -EAGAIN;	case IRQ_TYPE_EDGE_RISING:
	if (atomic_read(&p->real_cred->user->processes) >=	case IRQ_TYPE_EDGE_RISING:
			task_rlimit(p, RLIMIT_NPROC)) {	case IRQ_TYPE_EDGE_RISING:
		if (p->real_cred->user != INIT_USER &&	case IRQ_TYPE_EDGE_RISING:
		    !capable(CAP_SYS_RESOURCE) && !capable(CAP_SYS_ADMIN))	case IRQ_TYPE_EDGE_RISING:
			goto bad_fork_free;	case IRQ_TYPE_EDGE_RISING:
	}	case IRQ_TYPE_EDGE_RISING:
	current->flags &= ~PF_NPROC_EXCEEDED;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	retval = copy_creds(p, clone_flags);	case IRQ_TYPE_EDGE_RISING:
	if (retval < 0)	case IRQ_TYPE_EDGE_RISING:
		goto bad_fork_free;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	/*	case IRQ_TYPE_EDGE_RISING:
	 * If multiple threads are within copy_process(), then this check	case IRQ_TYPE_EDGE_RISING:
	 * triggers too late. This doesn't hurt, the check is only there	case IRQ_TYPE_EDGE_RISING:
	 * to stop root fork bombs.	case IRQ_TYPE_EDGE_RISING:
	 */	case IRQ_TYPE_EDGE_RISING:
	retval = -EAGAIN;	case IRQ_TYPE_EDGE_RISING:
	if (nr_threads >= max_threads)	case IRQ_TYPE_EDGE_RISING:
		goto bad_fork_cleanup_count;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	if (!try_module_get(task_thread_info(p)->exec_domain->module))	case IRQ_TYPE_EDGE_RISING:
		goto bad_fork_cleanup_count;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	delayacct_tsk_init(p);	/* Must remain after dup_task_struct() */	case IRQ_TYPE_EDGE_RISING:
	copy_flags(clone_flags, p);	case IRQ_TYPE_EDGE_RISING:
	INIT_LIST_HEAD(&p->children);	case IRQ_TYPE_EDGE_RISING:
	INIT_LIST_HEAD(&p->sibling);	case IRQ_TYPE_EDGE_RISING:
	rcu_copy_process(p);	case IRQ_TYPE_EDGE_RISING:
	p->vfork_done = NULL;	case IRQ_TYPE_EDGE_RISING:
	spin_lock_init(&p->alloc_lock);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	init_sigpending(&p->pending);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	p->utime = p->stime = p->gtime = 0;	case IRQ_TYPE_EDGE_RISING:
	p->utimescaled = p->stimescaled = 0;	case IRQ_TYPE_EDGE_RISING:
#ifndef CONFIG_VIRT_CPU_ACCOUNTING_NATIVE	case IRQ_TYPE_EDGE_RISING:
	p->prev_cputime.utime = p->prev_cputime.stime = 0;	case IRQ_TYPE_EDGE_RISING:
#endif	case IRQ_TYPE_EDGE_RISING:
#ifdef CONFIG_VIRT_CPU_ACCOUNTING_GEN	case IRQ_TYPE_EDGE_RISING:
	seqlock_init(&p->vtime_seqlock);	case IRQ_TYPE_EDGE_RISING:
	p->vtime_snap = 0;	case IRQ_TYPE_EDGE_RISING:
	p->vtime_snap_whence = VTIME_SLEEPING;	case IRQ_TYPE_EDGE_RISING:
#endif	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
#if defined(SPLIT_RSS_COUNTING)	case IRQ_TYPE_EDGE_RISING:
	memset(&p->rss_stat, 0, sizeof(p->rss_stat));	case IRQ_TYPE_EDGE_RISING:
#endif	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	p->default_timer_slack_ns = current->timer_slack_ns;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	task_io_accounting_init(&p->ioac);	case IRQ_TYPE_EDGE_RISING:
	acct_clear_integrals(p);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	posix_cpu_timers_init(p);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	do_posix_clock_monotonic_gettime(&p->start_time);	case IRQ_TYPE_EDGE_RISING:
	p->real_start_time = p->start_time;	case IRQ_TYPE_EDGE_RISING:
	monotonic_to_bootbased(&p->real_start_time);	case IRQ_TYPE_EDGE_RISING:
	p->io_context = NULL;	case IRQ_TYPE_EDGE_RISING:
	p->audit_context = NULL;	case IRQ_TYPE_EDGE_RISING:
	if (clone_flags & CLONE_THREAD)	case IRQ_TYPE_EDGE_RISING:
		threadgroup_change_begin(current);	case IRQ_TYPE_EDGE_RISING:
	cgroup_fork(p);	case IRQ_TYPE_EDGE_RISING:
#ifdef CONFIG_NUMA	case IRQ_TYPE_EDGE_RISING:
	p->mempolicy = mpol_dup(p->mempolicy);	case IRQ_TYPE_EDGE_RISING:
	if (IS_ERR(p->mempolicy)) {	case IRQ_TYPE_EDGE_RISING:
		retval = PTR_ERR(p->mempolicy);	case IRQ_TYPE_EDGE_RISING:
		p->mempolicy = NULL;	case IRQ_TYPE_EDGE_RISING:
		goto bad_fork_cleanup_cgroup;	case IRQ_TYPE_EDGE_RISING:
	}	case IRQ_TYPE_EDGE_RISING:
	mpol_fix_fork_child_flag(p);	case IRQ_TYPE_EDGE_RISING:
#endif	case IRQ_TYPE_EDGE_RISING:
#ifdef CONFIG_CPUSETS	case IRQ_TYPE_EDGE_RISING:
	p->cpuset_mem_spread_rotor = NUMA_NO_NODE;	case IRQ_TYPE_EDGE_RISING:
	p->cpuset_slab_spread_rotor = NUMA_NO_NODE;	case IRQ_TYPE_EDGE_RISING:
	seqcount_init(&p->mems_allowed_seq);	case IRQ_TYPE_EDGE_RISING:
#endif	case IRQ_TYPE_EDGE_RISING:
#ifdef CONFIG_TRACE_IRQFLAGS	case IRQ_TYPE_EDGE_RISING:
	p->irq_events = 0;	case IRQ_TYPE_EDGE_RISING:
	p->hardirqs_enabled = 0;	case IRQ_TYPE_EDGE_RISING:
	p->hardirq_enable_ip = 0;	case IRQ_TYPE_EDGE_RISING:
	p->hardirq_enable_event = 0;	case IRQ_TYPE_EDGE_RISING:
	p->hardirq_disable_ip = _THIS_IP_;	case IRQ_TYPE_EDGE_RISING:
	p->hardirq_disable_event = 0;	case IRQ_TYPE_EDGE_RISING:
	p->softirqs_enabled = 1;	case IRQ_TYPE_EDGE_RISING:
	p->softirq_enable_ip = _THIS_IP_;	case IRQ_TYPE_EDGE_RISING:
	p->softirq_enable_event = 0;	case IRQ_TYPE_EDGE_RISING:
	p->softirq_disable_ip = 0;	case IRQ_TYPE_EDGE_RISING:
	p->softirq_disable_event = 0;	case IRQ_TYPE_EDGE_RISING:
	p->hardirq_context = 0;	case IRQ_TYPE_EDGE_RISING:
	p->softirq_context = 0;	case IRQ_TYPE_EDGE_RISING:
#endif	case IRQ_TYPE_EDGE_RISING:
#ifdef CONFIG_LOCKDEP	case IRQ_TYPE_EDGE_RISING:
	p->lockdep_depth = 0; /* no locks held yet */	case IRQ_TYPE_EDGE_RISING:
	p->curr_chain_key = 0;	case IRQ_TYPE_EDGE_RISING:
	p->lockdep_recursion = 0;	case IRQ_TYPE_EDGE_RISING:
#endif	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
#ifdef CONFIG_DEBUG_MUTEXES	case IRQ_TYPE_EDGE_RISING:
	p->blocked_on = NULL; /* not blocked yet */	case IRQ_TYPE_EDGE_RISING:
#endif	case IRQ_TYPE_EDGE_RISING:
#ifdef CONFIG_MEMCG	case IRQ_TYPE_EDGE_RISING:
	p->memcg_batch.do_batch = 0;	case IRQ_TYPE_EDGE_RISING:
	p->memcg_batch.memcg = NULL;	case IRQ_TYPE_EDGE_RISING:
#endif	case IRQ_TYPE_EDGE_RISING:
#ifdef CONFIG_BCACHE	case IRQ_TYPE_EDGE_RISING:
	p->sequential_io	= 0;	case IRQ_TYPE_EDGE_RISING:
	p->sequential_io_avg	= 0;	case IRQ_TYPE_EDGE_RISING:
#endif	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	/* Perform scheduler related setup. Assign this task to a CPU. */	case IRQ_TYPE_EDGE_RISING:
	retval = sched_fork(clone_flags, p);	case IRQ_TYPE_EDGE_RISING:
	if (retval)	case IRQ_TYPE_EDGE_RISING:
		goto bad_fork_cleanup_policy;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	retval = perf_event_init_task(p);	case IRQ_TYPE_EDGE_RISING:
	if (retval)	case IRQ_TYPE_EDGE_RISING:
		goto bad_fork_cleanup_policy;	case IRQ_TYPE_EDGE_RISING:
	retval = audit_alloc(p);	case IRQ_TYPE_EDGE_RISING:
	if (retval)	case IRQ_TYPE_EDGE_RISING:
		goto bad_fork_cleanup_policy;	case IRQ_TYPE_EDGE_RISING:
	/* copy all the process information */	case IRQ_TYPE_EDGE_RISING:
	retval = copy_semundo(clone_flags, p);	case IRQ_TYPE_EDGE_RISING:
	if (retval)	case IRQ_TYPE_EDGE_RISING:
		goto bad_fork_cleanup_audit;	case IRQ_TYPE_EDGE_RISING:
	retval = copy_files(clone_flags, p);	case IRQ_TYPE_EDGE_RISING:
	if (retval)	case IRQ_TYPE_EDGE_RISING:
		goto bad_fork_cleanup_semundo;	case IRQ_TYPE_EDGE_RISING:
	retval = copy_fs(clone_flags, p);	case IRQ_TYPE_EDGE_RISING:
	if (retval)	case IRQ_TYPE_EDGE_RISING:
		goto bad_fork_cleanup_files;	case IRQ_TYPE_EDGE_RISING:
	retval = copy_sighand(clone_flags, p);	case IRQ_TYPE_EDGE_RISING:
	if (retval)	case IRQ_TYPE_EDGE_RISING:
		goto bad_fork_cleanup_fs;	case IRQ_TYPE_EDGE_RISING:
	retval = copy_signal(clone_flags, p);	case IRQ_TYPE_EDGE_RISING:
	if (retval)	case IRQ_TYPE_EDGE_RISING:
		goto bad_fork_cleanup_sighand;	case IRQ_TYPE_EDGE_RISING:
	retval = copy_mm(clone_flags, p);	case IRQ_TYPE_EDGE_RISING:
	if (retval)	case IRQ_TYPE_EDGE_RISING:
		goto bad_fork_cleanup_signal;	case IRQ_TYPE_EDGE_RISING:
	retval = copy_namespaces(clone_flags, p);	case IRQ_TYPE_EDGE_RISING:
	if (retval)	case IRQ_TYPE_EDGE_RISING:
		goto bad_fork_cleanup_mm;	case IRQ_TYPE_EDGE_RISING:
	retval = copy_io(clone_flags, p);	case IRQ_TYPE_EDGE_RISING:
	if (retval)	case IRQ_TYPE_EDGE_RISING:
		goto bad_fork_cleanup_namespaces;	case IRQ_TYPE_EDGE_RISING:
	retval = copy_thread(clone_flags, stack_start, stack_size, p);	case IRQ_TYPE_EDGE_RISING:
	if (retval)	case IRQ_TYPE_EDGE_RISING:
		goto bad_fork_cleanup_io;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	if (pid != &init_struct_pid) {	case IRQ_TYPE_EDGE_RISING:
		retval = -ENOMEM;	case IRQ_TYPE_EDGE_RISING:
		pid = alloc_pid(p->nsproxy->pid_ns_for_children);	case IRQ_TYPE_EDGE_RISING:
		if (!pid)	case IRQ_TYPE_EDGE_RISING:
			goto bad_fork_cleanup_io;	case IRQ_TYPE_EDGE_RISING:
	}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	p->set_child_tid = (clone_flags & CLONE_CHILD_SETTID) ? child_tidptr : NULL;	case IRQ_TYPE_EDGE_RISING:
	/*	case IRQ_TYPE_EDGE_RISING:
	 * Clear TID on mm_release()?	case IRQ_TYPE_EDGE_RISING:
	 */	case IRQ_TYPE_EDGE_RISING:
	p->clear_child_tid = (clone_flags & CLONE_CHILD_CLEARTID) ? child_tidptr : NULL;	case IRQ_TYPE_EDGE_RISING:
#ifdef CONFIG_BLOCK	case IRQ_TYPE_EDGE_RISING:
	p->plug = NULL;	case IRQ_TYPE_EDGE_RISING:
#endif	case IRQ_TYPE_EDGE_RISING:
#ifdef CONFIG_FUTEX	case IRQ_TYPE_EDGE_RISING:
	p->robust_list = NULL;	case IRQ_TYPE_EDGE_RISING:
#ifdef CONFIG_COMPAT	case IRQ_TYPE_EDGE_RISING:
	p->compat_robust_list = NULL;	case IRQ_TYPE_EDGE_RISING:
#endif	case IRQ_TYPE_EDGE_RISING:
	INIT_LIST_HEAD(&p->pi_state_list);	case IRQ_TYPE_EDGE_RISING:
	p->pi_state_cache = NULL;	case IRQ_TYPE_EDGE_RISING:
#endif	case IRQ_TYPE_EDGE_RISING:
	/*	case IRQ_TYPE_EDGE_RISING:
	 * sigaltstack should be cleared when sharing the same VM	case IRQ_TYPE_EDGE_RISING:
	 */	case IRQ_TYPE_EDGE_RISING:
	if ((clone_flags & (CLONE_VM|CLONE_VFORK)) == CLONE_VM)	case IRQ_TYPE_EDGE_RISING:
		p->sas_ss_sp = p->sas_ss_size = 0;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	/*	case IRQ_TYPE_EDGE_RISING:
	 * Syscall tracing and stepping should be turned off in the	case IRQ_TYPE_EDGE_RISING:
	 * child regardless of CLONE_PTRACE.	case IRQ_TYPE_EDGE_RISING:
	 */	case IRQ_TYPE_EDGE_RISING:
	user_disable_single_step(p);	case IRQ_TYPE_EDGE_RISING:
	clear_tsk_thread_flag(p, TIF_SYSCALL_TRACE);	case IRQ_TYPE_EDGE_RISING:
#ifdef TIF_SYSCALL_EMU	case IRQ_TYPE_EDGE_RISING:
	clear_tsk_thread_flag(p, TIF_SYSCALL_EMU);	case IRQ_TYPE_EDGE_RISING:
#endif	case IRQ_TYPE_EDGE_RISING:
	clear_all_latency_tracing(p);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	/* ok, now we should be set up.. */	case IRQ_TYPE_EDGE_RISING:
	p->pid = pid_nr(pid);	case IRQ_TYPE_EDGE_RISING:
	if (clone_flags & CLONE_THREAD) {	case IRQ_TYPE_EDGE_RISING:
		p->exit_signal = -1;	case IRQ_TYPE_EDGE_RISING:
		p->group_leader = current->group_leader;	case IRQ_TYPE_EDGE_RISING:
		p->tgid = current->tgid;	case IRQ_TYPE_EDGE_RISING:
	} else {	case IRQ_TYPE_EDGE_RISING:
		if (clone_flags & CLONE_PARENT)	case IRQ_TYPE_EDGE_RISING:
			p->exit_signal = current->group_leader->exit_signal;	case IRQ_TYPE_EDGE_RISING:
		else	case IRQ_TYPE_EDGE_RISING:
			p->exit_signal = (clone_flags & CSIGNAL);	case IRQ_TYPE_EDGE_RISING:
		p->group_leader = p;	case IRQ_TYPE_EDGE_RISING:
		p->tgid = p->pid;	case IRQ_TYPE_EDGE_RISING:
	}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	p->nr_dirtied = 0;	case IRQ_TYPE_EDGE_RISING:
	p->nr_dirtied_pause = 128 >> (PAGE_SHIFT - 10);	case IRQ_TYPE_EDGE_RISING:
	p->dirty_paused_when = 0;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	p->pdeath_signal = 0;	case IRQ_TYPE_EDGE_RISING:
	INIT_LIST_HEAD(&p->thread_group);	case IRQ_TYPE_EDGE_RISING:
	p->task_works = NULL;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	/*	case IRQ_TYPE_EDGE_RISING:
	 * Make it visible to the rest of the system, but dont wake it up yet.	case IRQ_TYPE_EDGE_RISING:
	 * Need tasklist lock for parent etc handling!	case IRQ_TYPE_EDGE_RISING:
	 */	case IRQ_TYPE_EDGE_RISING:
	write_lock_irq(&tasklist_lock);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	/* CLONE_PARENT re-uses the old parent */	case IRQ_TYPE_EDGE_RISING:
	if (clone_flags & (CLONE_PARENT|CLONE_THREAD)) {	case IRQ_TYPE_EDGE_RISING:
		p->real_parent = current->real_parent;	case IRQ_TYPE_EDGE_RISING:
		p->parent_exec_id = current->parent_exec_id;	case IRQ_TYPE_EDGE_RISING:
	} else {	case IRQ_TYPE_EDGE_RISING:
		p->real_parent = current;	case IRQ_TYPE_EDGE_RISING:
		p->parent_exec_id = current->self_exec_id;	case IRQ_TYPE_EDGE_RISING:
	}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	spin_lock(&current->sighand->siglock);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	/*	case IRQ_TYPE_EDGE_RISING:
	 * Process group and session signals need to be delivered to just the	case IRQ_TYPE_EDGE_RISING:
	 * parent before the fork or both the parent and the child after the	case IRQ_TYPE_EDGE_RISING:
	 * fork. Restart if a signal comes in before we add the new process to	case IRQ_TYPE_EDGE_RISING:
	 * it's process group.	case IRQ_TYPE_EDGE_RISING:
	 * A fatal signal pending means that current will exit, so the new	case IRQ_TYPE_EDGE_RISING:
	 * thread can't slip out of an OOM kill (or normal SIGKILL).	case IRQ_TYPE_EDGE_RISING:
	*/	case IRQ_TYPE_EDGE_RISING:
	recalc_sigpending();	case IRQ_TYPE_EDGE_RISING:
	if (signal_pending(current)) {	case IRQ_TYPE_EDGE_RISING:
		spin_unlock(&current->sighand->siglock);	case IRQ_TYPE_EDGE_RISING:
		write_unlock_irq(&tasklist_lock);	case IRQ_TYPE_EDGE_RISING:
		retval = -ERESTARTNOINTR;	case IRQ_TYPE_EDGE_RISING:
		goto bad_fork_free_pid;	case IRQ_TYPE_EDGE_RISING:
	}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	if (likely(p->pid)) {	case IRQ_TYPE_EDGE_RISING:
		ptrace_init_task(p, (clone_flags & CLONE_PTRACE) || trace);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
		init_task_pid(p, PIDTYPE_PID, pid);	case IRQ_TYPE_EDGE_RISING:
		if (thread_group_leader(p)) {	case IRQ_TYPE_EDGE_RISING:
			init_task_pid(p, PIDTYPE_PGID, task_pgrp(current));	case IRQ_TYPE_EDGE_RISING:
			init_task_pid(p, PIDTYPE_SID, task_session(current));	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
			if (is_child_reaper(pid)) {	case IRQ_TYPE_EDGE_RISING:
				ns_of_pid(pid)->child_reaper = p;	case IRQ_TYPE_EDGE_RISING:
				p->signal->flags |= SIGNAL_UNKILLABLE;	case IRQ_TYPE_EDGE_RISING:
			}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
			p->signal->leader_pid = pid;	case IRQ_TYPE_EDGE_RISING:
			p->signal->tty = tty_kref_get(current->signal->tty);	case IRQ_TYPE_EDGE_RISING:
			list_add_tail(&p->sibling, &p->real_parent->children);	case IRQ_TYPE_EDGE_RISING:
			list_add_tail_rcu(&p->tasks, &init_task.tasks);	case IRQ_TYPE_EDGE_RISING:
			attach_pid(p, PIDTYPE_PGID);	case IRQ_TYPE_EDGE_RISING:
			attach_pid(p, PIDTYPE_SID);	case IRQ_TYPE_EDGE_RISING:
			__this_cpu_inc(process_counts);	case IRQ_TYPE_EDGE_RISING:
		} else {	case IRQ_TYPE_EDGE_RISING:
			current->signal->nr_threads++;	case IRQ_TYPE_EDGE_RISING:
			atomic_inc(&current->signal->live);	case IRQ_TYPE_EDGE_RISING:
			atomic_inc(&current->signal->sigcnt);	case IRQ_TYPE_EDGE_RISING:
			list_add_tail_rcu(&p->thread_group,	case IRQ_TYPE_EDGE_RISING:
					  &p->group_leader->thread_group);	case IRQ_TYPE_EDGE_RISING:
			list_add_tail_rcu(&p->thread_node,	case IRQ_TYPE_EDGE_RISING:
					  &p->signal->thread_head);	case IRQ_TYPE_EDGE_RISING:
		}	case IRQ_TYPE_EDGE_RISING:
		attach_pid(p, PIDTYPE_PID);	case IRQ_TYPE_EDGE_RISING:
		nr_threads++;	case IRQ_TYPE_EDGE_RISING:
	}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	total_forks++;	case IRQ_TYPE_EDGE_RISING:
	spin_unlock(&current->sighand->siglock);	case IRQ_TYPE_EDGE_RISING:
	write_unlock_irq(&tasklist_lock);	case IRQ_TYPE_EDGE_RISING:
	proc_fork_connector(p);	case IRQ_TYPE_EDGE_RISING:
	cgroup_post_fork(p);	case IRQ_TYPE_EDGE_RISING:
	if (clone_flags & CLONE_THREAD)	case IRQ_TYPE_EDGE_RISING:
		threadgroup_change_end(current);	case IRQ_TYPE_EDGE_RISING:
	perf_event_fork(p);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	trace_task_newtask(p, clone_flags);	case IRQ_TYPE_EDGE_RISING:
	uprobe_copy_process(p, clone_flags);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	return p;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
bad_fork_free_pid:	case IRQ_TYPE_EDGE_RISING:
	if (pid != &init_struct_pid)	case IRQ_TYPE_EDGE_RISING:
		free_pid(pid);	case IRQ_TYPE_EDGE_RISING:
bad_fork_cleanup_io:	case IRQ_TYPE_EDGE_RISING:
	if (p->io_context)	case IRQ_TYPE_EDGE_RISING:
		exit_io_context(p);	case IRQ_TYPE_EDGE_RISING:
bad_fork_cleanup_namespaces:	case IRQ_TYPE_EDGE_RISING:
	exit_task_namespaces(p);	case IRQ_TYPE_EDGE_RISING:
bad_fork_cleanup_mm:	case IRQ_TYPE_EDGE_RISING:
	if (p->mm)	case IRQ_TYPE_EDGE_RISING:
		mmput(p->mm);	case IRQ_TYPE_EDGE_RISING:
bad_fork_cleanup_signal:	case IRQ_TYPE_EDGE_RISING:
	if (!(clone_flags & CLONE_THREAD))	case IRQ_TYPE_EDGE_RISING:
		free_signal_struct(p->signal);	case IRQ_TYPE_EDGE_RISING:
bad_fork_cleanup_sighand:	case IRQ_TYPE_EDGE_RISING:
	__cleanup_sighand(p->sighand);	case IRQ_TYPE_EDGE_RISING:
bad_fork_cleanup_fs:	case IRQ_TYPE_EDGE_RISING:
	exit_fs(p); /* blocking */	case IRQ_TYPE_EDGE_RISING:
bad_fork_cleanup_files:	case IRQ_TYPE_EDGE_RISING:
	exit_files(p); /* blocking */	case IRQ_TYPE_EDGE_RISING:
bad_fork_cleanup_semundo:	case IRQ_TYPE_EDGE_RISING:
	exit_sem(p);	case IRQ_TYPE_EDGE_RISING:
bad_fork_cleanup_audit:	case IRQ_TYPE_EDGE_RISING:
	audit_free(p);	case IRQ_TYPE_EDGE_RISING:
bad_fork_cleanup_policy:	case IRQ_TYPE_EDGE_RISING:
	perf_event_free_task(p);	case IRQ_TYPE_EDGE_RISING:
#ifdef CONFIG_NUMA	case IRQ_TYPE_EDGE_RISING:
	mpol_put(p->mempolicy);	case IRQ_TYPE_EDGE_RISING:
bad_fork_cleanup_cgroup:	case IRQ_TYPE_EDGE_RISING:
#endif	case IRQ_TYPE_EDGE_RISING:
	if (clone_flags & CLONE_THREAD)	case IRQ_TYPE_EDGE_RISING:
		threadgroup_change_end(current);	case IRQ_TYPE_EDGE_RISING:
	cgroup_exit(p, 0);	case IRQ_TYPE_EDGE_RISING:
	delayacct_tsk_free(p);	case IRQ_TYPE_EDGE_RISING:
	module_put(task_thread_info(p)->exec_domain->module);	case IRQ_TYPE_EDGE_RISING:
bad_fork_cleanup_count:	case IRQ_TYPE_EDGE_RISING:
	atomic_dec(&p->cred->user->processes);	case IRQ_TYPE_EDGE_RISING:
	exit_creds(p);	case IRQ_TYPE_EDGE_RISING:
bad_fork_free:	case IRQ_TYPE_EDGE_RISING:
	free_task(p);	case IRQ_TYPE_EDGE_RISING:
fork_out:	case IRQ_TYPE_EDGE_RISING:
	return ERR_PTR(retval);	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
static inline void init_idle_pids(struct pid_link *links)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	enum pid_type type;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	for (type = PIDTYPE_PID; type < PIDTYPE_MAX; ++type) {	case IRQ_TYPE_EDGE_RISING:
		INIT_HLIST_NODE(&links[type].node); /* not really needed */	case IRQ_TYPE_EDGE_RISING:
		links[type].pid = &init_struct_pid;	case IRQ_TYPE_EDGE_RISING:
	}	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
struct task_struct *fork_idle(int cpu)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	struct task_struct *task;	case IRQ_TYPE_EDGE_RISING:
	task = copy_process(CLONE_VM, 0, 0, NULL, &init_struct_pid, 0);	case IRQ_TYPE_EDGE_RISING:
	if (!IS_ERR(task)) {	case IRQ_TYPE_EDGE_RISING:
		init_idle_pids(task->pids);	case IRQ_TYPE_EDGE_RISING:
		init_idle(task, cpu);	case IRQ_TYPE_EDGE_RISING:
	}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	return task;	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
/*	case IRQ_TYPE_EDGE_RISING:
 *  Ok, this is the main fork-routine.	case IRQ_TYPE_EDGE_RISING:
 *	case IRQ_TYPE_EDGE_RISING:
 * It copies the process, and if successful kick-starts	case IRQ_TYPE_EDGE_RISING:
 * it and waits for it to finish using the VM if required.	case IRQ_TYPE_EDGE_RISING:
 */	case IRQ_TYPE_EDGE_RISING:
long do_fork(unsigned long clone_flags,	case IRQ_TYPE_EDGE_RISING:
	      unsigned long stack_start,	case IRQ_TYPE_EDGE_RISING:
	      unsigned long stack_size,	case IRQ_TYPE_EDGE_RISING:
	      int __user *parent_tidptr,	case IRQ_TYPE_EDGE_RISING:
	      int __user *child_tidptr)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	struct task_struct *p;	case IRQ_TYPE_EDGE_RISING:
	int trace = 0;	case IRQ_TYPE_EDGE_RISING:
	long nr;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	/*	case IRQ_TYPE_EDGE_RISING:
	 * Determine whether and which event to report to ptracer.  When	case IRQ_TYPE_EDGE_RISING:
	 * called from kernel_thread or CLONE_UNTRACED is explicitly	case IRQ_TYPE_EDGE_RISING:
	 * requested, no event is reported; otherwise, report if the event	case IRQ_TYPE_EDGE_RISING:
	 * for the type of forking is enabled.	case IRQ_TYPE_EDGE_RISING:
	 */	case IRQ_TYPE_EDGE_RISING:
	if (!(clone_flags & CLONE_UNTRACED)) {	case IRQ_TYPE_EDGE_RISING:
		if (clone_flags & CLONE_VFORK)	case IRQ_TYPE_EDGE_RISING:
			trace = PTRACE_EVENT_VFORK;	case IRQ_TYPE_EDGE_RISING:
		else if ((clone_flags & CSIGNAL) != SIGCHLD)	case IRQ_TYPE_EDGE_RISING:
			trace = PTRACE_EVENT_CLONE;	case IRQ_TYPE_EDGE_RISING:
		else	case IRQ_TYPE_EDGE_RISING:
			trace = PTRACE_EVENT_FORK;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
		if (likely(!ptrace_event_enabled(current, trace)))	case IRQ_TYPE_EDGE_RISING:
			trace = 0;	case IRQ_TYPE_EDGE_RISING:
	}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	p = copy_process(clone_flags, stack_start, stack_size,	case IRQ_TYPE_EDGE_RISING:
			 child_tidptr, NULL, trace);	case IRQ_TYPE_EDGE_RISING:
	/*	case IRQ_TYPE_EDGE_RISING:
	 * Do this prior waking up the new thread - the thread pointer	case IRQ_TYPE_EDGE_RISING:
	 * might get invalid after that point, if the thread exits quickly.	case IRQ_TYPE_EDGE_RISING:
	 */	case IRQ_TYPE_EDGE_RISING:
	if (!IS_ERR(p)) {	case IRQ_TYPE_EDGE_RISING:
		struct completion vfork;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
		trace_sched_process_fork(current, p);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
		nr = task_pid_vnr(p);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
		if (clone_flags & CLONE_PARENT_SETTID)	case IRQ_TYPE_EDGE_RISING:
			put_user(nr, parent_tidptr);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
		if (clone_flags & CLONE_VFORK) {	case IRQ_TYPE_EDGE_RISING:
			p->vfork_done = &vfork;	case IRQ_TYPE_EDGE_RISING:
			init_completion(&vfork);	case IRQ_TYPE_EDGE_RISING:
			get_task_struct(p);	case IRQ_TYPE_EDGE_RISING:
		}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
		wake_up_new_task(p);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
		/* forking complete and child started to run, tell ptracer */	case IRQ_TYPE_EDGE_RISING:
		if (unlikely(trace))	case IRQ_TYPE_EDGE_RISING:
			ptrace_event(trace, nr);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
		if (clone_flags & CLONE_VFORK) {	case IRQ_TYPE_EDGE_RISING:
			if (!wait_for_vfork_done(p, &vfork))	case IRQ_TYPE_EDGE_RISING:
				ptrace_event(PTRACE_EVENT_VFORK_DONE, nr);	case IRQ_TYPE_EDGE_RISING:
		}	case IRQ_TYPE_EDGE_RISING:
	} else {	case IRQ_TYPE_EDGE_RISING:
		nr = PTR_ERR(p);	case IRQ_TYPE_EDGE_RISING:
	}	case IRQ_TYPE_EDGE_RISING:
	return nr;	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
/*	case IRQ_TYPE_EDGE_RISING:
 * Create a kernel thread.	case IRQ_TYPE_EDGE_RISING:
 */	case IRQ_TYPE_EDGE_RISING:
pid_t kernel_thread(int (*fn)(void *), void *arg, unsigned long flags)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	return do_fork(flags|CLONE_VM|CLONE_UNTRACED, (unsigned long)fn,	case IRQ_TYPE_EDGE_RISING:
		(unsigned long)arg, NULL, NULL);	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
#ifdef __ARCH_WANT_SYS_FORK	case IRQ_TYPE_EDGE_RISING:
SYSCALL_DEFINE0(fork)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
#ifdef CONFIG_MMU	case IRQ_TYPE_EDGE_RISING:
	return do_fork(SIGCHLD, 0, 0, NULL, NULL);	case IRQ_TYPE_EDGE_RISING:
#else	case IRQ_TYPE_EDGE_RISING:
	/* can not support in nommu mode */	case IRQ_TYPE_EDGE_RISING:
	return -EINVAL;	case IRQ_TYPE_EDGE_RISING:
#endif	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
#endif	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
#ifdef __ARCH_WANT_SYS_VFORK	case IRQ_TYPE_EDGE_RISING:
SYSCALL_DEFINE0(vfork)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	return do_fork(CLONE_VFORK | CLONE_VM | SIGCHLD, 0,	case IRQ_TYPE_EDGE_RISING:
			0, NULL, NULL);	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
#endif	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
#ifdef __ARCH_WANT_SYS_CLONE	case IRQ_TYPE_EDGE_RISING:
#ifdef CONFIG_CLONE_BACKWARDS	case IRQ_TYPE_EDGE_RISING:
SYSCALL_DEFINE5(clone, unsigned long, clone_flags, unsigned long, newsp,	case IRQ_TYPE_EDGE_RISING:
		 int __user *, parent_tidptr,	case IRQ_TYPE_EDGE_RISING:
		 int, tls_val,	case IRQ_TYPE_EDGE_RISING:
		 int __user *, child_tidptr)	case IRQ_TYPE_EDGE_RISING:
#elif defined(CONFIG_CLONE_BACKWARDS2)	case IRQ_TYPE_EDGE_RISING:
SYSCALL_DEFINE5(clone, unsigned long, newsp, unsigned long, clone_flags,	case IRQ_TYPE_EDGE_RISING:
		 int __user *, parent_tidptr,	case IRQ_TYPE_EDGE_RISING:
		 int __user *, child_tidptr,	case IRQ_TYPE_EDGE_RISING:
		 int, tls_val)	case IRQ_TYPE_EDGE_RISING:
#elif defined(CONFIG_CLONE_BACKWARDS3)	case IRQ_TYPE_EDGE_RISING:
SYSCALL_DEFINE6(clone, unsigned long, clone_flags, unsigned long, newsp,	case IRQ_TYPE_EDGE_RISING:
		int, stack_size,	case IRQ_TYPE_EDGE_RISING:
		int __user *, parent_tidptr,	case IRQ_TYPE_EDGE_RISING:
		int __user *, child_tidptr,	case IRQ_TYPE_EDGE_RISING:
		int, tls_val)	case IRQ_TYPE_EDGE_RISING:
#else	case IRQ_TYPE_EDGE_RISING:
SYSCALL_DEFINE5(clone, unsigned long, clone_flags, unsigned long, newsp,	case IRQ_TYPE_EDGE_RISING:
		 int __user *, parent_tidptr,	case IRQ_TYPE_EDGE_RISING:
		 int __user *, child_tidptr,	case IRQ_TYPE_EDGE_RISING:
		 int, tls_val)	case IRQ_TYPE_EDGE_RISING:
#endif	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	return do_fork(clone_flags, newsp, 0, parent_tidptr, child_tidptr);	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
#endif	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
#ifndef ARCH_MIN_MMSTRUCT_ALIGN	case IRQ_TYPE_EDGE_RISING:
#define ARCH_MIN_MMSTRUCT_ALIGN 0	case IRQ_TYPE_EDGE_RISING:
#endif	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
static void sighand_ctor(void *data)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	struct sighand_struct *sighand = data;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	spin_lock_init(&sighand->siglock);	case IRQ_TYPE_EDGE_RISING:
	init_waitqueue_head(&sighand->signalfd_wqh);	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
void __init proc_caches_init(void)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	sighand_cachep = kmem_cache_create("sighand_cache",	case IRQ_TYPE_EDGE_RISING:
			sizeof(struct sighand_struct), 0,	case IRQ_TYPE_EDGE_RISING:
			SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_DESTROY_BY_RCU|	case IRQ_TYPE_EDGE_RISING:
			SLAB_NOTRACK, sighand_ctor);	case IRQ_TYPE_EDGE_RISING:
	signal_cachep = kmem_cache_create("signal_cache",	case IRQ_TYPE_EDGE_RISING:
			sizeof(struct signal_struct), 0,	case IRQ_TYPE_EDGE_RISING:
			SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_NOTRACK, NULL);	case IRQ_TYPE_EDGE_RISING:
	files_cachep = kmem_cache_create("files_cache",	case IRQ_TYPE_EDGE_RISING:
			sizeof(struct files_struct), 0,	case IRQ_TYPE_EDGE_RISING:
			SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_NOTRACK, NULL);	case IRQ_TYPE_EDGE_RISING:
	fs_cachep = kmem_cache_create("fs_cache",	case IRQ_TYPE_EDGE_RISING:
			sizeof(struct fs_struct), 0,	case IRQ_TYPE_EDGE_RISING:
			SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_NOTRACK, NULL);	case IRQ_TYPE_EDGE_RISING:
	/*	case IRQ_TYPE_EDGE_RISING:
	 * FIXME! The "sizeof(struct mm_struct)" currently includes the	case IRQ_TYPE_EDGE_RISING:
	 * whole struct cpumask for the OFFSTACK case. We could change	case IRQ_TYPE_EDGE_RISING:
	 * this to *only* allocate as much of it as required by the	case IRQ_TYPE_EDGE_RISING:
	 * maximum number of CPU's we can ever have.  The cpumask_allocation	case IRQ_TYPE_EDGE_RISING:
	 * is at the end of the structure, exactly for that reason.	case IRQ_TYPE_EDGE_RISING:
	 */	case IRQ_TYPE_EDGE_RISING:
	mm_cachep = kmem_cache_create("mm_struct",	case IRQ_TYPE_EDGE_RISING:
			sizeof(struct mm_struct), ARCH_MIN_MMSTRUCT_ALIGN,	case IRQ_TYPE_EDGE_RISING:
			SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_NOTRACK, NULL);	case IRQ_TYPE_EDGE_RISING:
	vm_area_cachep = KMEM_CACHE(vm_area_struct, SLAB_PANIC);	case IRQ_TYPE_EDGE_RISING:
	mmap_init();	case IRQ_TYPE_EDGE_RISING:
	nsproxy_cache_init();	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
/*	case IRQ_TYPE_EDGE_RISING:
 * Check constraints on flags passed to the unshare system call.	case IRQ_TYPE_EDGE_RISING:
 */	case IRQ_TYPE_EDGE_RISING:
static int check_unshare_flags(unsigned long unshare_flags)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	if (unshare_flags & ~(CLONE_THREAD|CLONE_FS|CLONE_NEWNS|CLONE_SIGHAND|	case IRQ_TYPE_EDGE_RISING:
				CLONE_VM|CLONE_FILES|CLONE_SYSVSEM|	case IRQ_TYPE_EDGE_RISING:
				CLONE_NEWUTS|CLONE_NEWIPC|CLONE_NEWNET|	case IRQ_TYPE_EDGE_RISING:
				CLONE_NEWUSER|CLONE_NEWPID))	case IRQ_TYPE_EDGE_RISING:
		return -EINVAL;	case IRQ_TYPE_EDGE_RISING:
	/*	case IRQ_TYPE_EDGE_RISING:
	 * Not implemented, but pretend it works if there is nothing to	case IRQ_TYPE_EDGE_RISING:
	 * unshare. Note that unsharing CLONE_THREAD or CLONE_SIGHAND	case IRQ_TYPE_EDGE_RISING:
	 * needs to unshare vm.	case IRQ_TYPE_EDGE_RISING:
	 */	case IRQ_TYPE_EDGE_RISING:
	if (unshare_flags & (CLONE_THREAD | CLONE_SIGHAND | CLONE_VM)) {	case IRQ_TYPE_EDGE_RISING:
		/* FIXME: get_task_mm() increments ->mm_users */	case IRQ_TYPE_EDGE_RISING:
		if (atomic_read(&current->mm->mm_users) > 1)	case IRQ_TYPE_EDGE_RISING:
			return -EINVAL;	case IRQ_TYPE_EDGE_RISING:
	}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	return 0;	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
/*	case IRQ_TYPE_EDGE_RISING:
 * Unshare the filesystem structure if it is being shared	case IRQ_TYPE_EDGE_RISING:
 */	case IRQ_TYPE_EDGE_RISING:
static int unshare_fs(unsigned long unshare_flags, struct fs_struct **new_fsp)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	struct fs_struct *fs = current->fs;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	if (!(unshare_flags & CLONE_FS) || !fs)	case IRQ_TYPE_EDGE_RISING:
		return 0;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	/* don't need lock here; in the worst case we'll do useless copy */	case IRQ_TYPE_EDGE_RISING:
	if (fs->users == 1)	case IRQ_TYPE_EDGE_RISING:
		return 0;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	*new_fsp = copy_fs_struct(fs);	case IRQ_TYPE_EDGE_RISING:
	if (!*new_fsp)	case IRQ_TYPE_EDGE_RISING:
		return -ENOMEM;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	return 0;	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
/*	case IRQ_TYPE_EDGE_RISING:
 * Unshare file descriptor table if it is being shared	case IRQ_TYPE_EDGE_RISING:
 */	case IRQ_TYPE_EDGE_RISING:
static int unshare_fd(unsigned long unshare_flags, struct files_struct **new_fdp)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	struct files_struct *fd = current->files;	case IRQ_TYPE_EDGE_RISING:
	int error = 0;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	if ((unshare_flags & CLONE_FILES) &&	case IRQ_TYPE_EDGE_RISING:
	    (fd && atomic_read(&fd->count) > 1)) {	case IRQ_TYPE_EDGE_RISING:
		*new_fdp = dup_fd(fd, &error);	case IRQ_TYPE_EDGE_RISING:
		if (!*new_fdp)	case IRQ_TYPE_EDGE_RISING:
			return error;	case IRQ_TYPE_EDGE_RISING:
	}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	return 0;	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
/*	case IRQ_TYPE_EDGE_RISING:
 * unshare allows a process to 'unshare' part of the process	case IRQ_TYPE_EDGE_RISING:
 * context which was originally shared using clone.  copy_*	case IRQ_TYPE_EDGE_RISING:
 * functions used by do_fork() cannot be used here directly	case IRQ_TYPE_EDGE_RISING:
 * because they modify an inactive task_struct that is being	case IRQ_TYPE_EDGE_RISING:
 * constructed. Here we are modifying the current, active,	case IRQ_TYPE_EDGE_RISING:
 * task_struct.	case IRQ_TYPE_EDGE_RISING:
 */	case IRQ_TYPE_EDGE_RISING:
SYSCALL_DEFINE1(unshare, unsigned long, unshare_flags)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	struct fs_struct *fs, *new_fs = NULL;	case IRQ_TYPE_EDGE_RISING:
	struct files_struct *fd, *new_fd = NULL;	case IRQ_TYPE_EDGE_RISING:
	struct cred *new_cred = NULL;	case IRQ_TYPE_EDGE_RISING:
	struct nsproxy *new_nsproxy = NULL;	case IRQ_TYPE_EDGE_RISING:
	int do_sysvsem = 0;	case IRQ_TYPE_EDGE_RISING:
	int err;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	/*	case IRQ_TYPE_EDGE_RISING:
	 * If unsharing a user namespace must also unshare the thread.	case IRQ_TYPE_EDGE_RISING:
	 */	case IRQ_TYPE_EDGE_RISING:
	if (unshare_flags & CLONE_NEWUSER)	case IRQ_TYPE_EDGE_RISING:
		unshare_flags |= CLONE_THREAD | CLONE_FS;	case IRQ_TYPE_EDGE_RISING:
	/*	case IRQ_TYPE_EDGE_RISING:
	 * If unsharing a thread from a thread group, must also unshare vm.	case IRQ_TYPE_EDGE_RISING:
	 */	case IRQ_TYPE_EDGE_RISING:
	if (unshare_flags & CLONE_THREAD)	case IRQ_TYPE_EDGE_RISING:
		unshare_flags |= CLONE_VM;	case IRQ_TYPE_EDGE_RISING:
	/*	case IRQ_TYPE_EDGE_RISING:
	 * If unsharing vm, must also unshare signal handlers.	case IRQ_TYPE_EDGE_RISING:
	 */	case IRQ_TYPE_EDGE_RISING:
	if (unshare_flags & CLONE_VM)	case IRQ_TYPE_EDGE_RISING:
		unshare_flags |= CLONE_SIGHAND;	case IRQ_TYPE_EDGE_RISING:
	/*	case IRQ_TYPE_EDGE_RISING:
	 * If unsharing namespace, must also unshare filesystem information.	case IRQ_TYPE_EDGE_RISING:
	 */	case IRQ_TYPE_EDGE_RISING:
	if (unshare_flags & CLONE_NEWNS)	case IRQ_TYPE_EDGE_RISING:
		unshare_flags |= CLONE_FS;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	err = check_unshare_flags(unshare_flags);	case IRQ_TYPE_EDGE_RISING:
	if (err)	case IRQ_TYPE_EDGE_RISING:
		goto bad_unshare_out;	case IRQ_TYPE_EDGE_RISING:
	/*	case IRQ_TYPE_EDGE_RISING:
	 * CLONE_NEWIPC must also detach from the undolist: after switching	case IRQ_TYPE_EDGE_RISING:
	 * to a new ipc namespace, the semaphore arrays from the old	case IRQ_TYPE_EDGE_RISING:
	 * namespace are unreachable.	case IRQ_TYPE_EDGE_RISING:
	 */	case IRQ_TYPE_EDGE_RISING:
	if (unshare_flags & (CLONE_NEWIPC|CLONE_SYSVSEM))	case IRQ_TYPE_EDGE_RISING:
		do_sysvsem = 1;	case IRQ_TYPE_EDGE_RISING:
	err = unshare_fs(unshare_flags, &new_fs);	case IRQ_TYPE_EDGE_RISING:
	if (err)	case IRQ_TYPE_EDGE_RISING:
		goto bad_unshare_out;	case IRQ_TYPE_EDGE_RISING:
	err = unshare_fd(unshare_flags, &new_fd);	case IRQ_TYPE_EDGE_RISING:
	if (err)	case IRQ_TYPE_EDGE_RISING:
		goto bad_unshare_cleanup_fs;	case IRQ_TYPE_EDGE_RISING:
	err = unshare_userns(unshare_flags, &new_cred);	case IRQ_TYPE_EDGE_RISING:
	if (err)	case IRQ_TYPE_EDGE_RISING:
		goto bad_unshare_cleanup_fd;	case IRQ_TYPE_EDGE_RISING:
	err = unshare_nsproxy_namespaces(unshare_flags, &new_nsproxy,	case IRQ_TYPE_EDGE_RISING:
					 new_cred, new_fs);	case IRQ_TYPE_EDGE_RISING:
	if (err)	case IRQ_TYPE_EDGE_RISING:
		goto bad_unshare_cleanup_cred;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	if (new_fs || new_fd || do_sysvsem || new_cred || new_nsproxy) {	case IRQ_TYPE_EDGE_RISING:
		if (do_sysvsem) {	case IRQ_TYPE_EDGE_RISING:
			/*	case IRQ_TYPE_EDGE_RISING:
			 * CLONE_SYSVSEM is equivalent to sys_exit().	case IRQ_TYPE_EDGE_RISING:
			 */	case IRQ_TYPE_EDGE_RISING:
			exit_sem(current);	case IRQ_TYPE_EDGE_RISING:
		}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
		if (new_nsproxy)	case IRQ_TYPE_EDGE_RISING:
			switch_task_namespaces(current, new_nsproxy);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
		task_lock(current);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
		if (new_fs) {	case IRQ_TYPE_EDGE_RISING:
			fs = current->fs;	case IRQ_TYPE_EDGE_RISING:
			spin_lock(&fs->lock);	case IRQ_TYPE_EDGE_RISING:
			current->fs = new_fs;	case IRQ_TYPE_EDGE_RISING:
			if (--fs->users)	case IRQ_TYPE_EDGE_RISING:
				new_fs = NULL;	case IRQ_TYPE_EDGE_RISING:
			else	case IRQ_TYPE_EDGE_RISING:
				new_fs = fs;	case IRQ_TYPE_EDGE_RISING:
			spin_unlock(&fs->lock);	case IRQ_TYPE_EDGE_RISING:
		}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
		if (new_fd) {	case IRQ_TYPE_EDGE_RISING:
			fd = current->files;	case IRQ_TYPE_EDGE_RISING:
			current->files = new_fd;	case IRQ_TYPE_EDGE_RISING:
			new_fd = fd;	case IRQ_TYPE_EDGE_RISING:
		}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
		task_unlock(current);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
		if (new_cred) {	case IRQ_TYPE_EDGE_RISING:
			/* Install the new user namespace */	case IRQ_TYPE_EDGE_RISING:
			commit_creds(new_cred);	case IRQ_TYPE_EDGE_RISING:
			new_cred = NULL;	case IRQ_TYPE_EDGE_RISING:
		}	case IRQ_TYPE_EDGE_RISING:
	}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
bad_unshare_cleanup_cred:	case IRQ_TYPE_EDGE_RISING:
	if (new_cred)	case IRQ_TYPE_EDGE_RISING:
		put_cred(new_cred);	case IRQ_TYPE_EDGE_RISING:
bad_unshare_cleanup_fd:	case IRQ_TYPE_EDGE_RISING:
	if (new_fd)	case IRQ_TYPE_EDGE_RISING:
		put_files_struct(new_fd);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
bad_unshare_cleanup_fs:	case IRQ_TYPE_EDGE_RISING:
	if (new_fs)	case IRQ_TYPE_EDGE_RISING:
		free_fs_struct(new_fs);	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
bad_unshare_out:	case IRQ_TYPE_EDGE_RISING:
	return err;	case IRQ_TYPE_EDGE_RISING:
}	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
/*	case IRQ_TYPE_EDGE_RISING:
 *	Helper to unshare the files of the current task.	case IRQ_TYPE_EDGE_RISING:
 *	We don't want to expose copy_files internals to	case IRQ_TYPE_EDGE_RISING:
 *	the exec layer of the kernel.	case IRQ_TYPE_EDGE_RISING:
 */	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
int unshare_files(struct files_struct **displaced)	case IRQ_TYPE_EDGE_RISING:
{	case IRQ_TYPE_EDGE_RISING:
	struct task_struct *task = current;	case IRQ_TYPE_EDGE_RISING:
	struct files_struct *copy = NULL;	case IRQ_TYPE_EDGE_RISING:
	int error;	case IRQ_TYPE_EDGE_RISING:
	case IRQ_TYPE_EDGE_RISING:
	error = unshare_fd(CLONE_FILES, &copy);	case IRQ_TYPE_EDGE_RISING:
	if (error || !copy) {	case IRQ_TYPE_EDGE_RISING:
		*displaced = NULL;	case IRQ_TYPE_EDGE_RISING:
		return error;	case IRQ_TYPE_EDGE_RISING:
	}	case IRQ_TYPE_EDGE_RISING:
	*displaced = task->files;	case IRQ_TYPE_EDGE_RISING:
	task_lock(task);	case IRQ_TYPE_EDGE_RISING:
	task->files = copy;	case IRQ_TYPE_EDGE_RISING:
	task_unlock(task);	case IRQ_TYPE_EDGE_RISING:
	return 0;	case IRQ_TYPE_EDGE_RISING:
}