	IMX31_GPIO,	/* runs on i.mx31 */
/*	IMX31_GPIO,	/* runs on i.mx31 */
 *  linux/kernel/fork.c	IMX31_GPIO,	/* runs on i.mx31 */
 *	IMX31_GPIO,	/* runs on i.mx31 */
 *  Copyright (C) 1991, 1992  Linus Torvalds	IMX31_GPIO,	/* runs on i.mx31 */
 */	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
/*	IMX31_GPIO,	/* runs on i.mx31 */
 *  'fork.c' contains the help-routines for the 'fork' system call	IMX31_GPIO,	/* runs on i.mx31 */
 * (see also entry.S and others).	IMX31_GPIO,	/* runs on i.mx31 */
 * Fork is rather simple, once you get the hang of it, but the memory	IMX31_GPIO,	/* runs on i.mx31 */
 * management can be a bitch. See 'mm/memory.c': 'copy_page_range()'	IMX31_GPIO,	/* runs on i.mx31 */
 */	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/slab.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/init.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/unistd.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/module.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/vmalloc.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/completion.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/personality.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/mempolicy.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/sem.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/file.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/fdtable.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/iocontext.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/key.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/binfmts.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/mman.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/mmu_notifier.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/fs.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/nsproxy.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/capability.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/cpu.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/cgroup.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/security.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/hugetlb.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/seccomp.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/swap.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/syscalls.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/jiffies.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/futex.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/compat.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/kthread.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/task_io_accounting_ops.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/rcupdate.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/ptrace.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/mount.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/audit.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/memcontrol.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/ftrace.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/proc_fs.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/profile.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/rmap.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/ksm.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/acct.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/tsacct_kern.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/cn_proc.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/freezer.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/delayacct.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/taskstats_kern.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/random.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/tty.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/blkdev.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/fs_struct.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/magic.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/perf_event.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/posix-timers.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/user-return-notifier.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/oom.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/khugepaged.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/signalfd.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/uprobes.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/aio.h>	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
#include <asm/pgtable.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <asm/pgalloc.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <asm/uaccess.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <asm/mmu_context.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <asm/cacheflush.h>	IMX31_GPIO,	/* runs on i.mx31 */
#include <asm/tlbflush.h>	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
#include <trace/events/sched.h>	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
#define CREATE_TRACE_POINTS	IMX31_GPIO,	/* runs on i.mx31 */
#include <trace/events/task.h>	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
/*	IMX31_GPIO,	/* runs on i.mx31 */
 * Protected counters by write_lock_irq(&tasklist_lock)	IMX31_GPIO,	/* runs on i.mx31 */
 */	IMX31_GPIO,	/* runs on i.mx31 */
unsigned long total_forks;	/* Handle normal Linux uptimes. */	IMX31_GPIO,	/* runs on i.mx31 */
int nr_threads;			/* The idle threads do not count.. */	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
int max_threads;		/* tunable limit on nr_threads */	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
DEFINE_PER_CPU(unsigned long, process_counts) = 0;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
__cacheline_aligned DEFINE_RWLOCK(tasklist_lock);  /* outer */	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
#ifdef CONFIG_PROVE_RCU	IMX31_GPIO,	/* runs on i.mx31 */
int lockdep_tasklist_lock_is_held(void)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	return lockdep_is_held(&tasklist_lock);	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
EXPORT_SYMBOL_GPL(lockdep_tasklist_lock_is_held);	IMX31_GPIO,	/* runs on i.mx31 */
#endif /* #ifdef CONFIG_PROVE_RCU */	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
int nr_processes(void)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	int cpu;	IMX31_GPIO,	/* runs on i.mx31 */
	int total = 0;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	for_each_possible_cpu(cpu)	IMX31_GPIO,	/* runs on i.mx31 */
		total += per_cpu(process_counts, cpu);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	return total;	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
void __weak arch_release_task_struct(struct task_struct *tsk)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
#ifndef CONFIG_ARCH_TASK_STRUCT_ALLOCATOR	IMX31_GPIO,	/* runs on i.mx31 */
static struct kmem_cache *task_struct_cachep;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
static inline struct task_struct *alloc_task_struct_node(int node)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	return kmem_cache_alloc_node(task_struct_cachep, GFP_KERNEL, node);	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
static inline void free_task_struct(struct task_struct *tsk)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	kmem_cache_free(task_struct_cachep, tsk);	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
#endif	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
void __weak arch_release_thread_info(struct thread_info *ti)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
#ifndef CONFIG_ARCH_THREAD_INFO_ALLOCATOR	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
/*	IMX31_GPIO,	/* runs on i.mx31 */
 * Allocate pages if THREAD_SIZE is >= PAGE_SIZE, otherwise use a	IMX31_GPIO,	/* runs on i.mx31 */
 * kmemcache based allocator.	IMX31_GPIO,	/* runs on i.mx31 */
 */	IMX31_GPIO,	/* runs on i.mx31 */
# if THREAD_SIZE >= PAGE_SIZE	IMX31_GPIO,	/* runs on i.mx31 */
static struct thread_info *alloc_thread_info_node(struct task_struct *tsk,	IMX31_GPIO,	/* runs on i.mx31 */
						  int node)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	struct page *page = alloc_pages_node(node, THREADINFO_GFP_ACCOUNTED,	IMX31_GPIO,	/* runs on i.mx31 */
					     THREAD_SIZE_ORDER);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	return page ? page_address(page) : NULL;	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
static inline void free_thread_info(struct thread_info *ti)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	free_memcg_kmem_pages((unsigned long)ti, THREAD_SIZE_ORDER);	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
# else	IMX31_GPIO,	/* runs on i.mx31 */
static struct kmem_cache *thread_info_cache;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
static struct thread_info *alloc_thread_info_node(struct task_struct *tsk,	IMX31_GPIO,	/* runs on i.mx31 */
						  int node)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	return kmem_cache_alloc_node(thread_info_cache, THREADINFO_GFP, node);	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
static void free_thread_info(struct thread_info *ti)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	kmem_cache_free(thread_info_cache, ti);	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
void thread_info_cache_init(void)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	thread_info_cache = kmem_cache_create("thread_info", THREAD_SIZE,	IMX31_GPIO,	/* runs on i.mx31 */
					      THREAD_SIZE, 0, NULL);	IMX31_GPIO,	/* runs on i.mx31 */
	BUG_ON(thread_info_cache == NULL);	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
# endif	IMX31_GPIO,	/* runs on i.mx31 */
#endif	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
/* SLAB cache for signal_struct structures (tsk->signal) */	IMX31_GPIO,	/* runs on i.mx31 */
static struct kmem_cache *signal_cachep;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
/* SLAB cache for sighand_struct structures (tsk->sighand) */	IMX31_GPIO,	/* runs on i.mx31 */
struct kmem_cache *sighand_cachep;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
/* SLAB cache for files_struct structures (tsk->files) */	IMX31_GPIO,	/* runs on i.mx31 */
struct kmem_cache *files_cachep;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
/* SLAB cache for fs_struct structures (tsk->fs) */	IMX31_GPIO,	/* runs on i.mx31 */
struct kmem_cache *fs_cachep;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
/* SLAB cache for vm_area_struct structures */	IMX31_GPIO,	/* runs on i.mx31 */
struct kmem_cache *vm_area_cachep;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
/* SLAB cache for mm_struct structures (tsk->mm) */	IMX31_GPIO,	/* runs on i.mx31 */
static struct kmem_cache *mm_cachep;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
static void account_kernel_stack(struct thread_info *ti, int account)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	struct zone *zone = page_zone(virt_to_page(ti));	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	mod_zone_page_state(zone, NR_KERNEL_STACK, account);	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
void free_task(struct task_struct *tsk)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	account_kernel_stack(tsk->stack, -1);	IMX31_GPIO,	/* runs on i.mx31 */
	arch_release_thread_info(tsk->stack);	IMX31_GPIO,	/* runs on i.mx31 */
	free_thread_info(tsk->stack);	IMX31_GPIO,	/* runs on i.mx31 */
	rt_mutex_debug_task_free(tsk);	IMX31_GPIO,	/* runs on i.mx31 */
	ftrace_graph_exit_task(tsk);	IMX31_GPIO,	/* runs on i.mx31 */
	put_seccomp_filter(tsk);	IMX31_GPIO,	/* runs on i.mx31 */
	arch_release_task_struct(tsk);	IMX31_GPIO,	/* runs on i.mx31 */
	free_task_struct(tsk);	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
EXPORT_SYMBOL(free_task);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
static inline void free_signal_struct(struct signal_struct *sig)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	taskstats_tgid_free(sig);	IMX31_GPIO,	/* runs on i.mx31 */
	sched_autogroup_exit(sig);	IMX31_GPIO,	/* runs on i.mx31 */
	kmem_cache_free(signal_cachep, sig);	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
static inline void put_signal_struct(struct signal_struct *sig)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	if (atomic_dec_and_test(&sig->sigcnt))	IMX31_GPIO,	/* runs on i.mx31 */
		free_signal_struct(sig);	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
void __put_task_struct(struct task_struct *tsk)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	WARN_ON(!tsk->exit_state);	IMX31_GPIO,	/* runs on i.mx31 */
	WARN_ON(atomic_read(&tsk->usage));	IMX31_GPIO,	/* runs on i.mx31 */
	WARN_ON(tsk == current);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	task_numa_free(tsk);	IMX31_GPIO,	/* runs on i.mx31 */
	security_task_free(tsk);	IMX31_GPIO,	/* runs on i.mx31 */
	exit_creds(tsk);	IMX31_GPIO,	/* runs on i.mx31 */
	delayacct_tsk_free(tsk);	IMX31_GPIO,	/* runs on i.mx31 */
	put_signal_struct(tsk->signal);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	if (!profile_handoff_task(tsk))	IMX31_GPIO,	/* runs on i.mx31 */
		free_task(tsk);	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
EXPORT_SYMBOL_GPL(__put_task_struct);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
void __init __weak arch_task_cache_init(void) { }	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
void __init fork_init(unsigned long mempages)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
#ifndef CONFIG_ARCH_TASK_STRUCT_ALLOCATOR	IMX31_GPIO,	/* runs on i.mx31 */
#ifndef ARCH_MIN_TASKALIGN	IMX31_GPIO,	/* runs on i.mx31 */
#define ARCH_MIN_TASKALIGN	L1_CACHE_BYTES	IMX31_GPIO,	/* runs on i.mx31 */
#endif	IMX31_GPIO,	/* runs on i.mx31 */
	/* create a slab on which task_structs can be allocated */	IMX31_GPIO,	/* runs on i.mx31 */
	task_struct_cachep =	IMX31_GPIO,	/* runs on i.mx31 */
		kmem_cache_create("task_struct", sizeof(struct task_struct),	IMX31_GPIO,	/* runs on i.mx31 */
			ARCH_MIN_TASKALIGN, SLAB_PANIC | SLAB_NOTRACK, NULL);	IMX31_GPIO,	/* runs on i.mx31 */
#endif	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	/* do the arch specific task caches init */	IMX31_GPIO,	/* runs on i.mx31 */
	arch_task_cache_init();	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	/*	IMX31_GPIO,	/* runs on i.mx31 */
	 * The default maximum number of threads is set to a safe	IMX31_GPIO,	/* runs on i.mx31 */
	 * value: the thread structures can take up at most half	IMX31_GPIO,	/* runs on i.mx31 */
	 * of memory.	IMX31_GPIO,	/* runs on i.mx31 */
	 */	IMX31_GPIO,	/* runs on i.mx31 */
	max_threads = mempages / (8 * THREAD_SIZE / PAGE_SIZE);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	/*	IMX31_GPIO,	/* runs on i.mx31 */
	 * we need to allow at least 20 threads to boot a system	IMX31_GPIO,	/* runs on i.mx31 */
	 */	IMX31_GPIO,	/* runs on i.mx31 */
	if (max_threads < 20)	IMX31_GPIO,	/* runs on i.mx31 */
		max_threads = 20;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	init_task.signal->rlim[RLIMIT_NPROC].rlim_cur = max_threads/2;	IMX31_GPIO,	/* runs on i.mx31 */
	init_task.signal->rlim[RLIMIT_NPROC].rlim_max = max_threads/2;	IMX31_GPIO,	/* runs on i.mx31 */
	init_task.signal->rlim[RLIMIT_SIGPENDING] =	IMX31_GPIO,	/* runs on i.mx31 */
		init_task.signal->rlim[RLIMIT_NPROC];	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
int __attribute__((weak)) arch_dup_task_struct(struct task_struct *dst,	IMX31_GPIO,	/* runs on i.mx31 */
					       struct task_struct *src)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	*dst = *src;	IMX31_GPIO,	/* runs on i.mx31 */
	return 0;	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
static struct task_struct *dup_task_struct(struct task_struct *orig)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	struct task_struct *tsk;	IMX31_GPIO,	/* runs on i.mx31 */
	struct thread_info *ti;	IMX31_GPIO,	/* runs on i.mx31 */
	unsigned long *stackend;	IMX31_GPIO,	/* runs on i.mx31 */
	int node = tsk_fork_get_node(orig);	IMX31_GPIO,	/* runs on i.mx31 */
	int err;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	tsk = alloc_task_struct_node(node);	IMX31_GPIO,	/* runs on i.mx31 */
	if (!tsk)	IMX31_GPIO,	/* runs on i.mx31 */
		return NULL;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	ti = alloc_thread_info_node(tsk, node);	IMX31_GPIO,	/* runs on i.mx31 */
	if (!ti)	IMX31_GPIO,	/* runs on i.mx31 */
		goto free_tsk;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	err = arch_dup_task_struct(tsk, orig);	IMX31_GPIO,	/* runs on i.mx31 */
	if (err)	IMX31_GPIO,	/* runs on i.mx31 */
		goto free_ti;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	tsk->stack = ti;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	setup_thread_stack(tsk, orig);	IMX31_GPIO,	/* runs on i.mx31 */
	clear_user_return_notifier(tsk);	IMX31_GPIO,	/* runs on i.mx31 */
	clear_tsk_need_resched(tsk);	IMX31_GPIO,	/* runs on i.mx31 */
	stackend = end_of_stack(tsk);	IMX31_GPIO,	/* runs on i.mx31 */
	*stackend = STACK_END_MAGIC;	/* for overflow detection */	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
#ifdef CONFIG_CC_STACKPROTECTOR	IMX31_GPIO,	/* runs on i.mx31 */
	tsk->stack_canary = get_random_int();	IMX31_GPIO,	/* runs on i.mx31 */
#endif	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	/*	IMX31_GPIO,	/* runs on i.mx31 */
	 * One for us, one for whoever does the "release_task()" (usually	IMX31_GPIO,	/* runs on i.mx31 */
	 * parent)	IMX31_GPIO,	/* runs on i.mx31 */
	 */	IMX31_GPIO,	/* runs on i.mx31 */
	atomic_set(&tsk->usage, 2);	IMX31_GPIO,	/* runs on i.mx31 */
#ifdef CONFIG_BLK_DEV_IO_TRACE	IMX31_GPIO,	/* runs on i.mx31 */
	tsk->btrace_seq = 0;	IMX31_GPIO,	/* runs on i.mx31 */
#endif	IMX31_GPIO,	/* runs on i.mx31 */
	tsk->splice_pipe = NULL;	IMX31_GPIO,	/* runs on i.mx31 */
	tsk->task_frag.page = NULL;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	account_kernel_stack(ti, 1);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	return tsk;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
free_ti:	IMX31_GPIO,	/* runs on i.mx31 */
	free_thread_info(ti);	IMX31_GPIO,	/* runs on i.mx31 */
free_tsk:	IMX31_GPIO,	/* runs on i.mx31 */
	free_task_struct(tsk);	IMX31_GPIO,	/* runs on i.mx31 */
	return NULL;	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
#ifdef CONFIG_MMU	IMX31_GPIO,	/* runs on i.mx31 */
static int dup_mmap(struct mm_struct *mm, struct mm_struct *oldmm)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	struct vm_area_struct *mpnt, *tmp, *prev, **pprev;	IMX31_GPIO,	/* runs on i.mx31 */
	struct rb_node **rb_link, *rb_parent;	IMX31_GPIO,	/* runs on i.mx31 */
	int retval;	IMX31_GPIO,	/* runs on i.mx31 */
	unsigned long charge;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	uprobe_start_dup_mmap();	IMX31_GPIO,	/* runs on i.mx31 */
	down_write(&oldmm->mmap_sem);	IMX31_GPIO,	/* runs on i.mx31 */
	flush_cache_dup_mm(oldmm);	IMX31_GPIO,	/* runs on i.mx31 */
	uprobe_dup_mmap(oldmm, mm);	IMX31_GPIO,	/* runs on i.mx31 */
	/*	IMX31_GPIO,	/* runs on i.mx31 */
	 * Not linked in yet - no deadlock potential:	IMX31_GPIO,	/* runs on i.mx31 */
	 */	IMX31_GPIO,	/* runs on i.mx31 */
	down_write_nested(&mm->mmap_sem, SINGLE_DEPTH_NESTING);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	mm->locked_vm = 0;	IMX31_GPIO,	/* runs on i.mx31 */
	mm->mmap = NULL;	IMX31_GPIO,	/* runs on i.mx31 */
	mm->mmap_cache = NULL;	IMX31_GPIO,	/* runs on i.mx31 */
	mm->map_count = 0;	IMX31_GPIO,	/* runs on i.mx31 */
	cpumask_clear(mm_cpumask(mm));	IMX31_GPIO,	/* runs on i.mx31 */
	mm->mm_rb = RB_ROOT;	IMX31_GPIO,	/* runs on i.mx31 */
	rb_link = &mm->mm_rb.rb_node;	IMX31_GPIO,	/* runs on i.mx31 */
	rb_parent = NULL;	IMX31_GPIO,	/* runs on i.mx31 */
	pprev = &mm->mmap;	IMX31_GPIO,	/* runs on i.mx31 */
	retval = ksm_fork(mm, oldmm);	IMX31_GPIO,	/* runs on i.mx31 */
	if (retval)	IMX31_GPIO,	/* runs on i.mx31 */
		goto out;	IMX31_GPIO,	/* runs on i.mx31 */
	retval = khugepaged_fork(mm, oldmm);	IMX31_GPIO,	/* runs on i.mx31 */
	if (retval)	IMX31_GPIO,	/* runs on i.mx31 */
		goto out;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	prev = NULL;	IMX31_GPIO,	/* runs on i.mx31 */
	for (mpnt = oldmm->mmap; mpnt; mpnt = mpnt->vm_next) {	IMX31_GPIO,	/* runs on i.mx31 */
		struct file *file;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
		if (mpnt->vm_flags & VM_DONTCOPY) {	IMX31_GPIO,	/* runs on i.mx31 */
			vm_stat_account(mm, mpnt->vm_flags, mpnt->vm_file,	IMX31_GPIO,	/* runs on i.mx31 */
							-vma_pages(mpnt));	IMX31_GPIO,	/* runs on i.mx31 */
			continue;	IMX31_GPIO,	/* runs on i.mx31 */
		}	IMX31_GPIO,	/* runs on i.mx31 */
		charge = 0;	IMX31_GPIO,	/* runs on i.mx31 */
		if (mpnt->vm_flags & VM_ACCOUNT) {	IMX31_GPIO,	/* runs on i.mx31 */
			unsigned long len = vma_pages(mpnt);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
			if (security_vm_enough_memory_mm(oldmm, len)) /* sic */	IMX31_GPIO,	/* runs on i.mx31 */
				goto fail_nomem;	IMX31_GPIO,	/* runs on i.mx31 */
			charge = len;	IMX31_GPIO,	/* runs on i.mx31 */
		}	IMX31_GPIO,	/* runs on i.mx31 */
		tmp = kmem_cache_alloc(vm_area_cachep, GFP_KERNEL);	IMX31_GPIO,	/* runs on i.mx31 */
		if (!tmp)	IMX31_GPIO,	/* runs on i.mx31 */
			goto fail_nomem;	IMX31_GPIO,	/* runs on i.mx31 */
		*tmp = *mpnt;	IMX31_GPIO,	/* runs on i.mx31 */
		INIT_LIST_HEAD(&tmp->anon_vma_chain);	IMX31_GPIO,	/* runs on i.mx31 */
		retval = vma_dup_policy(mpnt, tmp);	IMX31_GPIO,	/* runs on i.mx31 */
		if (retval)	IMX31_GPIO,	/* runs on i.mx31 */
			goto fail_nomem_policy;	IMX31_GPIO,	/* runs on i.mx31 */
		tmp->vm_mm = mm;	IMX31_GPIO,	/* runs on i.mx31 */
		if (anon_vma_fork(tmp, mpnt))	IMX31_GPIO,	/* runs on i.mx31 */
			goto fail_nomem_anon_vma_fork;	IMX31_GPIO,	/* runs on i.mx31 */
		tmp->vm_flags &= ~VM_LOCKED;	IMX31_GPIO,	/* runs on i.mx31 */
		tmp->vm_next = tmp->vm_prev = NULL;	IMX31_GPIO,	/* runs on i.mx31 */
		file = tmp->vm_file;	IMX31_GPIO,	/* runs on i.mx31 */
		if (file) {	IMX31_GPIO,	/* runs on i.mx31 */
			struct inode *inode = file_inode(file);	IMX31_GPIO,	/* runs on i.mx31 */
			struct address_space *mapping = file->f_mapping;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
			get_file(file);	IMX31_GPIO,	/* runs on i.mx31 */
			if (tmp->vm_flags & VM_DENYWRITE)	IMX31_GPIO,	/* runs on i.mx31 */
				atomic_dec(&inode->i_writecount);	IMX31_GPIO,	/* runs on i.mx31 */
			mutex_lock(&mapping->i_mmap_mutex);	IMX31_GPIO,	/* runs on i.mx31 */
			if (tmp->vm_flags & VM_SHARED)	IMX31_GPIO,	/* runs on i.mx31 */
				mapping->i_mmap_writable++;	IMX31_GPIO,	/* runs on i.mx31 */
			flush_dcache_mmap_lock(mapping);	IMX31_GPIO,	/* runs on i.mx31 */
			/* insert tmp into the share list, just after mpnt */	IMX31_GPIO,	/* runs on i.mx31 */
			if (unlikely(tmp->vm_flags & VM_NONLINEAR))	IMX31_GPIO,	/* runs on i.mx31 */
				vma_nonlinear_insert(tmp,	IMX31_GPIO,	/* runs on i.mx31 */
						&mapping->i_mmap_nonlinear);	IMX31_GPIO,	/* runs on i.mx31 */
			else	IMX31_GPIO,	/* runs on i.mx31 */
				vma_interval_tree_insert_after(tmp, mpnt,	IMX31_GPIO,	/* runs on i.mx31 */
							&mapping->i_mmap);	IMX31_GPIO,	/* runs on i.mx31 */
			flush_dcache_mmap_unlock(mapping);	IMX31_GPIO,	/* runs on i.mx31 */
			mutex_unlock(&mapping->i_mmap_mutex);	IMX31_GPIO,	/* runs on i.mx31 */
		}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
		/*	IMX31_GPIO,	/* runs on i.mx31 */
		 * Clear hugetlb-related page reserves for children. This only	IMX31_GPIO,	/* runs on i.mx31 */
		 * affects MAP_PRIVATE mappings. Faults generated by the child	IMX31_GPIO,	/* runs on i.mx31 */
		 * are not guaranteed to succeed, even if read-only	IMX31_GPIO,	/* runs on i.mx31 */
		 */	IMX31_GPIO,	/* runs on i.mx31 */
		if (is_vm_hugetlb_page(tmp))	IMX31_GPIO,	/* runs on i.mx31 */
			reset_vma_resv_huge_pages(tmp);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
		/*	IMX31_GPIO,	/* runs on i.mx31 */
		 * Link in the new vma and copy the page table entries.	IMX31_GPIO,	/* runs on i.mx31 */
		 */	IMX31_GPIO,	/* runs on i.mx31 */
		*pprev = tmp;	IMX31_GPIO,	/* runs on i.mx31 */
		pprev = &tmp->vm_next;	IMX31_GPIO,	/* runs on i.mx31 */
		tmp->vm_prev = prev;	IMX31_GPIO,	/* runs on i.mx31 */
		prev = tmp;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
		__vma_link_rb(mm, tmp, rb_link, rb_parent);	IMX31_GPIO,	/* runs on i.mx31 */
		rb_link = &tmp->vm_rb.rb_right;	IMX31_GPIO,	/* runs on i.mx31 */
		rb_parent = &tmp->vm_rb;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
		mm->map_count++;	IMX31_GPIO,	/* runs on i.mx31 */
		retval = copy_page_range(mm, oldmm, mpnt);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
		if (tmp->vm_ops && tmp->vm_ops->open)	IMX31_GPIO,	/* runs on i.mx31 */
			tmp->vm_ops->open(tmp);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
		if (retval)	IMX31_GPIO,	/* runs on i.mx31 */
			goto out;	IMX31_GPIO,	/* runs on i.mx31 */
	}	IMX31_GPIO,	/* runs on i.mx31 */
	/* a new mm has just been created */	IMX31_GPIO,	/* runs on i.mx31 */
	arch_dup_mmap(oldmm, mm);	IMX31_GPIO,	/* runs on i.mx31 */
	retval = 0;	IMX31_GPIO,	/* runs on i.mx31 */
out:	IMX31_GPIO,	/* runs on i.mx31 */
	up_write(&mm->mmap_sem);	IMX31_GPIO,	/* runs on i.mx31 */
	flush_tlb_mm(oldmm);	IMX31_GPIO,	/* runs on i.mx31 */
	up_write(&oldmm->mmap_sem);	IMX31_GPIO,	/* runs on i.mx31 */
	uprobe_end_dup_mmap();	IMX31_GPIO,	/* runs on i.mx31 */
	return retval;	IMX31_GPIO,	/* runs on i.mx31 */
fail_nomem_anon_vma_fork:	IMX31_GPIO,	/* runs on i.mx31 */
	mpol_put(vma_policy(tmp));	IMX31_GPIO,	/* runs on i.mx31 */
fail_nomem_policy:	IMX31_GPIO,	/* runs on i.mx31 */
	kmem_cache_free(vm_area_cachep, tmp);	IMX31_GPIO,	/* runs on i.mx31 */
fail_nomem:	IMX31_GPIO,	/* runs on i.mx31 */
	retval = -ENOMEM;	IMX31_GPIO,	/* runs on i.mx31 */
	vm_unacct_memory(charge);	IMX31_GPIO,	/* runs on i.mx31 */
	goto out;	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
static inline int mm_alloc_pgd(struct mm_struct *mm)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	mm->pgd = pgd_alloc(mm);	IMX31_GPIO,	/* runs on i.mx31 */
	if (unlikely(!mm->pgd))	IMX31_GPIO,	/* runs on i.mx31 */
		return -ENOMEM;	IMX31_GPIO,	/* runs on i.mx31 */
	return 0;	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
static inline void mm_free_pgd(struct mm_struct *mm)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	pgd_free(mm, mm->pgd);	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
#else	IMX31_GPIO,	/* runs on i.mx31 */
#define dup_mmap(mm, oldmm)	(0)	IMX31_GPIO,	/* runs on i.mx31 */
#define mm_alloc_pgd(mm)	(0)	IMX31_GPIO,	/* runs on i.mx31 */
#define mm_free_pgd(mm)	IMX31_GPIO,	/* runs on i.mx31 */
#endif /* CONFIG_MMU */	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
__cacheline_aligned_in_smp DEFINE_SPINLOCK(mmlist_lock);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
#define allocate_mm()	(kmem_cache_alloc(mm_cachep, GFP_KERNEL))	IMX31_GPIO,	/* runs on i.mx31 */
#define free_mm(mm)	(kmem_cache_free(mm_cachep, (mm)))	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
static unsigned long default_dump_filter = MMF_DUMP_FILTER_DEFAULT;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
static int __init coredump_filter_setup(char *s)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	default_dump_filter =	IMX31_GPIO,	/* runs on i.mx31 */
		(simple_strtoul(s, NULL, 0) << MMF_DUMP_FILTER_SHIFT) &	IMX31_GPIO,	/* runs on i.mx31 */
		MMF_DUMP_FILTER_MASK;	IMX31_GPIO,	/* runs on i.mx31 */
	return 1;	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
__setup("coredump_filter=", coredump_filter_setup);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
#include <linux/init_task.h>	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
static void mm_init_aio(struct mm_struct *mm)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
#ifdef CONFIG_AIO	IMX31_GPIO,	/* runs on i.mx31 */
	spin_lock_init(&mm->ioctx_lock);	IMX31_GPIO,	/* runs on i.mx31 */
	mm->ioctx_table = NULL;	IMX31_GPIO,	/* runs on i.mx31 */
#endif	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
static struct mm_struct *mm_init(struct mm_struct *mm, struct task_struct *p)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	atomic_set(&mm->mm_users, 1);	IMX31_GPIO,	/* runs on i.mx31 */
	atomic_set(&mm->mm_count, 1);	IMX31_GPIO,	/* runs on i.mx31 */
	init_rwsem(&mm->mmap_sem);	IMX31_GPIO,	/* runs on i.mx31 */
	INIT_LIST_HEAD(&mm->mmlist);	IMX31_GPIO,	/* runs on i.mx31 */
	mm->flags = (current->mm) ?	IMX31_GPIO,	/* runs on i.mx31 */
		(current->mm->flags & MMF_INIT_MASK) : default_dump_filter;	IMX31_GPIO,	/* runs on i.mx31 */
	mm->core_state = NULL;	IMX31_GPIO,	/* runs on i.mx31 */
	atomic_long_set(&mm->nr_ptes, 0);	IMX31_GPIO,	/* runs on i.mx31 */
	memset(&mm->rss_stat, 0, sizeof(mm->rss_stat));	IMX31_GPIO,	/* runs on i.mx31 */
	spin_lock_init(&mm->page_table_lock);	IMX31_GPIO,	/* runs on i.mx31 */
	mm_init_aio(mm);	IMX31_GPIO,	/* runs on i.mx31 */
	mm_init_owner(mm, p);	IMX31_GPIO,	/* runs on i.mx31 */
	clear_tlb_flush_pending(mm);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	if (likely(!mm_alloc_pgd(mm))) {	IMX31_GPIO,	/* runs on i.mx31 */
		mm->def_flags = 0;	IMX31_GPIO,	/* runs on i.mx31 */
		mmu_notifier_mm_init(mm);	IMX31_GPIO,	/* runs on i.mx31 */
		return mm;	IMX31_GPIO,	/* runs on i.mx31 */
	}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	free_mm(mm);	IMX31_GPIO,	/* runs on i.mx31 */
	return NULL;	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
static void check_mm(struct mm_struct *mm)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	int i;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	for (i = 0; i < NR_MM_COUNTERS; i++) {	IMX31_GPIO,	/* runs on i.mx31 */
		long x = atomic_long_read(&mm->rss_stat.count[i]);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
		if (unlikely(x))	IMX31_GPIO,	/* runs on i.mx31 */
			printk(KERN_ALERT "BUG: Bad rss-counter state "	IMX31_GPIO,	/* runs on i.mx31 */
					  "mm:%p idx:%d val:%ld\n", mm, i, x);	IMX31_GPIO,	/* runs on i.mx31 */
	}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
#if defined(CONFIG_TRANSPARENT_HUGEPAGE) && !USE_SPLIT_PMD_PTLOCKS	IMX31_GPIO,	/* runs on i.mx31 */
	VM_BUG_ON(mm->pmd_huge_pte);	IMX31_GPIO,	/* runs on i.mx31 */
#endif	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
/*	IMX31_GPIO,	/* runs on i.mx31 */
 * Allocate and initialize an mm_struct.	IMX31_GPIO,	/* runs on i.mx31 */
 */	IMX31_GPIO,	/* runs on i.mx31 */
struct mm_struct *mm_alloc(void)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	struct mm_struct *mm;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	mm = allocate_mm();	IMX31_GPIO,	/* runs on i.mx31 */
	if (!mm)	IMX31_GPIO,	/* runs on i.mx31 */
		return NULL;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	memset(mm, 0, sizeof(*mm));	IMX31_GPIO,	/* runs on i.mx31 */
	mm_init_cpumask(mm);	IMX31_GPIO,	/* runs on i.mx31 */
	return mm_init(mm, current);	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
/*	IMX31_GPIO,	/* runs on i.mx31 */
 * Called when the last reference to the mm	IMX31_GPIO,	/* runs on i.mx31 */
 * is dropped: either by a lazy thread or by	IMX31_GPIO,	/* runs on i.mx31 */
 * mmput. Free the page directory and the mm.	IMX31_GPIO,	/* runs on i.mx31 */
 */	IMX31_GPIO,	/* runs on i.mx31 */
void __mmdrop(struct mm_struct *mm)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	BUG_ON(mm == &init_mm);	IMX31_GPIO,	/* runs on i.mx31 */
	mm_free_pgd(mm);	IMX31_GPIO,	/* runs on i.mx31 */
	destroy_context(mm);	IMX31_GPIO,	/* runs on i.mx31 */
	mmu_notifier_mm_destroy(mm);	IMX31_GPIO,	/* runs on i.mx31 */
	check_mm(mm);	IMX31_GPIO,	/* runs on i.mx31 */
	free_mm(mm);	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
EXPORT_SYMBOL_GPL(__mmdrop);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
/*	IMX31_GPIO,	/* runs on i.mx31 */
 * Decrement the use count and release all resources for an mm.	IMX31_GPIO,	/* runs on i.mx31 */
 */	IMX31_GPIO,	/* runs on i.mx31 */
void mmput(struct mm_struct *mm)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	might_sleep();	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	if (atomic_dec_and_test(&mm->mm_users)) {	IMX31_GPIO,	/* runs on i.mx31 */
		uprobe_clear_state(mm);	IMX31_GPIO,	/* runs on i.mx31 */
		exit_aio(mm);	IMX31_GPIO,	/* runs on i.mx31 */
		ksm_exit(mm);	IMX31_GPIO,	/* runs on i.mx31 */
		khugepaged_exit(mm); /* must run before exit_mmap */	IMX31_GPIO,	/* runs on i.mx31 */
		exit_mmap(mm);	IMX31_GPIO,	/* runs on i.mx31 */
		set_mm_exe_file(mm, NULL);	IMX31_GPIO,	/* runs on i.mx31 */
		if (!list_empty(&mm->mmlist)) {	IMX31_GPIO,	/* runs on i.mx31 */
			spin_lock(&mmlist_lock);	IMX31_GPIO,	/* runs on i.mx31 */
			list_del(&mm->mmlist);	IMX31_GPIO,	/* runs on i.mx31 */
			spin_unlock(&mmlist_lock);	IMX31_GPIO,	/* runs on i.mx31 */
		}	IMX31_GPIO,	/* runs on i.mx31 */
		if (mm->binfmt)	IMX31_GPIO,	/* runs on i.mx31 */
			module_put(mm->binfmt->module);	IMX31_GPIO,	/* runs on i.mx31 */
		mmdrop(mm);	IMX31_GPIO,	/* runs on i.mx31 */
	}	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
EXPORT_SYMBOL_GPL(mmput);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
void set_mm_exe_file(struct mm_struct *mm, struct file *new_exe_file)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	if (new_exe_file)	IMX31_GPIO,	/* runs on i.mx31 */
		get_file(new_exe_file);	IMX31_GPIO,	/* runs on i.mx31 */
	if (mm->exe_file)	IMX31_GPIO,	/* runs on i.mx31 */
		fput(mm->exe_file);	IMX31_GPIO,	/* runs on i.mx31 */
	mm->exe_file = new_exe_file;	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
struct file *get_mm_exe_file(struct mm_struct *mm)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	struct file *exe_file;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	/* We need mmap_sem to protect against races with removal of exe_file */	IMX31_GPIO,	/* runs on i.mx31 */
	down_read(&mm->mmap_sem);	IMX31_GPIO,	/* runs on i.mx31 */
	exe_file = mm->exe_file;	IMX31_GPIO,	/* runs on i.mx31 */
	if (exe_file)	IMX31_GPIO,	/* runs on i.mx31 */
		get_file(exe_file);	IMX31_GPIO,	/* runs on i.mx31 */
	up_read(&mm->mmap_sem);	IMX31_GPIO,	/* runs on i.mx31 */
	return exe_file;	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
static void dup_mm_exe_file(struct mm_struct *oldmm, struct mm_struct *newmm)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	/* It's safe to write the exe_file pointer without exe_file_lock because	IMX31_GPIO,	/* runs on i.mx31 */
	 * this is called during fork when the task is not yet in /proc */	IMX31_GPIO,	/* runs on i.mx31 */
	newmm->exe_file = get_mm_exe_file(oldmm);	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
/**	IMX31_GPIO,	/* runs on i.mx31 */
 * get_task_mm - acquire a reference to the task's mm	IMX31_GPIO,	/* runs on i.mx31 */
 *	IMX31_GPIO,	/* runs on i.mx31 */
 * Returns %NULL if the task has no mm.  Checks PF_KTHREAD (meaning	IMX31_GPIO,	/* runs on i.mx31 */
 * this kernel workthread has transiently adopted a user mm with use_mm,	IMX31_GPIO,	/* runs on i.mx31 */
 * to do its AIO) is not set and if so returns a reference to it, after	IMX31_GPIO,	/* runs on i.mx31 */
 * bumping up the use count.  User must release the mm via mmput()	IMX31_GPIO,	/* runs on i.mx31 */
 * after use.  Typically used by /proc and ptrace.	IMX31_GPIO,	/* runs on i.mx31 */
 */	IMX31_GPIO,	/* runs on i.mx31 */
struct mm_struct *get_task_mm(struct task_struct *task)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	struct mm_struct *mm;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	task_lock(task);	IMX31_GPIO,	/* runs on i.mx31 */
	mm = task->mm;	IMX31_GPIO,	/* runs on i.mx31 */
	if (mm) {	IMX31_GPIO,	/* runs on i.mx31 */
		if (task->flags & PF_KTHREAD)	IMX31_GPIO,	/* runs on i.mx31 */
			mm = NULL;	IMX31_GPIO,	/* runs on i.mx31 */
		else	IMX31_GPIO,	/* runs on i.mx31 */
			atomic_inc(&mm->mm_users);	IMX31_GPIO,	/* runs on i.mx31 */
	}	IMX31_GPIO,	/* runs on i.mx31 */
	task_unlock(task);	IMX31_GPIO,	/* runs on i.mx31 */
	return mm;	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
EXPORT_SYMBOL_GPL(get_task_mm);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
struct mm_struct *mm_access(struct task_struct *task, unsigned int mode)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	struct mm_struct *mm;	IMX31_GPIO,	/* runs on i.mx31 */
	int err;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	err =  mutex_lock_killable(&task->signal->cred_guard_mutex);	IMX31_GPIO,	/* runs on i.mx31 */
	if (err)	IMX31_GPIO,	/* runs on i.mx31 */
		return ERR_PTR(err);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	mm = get_task_mm(task);	IMX31_GPIO,	/* runs on i.mx31 */
	if (mm && mm != current->mm &&	IMX31_GPIO,	/* runs on i.mx31 */
			!ptrace_may_access(task, mode)) {	IMX31_GPIO,	/* runs on i.mx31 */
		mmput(mm);	IMX31_GPIO,	/* runs on i.mx31 */
		mm = ERR_PTR(-EACCES);	IMX31_GPIO,	/* runs on i.mx31 */
	}	IMX31_GPIO,	/* runs on i.mx31 */
	mutex_unlock(&task->signal->cred_guard_mutex);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	return mm;	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
static void complete_vfork_done(struct task_struct *tsk)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	struct completion *vfork;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	task_lock(tsk);	IMX31_GPIO,	/* runs on i.mx31 */
	vfork = tsk->vfork_done;	IMX31_GPIO,	/* runs on i.mx31 */
	if (likely(vfork)) {	IMX31_GPIO,	/* runs on i.mx31 */
		tsk->vfork_done = NULL;	IMX31_GPIO,	/* runs on i.mx31 */
		complete(vfork);	IMX31_GPIO,	/* runs on i.mx31 */
	}	IMX31_GPIO,	/* runs on i.mx31 */
	task_unlock(tsk);	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
static int wait_for_vfork_done(struct task_struct *child,	IMX31_GPIO,	/* runs on i.mx31 */
				struct completion *vfork)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	int killed;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	freezer_do_not_count();	IMX31_GPIO,	/* runs on i.mx31 */
	killed = wait_for_completion_killable(vfork);	IMX31_GPIO,	/* runs on i.mx31 */
	freezer_count();	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	if (killed) {	IMX31_GPIO,	/* runs on i.mx31 */
		task_lock(child);	IMX31_GPIO,	/* runs on i.mx31 */
		child->vfork_done = NULL;	IMX31_GPIO,	/* runs on i.mx31 */
		task_unlock(child);	IMX31_GPIO,	/* runs on i.mx31 */
	}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	put_task_struct(child);	IMX31_GPIO,	/* runs on i.mx31 */
	return killed;	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
/* Please note the differences between mmput and mm_release.	IMX31_GPIO,	/* runs on i.mx31 */
 * mmput is called whenever we stop holding onto a mm_struct,	IMX31_GPIO,	/* runs on i.mx31 */
 * error success whatever.	IMX31_GPIO,	/* runs on i.mx31 */
 *	IMX31_GPIO,	/* runs on i.mx31 */
 * mm_release is called after a mm_struct has been removed	IMX31_GPIO,	/* runs on i.mx31 */
 * from the current process.	IMX31_GPIO,	/* runs on i.mx31 */
 *	IMX31_GPIO,	/* runs on i.mx31 */
 * This difference is important for error handling, when we	IMX31_GPIO,	/* runs on i.mx31 */
 * only half set up a mm_struct for a new process and need to restore	IMX31_GPIO,	/* runs on i.mx31 */
 * the old one.  Because we mmput the new mm_struct before	IMX31_GPIO,	/* runs on i.mx31 */
 * restoring the old one. . .	IMX31_GPIO,	/* runs on i.mx31 */
 * Eric Biederman 10 January 1998	IMX31_GPIO,	/* runs on i.mx31 */
 */	IMX31_GPIO,	/* runs on i.mx31 */
void mm_release(struct task_struct *tsk, struct mm_struct *mm)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	/* Get rid of any futexes when releasing the mm */	IMX31_GPIO,	/* runs on i.mx31 */
#ifdef CONFIG_FUTEX	IMX31_GPIO,	/* runs on i.mx31 */
	if (unlikely(tsk->robust_list)) {	IMX31_GPIO,	/* runs on i.mx31 */
		exit_robust_list(tsk);	IMX31_GPIO,	/* runs on i.mx31 */
		tsk->robust_list = NULL;	IMX31_GPIO,	/* runs on i.mx31 */
	}	IMX31_GPIO,	/* runs on i.mx31 */
#ifdef CONFIG_COMPAT	IMX31_GPIO,	/* runs on i.mx31 */
	if (unlikely(tsk->compat_robust_list)) {	IMX31_GPIO,	/* runs on i.mx31 */
		compat_exit_robust_list(tsk);	IMX31_GPIO,	/* runs on i.mx31 */
		tsk->compat_robust_list = NULL;	IMX31_GPIO,	/* runs on i.mx31 */
	}	IMX31_GPIO,	/* runs on i.mx31 */
#endif	IMX31_GPIO,	/* runs on i.mx31 */
	if (unlikely(!list_empty(&tsk->pi_state_list)))	IMX31_GPIO,	/* runs on i.mx31 */
		exit_pi_state_list(tsk);	IMX31_GPIO,	/* runs on i.mx31 */
#endif	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	uprobe_free_utask(tsk);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	/* Get rid of any cached register state */	IMX31_GPIO,	/* runs on i.mx31 */
	deactivate_mm(tsk, mm);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	/*	IMX31_GPIO,	/* runs on i.mx31 */
	 * If we're exiting normally, clear a user-space tid field if	IMX31_GPIO,	/* runs on i.mx31 */
	 * requested.  We leave this alone when dying by signal, to leave	IMX31_GPIO,	/* runs on i.mx31 */
	 * the value intact in a core dump, and to save the unnecessary	IMX31_GPIO,	/* runs on i.mx31 */
	 * trouble, say, a killed vfork parent shouldn't touch this mm.	IMX31_GPIO,	/* runs on i.mx31 */
	 * Userland only wants this done for a sys_exit.	IMX31_GPIO,	/* runs on i.mx31 */
	 */	IMX31_GPIO,	/* runs on i.mx31 */
	if (tsk->clear_child_tid) {	IMX31_GPIO,	/* runs on i.mx31 */
		if (!(tsk->flags & PF_SIGNALED) &&	IMX31_GPIO,	/* runs on i.mx31 */
		    atomic_read(&mm->mm_users) > 1) {	IMX31_GPIO,	/* runs on i.mx31 */
			/*	IMX31_GPIO,	/* runs on i.mx31 */
			 * We don't check the error code - if userspace has	IMX31_GPIO,	/* runs on i.mx31 */
			 * not set up a proper pointer then tough luck.	IMX31_GPIO,	/* runs on i.mx31 */
			 */	IMX31_GPIO,	/* runs on i.mx31 */
			put_user(0, tsk->clear_child_tid);	IMX31_GPIO,	/* runs on i.mx31 */
			sys_futex(tsk->clear_child_tid, FUTEX_WAKE,	IMX31_GPIO,	/* runs on i.mx31 */
					1, NULL, NULL, 0);	IMX31_GPIO,	/* runs on i.mx31 */
		}	IMX31_GPIO,	/* runs on i.mx31 */
		tsk->clear_child_tid = NULL;	IMX31_GPIO,	/* runs on i.mx31 */
	}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	/*	IMX31_GPIO,	/* runs on i.mx31 */
	 * All done, finally we can wake up parent and return this mm to him.	IMX31_GPIO,	/* runs on i.mx31 */
	 * Also kthread_stop() uses this completion for synchronization.	IMX31_GPIO,	/* runs on i.mx31 */
	 */	IMX31_GPIO,	/* runs on i.mx31 */
	if (tsk->vfork_done)	IMX31_GPIO,	/* runs on i.mx31 */
		complete_vfork_done(tsk);	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
/*	IMX31_GPIO,	/* runs on i.mx31 */
 * Allocate a new mm structure and copy contents from the	IMX31_GPIO,	/* runs on i.mx31 */
 * mm structure of the passed in task structure.	IMX31_GPIO,	/* runs on i.mx31 */
 */	IMX31_GPIO,	/* runs on i.mx31 */
static struct mm_struct *dup_mm(struct task_struct *tsk)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	struct mm_struct *mm, *oldmm = current->mm;	IMX31_GPIO,	/* runs on i.mx31 */
	int err;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	mm = allocate_mm();	IMX31_GPIO,	/* runs on i.mx31 */
	if (!mm)	IMX31_GPIO,	/* runs on i.mx31 */
		goto fail_nomem;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	memcpy(mm, oldmm, sizeof(*mm));	IMX31_GPIO,	/* runs on i.mx31 */
	mm_init_cpumask(mm);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
#if defined(CONFIG_TRANSPARENT_HUGEPAGE) && !USE_SPLIT_PMD_PTLOCKS	IMX31_GPIO,	/* runs on i.mx31 */
	mm->pmd_huge_pte = NULL;	IMX31_GPIO,	/* runs on i.mx31 */
#endif	IMX31_GPIO,	/* runs on i.mx31 */
	if (!mm_init(mm, tsk))	IMX31_GPIO,	/* runs on i.mx31 */
		goto fail_nomem;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	if (init_new_context(tsk, mm))	IMX31_GPIO,	/* runs on i.mx31 */
		goto fail_nocontext;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	dup_mm_exe_file(oldmm, mm);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	err = dup_mmap(mm, oldmm);	IMX31_GPIO,	/* runs on i.mx31 */
	if (err)	IMX31_GPIO,	/* runs on i.mx31 */
		goto free_pt;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	mm->hiwater_rss = get_mm_rss(mm);	IMX31_GPIO,	/* runs on i.mx31 */
	mm->hiwater_vm = mm->total_vm;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	if (mm->binfmt && !try_module_get(mm->binfmt->module))	IMX31_GPIO,	/* runs on i.mx31 */
		goto free_pt;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	return mm;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
free_pt:	IMX31_GPIO,	/* runs on i.mx31 */
	/* don't put binfmt in mmput, we haven't got module yet */	IMX31_GPIO,	/* runs on i.mx31 */
	mm->binfmt = NULL;	IMX31_GPIO,	/* runs on i.mx31 */
	mmput(mm);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
fail_nomem:	IMX31_GPIO,	/* runs on i.mx31 */
	return NULL;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
fail_nocontext:	IMX31_GPIO,	/* runs on i.mx31 */
	/*	IMX31_GPIO,	/* runs on i.mx31 */
	 * If init_new_context() failed, we cannot use mmput() to free the mm	IMX31_GPIO,	/* runs on i.mx31 */
	 * because it calls destroy_context()	IMX31_GPIO,	/* runs on i.mx31 */
	 */	IMX31_GPIO,	/* runs on i.mx31 */
	mm_free_pgd(mm);	IMX31_GPIO,	/* runs on i.mx31 */
	free_mm(mm);	IMX31_GPIO,	/* runs on i.mx31 */
	return NULL;	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
static int copy_mm(unsigned long clone_flags, struct task_struct *tsk)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	struct mm_struct *mm, *oldmm;	IMX31_GPIO,	/* runs on i.mx31 */
	int retval;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	tsk->min_flt = tsk->maj_flt = 0;	IMX31_GPIO,	/* runs on i.mx31 */
	tsk->nvcsw = tsk->nivcsw = 0;	IMX31_GPIO,	/* runs on i.mx31 */
#ifdef CONFIG_DETECT_HUNG_TASK	IMX31_GPIO,	/* runs on i.mx31 */
	tsk->last_switch_count = tsk->nvcsw + tsk->nivcsw;	IMX31_GPIO,	/* runs on i.mx31 */
#endif	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	tsk->mm = NULL;	IMX31_GPIO,	/* runs on i.mx31 */
	tsk->active_mm = NULL;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	/*	IMX31_GPIO,	/* runs on i.mx31 */
	 * Are we cloning a kernel thread?	IMX31_GPIO,	/* runs on i.mx31 */
	 *	IMX31_GPIO,	/* runs on i.mx31 */
	 * We need to steal a active VM for that..	IMX31_GPIO,	/* runs on i.mx31 */
	 */	IMX31_GPIO,	/* runs on i.mx31 */
	oldmm = current->mm;	IMX31_GPIO,	/* runs on i.mx31 */
	if (!oldmm)	IMX31_GPIO,	/* runs on i.mx31 */
		return 0;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	if (clone_flags & CLONE_VM) {	IMX31_GPIO,	/* runs on i.mx31 */
		atomic_inc(&oldmm->mm_users);	IMX31_GPIO,	/* runs on i.mx31 */
		mm = oldmm;	IMX31_GPIO,	/* runs on i.mx31 */
		goto good_mm;	IMX31_GPIO,	/* runs on i.mx31 */
	}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	retval = -ENOMEM;	IMX31_GPIO,	/* runs on i.mx31 */
	mm = dup_mm(tsk);	IMX31_GPIO,	/* runs on i.mx31 */
	if (!mm)	IMX31_GPIO,	/* runs on i.mx31 */
		goto fail_nomem;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
good_mm:	IMX31_GPIO,	/* runs on i.mx31 */
	tsk->mm = mm;	IMX31_GPIO,	/* runs on i.mx31 */
	tsk->active_mm = mm;	IMX31_GPIO,	/* runs on i.mx31 */
	return 0;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
fail_nomem:	IMX31_GPIO,	/* runs on i.mx31 */
	return retval;	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
static int copy_fs(unsigned long clone_flags, struct task_struct *tsk)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	struct fs_struct *fs = current->fs;	IMX31_GPIO,	/* runs on i.mx31 */
	if (clone_flags & CLONE_FS) {	IMX31_GPIO,	/* runs on i.mx31 */
		/* tsk->fs is already what we want */	IMX31_GPIO,	/* runs on i.mx31 */
		spin_lock(&fs->lock);	IMX31_GPIO,	/* runs on i.mx31 */
		if (fs->in_exec) {	IMX31_GPIO,	/* runs on i.mx31 */
			spin_unlock(&fs->lock);	IMX31_GPIO,	/* runs on i.mx31 */
			return -EAGAIN;	IMX31_GPIO,	/* runs on i.mx31 */
		}	IMX31_GPIO,	/* runs on i.mx31 */
		fs->users++;	IMX31_GPIO,	/* runs on i.mx31 */
		spin_unlock(&fs->lock);	IMX31_GPIO,	/* runs on i.mx31 */
		return 0;	IMX31_GPIO,	/* runs on i.mx31 */
	}	IMX31_GPIO,	/* runs on i.mx31 */
	tsk->fs = copy_fs_struct(fs);	IMX31_GPIO,	/* runs on i.mx31 */
	if (!tsk->fs)	IMX31_GPIO,	/* runs on i.mx31 */
		return -ENOMEM;	IMX31_GPIO,	/* runs on i.mx31 */
	return 0;	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
static int copy_files(unsigned long clone_flags, struct task_struct *tsk)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	struct files_struct *oldf, *newf;	IMX31_GPIO,	/* runs on i.mx31 */
	int error = 0;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	/*	IMX31_GPIO,	/* runs on i.mx31 */
	 * A background process may not have any files ...	IMX31_GPIO,	/* runs on i.mx31 */
	 */	IMX31_GPIO,	/* runs on i.mx31 */
	oldf = current->files;	IMX31_GPIO,	/* runs on i.mx31 */
	if (!oldf)	IMX31_GPIO,	/* runs on i.mx31 */
		goto out;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	if (clone_flags & CLONE_FILES) {	IMX31_GPIO,	/* runs on i.mx31 */
		atomic_inc(&oldf->count);	IMX31_GPIO,	/* runs on i.mx31 */
		goto out;	IMX31_GPIO,	/* runs on i.mx31 */
	}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	newf = dup_fd(oldf, &error);	IMX31_GPIO,	/* runs on i.mx31 */
	if (!newf)	IMX31_GPIO,	/* runs on i.mx31 */
		goto out;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	tsk->files = newf;	IMX31_GPIO,	/* runs on i.mx31 */
	error = 0;	IMX31_GPIO,	/* runs on i.mx31 */
out:	IMX31_GPIO,	/* runs on i.mx31 */
	return error;	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
static int copy_io(unsigned long clone_flags, struct task_struct *tsk)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
#ifdef CONFIG_BLOCK	IMX31_GPIO,	/* runs on i.mx31 */
	struct io_context *ioc = current->io_context;	IMX31_GPIO,	/* runs on i.mx31 */
	struct io_context *new_ioc;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	if (!ioc)	IMX31_GPIO,	/* runs on i.mx31 */
		return 0;	IMX31_GPIO,	/* runs on i.mx31 */
	/*	IMX31_GPIO,	/* runs on i.mx31 */
	 * Share io context with parent, if CLONE_IO is set	IMX31_GPIO,	/* runs on i.mx31 */
	 */	IMX31_GPIO,	/* runs on i.mx31 */
	if (clone_flags & CLONE_IO) {	IMX31_GPIO,	/* runs on i.mx31 */
		ioc_task_link(ioc);	IMX31_GPIO,	/* runs on i.mx31 */
		tsk->io_context = ioc;	IMX31_GPIO,	/* runs on i.mx31 */
	} else if (ioprio_valid(ioc->ioprio)) {	IMX31_GPIO,	/* runs on i.mx31 */
		new_ioc = get_task_io_context(tsk, GFP_KERNEL, NUMA_NO_NODE);	IMX31_GPIO,	/* runs on i.mx31 */
		if (unlikely(!new_ioc))	IMX31_GPIO,	/* runs on i.mx31 */
			return -ENOMEM;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
		new_ioc->ioprio = ioc->ioprio;	IMX31_GPIO,	/* runs on i.mx31 */
		put_io_context(new_ioc);	IMX31_GPIO,	/* runs on i.mx31 */
	}	IMX31_GPIO,	/* runs on i.mx31 */
#endif	IMX31_GPIO,	/* runs on i.mx31 */
	return 0;	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
static int copy_sighand(unsigned long clone_flags, struct task_struct *tsk)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	struct sighand_struct *sig;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	if (clone_flags & CLONE_SIGHAND) {	IMX31_GPIO,	/* runs on i.mx31 */
		atomic_inc(&current->sighand->count);	IMX31_GPIO,	/* runs on i.mx31 */
		return 0;	IMX31_GPIO,	/* runs on i.mx31 */
	}	IMX31_GPIO,	/* runs on i.mx31 */
	sig = kmem_cache_alloc(sighand_cachep, GFP_KERNEL);	IMX31_GPIO,	/* runs on i.mx31 */
	rcu_assign_pointer(tsk->sighand, sig);	IMX31_GPIO,	/* runs on i.mx31 */
	if (!sig)	IMX31_GPIO,	/* runs on i.mx31 */
		return -ENOMEM;	IMX31_GPIO,	/* runs on i.mx31 */
	atomic_set(&sig->count, 1);	IMX31_GPIO,	/* runs on i.mx31 */
	memcpy(sig->action, current->sighand->action, sizeof(sig->action));	IMX31_GPIO,	/* runs on i.mx31 */
	return 0;	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
void __cleanup_sighand(struct sighand_struct *sighand)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	if (atomic_dec_and_test(&sighand->count)) {	IMX31_GPIO,	/* runs on i.mx31 */
		signalfd_cleanup(sighand);	IMX31_GPIO,	/* runs on i.mx31 */
		kmem_cache_free(sighand_cachep, sighand);	IMX31_GPIO,	/* runs on i.mx31 */
	}	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
/*	IMX31_GPIO,	/* runs on i.mx31 */
 * Initialize POSIX timer handling for a thread group.	IMX31_GPIO,	/* runs on i.mx31 */
 */	IMX31_GPIO,	/* runs on i.mx31 */
static void posix_cpu_timers_init_group(struct signal_struct *sig)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	unsigned long cpu_limit;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	/* Thread group counters. */	IMX31_GPIO,	/* runs on i.mx31 */
	thread_group_cputime_init(sig);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	cpu_limit = ACCESS_ONCE(sig->rlim[RLIMIT_CPU].rlim_cur);	IMX31_GPIO,	/* runs on i.mx31 */
	if (cpu_limit != RLIM_INFINITY) {	IMX31_GPIO,	/* runs on i.mx31 */
		sig->cputime_expires.prof_exp = secs_to_cputime(cpu_limit);	IMX31_GPIO,	/* runs on i.mx31 */
		sig->cputimer.running = 1;	IMX31_GPIO,	/* runs on i.mx31 */
	}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	/* The timer lists. */	IMX31_GPIO,	/* runs on i.mx31 */
	INIT_LIST_HEAD(&sig->cpu_timers[0]);	IMX31_GPIO,	/* runs on i.mx31 */
	INIT_LIST_HEAD(&sig->cpu_timers[1]);	IMX31_GPIO,	/* runs on i.mx31 */
	INIT_LIST_HEAD(&sig->cpu_timers[2]);	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
static int copy_signal(unsigned long clone_flags, struct task_struct *tsk)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	struct signal_struct *sig;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	if (clone_flags & CLONE_THREAD)	IMX31_GPIO,	/* runs on i.mx31 */
		return 0;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	sig = kmem_cache_zalloc(signal_cachep, GFP_KERNEL);	IMX31_GPIO,	/* runs on i.mx31 */
	tsk->signal = sig;	IMX31_GPIO,	/* runs on i.mx31 */
	if (!sig)	IMX31_GPIO,	/* runs on i.mx31 */
		return -ENOMEM;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	sig->nr_threads = 1;	IMX31_GPIO,	/* runs on i.mx31 */
	atomic_set(&sig->live, 1);	IMX31_GPIO,	/* runs on i.mx31 */
	atomic_set(&sig->sigcnt, 1);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	/* list_add(thread_node, thread_head) without INIT_LIST_HEAD() */	IMX31_GPIO,	/* runs on i.mx31 */
	sig->thread_head = (struct list_head)LIST_HEAD_INIT(tsk->thread_node);	IMX31_GPIO,	/* runs on i.mx31 */
	tsk->thread_node = (struct list_head)LIST_HEAD_INIT(sig->thread_head);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	init_waitqueue_head(&sig->wait_chldexit);	IMX31_GPIO,	/* runs on i.mx31 */
	sig->curr_target = tsk;	IMX31_GPIO,	/* runs on i.mx31 */
	init_sigpending(&sig->shared_pending);	IMX31_GPIO,	/* runs on i.mx31 */
	INIT_LIST_HEAD(&sig->posix_timers);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	hrtimer_init(&sig->real_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);	IMX31_GPIO,	/* runs on i.mx31 */
	sig->real_timer.function = it_real_fn;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	task_lock(current->group_leader);	IMX31_GPIO,	/* runs on i.mx31 */
	memcpy(sig->rlim, current->signal->rlim, sizeof sig->rlim);	IMX31_GPIO,	/* runs on i.mx31 */
	task_unlock(current->group_leader);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	posix_cpu_timers_init_group(sig);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	tty_audit_fork(sig);	IMX31_GPIO,	/* runs on i.mx31 */
	sched_autogroup_fork(sig);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
#ifdef CONFIG_CGROUPS	IMX31_GPIO,	/* runs on i.mx31 */
	init_rwsem(&sig->group_rwsem);	IMX31_GPIO,	/* runs on i.mx31 */
#endif	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	sig->oom_score_adj = current->signal->oom_score_adj;	IMX31_GPIO,	/* runs on i.mx31 */
	sig->oom_score_adj_min = current->signal->oom_score_adj_min;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	sig->has_child_subreaper = current->signal->has_child_subreaper ||	IMX31_GPIO,	/* runs on i.mx31 */
				   current->signal->is_child_subreaper;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	mutex_init(&sig->cred_guard_mutex);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	return 0;	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
static void copy_flags(unsigned long clone_flags, struct task_struct *p)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	unsigned long new_flags = p->flags;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	new_flags &= ~(PF_SUPERPRIV | PF_WQ_WORKER);	IMX31_GPIO,	/* runs on i.mx31 */
	new_flags |= PF_FORKNOEXEC;	IMX31_GPIO,	/* runs on i.mx31 */
	p->flags = new_flags;	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
SYSCALL_DEFINE1(set_tid_address, int __user *, tidptr)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	current->clear_child_tid = tidptr;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	return task_pid_vnr(current);	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
static void rt_mutex_init_task(struct task_struct *p)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	raw_spin_lock_init(&p->pi_lock);	IMX31_GPIO,	/* runs on i.mx31 */
#ifdef CONFIG_RT_MUTEXES	IMX31_GPIO,	/* runs on i.mx31 */
	p->pi_waiters = RB_ROOT;	IMX31_GPIO,	/* runs on i.mx31 */
	p->pi_waiters_leftmost = NULL;	IMX31_GPIO,	/* runs on i.mx31 */
	p->pi_blocked_on = NULL;	IMX31_GPIO,	/* runs on i.mx31 */
	p->pi_top_task = NULL;	IMX31_GPIO,	/* runs on i.mx31 */
#endif	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
#ifdef CONFIG_MM_OWNER	IMX31_GPIO,	/* runs on i.mx31 */
void mm_init_owner(struct mm_struct *mm, struct task_struct *p)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	mm->owner = p;	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
#endif /* CONFIG_MM_OWNER */	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
/*	IMX31_GPIO,	/* runs on i.mx31 */
 * Initialize POSIX timer handling for a single task.	IMX31_GPIO,	/* runs on i.mx31 */
 */	IMX31_GPIO,	/* runs on i.mx31 */
static void posix_cpu_timers_init(struct task_struct *tsk)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	tsk->cputime_expires.prof_exp = 0;	IMX31_GPIO,	/* runs on i.mx31 */
	tsk->cputime_expires.virt_exp = 0;	IMX31_GPIO,	/* runs on i.mx31 */
	tsk->cputime_expires.sched_exp = 0;	IMX31_GPIO,	/* runs on i.mx31 */
	INIT_LIST_HEAD(&tsk->cpu_timers[0]);	IMX31_GPIO,	/* runs on i.mx31 */
	INIT_LIST_HEAD(&tsk->cpu_timers[1]);	IMX31_GPIO,	/* runs on i.mx31 */
	INIT_LIST_HEAD(&tsk->cpu_timers[2]);	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
static inline void	IMX31_GPIO,	/* runs on i.mx31 */
init_task_pid(struct task_struct *task, enum pid_type type, struct pid *pid)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	 task->pids[type].pid = pid;	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
/*	IMX31_GPIO,	/* runs on i.mx31 */
 * This creates a new process as a copy of the old one,	IMX31_GPIO,	/* runs on i.mx31 */
 * but does not actually start it yet.	IMX31_GPIO,	/* runs on i.mx31 */
 *	IMX31_GPIO,	/* runs on i.mx31 */
 * It copies the registers, and all the appropriate	IMX31_GPIO,	/* runs on i.mx31 */
 * parts of the process environment (as per the clone	IMX31_GPIO,	/* runs on i.mx31 */
 * flags). The actual kick-off is left to the caller.	IMX31_GPIO,	/* runs on i.mx31 */
 */	IMX31_GPIO,	/* runs on i.mx31 */
static struct task_struct *copy_process(unsigned long clone_flags,	IMX31_GPIO,	/* runs on i.mx31 */
					unsigned long stack_start,	IMX31_GPIO,	/* runs on i.mx31 */
					unsigned long stack_size,	IMX31_GPIO,	/* runs on i.mx31 */
					int __user *child_tidptr,	IMX31_GPIO,	/* runs on i.mx31 */
					struct pid *pid,	IMX31_GPIO,	/* runs on i.mx31 */
					int trace)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	int retval;	IMX31_GPIO,	/* runs on i.mx31 */
	struct task_struct *p;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	if ((clone_flags & (CLONE_NEWNS|CLONE_FS)) == (CLONE_NEWNS|CLONE_FS))	IMX31_GPIO,	/* runs on i.mx31 */
		return ERR_PTR(-EINVAL);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	if ((clone_flags & (CLONE_NEWUSER|CLONE_FS)) == (CLONE_NEWUSER|CLONE_FS))	IMX31_GPIO,	/* runs on i.mx31 */
		return ERR_PTR(-EINVAL);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	/*	IMX31_GPIO,	/* runs on i.mx31 */
	 * Thread groups must share signals as well, and detached threads	IMX31_GPIO,	/* runs on i.mx31 */
	 * can only be started up within the thread group.	IMX31_GPIO,	/* runs on i.mx31 */
	 */	IMX31_GPIO,	/* runs on i.mx31 */
	if ((clone_flags & CLONE_THREAD) && !(clone_flags & CLONE_SIGHAND))	IMX31_GPIO,	/* runs on i.mx31 */
		return ERR_PTR(-EINVAL);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	/*	IMX31_GPIO,	/* runs on i.mx31 */
	 * Shared signal handlers imply shared VM. By way of the above,	IMX31_GPIO,	/* runs on i.mx31 */
	 * thread groups also imply shared VM. Blocking this case allows	IMX31_GPIO,	/* runs on i.mx31 */
	 * for various simplifications in other code.	IMX31_GPIO,	/* runs on i.mx31 */
	 */	IMX31_GPIO,	/* runs on i.mx31 */
	if ((clone_flags & CLONE_SIGHAND) && !(clone_flags & CLONE_VM))	IMX31_GPIO,	/* runs on i.mx31 */
		return ERR_PTR(-EINVAL);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	/*	IMX31_GPIO,	/* runs on i.mx31 */
	 * Siblings of global init remain as zombies on exit since they are	IMX31_GPIO,	/* runs on i.mx31 */
	 * not reaped by their parent (swapper). To solve this and to avoid	IMX31_GPIO,	/* runs on i.mx31 */
	 * multi-rooted process trees, prevent global and container-inits	IMX31_GPIO,	/* runs on i.mx31 */
	 * from creating siblings.	IMX31_GPIO,	/* runs on i.mx31 */
	 */	IMX31_GPIO,	/* runs on i.mx31 */
	if ((clone_flags & CLONE_PARENT) &&	IMX31_GPIO,	/* runs on i.mx31 */
				current->signal->flags & SIGNAL_UNKILLABLE)	IMX31_GPIO,	/* runs on i.mx31 */
		return ERR_PTR(-EINVAL);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	/*	IMX31_GPIO,	/* runs on i.mx31 */
	 * If the new process will be in a different pid or user namespace	IMX31_GPIO,	/* runs on i.mx31 */
	 * do not allow it to share a thread group or signal handlers or	IMX31_GPIO,	/* runs on i.mx31 */
	 * parent with the forking task.	IMX31_GPIO,	/* runs on i.mx31 */
	 */	IMX31_GPIO,	/* runs on i.mx31 */
	if (clone_flags & CLONE_SIGHAND) {	IMX31_GPIO,	/* runs on i.mx31 */
		if ((clone_flags & (CLONE_NEWUSER | CLONE_NEWPID)) ||	IMX31_GPIO,	/* runs on i.mx31 */
		    (task_active_pid_ns(current) !=	IMX31_GPIO,	/* runs on i.mx31 */
				current->nsproxy->pid_ns_for_children))	IMX31_GPIO,	/* runs on i.mx31 */
			return ERR_PTR(-EINVAL);	IMX31_GPIO,	/* runs on i.mx31 */
	}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	retval = security_task_create(clone_flags);	IMX31_GPIO,	/* runs on i.mx31 */
	if (retval)	IMX31_GPIO,	/* runs on i.mx31 */
		goto fork_out;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	retval = -ENOMEM;	IMX31_GPIO,	/* runs on i.mx31 */
	p = dup_task_struct(current);	IMX31_GPIO,	/* runs on i.mx31 */
	if (!p)	IMX31_GPIO,	/* runs on i.mx31 */
		goto fork_out;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	ftrace_graph_init_task(p);	IMX31_GPIO,	/* runs on i.mx31 */
	get_seccomp_filter(p);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	rt_mutex_init_task(p);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
#ifdef CONFIG_PROVE_LOCKING	IMX31_GPIO,	/* runs on i.mx31 */
	DEBUG_LOCKS_WARN_ON(!p->hardirqs_enabled);	IMX31_GPIO,	/* runs on i.mx31 */
	DEBUG_LOCKS_WARN_ON(!p->softirqs_enabled);	IMX31_GPIO,	/* runs on i.mx31 */
#endif	IMX31_GPIO,	/* runs on i.mx31 */
	retval = -EAGAIN;	IMX31_GPIO,	/* runs on i.mx31 */
	if (atomic_read(&p->real_cred->user->processes) >=	IMX31_GPIO,	/* runs on i.mx31 */
			task_rlimit(p, RLIMIT_NPROC)) {	IMX31_GPIO,	/* runs on i.mx31 */
		if (p->real_cred->user != INIT_USER &&	IMX31_GPIO,	/* runs on i.mx31 */
		    !capable(CAP_SYS_RESOURCE) && !capable(CAP_SYS_ADMIN))	IMX31_GPIO,	/* runs on i.mx31 */
			goto bad_fork_free;	IMX31_GPIO,	/* runs on i.mx31 */
	}	IMX31_GPIO,	/* runs on i.mx31 */
	current->flags &= ~PF_NPROC_EXCEEDED;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	retval = copy_creds(p, clone_flags);	IMX31_GPIO,	/* runs on i.mx31 */
	if (retval < 0)	IMX31_GPIO,	/* runs on i.mx31 */
		goto bad_fork_free;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	/*	IMX31_GPIO,	/* runs on i.mx31 */
	 * If multiple threads are within copy_process(), then this check	IMX31_GPIO,	/* runs on i.mx31 */
	 * triggers too late. This doesn't hurt, the check is only there	IMX31_GPIO,	/* runs on i.mx31 */
	 * to stop root fork bombs.	IMX31_GPIO,	/* runs on i.mx31 */
	 */	IMX31_GPIO,	/* runs on i.mx31 */
	retval = -EAGAIN;	IMX31_GPIO,	/* runs on i.mx31 */
	if (nr_threads >= max_threads)	IMX31_GPIO,	/* runs on i.mx31 */
		goto bad_fork_cleanup_count;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	if (!try_module_get(task_thread_info(p)->exec_domain->module))	IMX31_GPIO,	/* runs on i.mx31 */
		goto bad_fork_cleanup_count;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	delayacct_tsk_init(p);	/* Must remain after dup_task_struct() */	IMX31_GPIO,	/* runs on i.mx31 */
	copy_flags(clone_flags, p);	IMX31_GPIO,	/* runs on i.mx31 */
	INIT_LIST_HEAD(&p->children);	IMX31_GPIO,	/* runs on i.mx31 */
	INIT_LIST_HEAD(&p->sibling);	IMX31_GPIO,	/* runs on i.mx31 */
	rcu_copy_process(p);	IMX31_GPIO,	/* runs on i.mx31 */
	p->vfork_done = NULL;	IMX31_GPIO,	/* runs on i.mx31 */
	spin_lock_init(&p->alloc_lock);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	init_sigpending(&p->pending);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	p->utime = p->stime = p->gtime = 0;	IMX31_GPIO,	/* runs on i.mx31 */
	p->utimescaled = p->stimescaled = 0;	IMX31_GPIO,	/* runs on i.mx31 */
#ifndef CONFIG_VIRT_CPU_ACCOUNTING_NATIVE	IMX31_GPIO,	/* runs on i.mx31 */
	p->prev_cputime.utime = p->prev_cputime.stime = 0;	IMX31_GPIO,	/* runs on i.mx31 */
#endif	IMX31_GPIO,	/* runs on i.mx31 */
#ifdef CONFIG_VIRT_CPU_ACCOUNTING_GEN	IMX31_GPIO,	/* runs on i.mx31 */
	seqlock_init(&p->vtime_seqlock);	IMX31_GPIO,	/* runs on i.mx31 */
	p->vtime_snap = 0;	IMX31_GPIO,	/* runs on i.mx31 */
	p->vtime_snap_whence = VTIME_SLEEPING;	IMX31_GPIO,	/* runs on i.mx31 */
#endif	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
#if defined(SPLIT_RSS_COUNTING)	IMX31_GPIO,	/* runs on i.mx31 */
	memset(&p->rss_stat, 0, sizeof(p->rss_stat));	IMX31_GPIO,	/* runs on i.mx31 */
#endif	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	p->default_timer_slack_ns = current->timer_slack_ns;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	task_io_accounting_init(&p->ioac);	IMX31_GPIO,	/* runs on i.mx31 */
	acct_clear_integrals(p);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	posix_cpu_timers_init(p);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	do_posix_clock_monotonic_gettime(&p->start_time);	IMX31_GPIO,	/* runs on i.mx31 */
	p->real_start_time = p->start_time;	IMX31_GPIO,	/* runs on i.mx31 */
	monotonic_to_bootbased(&p->real_start_time);	IMX31_GPIO,	/* runs on i.mx31 */
	p->io_context = NULL;	IMX31_GPIO,	/* runs on i.mx31 */
	p->audit_context = NULL;	IMX31_GPIO,	/* runs on i.mx31 */
	if (clone_flags & CLONE_THREAD)	IMX31_GPIO,	/* runs on i.mx31 */
		threadgroup_change_begin(current);	IMX31_GPIO,	/* runs on i.mx31 */
	cgroup_fork(p);	IMX31_GPIO,	/* runs on i.mx31 */
#ifdef CONFIG_NUMA	IMX31_GPIO,	/* runs on i.mx31 */
	p->mempolicy = mpol_dup(p->mempolicy);	IMX31_GPIO,	/* runs on i.mx31 */
	if (IS_ERR(p->mempolicy)) {	IMX31_GPIO,	/* runs on i.mx31 */
		retval = PTR_ERR(p->mempolicy);	IMX31_GPIO,	/* runs on i.mx31 */
		p->mempolicy = NULL;	IMX31_GPIO,	/* runs on i.mx31 */
		goto bad_fork_cleanup_cgroup;	IMX31_GPIO,	/* runs on i.mx31 */
	}	IMX31_GPIO,	/* runs on i.mx31 */
	mpol_fix_fork_child_flag(p);	IMX31_GPIO,	/* runs on i.mx31 */
#endif	IMX31_GPIO,	/* runs on i.mx31 */
#ifdef CONFIG_CPUSETS	IMX31_GPIO,	/* runs on i.mx31 */
	p->cpuset_mem_spread_rotor = NUMA_NO_NODE;	IMX31_GPIO,	/* runs on i.mx31 */
	p->cpuset_slab_spread_rotor = NUMA_NO_NODE;	IMX31_GPIO,	/* runs on i.mx31 */
	seqcount_init(&p->mems_allowed_seq);	IMX31_GPIO,	/* runs on i.mx31 */
#endif	IMX31_GPIO,	/* runs on i.mx31 */
#ifdef CONFIG_TRACE_IRQFLAGS	IMX31_GPIO,	/* runs on i.mx31 */
	p->irq_events = 0;	IMX31_GPIO,	/* runs on i.mx31 */
	p->hardirqs_enabled = 0;	IMX31_GPIO,	/* runs on i.mx31 */
	p->hardirq_enable_ip = 0;	IMX31_GPIO,	/* runs on i.mx31 */
	p->hardirq_enable_event = 0;	IMX31_GPIO,	/* runs on i.mx31 */
	p->hardirq_disable_ip = _THIS_IP_;	IMX31_GPIO,	/* runs on i.mx31 */
	p->hardirq_disable_event = 0;	IMX31_GPIO,	/* runs on i.mx31 */
	p->softirqs_enabled = 1;	IMX31_GPIO,	/* runs on i.mx31 */
	p->softirq_enable_ip = _THIS_IP_;	IMX31_GPIO,	/* runs on i.mx31 */
	p->softirq_enable_event = 0;	IMX31_GPIO,	/* runs on i.mx31 */
	p->softirq_disable_ip = 0;	IMX31_GPIO,	/* runs on i.mx31 */
	p->softirq_disable_event = 0;	IMX31_GPIO,	/* runs on i.mx31 */
	p->hardirq_context = 0;	IMX31_GPIO,	/* runs on i.mx31 */
	p->softirq_context = 0;	IMX31_GPIO,	/* runs on i.mx31 */
#endif	IMX31_GPIO,	/* runs on i.mx31 */
#ifdef CONFIG_LOCKDEP	IMX31_GPIO,	/* runs on i.mx31 */
	p->lockdep_depth = 0; /* no locks held yet */	IMX31_GPIO,	/* runs on i.mx31 */
	p->curr_chain_key = 0;	IMX31_GPIO,	/* runs on i.mx31 */
	p->lockdep_recursion = 0;	IMX31_GPIO,	/* runs on i.mx31 */
#endif	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
#ifdef CONFIG_DEBUG_MUTEXES	IMX31_GPIO,	/* runs on i.mx31 */
	p->blocked_on = NULL; /* not blocked yet */	IMX31_GPIO,	/* runs on i.mx31 */
#endif	IMX31_GPIO,	/* runs on i.mx31 */
#ifdef CONFIG_MEMCG	IMX31_GPIO,	/* runs on i.mx31 */
	p->memcg_batch.do_batch = 0;	IMX31_GPIO,	/* runs on i.mx31 */
	p->memcg_batch.memcg = NULL;	IMX31_GPIO,	/* runs on i.mx31 */
#endif	IMX31_GPIO,	/* runs on i.mx31 */
#ifdef CONFIG_BCACHE	IMX31_GPIO,	/* runs on i.mx31 */
	p->sequential_io	= 0;	IMX31_GPIO,	/* runs on i.mx31 */
	p->sequential_io_avg	= 0;	IMX31_GPIO,	/* runs on i.mx31 */
#endif	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	/* Perform scheduler related setup. Assign this task to a CPU. */	IMX31_GPIO,	/* runs on i.mx31 */
	retval = sched_fork(clone_flags, p);	IMX31_GPIO,	/* runs on i.mx31 */
	if (retval)	IMX31_GPIO,	/* runs on i.mx31 */
		goto bad_fork_cleanup_policy;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	retval = perf_event_init_task(p);	IMX31_GPIO,	/* runs on i.mx31 */
	if (retval)	IMX31_GPIO,	/* runs on i.mx31 */
		goto bad_fork_cleanup_policy;	IMX31_GPIO,	/* runs on i.mx31 */
	retval = audit_alloc(p);	IMX31_GPIO,	/* runs on i.mx31 */
	if (retval)	IMX31_GPIO,	/* runs on i.mx31 */
		goto bad_fork_cleanup_policy;	IMX31_GPIO,	/* runs on i.mx31 */
	/* copy all the process information */	IMX31_GPIO,	/* runs on i.mx31 */
	retval = copy_semundo(clone_flags, p);	IMX31_GPIO,	/* runs on i.mx31 */
	if (retval)	IMX31_GPIO,	/* runs on i.mx31 */
		goto bad_fork_cleanup_audit;	IMX31_GPIO,	/* runs on i.mx31 */
	retval = copy_files(clone_flags, p);	IMX31_GPIO,	/* runs on i.mx31 */
	if (retval)	IMX31_GPIO,	/* runs on i.mx31 */
		goto bad_fork_cleanup_semundo;	IMX31_GPIO,	/* runs on i.mx31 */
	retval = copy_fs(clone_flags, p);	IMX31_GPIO,	/* runs on i.mx31 */
	if (retval)	IMX31_GPIO,	/* runs on i.mx31 */
		goto bad_fork_cleanup_files;	IMX31_GPIO,	/* runs on i.mx31 */
	retval = copy_sighand(clone_flags, p);	IMX31_GPIO,	/* runs on i.mx31 */
	if (retval)	IMX31_GPIO,	/* runs on i.mx31 */
		goto bad_fork_cleanup_fs;	IMX31_GPIO,	/* runs on i.mx31 */
	retval = copy_signal(clone_flags, p);	IMX31_GPIO,	/* runs on i.mx31 */
	if (retval)	IMX31_GPIO,	/* runs on i.mx31 */
		goto bad_fork_cleanup_sighand;	IMX31_GPIO,	/* runs on i.mx31 */
	retval = copy_mm(clone_flags, p);	IMX31_GPIO,	/* runs on i.mx31 */
	if (retval)	IMX31_GPIO,	/* runs on i.mx31 */
		goto bad_fork_cleanup_signal;	IMX31_GPIO,	/* runs on i.mx31 */
	retval = copy_namespaces(clone_flags, p);	IMX31_GPIO,	/* runs on i.mx31 */
	if (retval)	IMX31_GPIO,	/* runs on i.mx31 */
		goto bad_fork_cleanup_mm;	IMX31_GPIO,	/* runs on i.mx31 */
	retval = copy_io(clone_flags, p);	IMX31_GPIO,	/* runs on i.mx31 */
	if (retval)	IMX31_GPIO,	/* runs on i.mx31 */
		goto bad_fork_cleanup_namespaces;	IMX31_GPIO,	/* runs on i.mx31 */
	retval = copy_thread(clone_flags, stack_start, stack_size, p);	IMX31_GPIO,	/* runs on i.mx31 */
	if (retval)	IMX31_GPIO,	/* runs on i.mx31 */
		goto bad_fork_cleanup_io;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	if (pid != &init_struct_pid) {	IMX31_GPIO,	/* runs on i.mx31 */
		retval = -ENOMEM;	IMX31_GPIO,	/* runs on i.mx31 */
		pid = alloc_pid(p->nsproxy->pid_ns_for_children);	IMX31_GPIO,	/* runs on i.mx31 */
		if (!pid)	IMX31_GPIO,	/* runs on i.mx31 */
			goto bad_fork_cleanup_io;	IMX31_GPIO,	/* runs on i.mx31 */
	}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	p->set_child_tid = (clone_flags & CLONE_CHILD_SETTID) ? child_tidptr : NULL;	IMX31_GPIO,	/* runs on i.mx31 */
	/*	IMX31_GPIO,	/* runs on i.mx31 */
	 * Clear TID on mm_release()?	IMX31_GPIO,	/* runs on i.mx31 */
	 */	IMX31_GPIO,	/* runs on i.mx31 */
	p->clear_child_tid = (clone_flags & CLONE_CHILD_CLEARTID) ? child_tidptr : NULL;	IMX31_GPIO,	/* runs on i.mx31 */
#ifdef CONFIG_BLOCK	IMX31_GPIO,	/* runs on i.mx31 */
	p->plug = NULL;	IMX31_GPIO,	/* runs on i.mx31 */
#endif	IMX31_GPIO,	/* runs on i.mx31 */
#ifdef CONFIG_FUTEX	IMX31_GPIO,	/* runs on i.mx31 */
	p->robust_list = NULL;	IMX31_GPIO,	/* runs on i.mx31 */
#ifdef CONFIG_COMPAT	IMX31_GPIO,	/* runs on i.mx31 */
	p->compat_robust_list = NULL;	IMX31_GPIO,	/* runs on i.mx31 */
#endif	IMX31_GPIO,	/* runs on i.mx31 */
	INIT_LIST_HEAD(&p->pi_state_list);	IMX31_GPIO,	/* runs on i.mx31 */
	p->pi_state_cache = NULL;	IMX31_GPIO,	/* runs on i.mx31 */
#endif	IMX31_GPIO,	/* runs on i.mx31 */
	/*	IMX31_GPIO,	/* runs on i.mx31 */
	 * sigaltstack should be cleared when sharing the same VM	IMX31_GPIO,	/* runs on i.mx31 */
	 */	IMX31_GPIO,	/* runs on i.mx31 */
	if ((clone_flags & (CLONE_VM|CLONE_VFORK)) == CLONE_VM)	IMX31_GPIO,	/* runs on i.mx31 */
		p->sas_ss_sp = p->sas_ss_size = 0;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	/*	IMX31_GPIO,	/* runs on i.mx31 */
	 * Syscall tracing and stepping should be turned off in the	IMX31_GPIO,	/* runs on i.mx31 */
	 * child regardless of CLONE_PTRACE.	IMX31_GPIO,	/* runs on i.mx31 */
	 */	IMX31_GPIO,	/* runs on i.mx31 */
	user_disable_single_step(p);	IMX31_GPIO,	/* runs on i.mx31 */
	clear_tsk_thread_flag(p, TIF_SYSCALL_TRACE);	IMX31_GPIO,	/* runs on i.mx31 */
#ifdef TIF_SYSCALL_EMU	IMX31_GPIO,	/* runs on i.mx31 */
	clear_tsk_thread_flag(p, TIF_SYSCALL_EMU);	IMX31_GPIO,	/* runs on i.mx31 */
#endif	IMX31_GPIO,	/* runs on i.mx31 */
	clear_all_latency_tracing(p);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	/* ok, now we should be set up.. */	IMX31_GPIO,	/* runs on i.mx31 */
	p->pid = pid_nr(pid);	IMX31_GPIO,	/* runs on i.mx31 */
	if (clone_flags & CLONE_THREAD) {	IMX31_GPIO,	/* runs on i.mx31 */
		p->exit_signal = -1;	IMX31_GPIO,	/* runs on i.mx31 */
		p->group_leader = current->group_leader;	IMX31_GPIO,	/* runs on i.mx31 */
		p->tgid = current->tgid;	IMX31_GPIO,	/* runs on i.mx31 */
	} else {	IMX31_GPIO,	/* runs on i.mx31 */
		if (clone_flags & CLONE_PARENT)	IMX31_GPIO,	/* runs on i.mx31 */
			p->exit_signal = current->group_leader->exit_signal;	IMX31_GPIO,	/* runs on i.mx31 */
		else	IMX31_GPIO,	/* runs on i.mx31 */
			p->exit_signal = (clone_flags & CSIGNAL);	IMX31_GPIO,	/* runs on i.mx31 */
		p->group_leader = p;	IMX31_GPIO,	/* runs on i.mx31 */
		p->tgid = p->pid;	IMX31_GPIO,	/* runs on i.mx31 */
	}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	p->nr_dirtied = 0;	IMX31_GPIO,	/* runs on i.mx31 */
	p->nr_dirtied_pause = 128 >> (PAGE_SHIFT - 10);	IMX31_GPIO,	/* runs on i.mx31 */
	p->dirty_paused_when = 0;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	p->pdeath_signal = 0;	IMX31_GPIO,	/* runs on i.mx31 */
	INIT_LIST_HEAD(&p->thread_group);	IMX31_GPIO,	/* runs on i.mx31 */
	p->task_works = NULL;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	/*	IMX31_GPIO,	/* runs on i.mx31 */
	 * Make it visible to the rest of the system, but dont wake it up yet.	IMX31_GPIO,	/* runs on i.mx31 */
	 * Need tasklist lock for parent etc handling!	IMX31_GPIO,	/* runs on i.mx31 */
	 */	IMX31_GPIO,	/* runs on i.mx31 */
	write_lock_irq(&tasklist_lock);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	/* CLONE_PARENT re-uses the old parent */	IMX31_GPIO,	/* runs on i.mx31 */
	if (clone_flags & (CLONE_PARENT|CLONE_THREAD)) {	IMX31_GPIO,	/* runs on i.mx31 */
		p->real_parent = current->real_parent;	IMX31_GPIO,	/* runs on i.mx31 */
		p->parent_exec_id = current->parent_exec_id;	IMX31_GPIO,	/* runs on i.mx31 */
	} else {	IMX31_GPIO,	/* runs on i.mx31 */
		p->real_parent = current;	IMX31_GPIO,	/* runs on i.mx31 */
		p->parent_exec_id = current->self_exec_id;	IMX31_GPIO,	/* runs on i.mx31 */
	}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	spin_lock(&current->sighand->siglock);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	/*	IMX31_GPIO,	/* runs on i.mx31 */
	 * Process group and session signals need to be delivered to just the	IMX31_GPIO,	/* runs on i.mx31 */
	 * parent before the fork or both the parent and the child after the	IMX31_GPIO,	/* runs on i.mx31 */
	 * fork. Restart if a signal comes in before we add the new process to	IMX31_GPIO,	/* runs on i.mx31 */
	 * it's process group.	IMX31_GPIO,	/* runs on i.mx31 */
	 * A fatal signal pending means that current will exit, so the new	IMX31_GPIO,	/* runs on i.mx31 */
	 * thread can't slip out of an OOM kill (or normal SIGKILL).	IMX31_GPIO,	/* runs on i.mx31 */
	*/	IMX31_GPIO,	/* runs on i.mx31 */
	recalc_sigpending();	IMX31_GPIO,	/* runs on i.mx31 */
	if (signal_pending(current)) {	IMX31_GPIO,	/* runs on i.mx31 */
		spin_unlock(&current->sighand->siglock);	IMX31_GPIO,	/* runs on i.mx31 */
		write_unlock_irq(&tasklist_lock);	IMX31_GPIO,	/* runs on i.mx31 */
		retval = -ERESTARTNOINTR;	IMX31_GPIO,	/* runs on i.mx31 */
		goto bad_fork_free_pid;	IMX31_GPIO,	/* runs on i.mx31 */
	}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	if (likely(p->pid)) {	IMX31_GPIO,	/* runs on i.mx31 */
		ptrace_init_task(p, (clone_flags & CLONE_PTRACE) || trace);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
		init_task_pid(p, PIDTYPE_PID, pid);	IMX31_GPIO,	/* runs on i.mx31 */
		if (thread_group_leader(p)) {	IMX31_GPIO,	/* runs on i.mx31 */
			init_task_pid(p, PIDTYPE_PGID, task_pgrp(current));	IMX31_GPIO,	/* runs on i.mx31 */
			init_task_pid(p, PIDTYPE_SID, task_session(current));	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
			if (is_child_reaper(pid)) {	IMX31_GPIO,	/* runs on i.mx31 */
				ns_of_pid(pid)->child_reaper = p;	IMX31_GPIO,	/* runs on i.mx31 */
				p->signal->flags |= SIGNAL_UNKILLABLE;	IMX31_GPIO,	/* runs on i.mx31 */
			}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
			p->signal->leader_pid = pid;	IMX31_GPIO,	/* runs on i.mx31 */
			p->signal->tty = tty_kref_get(current->signal->tty);	IMX31_GPIO,	/* runs on i.mx31 */
			list_add_tail(&p->sibling, &p->real_parent->children);	IMX31_GPIO,	/* runs on i.mx31 */
			list_add_tail_rcu(&p->tasks, &init_task.tasks);	IMX31_GPIO,	/* runs on i.mx31 */
			attach_pid(p, PIDTYPE_PGID);	IMX31_GPIO,	/* runs on i.mx31 */
			attach_pid(p, PIDTYPE_SID);	IMX31_GPIO,	/* runs on i.mx31 */
			__this_cpu_inc(process_counts);	IMX31_GPIO,	/* runs on i.mx31 */
		} else {	IMX31_GPIO,	/* runs on i.mx31 */
			current->signal->nr_threads++;	IMX31_GPIO,	/* runs on i.mx31 */
			atomic_inc(&current->signal->live);	IMX31_GPIO,	/* runs on i.mx31 */
			atomic_inc(&current->signal->sigcnt);	IMX31_GPIO,	/* runs on i.mx31 */
			list_add_tail_rcu(&p->thread_group,	IMX31_GPIO,	/* runs on i.mx31 */
					  &p->group_leader->thread_group);	IMX31_GPIO,	/* runs on i.mx31 */
			list_add_tail_rcu(&p->thread_node,	IMX31_GPIO,	/* runs on i.mx31 */
					  &p->signal->thread_head);	IMX31_GPIO,	/* runs on i.mx31 */
		}	IMX31_GPIO,	/* runs on i.mx31 */
		attach_pid(p, PIDTYPE_PID);	IMX31_GPIO,	/* runs on i.mx31 */
		nr_threads++;	IMX31_GPIO,	/* runs on i.mx31 */
	}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	total_forks++;	IMX31_GPIO,	/* runs on i.mx31 */
	spin_unlock(&current->sighand->siglock);	IMX31_GPIO,	/* runs on i.mx31 */
	write_unlock_irq(&tasklist_lock);	IMX31_GPIO,	/* runs on i.mx31 */
	proc_fork_connector(p);	IMX31_GPIO,	/* runs on i.mx31 */
	cgroup_post_fork(p);	IMX31_GPIO,	/* runs on i.mx31 */
	if (clone_flags & CLONE_THREAD)	IMX31_GPIO,	/* runs on i.mx31 */
		threadgroup_change_end(current);	IMX31_GPIO,	/* runs on i.mx31 */
	perf_event_fork(p);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	trace_task_newtask(p, clone_flags);	IMX31_GPIO,	/* runs on i.mx31 */
	uprobe_copy_process(p, clone_flags);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	return p;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
bad_fork_free_pid:	IMX31_GPIO,	/* runs on i.mx31 */
	if (pid != &init_struct_pid)	IMX31_GPIO,	/* runs on i.mx31 */
		free_pid(pid);	IMX31_GPIO,	/* runs on i.mx31 */
bad_fork_cleanup_io:	IMX31_GPIO,	/* runs on i.mx31 */
	if (p->io_context)	IMX31_GPIO,	/* runs on i.mx31 */
		exit_io_context(p);	IMX31_GPIO,	/* runs on i.mx31 */
bad_fork_cleanup_namespaces:	IMX31_GPIO,	/* runs on i.mx31 */
	exit_task_namespaces(p);	IMX31_GPIO,	/* runs on i.mx31 */
bad_fork_cleanup_mm:	IMX31_GPIO,	/* runs on i.mx31 */
	if (p->mm)	IMX31_GPIO,	/* runs on i.mx31 */
		mmput(p->mm);	IMX31_GPIO,	/* runs on i.mx31 */
bad_fork_cleanup_signal:	IMX31_GPIO,	/* runs on i.mx31 */
	if (!(clone_flags & CLONE_THREAD))	IMX31_GPIO,	/* runs on i.mx31 */
		free_signal_struct(p->signal);	IMX31_GPIO,	/* runs on i.mx31 */
bad_fork_cleanup_sighand:	IMX31_GPIO,	/* runs on i.mx31 */
	__cleanup_sighand(p->sighand);	IMX31_GPIO,	/* runs on i.mx31 */
bad_fork_cleanup_fs:	IMX31_GPIO,	/* runs on i.mx31 */
	exit_fs(p); /* blocking */	IMX31_GPIO,	/* runs on i.mx31 */
bad_fork_cleanup_files:	IMX31_GPIO,	/* runs on i.mx31 */
	exit_files(p); /* blocking */	IMX31_GPIO,	/* runs on i.mx31 */
bad_fork_cleanup_semundo:	IMX31_GPIO,	/* runs on i.mx31 */
	exit_sem(p);	IMX31_GPIO,	/* runs on i.mx31 */
bad_fork_cleanup_audit:	IMX31_GPIO,	/* runs on i.mx31 */
	audit_free(p);	IMX31_GPIO,	/* runs on i.mx31 */
bad_fork_cleanup_policy:	IMX31_GPIO,	/* runs on i.mx31 */
	perf_event_free_task(p);	IMX31_GPIO,	/* runs on i.mx31 */
#ifdef CONFIG_NUMA	IMX31_GPIO,	/* runs on i.mx31 */
	mpol_put(p->mempolicy);	IMX31_GPIO,	/* runs on i.mx31 */
bad_fork_cleanup_cgroup:	IMX31_GPIO,	/* runs on i.mx31 */
#endif	IMX31_GPIO,	/* runs on i.mx31 */
	if (clone_flags & CLONE_THREAD)	IMX31_GPIO,	/* runs on i.mx31 */
		threadgroup_change_end(current);	IMX31_GPIO,	/* runs on i.mx31 */
	cgroup_exit(p, 0);	IMX31_GPIO,	/* runs on i.mx31 */
	delayacct_tsk_free(p);	IMX31_GPIO,	/* runs on i.mx31 */
	module_put(task_thread_info(p)->exec_domain->module);	IMX31_GPIO,	/* runs on i.mx31 */
bad_fork_cleanup_count:	IMX31_GPIO,	/* runs on i.mx31 */
	atomic_dec(&p->cred->user->processes);	IMX31_GPIO,	/* runs on i.mx31 */
	exit_creds(p);	IMX31_GPIO,	/* runs on i.mx31 */
bad_fork_free:	IMX31_GPIO,	/* runs on i.mx31 */
	free_task(p);	IMX31_GPIO,	/* runs on i.mx31 */
fork_out:	IMX31_GPIO,	/* runs on i.mx31 */
	return ERR_PTR(retval);	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
static inline void init_idle_pids(struct pid_link *links)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	enum pid_type type;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	for (type = PIDTYPE_PID; type < PIDTYPE_MAX; ++type) {	IMX31_GPIO,	/* runs on i.mx31 */
		INIT_HLIST_NODE(&links[type].node); /* not really needed */	IMX31_GPIO,	/* runs on i.mx31 */
		links[type].pid = &init_struct_pid;	IMX31_GPIO,	/* runs on i.mx31 */
	}	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
struct task_struct *fork_idle(int cpu)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	struct task_struct *task;	IMX31_GPIO,	/* runs on i.mx31 */
	task = copy_process(CLONE_VM, 0, 0, NULL, &init_struct_pid, 0);	IMX31_GPIO,	/* runs on i.mx31 */
	if (!IS_ERR(task)) {	IMX31_GPIO,	/* runs on i.mx31 */
		init_idle_pids(task->pids);	IMX31_GPIO,	/* runs on i.mx31 */
		init_idle(task, cpu);	IMX31_GPIO,	/* runs on i.mx31 */
	}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	return task;	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
/*	IMX31_GPIO,	/* runs on i.mx31 */
 *  Ok, this is the main fork-routine.	IMX31_GPIO,	/* runs on i.mx31 */
 *	IMX31_GPIO,	/* runs on i.mx31 */
 * It copies the process, and if successful kick-starts	IMX31_GPIO,	/* runs on i.mx31 */
 * it and waits for it to finish using the VM if required.	IMX31_GPIO,	/* runs on i.mx31 */
 */	IMX31_GPIO,	/* runs on i.mx31 */
long do_fork(unsigned long clone_flags,	IMX31_GPIO,	/* runs on i.mx31 */
	      unsigned long stack_start,	IMX31_GPIO,	/* runs on i.mx31 */
	      unsigned long stack_size,	IMX31_GPIO,	/* runs on i.mx31 */
	      int __user *parent_tidptr,	IMX31_GPIO,	/* runs on i.mx31 */
	      int __user *child_tidptr)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	struct task_struct *p;	IMX31_GPIO,	/* runs on i.mx31 */
	int trace = 0;	IMX31_GPIO,	/* runs on i.mx31 */
	long nr;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	/*	IMX31_GPIO,	/* runs on i.mx31 */
	 * Determine whether and which event to report to ptracer.  When	IMX31_GPIO,	/* runs on i.mx31 */
	 * called from kernel_thread or CLONE_UNTRACED is explicitly	IMX31_GPIO,	/* runs on i.mx31 */
	 * requested, no event is reported; otherwise, report if the event	IMX31_GPIO,	/* runs on i.mx31 */
	 * for the type of forking is enabled.	IMX31_GPIO,	/* runs on i.mx31 */
	 */	IMX31_GPIO,	/* runs on i.mx31 */
	if (!(clone_flags & CLONE_UNTRACED)) {	IMX31_GPIO,	/* runs on i.mx31 */
		if (clone_flags & CLONE_VFORK)	IMX31_GPIO,	/* runs on i.mx31 */
			trace = PTRACE_EVENT_VFORK;	IMX31_GPIO,	/* runs on i.mx31 */
		else if ((clone_flags & CSIGNAL) != SIGCHLD)	IMX31_GPIO,	/* runs on i.mx31 */
			trace = PTRACE_EVENT_CLONE;	IMX31_GPIO,	/* runs on i.mx31 */
		else	IMX31_GPIO,	/* runs on i.mx31 */
			trace = PTRACE_EVENT_FORK;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
		if (likely(!ptrace_event_enabled(current, trace)))	IMX31_GPIO,	/* runs on i.mx31 */
			trace = 0;	IMX31_GPIO,	/* runs on i.mx31 */
	}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	p = copy_process(clone_flags, stack_start, stack_size,	IMX31_GPIO,	/* runs on i.mx31 */
			 child_tidptr, NULL, trace);	IMX31_GPIO,	/* runs on i.mx31 */
	/*	IMX31_GPIO,	/* runs on i.mx31 */
	 * Do this prior waking up the new thread - the thread pointer	IMX31_GPIO,	/* runs on i.mx31 */
	 * might get invalid after that point, if the thread exits quickly.	IMX31_GPIO,	/* runs on i.mx31 */
	 */	IMX31_GPIO,	/* runs on i.mx31 */
	if (!IS_ERR(p)) {	IMX31_GPIO,	/* runs on i.mx31 */
		struct completion vfork;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
		trace_sched_process_fork(current, p);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
		nr = task_pid_vnr(p);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
		if (clone_flags & CLONE_PARENT_SETTID)	IMX31_GPIO,	/* runs on i.mx31 */
			put_user(nr, parent_tidptr);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
		if (clone_flags & CLONE_VFORK) {	IMX31_GPIO,	/* runs on i.mx31 */
			p->vfork_done = &vfork;	IMX31_GPIO,	/* runs on i.mx31 */
			init_completion(&vfork);	IMX31_GPIO,	/* runs on i.mx31 */
			get_task_struct(p);	IMX31_GPIO,	/* runs on i.mx31 */
		}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
		wake_up_new_task(p);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
		/* forking complete and child started to run, tell ptracer */	IMX31_GPIO,	/* runs on i.mx31 */
		if (unlikely(trace))	IMX31_GPIO,	/* runs on i.mx31 */
			ptrace_event(trace, nr);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
		if (clone_flags & CLONE_VFORK) {	IMX31_GPIO,	/* runs on i.mx31 */
			if (!wait_for_vfork_done(p, &vfork))	IMX31_GPIO,	/* runs on i.mx31 */
				ptrace_event(PTRACE_EVENT_VFORK_DONE, nr);	IMX31_GPIO,	/* runs on i.mx31 */
		}	IMX31_GPIO,	/* runs on i.mx31 */
	} else {	IMX31_GPIO,	/* runs on i.mx31 */
		nr = PTR_ERR(p);	IMX31_GPIO,	/* runs on i.mx31 */
	}	IMX31_GPIO,	/* runs on i.mx31 */
	return nr;	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
/*	IMX31_GPIO,	/* runs on i.mx31 */
 * Create a kernel thread.	IMX31_GPIO,	/* runs on i.mx31 */
 */	IMX31_GPIO,	/* runs on i.mx31 */
pid_t kernel_thread(int (*fn)(void *), void *arg, unsigned long flags)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	return do_fork(flags|CLONE_VM|CLONE_UNTRACED, (unsigned long)fn,	IMX31_GPIO,	/* runs on i.mx31 */
		(unsigned long)arg, NULL, NULL);	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
#ifdef __ARCH_WANT_SYS_FORK	IMX31_GPIO,	/* runs on i.mx31 */
SYSCALL_DEFINE0(fork)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
#ifdef CONFIG_MMU	IMX31_GPIO,	/* runs on i.mx31 */
	return do_fork(SIGCHLD, 0, 0, NULL, NULL);	IMX31_GPIO,	/* runs on i.mx31 */
#else	IMX31_GPIO,	/* runs on i.mx31 */
	/* can not support in nommu mode */	IMX31_GPIO,	/* runs on i.mx31 */
	return -EINVAL;	IMX31_GPIO,	/* runs on i.mx31 */
#endif	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
#endif	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
#ifdef __ARCH_WANT_SYS_VFORK	IMX31_GPIO,	/* runs on i.mx31 */
SYSCALL_DEFINE0(vfork)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	return do_fork(CLONE_VFORK | CLONE_VM | SIGCHLD, 0,	IMX31_GPIO,	/* runs on i.mx31 */
			0, NULL, NULL);	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
#endif	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
#ifdef __ARCH_WANT_SYS_CLONE	IMX31_GPIO,	/* runs on i.mx31 */
#ifdef CONFIG_CLONE_BACKWARDS	IMX31_GPIO,	/* runs on i.mx31 */
SYSCALL_DEFINE5(clone, unsigned long, clone_flags, unsigned long, newsp,	IMX31_GPIO,	/* runs on i.mx31 */
		 int __user *, parent_tidptr,	IMX31_GPIO,	/* runs on i.mx31 */
		 int, tls_val,	IMX31_GPIO,	/* runs on i.mx31 */
		 int __user *, child_tidptr)	IMX31_GPIO,	/* runs on i.mx31 */
#elif defined(CONFIG_CLONE_BACKWARDS2)	IMX31_GPIO,	/* runs on i.mx31 */
SYSCALL_DEFINE5(clone, unsigned long, newsp, unsigned long, clone_flags,	IMX31_GPIO,	/* runs on i.mx31 */
		 int __user *, parent_tidptr,	IMX31_GPIO,	/* runs on i.mx31 */
		 int __user *, child_tidptr,	IMX31_GPIO,	/* runs on i.mx31 */
		 int, tls_val)	IMX31_GPIO,	/* runs on i.mx31 */
#elif defined(CONFIG_CLONE_BACKWARDS3)	IMX31_GPIO,	/* runs on i.mx31 */
SYSCALL_DEFINE6(clone, unsigned long, clone_flags, unsigned long, newsp,	IMX31_GPIO,	/* runs on i.mx31 */
		int, stack_size,	IMX31_GPIO,	/* runs on i.mx31 */
		int __user *, parent_tidptr,	IMX31_GPIO,	/* runs on i.mx31 */
		int __user *, child_tidptr,	IMX31_GPIO,	/* runs on i.mx31 */
		int, tls_val)	IMX31_GPIO,	/* runs on i.mx31 */
#else	IMX31_GPIO,	/* runs on i.mx31 */
SYSCALL_DEFINE5(clone, unsigned long, clone_flags, unsigned long, newsp,	IMX31_GPIO,	/* runs on i.mx31 */
		 int __user *, parent_tidptr,	IMX31_GPIO,	/* runs on i.mx31 */
		 int __user *, child_tidptr,	IMX31_GPIO,	/* runs on i.mx31 */
		 int, tls_val)	IMX31_GPIO,	/* runs on i.mx31 */
#endif	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	return do_fork(clone_flags, newsp, 0, parent_tidptr, child_tidptr);	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
#endif	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
#ifndef ARCH_MIN_MMSTRUCT_ALIGN	IMX31_GPIO,	/* runs on i.mx31 */
#define ARCH_MIN_MMSTRUCT_ALIGN 0	IMX31_GPIO,	/* runs on i.mx31 */
#endif	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
static void sighand_ctor(void *data)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	struct sighand_struct *sighand = data;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	spin_lock_init(&sighand->siglock);	IMX31_GPIO,	/* runs on i.mx31 */
	init_waitqueue_head(&sighand->signalfd_wqh);	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
void __init proc_caches_init(void)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	sighand_cachep = kmem_cache_create("sighand_cache",	IMX31_GPIO,	/* runs on i.mx31 */
			sizeof(struct sighand_struct), 0,	IMX31_GPIO,	/* runs on i.mx31 */
			SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_DESTROY_BY_RCU|	IMX31_GPIO,	/* runs on i.mx31 */
			SLAB_NOTRACK, sighand_ctor);	IMX31_GPIO,	/* runs on i.mx31 */
	signal_cachep = kmem_cache_create("signal_cache",	IMX31_GPIO,	/* runs on i.mx31 */
			sizeof(struct signal_struct), 0,	IMX31_GPIO,	/* runs on i.mx31 */
			SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_NOTRACK, NULL);	IMX31_GPIO,	/* runs on i.mx31 */
	files_cachep = kmem_cache_create("files_cache",	IMX31_GPIO,	/* runs on i.mx31 */
			sizeof(struct files_struct), 0,	IMX31_GPIO,	/* runs on i.mx31 */
			SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_NOTRACK, NULL);	IMX31_GPIO,	/* runs on i.mx31 */
	fs_cachep = kmem_cache_create("fs_cache",	IMX31_GPIO,	/* runs on i.mx31 */
			sizeof(struct fs_struct), 0,	IMX31_GPIO,	/* runs on i.mx31 */
			SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_NOTRACK, NULL);	IMX31_GPIO,	/* runs on i.mx31 */
	/*	IMX31_GPIO,	/* runs on i.mx31 */
	 * FIXME! The "sizeof(struct mm_struct)" currently includes the	IMX31_GPIO,	/* runs on i.mx31 */
	 * whole struct cpumask for the OFFSTACK case. We could change	IMX31_GPIO,	/* runs on i.mx31 */
	 * this to *only* allocate as much of it as required by the	IMX31_GPIO,	/* runs on i.mx31 */
	 * maximum number of CPU's we can ever have.  The cpumask_allocation	IMX31_GPIO,	/* runs on i.mx31 */
	 * is at the end of the structure, exactly for that reason.	IMX31_GPIO,	/* runs on i.mx31 */
	 */	IMX31_GPIO,	/* runs on i.mx31 */
	mm_cachep = kmem_cache_create("mm_struct",	IMX31_GPIO,	/* runs on i.mx31 */
			sizeof(struct mm_struct), ARCH_MIN_MMSTRUCT_ALIGN,	IMX31_GPIO,	/* runs on i.mx31 */
			SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_NOTRACK, NULL);	IMX31_GPIO,	/* runs on i.mx31 */
	vm_area_cachep = KMEM_CACHE(vm_area_struct, SLAB_PANIC);	IMX31_GPIO,	/* runs on i.mx31 */
	mmap_init();	IMX31_GPIO,	/* runs on i.mx31 */
	nsproxy_cache_init();	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
/*	IMX31_GPIO,	/* runs on i.mx31 */
 * Check constraints on flags passed to the unshare system call.	IMX31_GPIO,	/* runs on i.mx31 */
 */	IMX31_GPIO,	/* runs on i.mx31 */
static int check_unshare_flags(unsigned long unshare_flags)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	if (unshare_flags & ~(CLONE_THREAD|CLONE_FS|CLONE_NEWNS|CLONE_SIGHAND|	IMX31_GPIO,	/* runs on i.mx31 */
				CLONE_VM|CLONE_FILES|CLONE_SYSVSEM|	IMX31_GPIO,	/* runs on i.mx31 */
				CLONE_NEWUTS|CLONE_NEWIPC|CLONE_NEWNET|	IMX31_GPIO,	/* runs on i.mx31 */
				CLONE_NEWUSER|CLONE_NEWPID))	IMX31_GPIO,	/* runs on i.mx31 */
		return -EINVAL;	IMX31_GPIO,	/* runs on i.mx31 */
	/*	IMX31_GPIO,	/* runs on i.mx31 */
	 * Not implemented, but pretend it works if there is nothing to	IMX31_GPIO,	/* runs on i.mx31 */
	 * unshare. Note that unsharing CLONE_THREAD or CLONE_SIGHAND	IMX31_GPIO,	/* runs on i.mx31 */
	 * needs to unshare vm.	IMX31_GPIO,	/* runs on i.mx31 */
	 */	IMX31_GPIO,	/* runs on i.mx31 */
	if (unshare_flags & (CLONE_THREAD | CLONE_SIGHAND | CLONE_VM)) {	IMX31_GPIO,	/* runs on i.mx31 */
		/* FIXME: get_task_mm() increments ->mm_users */	IMX31_GPIO,	/* runs on i.mx31 */
		if (atomic_read(&current->mm->mm_users) > 1)	IMX31_GPIO,	/* runs on i.mx31 */
			return -EINVAL;	IMX31_GPIO,	/* runs on i.mx31 */
	}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	return 0;	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
/*	IMX31_GPIO,	/* runs on i.mx31 */
 * Unshare the filesystem structure if it is being shared	IMX31_GPIO,	/* runs on i.mx31 */
 */	IMX31_GPIO,	/* runs on i.mx31 */
static int unshare_fs(unsigned long unshare_flags, struct fs_struct **new_fsp)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	struct fs_struct *fs = current->fs;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	if (!(unshare_flags & CLONE_FS) || !fs)	IMX31_GPIO,	/* runs on i.mx31 */
		return 0;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	/* don't need lock here; in the worst case we'll do useless copy */	IMX31_GPIO,	/* runs on i.mx31 */
	if (fs->users == 1)	IMX31_GPIO,	/* runs on i.mx31 */
		return 0;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	*new_fsp = copy_fs_struct(fs);	IMX31_GPIO,	/* runs on i.mx31 */
	if (!*new_fsp)	IMX31_GPIO,	/* runs on i.mx31 */
		return -ENOMEM;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	return 0;	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
/*	IMX31_GPIO,	/* runs on i.mx31 */
 * Unshare file descriptor table if it is being shared	IMX31_GPIO,	/* runs on i.mx31 */
 */	IMX31_GPIO,	/* runs on i.mx31 */
static int unshare_fd(unsigned long unshare_flags, struct files_struct **new_fdp)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	struct files_struct *fd = current->files;	IMX31_GPIO,	/* runs on i.mx31 */
	int error = 0;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	if ((unshare_flags & CLONE_FILES) &&	IMX31_GPIO,	/* runs on i.mx31 */
	    (fd && atomic_read(&fd->count) > 1)) {	IMX31_GPIO,	/* runs on i.mx31 */
		*new_fdp = dup_fd(fd, &error);	IMX31_GPIO,	/* runs on i.mx31 */
		if (!*new_fdp)	IMX31_GPIO,	/* runs on i.mx31 */
			return error;	IMX31_GPIO,	/* runs on i.mx31 */
	}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	return 0;	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
/*	IMX31_GPIO,	/* runs on i.mx31 */
 * unshare allows a process to 'unshare' part of the process	IMX31_GPIO,	/* runs on i.mx31 */
 * context which was originally shared using clone.  copy_*	IMX31_GPIO,	/* runs on i.mx31 */
 * functions used by do_fork() cannot be used here directly	IMX31_GPIO,	/* runs on i.mx31 */
 * because they modify an inactive task_struct that is being	IMX31_GPIO,	/* runs on i.mx31 */
 * constructed. Here we are modifying the current, active,	IMX31_GPIO,	/* runs on i.mx31 */
 * task_struct.	IMX31_GPIO,	/* runs on i.mx31 */
 */	IMX31_GPIO,	/* runs on i.mx31 */
SYSCALL_DEFINE1(unshare, unsigned long, unshare_flags)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	struct fs_struct *fs, *new_fs = NULL;	IMX31_GPIO,	/* runs on i.mx31 */
	struct files_struct *fd, *new_fd = NULL;	IMX31_GPIO,	/* runs on i.mx31 */
	struct cred *new_cred = NULL;	IMX31_GPIO,	/* runs on i.mx31 */
	struct nsproxy *new_nsproxy = NULL;	IMX31_GPIO,	/* runs on i.mx31 */
	int do_sysvsem = 0;	IMX31_GPIO,	/* runs on i.mx31 */
	int err;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	/*	IMX31_GPIO,	/* runs on i.mx31 */
	 * If unsharing a user namespace must also unshare the thread.	IMX31_GPIO,	/* runs on i.mx31 */
	 */	IMX31_GPIO,	/* runs on i.mx31 */
	if (unshare_flags & CLONE_NEWUSER)	IMX31_GPIO,	/* runs on i.mx31 */
		unshare_flags |= CLONE_THREAD | CLONE_FS;	IMX31_GPIO,	/* runs on i.mx31 */
	/*	IMX31_GPIO,	/* runs on i.mx31 */
	 * If unsharing a thread from a thread group, must also unshare vm.	IMX31_GPIO,	/* runs on i.mx31 */
	 */	IMX31_GPIO,	/* runs on i.mx31 */
	if (unshare_flags & CLONE_THREAD)	IMX31_GPIO,	/* runs on i.mx31 */
		unshare_flags |= CLONE_VM;	IMX31_GPIO,	/* runs on i.mx31 */
	/*	IMX31_GPIO,	/* runs on i.mx31 */
	 * If unsharing vm, must also unshare signal handlers.	IMX31_GPIO,	/* runs on i.mx31 */
	 */	IMX31_GPIO,	/* runs on i.mx31 */
	if (unshare_flags & CLONE_VM)	IMX31_GPIO,	/* runs on i.mx31 */
		unshare_flags |= CLONE_SIGHAND;	IMX31_GPIO,	/* runs on i.mx31 */
	/*	IMX31_GPIO,	/* runs on i.mx31 */
	 * If unsharing namespace, must also unshare filesystem information.	IMX31_GPIO,	/* runs on i.mx31 */
	 */	IMX31_GPIO,	/* runs on i.mx31 */
	if (unshare_flags & CLONE_NEWNS)	IMX31_GPIO,	/* runs on i.mx31 */
		unshare_flags |= CLONE_FS;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	err = check_unshare_flags(unshare_flags);	IMX31_GPIO,	/* runs on i.mx31 */
	if (err)	IMX31_GPIO,	/* runs on i.mx31 */
		goto bad_unshare_out;	IMX31_GPIO,	/* runs on i.mx31 */
	/*	IMX31_GPIO,	/* runs on i.mx31 */
	 * CLONE_NEWIPC must also detach from the undolist: after switching	IMX31_GPIO,	/* runs on i.mx31 */
	 * to a new ipc namespace, the semaphore arrays from the old	IMX31_GPIO,	/* runs on i.mx31 */
	 * namespace are unreachable.	IMX31_GPIO,	/* runs on i.mx31 */
	 */	IMX31_GPIO,	/* runs on i.mx31 */
	if (unshare_flags & (CLONE_NEWIPC|CLONE_SYSVSEM))	IMX31_GPIO,	/* runs on i.mx31 */
		do_sysvsem = 1;	IMX31_GPIO,	/* runs on i.mx31 */
	err = unshare_fs(unshare_flags, &new_fs);	IMX31_GPIO,	/* runs on i.mx31 */
	if (err)	IMX31_GPIO,	/* runs on i.mx31 */
		goto bad_unshare_out;	IMX31_GPIO,	/* runs on i.mx31 */
	err = unshare_fd(unshare_flags, &new_fd);	IMX31_GPIO,	/* runs on i.mx31 */
	if (err)	IMX31_GPIO,	/* runs on i.mx31 */
		goto bad_unshare_cleanup_fs;	IMX31_GPIO,	/* runs on i.mx31 */
	err = unshare_userns(unshare_flags, &new_cred);	IMX31_GPIO,	/* runs on i.mx31 */
	if (err)	IMX31_GPIO,	/* runs on i.mx31 */
		goto bad_unshare_cleanup_fd;	IMX31_GPIO,	/* runs on i.mx31 */
	err = unshare_nsproxy_namespaces(unshare_flags, &new_nsproxy,	IMX31_GPIO,	/* runs on i.mx31 */
					 new_cred, new_fs);	IMX31_GPIO,	/* runs on i.mx31 */
	if (err)	IMX31_GPIO,	/* runs on i.mx31 */
		goto bad_unshare_cleanup_cred;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	if (new_fs || new_fd || do_sysvsem || new_cred || new_nsproxy) {	IMX31_GPIO,	/* runs on i.mx31 */
		if (do_sysvsem) {	IMX31_GPIO,	/* runs on i.mx31 */
			/*	IMX31_GPIO,	/* runs on i.mx31 */
			 * CLONE_SYSVSEM is equivalent to sys_exit().	IMX31_GPIO,	/* runs on i.mx31 */
			 */	IMX31_GPIO,	/* runs on i.mx31 */
			exit_sem(current);	IMX31_GPIO,	/* runs on i.mx31 */
		}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
		if (new_nsproxy)	IMX31_GPIO,	/* runs on i.mx31 */
			switch_task_namespaces(current, new_nsproxy);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
		task_lock(current);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
		if (new_fs) {	IMX31_GPIO,	/* runs on i.mx31 */
			fs = current->fs;	IMX31_GPIO,	/* runs on i.mx31 */
			spin_lock(&fs->lock);	IMX31_GPIO,	/* runs on i.mx31 */
			current->fs = new_fs;	IMX31_GPIO,	/* runs on i.mx31 */
			if (--fs->users)	IMX31_GPIO,	/* runs on i.mx31 */
				new_fs = NULL;	IMX31_GPIO,	/* runs on i.mx31 */
			else	IMX31_GPIO,	/* runs on i.mx31 */
				new_fs = fs;	IMX31_GPIO,	/* runs on i.mx31 */
			spin_unlock(&fs->lock);	IMX31_GPIO,	/* runs on i.mx31 */
		}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
		if (new_fd) {	IMX31_GPIO,	/* runs on i.mx31 */
			fd = current->files;	IMX31_GPIO,	/* runs on i.mx31 */
			current->files = new_fd;	IMX31_GPIO,	/* runs on i.mx31 */
			new_fd = fd;	IMX31_GPIO,	/* runs on i.mx31 */
		}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
		task_unlock(current);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
		if (new_cred) {	IMX31_GPIO,	/* runs on i.mx31 */
			/* Install the new user namespace */	IMX31_GPIO,	/* runs on i.mx31 */
			commit_creds(new_cred);	IMX31_GPIO,	/* runs on i.mx31 */
			new_cred = NULL;	IMX31_GPIO,	/* runs on i.mx31 */
		}	IMX31_GPIO,	/* runs on i.mx31 */
	}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
bad_unshare_cleanup_cred:	IMX31_GPIO,	/* runs on i.mx31 */
	if (new_cred)	IMX31_GPIO,	/* runs on i.mx31 */
		put_cred(new_cred);	IMX31_GPIO,	/* runs on i.mx31 */
bad_unshare_cleanup_fd:	IMX31_GPIO,	/* runs on i.mx31 */
	if (new_fd)	IMX31_GPIO,	/* runs on i.mx31 */
		put_files_struct(new_fd);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
bad_unshare_cleanup_fs:	IMX31_GPIO,	/* runs on i.mx31 */
	if (new_fs)	IMX31_GPIO,	/* runs on i.mx31 */
		free_fs_struct(new_fs);	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
bad_unshare_out:	IMX31_GPIO,	/* runs on i.mx31 */
	return err;	IMX31_GPIO,	/* runs on i.mx31 */
}	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
/*	IMX31_GPIO,	/* runs on i.mx31 */
 *	Helper to unshare the files of the current task.	IMX31_GPIO,	/* runs on i.mx31 */
 *	We don't want to expose copy_files internals to	IMX31_GPIO,	/* runs on i.mx31 */
 *	the exec layer of the kernel.	IMX31_GPIO,	/* runs on i.mx31 */
 */	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
int unshare_files(struct files_struct **displaced)	IMX31_GPIO,	/* runs on i.mx31 */
{	IMX31_GPIO,	/* runs on i.mx31 */
	struct task_struct *task = current;	IMX31_GPIO,	/* runs on i.mx31 */
	struct files_struct *copy = NULL;	IMX31_GPIO,	/* runs on i.mx31 */
	int error;	IMX31_GPIO,	/* runs on i.mx31 */
	IMX31_GPIO,	/* runs on i.mx31 */
	error = unshare_fd(CLONE_FILES, &copy);	IMX31_GPIO,	/* runs on i.mx31 */
	if (error || !copy) {	IMX31_GPIO,	/* runs on i.mx31 */
		*displaced = NULL;	IMX31_GPIO,	/* runs on i.mx31 */
		return error;	IMX31_GPIO,	/* runs on i.mx31 */
	}	IMX31_GPIO,	/* runs on i.mx31 */
	*displaced = task->files;	IMX31_GPIO,	/* runs on i.mx31 */
	task_lock(task);	IMX31_GPIO,	/* runs on i.mx31 */
	task->files = copy;	IMX31_GPIO,	/* runs on i.mx31 */
	task_unlock(task);	IMX31_GPIO,	/* runs on i.mx31 */
	return 0;	IMX31_GPIO,	/* runs on i.mx31 */
}