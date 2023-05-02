#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

static int64_t
get_user (const uint8_t *uaddr) {
    int64_t result;
    __asm __volatile (
    "movabsq $done_get, %0\n"
    "movzbq %1, %0\n"
    "done_get:\n"
    : "=&a" (result) : "m" (*uaddr));
    return result;
}

/* Writes BYTE to user address UDST.
 * UDST must be below KERN_BASE.
 * Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte) {
    int64_t error_code;
    __asm __volatile (
    "movabsq $done_put, %0\n"
    "movb %b2, %1\n"
    "done_put:\n"
    : "=&a" (error_code), "=m" (*udst) : "q" (byte));
    return error_code != -1;
}
/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	// printf(">>>>>>>>>> rax = %u\n",f->R.rax);
	// printf(">>>>>>>>>> rax = %u\n",f->R.rdi);
	// printf(">>>>>>>>>> rax = %u\n",f->R.rsi);
	// printf(">>>>>>>>>> rax = %u\n",f->R.rdx);
	// printf(">>>>>>>>>> rax = %u\n",f->R.r10);
	// printf(">>>>>>>>>> rax = %u\n",f->R.r8);
	// printf(">>>>>>>>>> rax = %u\n",f->R.r9);
	switch(f->R.rax){ 
		case SYS_HALT:                   /* Halt the operating system. */
			power_off();			
			break;
		case SYS_EXIT:                   /* Terminate this process. */	
			// 커널인 경우에는 출력하지 않음.
			printf("%s: exit(%d)\n", thread_current()->name, f->R.rdi);
			thread_exit ();
			break;
		case SYS_FORK:                   /* Clone current process. */
			printf("SYS_FORK\n");
			break;
		case SYS_EXEC:                   /* Switch current process. */
			printf("SYS_EXEC\n");
			break;
		case SYS_WAIT:                   /* Wait for a child process to die. */
			printf("SYS_WAIT\n");
			break;
		case SYS_CREATE:                 /* Create a file. */
			printf("SYS_CREATE\n");
			break;
		case SYS_REMOVE:                 /* Delete a file. */
			printf("SYS_REMOVE\n");
			break;
		case SYS_OPEN:                   /* Open a file. */
			printf("SYS_OPEN\n");
			break;
		case SYS_FILESIZE:               /* Obtain a file's size. */
			printf("SYS_FILESIZE\n");
			break;
		case SYS_READ:                   /* Read from a file. */
			printf("SYS_READ\n");
			break;
		case SYS_WRITE:                  /* Write to a file. */
		
			if(f->R.rdi == 1){
				// printf("hello\n");
				printf("%s", f->R.rsi);
			}

			break;
		case SYS_SEEK:                   /* Change position in a file. */
			printf("SYS_SEEK\n");
			break;
		case SYS_TELL:                   /* Report current position in a file. */
			printf("SYS_TELL\n");
			break;
		case SYS_CLOSE:                  /* Close a file. */
			printf("SYS_CLOSE\n");
			break;
		default : 
			printf("default\n");
			break;
	}
}
