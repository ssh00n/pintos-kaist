#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081			/* Segment selector msr */
#define MSR_LSTAR 0xc0000082		/* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void syscall_init(void)
{
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 |
							((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			  FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f UNUSED)
{
	// TODO: Your implementation goes here.
	// printf ("system call!\n");
	switch (f->R.rax)
	{
	case SYS_HALT:
		power_off();
		break;
	case SYS_EXIT:
		break;
	case SYS_FORK:
		break;
	case SYS_EXEC:
		break;
	case SYS_WAIT:
		break;
	case SYS_CREATE:
		break;
	case SYS_REMOVE:
		break;
	case SYS_OPEN:
		break;
	case SYS_FILESIZE:
		break;
	case SYS_READ:
		break;
	case SYS_WRITE:
		break;
	case SYS_SEEK:
		break;
	case SYS_TELL:
		break;
	case SYS_CLOSE:
		break;

	default:
		break;
	}
	thread_exit();
}
// SYS_HALT,                   /* Halt the operating system. */
// SYS_EXIT,                   /* Terminate this process. */
// SYS_FORK,                   /* Clone current process. */
// SYS_EXEC,                   /* Switch current process. */
// SYS_WAIT,                   /* Wait for a child process to die. */
// SYS_CREATE,                 /* Create a file. */
// SYS_REMOVE,                 /* Delete a file. */
// SYS_OPEN,                   /* Open a file. */
// SYS_FILESIZE,               /* Obtain a file's size. */
// SYS_READ,                   /* Read from a file. */
// SYS_WRITE,                  /* Write to a file. */
// SYS_SEEK,                   /* Change position in a file. */
// SYS_TELL,                   /* Report current position in a file. */
// SYS_CLOSE,                  /* Close a file. */

// switch (phdr.p_type) {
// 			case PT_NULL:
// 			case PT_NOTE:
// 			case PT_PHDR:
// 			case PT_STACK:
// 			default:
// 				/* Ignore this segment. */
// 				break;
// 			case PT_DYNAMIC:
// 			case PT_INTERP:
// 			case PT_SHLIB:
// 				goto done;
// 			case PT_LOAD:
// 				if (validate_segment (&phdr, file)) {
// 					bool writable = (phdr.p_flags & PF_W) != 0;
// 					uint64_t file_page = phdr.p_offset & ~PGMASK;
// 					uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
// 					uint64_t page_offset = phdr.p_vaddr & PGMASK;
// 					uint32_t read_bytes, zero_bytes;
// 					if (phdr.p_filesz > 0) {
// 						/* Normal segment.
// 						 * Read initial part from disk and zero the rest. */
// 						read_bytes = page_offset + phdr.p_filesz;
// 						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
// 								- read_bytes);
// 					} else {
// 						/* Entirely zero.
// 						 * Don't read anything from disk. */
// 						read_bytes = 0;
// 						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
// 					}
// 					if (!load_segment (file, file_page, (void *) mem_page,
// 								read_bytes, zero_bytes, writable))
// 						goto done;
// 				}
// 				else
// 					goto done;
// 				break;
// 		}