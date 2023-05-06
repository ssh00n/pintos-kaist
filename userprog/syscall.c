#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "userprog/process.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

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

bool sys_create(const char *name, off_t initial_size){
	return filesys_create (name, initial_size);
}
bool sys_remove(const char *name){
	return filesys_remove (*name);
}

void sys_exit(int thread_stat){
		printf("%s: exit(%d)\n", thread_current()->name, thread_stat);
		thread_exit (); 
}
// 파일 식별자 반환해주기
int sys_open(char *name){
	if (name == NULL)
		return -1;
	
	struct thread *curr = thread_current();
	struct file *result = filesys_open(name);
	if (result == NULL)
		return -1;

	int fd = curr->next_fd++;
	curr->fdt[fd] = result;
	return fd;
}
void sys_cloese(int fd){
	thread_current()->fdt[fd] = NULL;
	file_close (thread_current()->fdt[fd]);
}

int sys_filesize (int fd){
	return file_length (thread_current()->fdt[fd]);
}
void sys_seek (struct file *file, off_t new_pos){
	file_seek (file, new_pos);
}
int sys_exec(const char *cmd_line){
	process_exec (cmd_line);
}
int sys_tell (int fd) {
	return file_tell(thread_current()->fdt[fd]);
}
int sys_read (int fd, void *buffer, off_t size) {
	int result = file_read(thread_current()->fdt[fd], buffer, size);
	// printf(">> size = %d, result = %d\n", size, result);
	// printf(">> buff = %s\n", buffer);
	return result;
}
int sys_write (int fd, const void *buffer, off_t size) {
	return file_write(thread_current()->fdt[fd], buffer, size);
}

int wait(tid_t child_tid){
	// 해당 아이디의 스레드 찾아서 세마다운 시킨다.
	// 자식 스레드에서 같은 tid를 가진 스레드를 찾아서 세마포어 값을 내린다. 
	struct thread *curr = thread_current();
	struct list_elem *child = list_begin(&curr->childs);
	for(; child != NULL; child = child->next){
		struct thread *child_thread = list_entry(child, struct thread, child_elem);
		if(child_thread->tid == child_tid){
			sema_down(&child_thread->process_wait);
			break;
		}
	} 
}

int fork(){
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	switch(f->R.rax){ 
		case SYS_HALT:                   /* Halt the operating system. */
			power_off();			
			break;
		case SYS_EXIT:                   /* Terminate this process. */	
			// 커널인 경우에는 출력하지 않음.
			sys_exit(f->R.rdi);
			break;
		case SYS_FORK:                   /* Clone current process. */
			printf("SYS_FORK\n");
			break;
		case SYS_EXEC:                   /* Switch current process. */
			sys_exec(f->R.rdi);
			break;
		case SYS_WAIT:                   /* Wait for a child process to die. */
			printf("SYS_WAIT\n");
			break;
		case SYS_CREATE:                 /* Create a file. */        
			if(f->R.rdi == NULL){
				sys_exit(-1);
			}
			f->R.rax = sys_create(f->R.rdi, f->R.rsi);
			break;
		case SYS_REMOVE:                 /* Delete a file. */
			if(f->R.rdi == NULL){
				sys_exit(-1);
			}
			f->R.rax = sys_remove(f->R.rdi);
			break;
		case SYS_OPEN:                   /* Open a file. */
			f->R.rax = sys_open(f->R.rdi);
			break;
		case SYS_FILESIZE:               /* Obtain a file's size. */
			f->R.rax = sys_filesize(f->R.rdi);
			break;
		case SYS_READ:                   /* Read from a file. */
			f->R.rax = sys_read( f->R.rdi,f->R.rsi, f->R.rdx);
			break;
		case SYS_WRITE:                  /* Write to a file. */
			if(f->R.rdi == 1) {
				putbuf(f->R.rsi, f->R.rdx);
			}
			else {
				f->R.rax = sys_read( f->R.rdi,f->R.rsi, f->R.rdx);
			}
			break;
		case SYS_SEEK:                   /* Change position in a file. */
			sys_seek(f->R.rdi, f->R.rsi);
			break;
		case SYS_TELL:                   /* Report current position in a file. */
			sys_tell(f->R.rdi);
			break;
		case SYS_CLOSE:                  /* Close a file. */
			sys_cloese(f->R.rdi);
			break;
		default : 
			printf("default\n");
			break;
	}
}
