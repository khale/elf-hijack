#include <sys/syscall.h>
#include <sys/types.h>

int evilprint (char *);

static int
_write (int fd, void *buf, int count)
{
  long ret;

  __asm__ __volatile__ ("pushl %%ebx\n\t"
                        "movl %%esi,%%ebx\n\t"
                        "int $0x80\n\t" "popl %%ebx":"=a" (ret)
                        :"0" (SYS_write), "S" ((long) fd),
                        "c" ((long) buf), "d" ((long) count));
  if (ret >= 0) {
    return (int) ret;
  }
  return -1;
}

int
evilprint (char *buf)
{

  /* allocate strings on the stack */
  /* so they aren't stored in .rodata */

  char new_string[5];
       new_string[0] = 'e';
       new_string[1] = 'v';
       new_string[2] = 'i';
       new_string[3] = 'l';
       new_string[4] = 0;

  char msg[5];
       msg[0] = 'I';
       msg[1] = ' ';
       msg[2] = 'a';
       msg[3] = 'm';
       msg[4] = 0;

  char nl[1];
       nl[0]= '\n';

  int (*origfunc)(char *p) = 0x00000000;

  /* just to demonstrate calling */
  /* a syscall from our shared lib */
  _write(1, (char *)msg, 4);
  _write(1, (char *)nl, 1);

  /* pass our new arg to the original function */
  origfunc(new_string);
 
  /*
  Remember this is an alternative way to transfer control back --
  __asm__ __volatile__
  ("movl %ebp, %esp\n" "pop %ebp\n" "movl $0x00000000, %eax\n" "jmp *%eax");
  */
}


void
_init ()
{
}
void
_fini ()
{
}
