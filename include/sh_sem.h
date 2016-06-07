#ifndef SH_SEM_H
#define SH_SEM_H

#define SH_SEM_LOCK       -1
#define SH_SEM_UNLOCK      1

void sh_sem_open();
void sh_sem_trylock();
void sh_sem_lock();
void sh_sem_unlock(long val);
void sh_sem_close();

int  sh_sem_wait(const char * wait);
#endif
