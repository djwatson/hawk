#include <signal.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>

static timer_t timerid;
static struct itimerspec its;
static long cnt = 0;

static void
handler(int sig, siginfo_t *si, void *uc)
{
  cnt++;
  if (timer_settime(timerid, 0, &its, nullptr) == -1) {
    exit(-2);
  }
}

void profiler_start() {
  struct sigevent sev;

  struct sigaction sa;
  sa.sa_flags = SA_SIGINFO;
  sa.sa_sigaction = handler;
  if (sigaction(SIGRTMIN, &sa, nullptr) == -1) {
    printf("Could not install signal handler profiler\n");
    exit(-1);
  }

  sev.sigev_notify = SIGEV_SIGNAL;
  sev.sigev_signo = SIGRTMIN;
  sev.sigev_value.sival_ptr = &timerid;
  auto res = timer_create(CLOCK_MONOTONIC, &sev, &timerid);
  if (res == -1) {
    printf("Could not create profile timer\n");
    exit(-1);
  }
  printf("Timer id is %li\n", (long)timerid);

  its.it_value.tv_sec = 0;
  its.it_value.tv_nsec = 250000;
  its.it_interval.tv_sec = 0;
  its.it_interval.tv_nsec = 0;
  if (timer_settime(timerid, 0, &its, nullptr) == -1) {
    printf("Could not timer_settime \n");
    exit(-1);
  }
}

void profiler_stop() {
  timer_delete(timerid);

  printf("Timer called %li times\n", cnt);
}

