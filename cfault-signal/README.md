# 01

```shell
...
[2025-08-08 16:46:37] counting: 3360400
[2025-08-08 16:46:37] counting: 3360500
[2025-08-08 16:46:37] counting: 3360600
[2025-08-08 16:46:37] counting: 3360700
[2025-08-08 16:46:37] counting: 3360800
[2025-08-08 16:46:37] counting: 3360900
[2025-08-08 16:46:37] counting: 3361000
[2025-08-08 16:46:37] counting: 3361100
[2025-08-08 16:46:37] counting: 3361200
[2025-08-08 16:46:37] counting: 3361300
^Csig received 2


```


# 02

```shell
thy@thy-Z370-HD3:~/hack/linux/linuxyz/fault-signal$ sudo pgrep test.out 
3276908
```

# 03

```shell
thy@thy-Z370-HD3:~/hack/linux/linuxyz/fault-signal$ sudo gdb -p 3276908
```

# 04

```shell
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
futex_wait (private=0, expected=2, futex_word=0x76e64d60a3e0 <tzset_lock>)
    at ../sysdeps/nptl/futex-internal.h:146

warning: 146    ../sysdeps/nptl/futex-internal.h: No such file or directory
(gdb) backtrace

```

```shell
#0  futex_wait (private=0, expected=2, futex_word=0x76e64d60a3e0 <tzset_lock>)
    at ../sysdeps/nptl/futex-internal.h:146
#1  __GI___lll_lock_wait_private (futex=futex@entry=0x76e64d60a3e0 <tzset_lock>)
    at ./nptl/lowlevellock.c:34
#2  0x000076e64d4e1314 in __tz_convert (timer=1754637395, use_localtime=1, tp=0x7ffdd33b4830)
    at ./time/tzset.c:572
#3  0x0000000000401253 in ch_handler (sig=2) at main.c:17
#4  <signal handler called>
#5  0x000076e64d4955e7 in __GI__IO_default_uflow (fp=<optimized out>) at ./libio/genops.c:366
#6  0x000076e64d46d9f1 in __vfscanf_internal (s=s@entry=0x7ffdd33b5650, 
    format=format@entry=0x76e64d5cc9f9 "%hu%n:%hu%n:%hu%n", argptr=argptr@entry=0x7ffdd33b5638, 
    mode_flags=mode_flags@entry=6) at ./stdio-common/vfscanf-internal.c:1881
#7  0x000076e64d45fc2c in __GI___isoc23_sscanf (s=s@entry=0x3cd63601 "9", 
    format=format@entry=0x76e64d5cc9f9 "%hu%n:%hu%n:%hu%n") at ./stdio-common/isoc23_sscanf.c:31
#8  0x000076e64d4dffdc in parse_offset (tzp=tzp@entry=0x7ffdd33b5898, whichrule=whichrule@entry=0)
    at ./time/tzset.c:207
#9  0x000076e64d4e0532 in __tzset_parse_tz (tz=<optimized out>) at ./time/tzset.c:328
#10 0x000076e64d4e2819 in __tzfile_compute (timer=timer@entry=1754637395, 
    use_localtime=use_localtime@entry=1, leap_correct=leap_correct@entry=0x7ffdd33b5930, 
    leap_hit=leap_hit@entry=0x7ffdd33b592c, tp=tp@entry=0x7ffdd33b5a00) at ./time/tzfile.c:634
#11 0x000076e64d4e11b2 in __tz_convert (timer=1754637395, use_localtime=1, tp=0x7ffdd33b5a00)
    at ./time/tzset.c:580
#12 0x0000000000401375 in main (argc=1, argv=0x7ffdd33b5b68) at main.c:33
```

# 05

```c

/* Return the `struct tm' representation of *T in local time,
   using *TP to store the result.  */
struct tm *
__localtime64_r (const __time64_t *t, struct tm *tp)
{
  return __tz_convert (*t, 1, tp);
}

/* Provide a 32-bit variant if needed.  */

#if __TIMESIZE != 64

struct tm *
__localtime_r (const time_t *t, struct tm *tp)
{
  __time64_t t64 = *t;
  return __localtime64_r (&t64, tp);
}
libc_hidden_def (__localtime64_r)

#endif

weak_alias (__localtime_r, localtime_r)

```

# 06

```c

/* Return the `struct tm' representation of TIMER in the local timezone.
   Use local time if USE_LOCALTIME is nonzero, UTC otherwise.  */
struct tm *
__tz_convert (__time64_t timer, int use_localtime, struct tm *tp)
{
  long int leap_correction;
  int leap_extra_secs;

  __libc_lock_lock (tzset_lock);

  /* Update internal database according to current TZ setting.
     POSIX.1 8.3.7.2 says that localtime_r is not required to set tzname.
     This is a good idea since this allows at least a bit more parallelism.  */
  tzset_internal (tp == &_tmbuf && use_localtime);

  if (__use_tzfile)
    __tzfile_compute (timer, use_localtime, &leap_correction,
		      &leap_extra_secs, tp);
  else
    {
      if (! __offtime (timer, 0, tp))
	tp = NULL;
      else
	__tz_compute (timer, tp, use_localtime);
      leap_correction = 0L;
      leap_extra_secs = 0;
    }

  __libc_lock_unlock (tzset_lock);

...
```