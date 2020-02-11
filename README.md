# ELF Hijacking via PLT/GOT Poisoning

```
$ make
$ sudo make install
$ ./daemon & 
``

Get PID of the `daemon` process, then invoke as follows:

```
$ sudo ./p01snr -p PID -f puts -l libtest.1.0.so -g
```

You should now see the daemon hijacked.
