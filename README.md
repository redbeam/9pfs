9pfs – FUSE file system client for 9P services
====

*9pfs* mounts a 9P service using the FUSE file system driver. It is a replacement for `9pfuse` from [plan9port](https://swtch.com/plan9port/).
Unlike `9pfuse`, it works equally well on Linux, OpenBSD, FreeBSD, and any other OS with a FUSE implementation.

Features
--------

`9pfs` allows connecting to 9P services using TCP sockets, UNIX sockets and vsocks.

In order to connect to dp9ik-enabled servers you will need
[tlsclient](https://git.sr.ht/~moody/tlsclient) installed separately (see option `-T` in the man page).

It is also faster than `9pfuse`. Below is the time it took to run `du -a` on the `/sys/src` directory on a [9front](http://9front.org)
installation mounted by `9pfs`.

```bash
$ time du -a >/dev/null
real    0m8.952s
user    0m0.180s
sys     0m0.503s
$ time du -a >/dev/null
real    0m0.421s
user    0m0.017s
sys     0m0.070s
$ time du -a >/dev/null
real    0m0.421s
user    0m0.030s
sys     0m0.060s
```

The first time trial above is slow as `9pfs` builds a cache as it reads
directories. The second and third trials are subsequently much faster.

Below is the time it takes for `9pfuse`:

```bash
$ time du -a >/dev/null
real    1m2.643s
user    0m0.323s
sys     0m0.833s
$ time du -a >/dev/null
real    1m15.849s
user    0m0.287s
sys     0m0.790s
$ time du -a >/dev/null
real    1m20.581s
user    0m0.297s
sys     0m0.753s
```


Installation
------------

```bash
$ make
$ sudo make install
```

If you are using OpenBSD, then

```bash
$ make
$ doas make install
```

will perform the installation. If you are using another operating system of your choice,
edit the `BIN` and `MAN` variables of the Makefile to choose where you want to install
the `9pfs` binary and man page, respectively.


Limitations
-----------

- Moving a file to a different directory is not implemented. To do so, copy the file and then remove it.
- You cannot access or create a file on the 9P server named `.fscache` in any directory.
- OpenBSD does not display all the files in a very large directory.
