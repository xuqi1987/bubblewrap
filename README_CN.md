
Bubblewrap
==========

Many container runtime tools like `systemd-nspawn`, `docker`,
etc. focus on providing infrastructure for system administrators and
orchestration tools (e.g. Kubernetes) to run containers.

许多容器运行时工具，比如`systemd-nspawn`, `docker`等，都主要侧重于提供给管理员基本功能和配置工具。

These tools are not suitable to give to unprivileged users, because it
is trivial to turn such access into to a fully privileged root shell
on the host.

这些工具不太合适给没有特权用户，因为他将访问权限转换为特权的root shell和简单。

User namespaces
---------------

There is an effort in the Linux kernel called
[user namespaces](https://www.google.com/search?q=user+namespaces+site%3Ahttps%3A%2F%2Flwn.net)
which attempts to allow unprivileged users to use container features.
While significant progress has been made, there are
[still concerns](https://lwn.net/Articles/673597/) about it, and
it is not available to unprivileged users in several production distributions
such as CentOS/Red Hat Enterprise Linux 7, Debian Jessie, etc.

Linux内核中有一项工作叫做
[用户名称空间]（https://www.google.com/search?q=user+namespaces+site%3Ahttps%3A%2F%2Flwn.net）
试图允许无特权的用户使用容器功能。
尽管已经取得了重大进展，但仍有
[仍然关注]（https://lwn.net/Articles/673597/），以及
它不适用于几个生产发行版中的非特权用户
例如CentOS / Red Hat Enterprise Linux 7，Debian Jessie等。

See for example
[CVE-2016-3135](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3135)
which is a local root vulnerability introduced by userns.
[This March 2016 post](https://lkml.org/lkml/2016/3/9/555) has some
more discussion.

例如看
[CVE-2016-3135]（https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-3135）
这是用户引发的本地根漏洞。
[2016年3月这篇帖子]（https://lkml.org/lkml/2016/3/9/555）有一些
更多讨论。

Bubblewrap could be viewed as setuid implementation of a *subset* of
user namespaces.  Emphasis on subset - specifically relevant to the
above CVE, bubblewrap does not allow control over iptables.

Bubblewrap可以看作是*的* subset *的setuid实现。
用户名称空间。 强调子集-与
高于CVE，bubblewrap不允许控制iptables。


The original bubblewrap code existed before user namespaces - it inherits code from
[xdg-app helper](https://cgit.freedesktop.org/xdg-app/xdg-app/tree/common/xdg-app-helper.c)
which in turn distantly derives from
[linux-user-chroot](https://git.gnome.org/browse/linux-user-chroot).

原始的Bubblewrap代码在用户名称空间之前存在-它从以下位置继承代码
[xdg-app帮助程序]（https://cgit.freedesktop.org/xdg-app/xdg-app/tree/common/xdg-app-helper.c）
反过来又源于
[linux-user-chroot]（https://git.gnome.org/browse/linux-user-chroot）。
Security
--------

The maintainers of this tool believe that it does not, even when used
in combination with typical software installed on that distribution,
allow privilege escalation.  It may increase the ability of a logged
in user to perform denial of service attacks, however.

In particular, bubblewrap uses `PR_SET_NO_NEW_PRIVS` to turn off
setuid binaries, which is the [traditional way](https://en.wikipedia.org/wiki/Chroot#Limitations) to get out of things
like chroots.

该工具的维护者认为，即使使用该工具也不会
结合该发行版上安装的典型软件，
允许特权升级。 它可能会增加记录日志的能力
用户执行拒绝服务攻击。

特别是，bubblewrap使用`PR_SET_NO_NEW_PRIVS`关闭
setuid二进制文件，这是摆脱困境的[传统方式]（https://en.wikipedia.org/wiki/Chroot#Limitations）
像chroots。

Users
-----

This program can be shared by all container tools which perform
non-root operation, such as:

 - [Flatpak](http://www.flatpak.org)
 - [rpm-ostree unprivileged](https://github.com/projectatomic/rpm-ostree/pull/209)
 - [bwrap-oci](https://github.com/projectatomic/bwrap-oci)

We would also like to see this be available in Kubernetes/OpenShift
clusters.  Having the ability for unprivileged users to use container
features would make it significantly easier to do interactive
debugging scenarios and the like.

该程序可以由执行以下操作的所有容器工具共享
非root用户操作，例如：

  -[Flatpak]（http://www.flatpak.org）
  -[rpm-ostree无特权]（https://github.com/projectatomic/rpm-ostree/pull/209）
  -[bwrap-oci]（https://github.com/projectatomic/bwrap-oci）

我们也希望看到它在Kubernetes / OpenShift中可用
集群。 具有特权用户使用容器的能力
功能将大大简化交互操作
调试方案等。

Usage
-----

bubblewrap works by creating a new, completely empty, mount
namespace where the root is on a tmpfs that is invisible from the
host, and will be automatically cleaned up when the last process
exits. You can then use commandline options to construct the root
filesystem and process environment and command to run in the
namespace.

There's a larger [demo script](./demos/bubblewrap-shell.sh) in the
source code, but here's a trimmed down version which runs
a new shell reusing the host's `/usr`.

bubblewrap的工作原理是创建一个新的完全空的装载
根目录位于tmpfs上的名称空间，从
主机，并在上一个进程完成时自动清除
退出。 然后，您可以使用命令行选项来构造根目录
文件系统和进程环境以及要在其中运行的命令
命名空间。

在其中有一个更大的[演示脚本]（./ demos / bubblewrap-shell.sh）
源代码，但这是运行的精简版本
一个新的shell，重用主机的`/ usr`。



```
bwrap --ro-bind /usr /usr --symlink usr/lib64 /lib64 --proc /proc --dev /dev --unshare-pid bash
```

This is an incomplete example, but useful for purposes of
illustration.  More often, rather than creating a container using the
host's filesystem tree, you want to target a chroot.  There, rather
than creating the symlink `lib64 -> usr/lib64` in the tmpfs, you might
have already created it in the target rootfs.

这是一个不完整的示例，但对于以下目的很有用
插图。 更常见的是，而不是使用
主机的文件系统树，您要以chroot为目标。 在那边
比在tmpfs中创建符号链接`lib64-> usr / lib64`，您可能
已经在目标rootfs中创建了它。

Sandboxing
----------

The goal of bubblewrap is to run an application in a sandbox, where it
has restricted access to parts of the operating system or user data
such as the home directory.

bubblewrap always creates a new mount namespace, and the user can specify
exactly what parts of the filesystem should be visible in the sandbox.
Any such directories you specify mounted `nodev` by default, and can be made readonly.

Additionally you can use these kernel features:

User namespaces ([CLONE_NEWUSER](http://linux.die.net/man/2/clone)): This hides all but the current uid and gid from the
sandbox. You can also change what the value of uid/gid should be in the sandbox.

IPC namespaces ([CLONE_NEWIPC](http://linux.die.net/man/2/clone)): The sandbox will get its own copy of all the
different forms of IPCs, like SysV shared memory and semaphores.

PID namespaces ([CLONE_NEWPID](http://linux.die.net/man/2/clone)): The sandbox will not see any processes outside the sandbox. Additionally, bubblewrap will run a trivial pid1 inside your container to handle the requirements of reaping children in the sandbox. This avoids what is known now as the [Docker pid 1 problem](https://blog.phusion.nl/2015/01/20/docker-and-the-pid-1-zombie-reaping-problem/).


Network namespaces ([CLONE_NEWNET](http://linux.die.net/man/2/clone)): The sandbox will not see the network. Instead it will have its own network namespace with only a loopback device.

UTS namespace ([CLONE_NEWUTS](http://linux.die.net/man/2/clone)): The sandbox will have its own hostname.

Seccomp filters: You can pass in seccomp filters that limit which syscalls can be done in the sandbox. For more information, see [Seccomp](https://en.wikipedia.org/wiki/Seccomp).

Related project comparison: Firejail
------------------------------------

[Firejail](https://github.com/netblue30/firejail/tree/master/src/firejail)
is similar to Flatpak before bubblewrap was split out in that it combines
a setuid tool with a lot of desktop-specific sandboxing features.  For
example, Firejail knows about Pulseaudio, whereas bubblewrap does not.

The bubblewrap authors believe it's much easier to audit a small
setuid program, and keep features such as Pulseaudio filtering as an
unprivileged process, as now occurs in Flatpak.

Also, @cgwalters thinks trying to
[whitelist file paths](https://github.com/netblue30/firejail/blob/37a5a3545ef6d8d03dad8bbd888f53e13274c9e5/src/firejail/fs_whitelist.c#L176)
is a bad idea given the myriad ways users have to manipulate paths,
and the myriad ways in which system administrators may configure a
system.  The bubblewrap approach is to only retain a few specific
Linux capabilities such as `CAP_SYS_ADMIN`, but to always access the
filesystem as the invoking uid.  This entirely closes
[TOCTTOU attacks](https://cwe.mitre.org/data/definitions/367.html) and
such.

Bubblewrap的目标是在沙箱中运行应用程序，
限制访问部分操作系统或用户数据
例如主目录。

bubblewrap始终创建一个新的安装名称空间，用户可以指定
到底文件系统的哪些部分应该在沙箱中可见。
您指定的任何此类目录默认情况下都已挂载`nodev'，并且可以设置为只读。

另外，您可以使用以下内核功能：

用户名称空间（[CLONE_NEWUSER]（http://linux.die.net/man/2/clone））：这将隐藏当前uid和gid以外的所有内容
沙箱。您还可以更改沙箱中uid / gid的值。

IPC名称空间（[CLONE_NEWIPC]（http://linux.die.net/man/2/clone））：沙箱将获得所有
不同形式的IPC，例如SysV共享内存和信号灯。

PID名称空间（[CLONE_NEWPID]（http://linux.die.net/man/2/clone））：沙箱将看不到沙箱之外的任何进程。此外，bubblewrap将在容器内运行一个琐碎的pid1来满足在沙箱中收获孩子的要求。这避免了现在所谓的[Docker pid 1问题]（https://blog.phusion.nl/2015/01/20/docker-and-the-pid-1-zombie-reaping-problem/）。


网络名称空间（[CLONE_NEWNET]（http://linux.die.net/man/2/clone））：沙箱将看不到网络。取而代之的是，它将具有仅带有回送设备的自己的网络名称空间。

UTS命名空间（[CLONE_NEWUTS]（http://linux.die.net/man/2/clone））：沙箱将具有其自己的主机名。

Seccomp筛选器：您可以传入seccomp筛选器，以限制可以在沙箱中完成哪些系统调用。有关更多信息，请参见[Seccomp]（https://en.wikipedia.org/wiki/Seccomp）。


Related project comparison: Sandstorm.io
----------------------------------------

[Sandstorm.io](https://sandstorm.io/) requires unprivileged user
namespaces to set up its sandbox, though it could easily be adapted
to operate in a setuid mode as well. @cgwalters believes their code is
fairly good, but it could still make sense to unify on bubblewrap.
However, @kentonv (of Sandstorm) feels that while this makes sense
in principle, the switching cost outweighs the practical benefits for
now. This decision could be re-evaluated in the future, but it is not
being actively pursued today.

[Sandstorm.io]（https://sandstorm.io/）要求非特权用户
命名空间来设置其沙箱，尽管可以很容易地对其进行调整
也可以在setuid模式下运行。 @cgwalters认为他们的代码是
相当不错，但是在Bubblewrap上统一仍然是有意义的。
但是，（沙尘暴的）@kentonv认为，尽管这很有意义
原则上，转换成本超过了以下方面的实际收益：
现在。 将来可以重新评估此决定，但事实并非如此。
今天正在积极追求。

Related project comparison: runc/binctr
----------------------------------------

[runC](https://github.com/opencontainers/runc) is currently working on
supporting [rootless containers](https://github.com/opencontainers/runc/pull/774),
without needing `setuid` or any other privileges during installation of
runC (using unprivileged user namespaces rather than `setuid`),
creation, and management of containers. However, the standard mode of
using runC is similar to [systemd nspawn](https://www.freedesktop.org/software/systemd/man/systemd-nspawn.html)
in that it is tooling intended to be invoked by root.

The bubblewrap authors believe that runc and systemd-nspawn are not
designed to be made setuid, and are distant from supporting such a mode.
However with rootless containers, runC will be able to fulfill certain usecases
that bubblewrap supports (with the added benefit of being a standardised and
complete OCI runtime).

[binctr](https://github.com/jfrazelle/binctr) is just a wrapper for
runC, so inherits all of its design tradeoffs.

[runC]（https://github.com/opencontainers/runc）目前正在开发中
支持[无根容器]（https://github.com/opencontainers/runc/pull/774），
在安装过程中不需要`setuid`或任何其他特权
runC（使用非特权用户名称空间而不是`setuid`），
创建和管理容器。 但是，标准模式
使用runC类似于[systemd nspawn]（https://www.freedesktop.org/software/systemd/man/systemd-nspawn.html）
因为它是旨在由root调用的工具。

Bubblewrap作者认为runc和systemd-nspawn不是
设计为setuid，并且远离支持这种模式。
但是，对于无根容器，runC将能够满足某些用例
bubblewrap支持（具有标准化和额外的好处
完整的OCI运行时）。

[binctr]（https://github.com/jfrazelle/binctr）只是一个包装
runC，因此继承了其所有设计权衡。

What's with the name?!
----------------------

The name bubblewrap was chosen to convey that this
tool runs as the parent of the application (so wraps it in some sense) and creates
a protective layer (the sandbox) around it.

![](bubblewrap.jpg)

(Bubblewrap cat by [dancing_stupidity](https://www.flickr.com/photos/27549668@N03/))
