# libssh2.net
This is a .NET wrapper for [https://www.libssh2.org/](libssh2) 1.8.0.

In Windows, it assumes the following directory structure:
```
Directory/
|
+-- libssh2.net.dll
+-- libssh/
    |
    +-- x86/
    |   |
    |   +-- libssh2.dll
    |   +-- zlib1.dll
    |   +-- vcruntime140.dll
    +-- x64/
        +-- libssh2.dll
        +-- zlib1.dll
        +-- vcruntime140.dll
```

It also assumes that libssh2 was built against WinCNG, and no other crypto backend.

In Linux, it is assumed that the link loader will find the file `libssh2.so.1` in the regular library search paths.

# Alternatives
There are not many alternatives in .NET. One that I know of, and have worked with is https://github.com/sshnet/SSH.NET, and it is fine for projects where
the number of concurrent connections are low (< 20). Because it's very heavy on thread usages, it does not scale well. That's the primary reason why I
wrote this wrapper.

libssh2 does not require any threads. It can easily be used by multiplexed I/O (select/poll/WSAAsyncSelect/etc.).

In a project I was involved with, we were communicating with just over 100 devices. Each device exposed a shell over SSH, to which the control software connected to.
The entire operation took just over 5 minutes, and approximately 10% of all devices timed out. With libssh2 under the hood, the same operation took approximately 30 seconds.
