##### tcp_nodelay /tcp_nopush 刨根问底

> 缘起：一份nginx中的常用配置

```
sendfile on; // default on
tcp_nopush on; // default off
tcp_nodelay on; // default off
```

> 这里，TCP_NODELAY 和 TCP_CORK 都是socket的套接字选项，通过setsocketopt 设置的，所以看源码时候可以直接去grep 这个函数。sendfile是系统调用，可以实现[零拷贝的数据传输](https://blog.csdn.net/caianye/article/details/7576198)。之前对这些都有所了解，但是这俩参数混合到一起就郁闷了，感觉这明明是互斥的。

##### 一，这里先补充下相关知识点

> - TCP_NODELAY  ，开启Nagle's Algorithm，当链路上有至少一个未被确认的包时，小包是被积攒延迟发送的。超时一般200ms。
> - TCP_CORK，一般配合sendfile使用，数据包header头和包体攒到一起发送。超时一般也是200ms。
> - 延迟确认超时一般40ms。
> - readv/writev/mmap

```
// Nagle's Algorithm 
if there is new data to send
  if the window size >= MSS and available data is >= MSS
    send complete MSS segment now
  else
    if there is unconfirmed data still in the pipe
      enqueue data in the buffer until an acknowledge is received
    else
      send data immediately
    end if
  end if
end if
```



##### 二，翻阅nginx[说明文档](http://nginx.org/en/docs/http/ngx_http_core_module.html)

- tcp_nodelay

```
Enables or disables the use of the TCP_NODELAY option. The option is enabled when a connection is transitioned into the keep-alive state. Additionally, it is enabled on SSL connections, for unbuffered proxying, and for WebSocket proxying.
```

- tcp_nopush

```
Enables or disables the use of the TCP_NOPUSH socket option on FreeBSD or the TCP_CORK socket option on Linux. The options are enabled only when sendfile is used. Enabling the option allows:
1,sending the response header and the beginning of a file in one packet, on Linux and FreeBSD 4.*;
2,sending a file in full packets.
```

- sendfile

```
Enables or disables the use of sendfile().
```

> - tcp_nopush这个叫法是考虑到平台移植性，freebasd中使用tcp_nopush，linux下使用tcp_cork。
> - nginx下tcp_nodelay只会在场链接时候才会启用，短链接一般 write->read模式，该参数不会对系统吞吐产生负面影响。

##### 三，查看man手册

- man tcp

```
TCP_CORK (since Linux 2.2)
              If set, don't send out partial frames.  All queued partial frames are sent when the option is cleared again.  This is useful for  prepending
              headers  before  calling  sendfile(2),  or for throughput optimization.  As currently implemented, there is a 200 millisecond ceiling on the
              time for which output is corked by TCP_CORK.  If this ceiling is reached, then queued data is automatically transmitted.  This option can be
              combined with TCP_NODELAY only since Linux 2.5.71.  This option should not be used in code intended to be portable.

```

```
TCP_NODELAY
              If  set, disable the Nagle algorithm.  This means that segments are always sent as soon as possible, even if there is only a small amount of
              data.  When not set, data is buffered until there is a sufficient amount to send out, thereby avoiding the frequent sending of  small  pack‐
              ets,  which  results  in  poor  utilization  of  the network.  This option is overridden by TCP_CORK; however, setting this option forces an
              explicit flush of pending output, even if TCP_CORK is currently set.

```

- man sendfile

```
DESCRIPTION
       sendfile()  copies data between one file descriptor and another.  Because this copying is done within the kernel, sendfile() is more efficient than
       the combination of read(2) and write(2), which would require transferring data to and from user space.

       in_fd should be a file descriptor opened for reading and out_fd should be a descriptor opened for writing.

       If offset is not NULL, then it points to a variable holding the file offset from which sendfile() will start reading data from in_fd.   When  send‐
       file()  returns, this variable will be set to the offset of the byte following the last byte that was read.  If offset is not NULL, then sendfile()
       does not modify the current file offset of in_fd; otherwise the current file offset is adjusted to reflect the number of bytes read from in_fd.

       If offset is NULL, then data will be read from in_fd starting at the current file offset, and the file offset will be updated by the call.

       count is the number of bytes to copy between the file descriptors.

       The in_fd argument must correspond to a file which supports mmap(2)-like operations (i.e., it cannot be a socket).

       In Linux kernels before 2.6.33, out_fd must refer to a socket.  Since Linux 2.6.33 it can be any file.  If it is a regular  file,  then  sendfile()
       changes the file offset appropriately.
```

> - TCP_NODELAY和TCP_CORK同时开启的话，只有TCP_NODELAY会生效，所以代码中不能在一个socket中两者同时设置。
> - sendfile 一般只能把文件里面的内容发送到socket中，不能反过来，也不能socket对socket

##### 四，查阅第三方资料

- 站外资料，[点击查看](https://thoughts.t37.net/nginx-optimization-understanding-sendfile-tcp-nodelay-and-tcp-nopush-c55cdd276765)

```
/* Return false, if packet can be sent now without violation Nagle's rules:
 * 1. It is full sized.
 * 2. Or it contains FIN. (already checked by caller)
 * 3. Or TCP_CORK is not set, and TCP_NODELAY is set.
 * 4. Or TCP_CORK is not set, and all sent packets are ACKed.
 *    With Minshall's modification: all sent small packets are ACKed.
 */
static inline bool tcp_nagle_check(const struct tcp_sock *tp,
const struct sk_buff *skb,
unsigned int mss_now, int nonagle)
return skb->len < mss_now &&
((nonagle & TCP_NAGLE_CORK) (!nonagle && tp->packets_out && tcp_minshall_check(tp)));
}
```

```
Things get really interesting when you mix senfile, tcp_nodelay and tcp_nopush together. I was wondering why anyone would mix 2 antithetic and mutually exclusive options. The answer lies deep inside a 2005 thread from the (Russian) Nginx mailing list.
Combined to sendfile, tcp_nopush ensures that the packets are full before being sent to the client. This greatly reduces network overhead and speeds the way files are sent. Then, when it reaches the last — probably halt — packet, Nginx removes tcp_nopush. Then, tcp_nodelay forces the socket to send the data, saving up to 0.2 seconds per file.
```

> - nginx的思路是在做静态文件代理的时候，首先前面发包使用sendfile+tcp_cork，等到最后再使用tcp_nodelay把最后一个小包强制发走。

##### 五，nginx源码阅读

- os/unix/ngx_linux_init.c

```
 16 static ngx_os_io_t ngx_linux_io = {
 17     ngx_unix_recv,
 18     ngx_readv_chain,
 19     ngx_udp_unix_recv,
 20     ngx_unix_send,
 21     ngx_udp_unix_send,
 22     ngx_udp_unix_sendmsg_chain,
 23 #if (NGX_HAVE_SENDFILE)
 24     ngx_linux_sendfile_chain,
 25     NGX_IO_SENDFILE
 26 #else
 27     ngx_writev_chain,
 28     0
 29 #endif
 30 };
```

- os/unix/ngx_linux_sendfile_chain.c

```
131             if (c->tcp_nodelay == NGX_TCP_NODELAY_UNSET) {
132 
133                 if (ngx_tcp_nopush(c->fd) == -1) {
134                     err = ngx_socket_errno;
135 
136                     /*
137                      * there is a tiny chance to be interrupted, however,
138                      * we continue a processing without the TCP_CORK
139                      */
140 
141                     if (err != NGX_EINTR) {
142                         wev->error = 1;
143                         ngx_connection_error(c, err,
144                                              ngx_tcp_nopush_n " failed");
145                         return NGX_CHAIN_ERROR;
146                     }
147 
148                 } else {
149                     c->tcp_nopush = NGX_TCP_NOPUSH_SET;
150 
151                     ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
152                                    "tcp_nopush");
153                 }
154             }
```

- http/ngx_http_request.c

```
3176     c->log->action = "keepalive";
3177 
3178     if (c->tcp_nopush == NGX_TCP_NOPUSH_SET) {
3179         if (ngx_tcp_push(c->fd) == -1) {
3180             ngx_connection_error(c, ngx_socket_errno, ngx_tcp_push_n " failed");
3181             ngx_http_close_connection(c);
3182             return;
3183         }
3184 
3185         c->tcp_nopush = NGX_TCP_NOPUSH_UNSET;
3186         tcp_nodelay = ngx_tcp_nodelay_and_tcp_nopush ? 1 : 0;
3187 
3188     } else {
3189         tcp_nodelay = 1;
3190     }
3191 
3192     if (tcp_nodelay && clcf->tcp_nodelay && ngx_tcp_nodelay(c) != NGX_OK) {
3193         ngx_http_close_connection(c);
3194         return;
3195     }
```

- os/unix/ngx_linux_init.c

```
 16 static ngx_os_io_t ngx_linux_io = {
 17     ngx_unix_recv,
 18     ngx_readv_chain,
 19     ngx_udp_unix_recv,
 20     ngx_unix_send,
 21     ngx_udp_unix_send,
 22     ngx_udp_unix_sendmsg_chain,
 23 #if (NGX_HAVE_SENDFILE)
 24     ngx_linux_sendfile_chain,
 25     NGX_IO_SENDFILE
 26 #else
 27     ngx_writev_chain,
 28     0
 29 #endif
 30 };
```



> - 发送静态文件时候，和header头一起发送的时候 开启了cork，关闭了nagle 
> - 建立场链接时候，关闭了nagle，关闭了cork。
> - Writev gather I/O，使用注意，返回的是已经发送的字节数，需要自己再定位下次发送到哪里，可能在一个iov的中间

