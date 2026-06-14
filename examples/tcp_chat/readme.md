### lwIP TCP Chat Example

Connects to `SERVER_IP:4242` with `LWIP_PROTO_TCP` and opens a small-font chat console. Set the server IP at build time:

```sh
make -C examples/tcp_chat SERVER_IP=192.168.2.1
```

Use `Alpha` to toggle letter entry, `Enter` to send, `Del` to erase, and `Clear` on an empty line to exit.
