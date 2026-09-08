# IRC Chat Example

Connects to EFnet IRC and joins `#cemetech` using plain TCP.

Build:

```sh
make -C examples/irc_chat
```

Defaults:

- Server: `irc.efnet.org`
- Port: `6667`
- Channel: `#cemetech`
- Nick prefix: `LWIPCE`

Override at build time:

```sh
make -C examples/irc_chat IRC_HOST=irc.efnet.org IRC_CHANNEL='\\#cemetech' IRC_NICK=MYNICK
```

Controls:

- Type a line and press `Enter` to send it to the channel.
- Type `/raw ...` to send a raw IRC command.
- Press `Alpha` to cycle lower/upper/number input.
- Press `Clear` to quit.
- Press `Stat` to toggle lwIP memory stats.
