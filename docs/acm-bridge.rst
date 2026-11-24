Using the ACM Bridge (macOS and Linux)
======================================

The ACM bridge gives the calculator internet access through a macOS or Linux
computer over the calculator's stock USB cable. It needs no adapter and no
extra hardware. It is a single Python script, ``lwip-acm-bridge.py``. In a
release it is in ``tools/``. In the source tree it is in ``tools/bridge/``.

The calculator is the network client, and the computer is its router and NAT
gateway. The calculator can open outbound IPv4 connections (TCP, UDP, DNS,
TLS) as it would on any other network. Nothing on the internet or your LAN can
connect to the calculator, and the bridge itself opens no network listener or
remote command interface.

Quick start
-----------

1. Install Python 3.10 or later. On Linux, also install ``pyusb`` (see
   `Requirements`_).
2. Connect the calculator to the computer with its stock USB cable.
3. Run the bridge as your normal user, **not** with ``sudo``:

   .. code-block:: sh

      python3 tools/lwip-acm-bridge.py

   It asks for your password through ``sudo`` once, for the network setup.
4. On the calculator, start a program that uses the network. The bridge
   connects, gives the calculator an address over DHCP, and starts forwarding.
5. Press **Ctrl+C** to stop. The bridge undoes every change it made to the
   computer.

After a disconnect, the bridge waits for the calculator to come back. Pass
``--once`` to exit instead.

Requirements
------------

- Python 3.10 or later.
- **macOS:** ``sudo`` access, for the network interface and firewall (PF)
  changes.
- **Linux:**

  - ``pyusb``: ``dnf install python3-pyusb``, ``apt install python3-usb``, or
    ``pip install pyusb``.
  - ``iproute2`` and ``nftables``.
  - ``sudo`` access for the temporary setup, unless you do the one-time setup
    in `Linux without root`_.
  - ``getfacl`` and ``setfacl``, if no udev rule already grants your user
    access to the calculator's USB device.

- **Optional:** Python's ``cryptography`` package, only for
  ``--accelerate-crypto``.

Options
-------

.. list-table::
   :header-rows: 1
   :widths: 32 68

   * - Option
     - Effect
   * - ``--odevice IFACE`` (or ``--uplink``)
     - Outbound interface to share. Default: the interface that carries the
       default route.
   * - ``--host-ip IP``
     - The computer's address on the link. Default ``10.84.0.1``.
   * - ``--client-ip IP``
     - The address DHCP gives the calculator. Default ``10.84.0.10``.
   * - ``--dns IP``
     - DNS server advertised by DHCP. Default ``1.1.1.1``.
   * - ``--ntp IP``
     - NTP server advertised by DHCP. Default ``162.159.200.1``.
   * - ``--accelerate-crypto``
     - Answer the calculator's crypto offload requests on the computer: X25519,
       P-256, RSA and ECDSA signature checks, and random bytes. Read
       `Crypto offload and secrets`_ first.
   * - ``--once``
     - Exit when the calculator disconnects instead of waiting for it again.
   * - ``--seconds N``
     - Stop after N seconds.
   * - ``--quiet``
     - Don't print periodic packet counters.
   * - ``--debug``
     - Also log frame directions and byte counts. Packet contents are never
       logged.
   * - ``--log-file PATH``
     - Write the log to PATH instead of the default location.
   * - ``--port PATH``
     - macOS only: the serial port to use. Default: detected automatically.
   * - ``--tap IFACE``
     - Linux only: use an existing TAP interface. See `Linux without root`_.
   * - ``--print-setup``
     - Linux only: print the one-time root setup commands and exit.

Logging
-------

The bridge writes a timestamped log to your user log directory:

- **macOS:** ``~/Library/Logs/lwip-acm-bridge/bridge.log``, also visible in
  Console.app.
- **Linux:** ``$XDG_STATE_HOME/lwip-acm-bridge/bridge.log``, or
  ``~/.local/state/lwip-acm-bridge/bridge.log`` when ``XDG_STATE_HOME`` is
  unset.

The log records changes to the computer's settings, whether they were
restored, errors, and packet counters. It never contains packet contents. The
file is readable only by your user (mode ``0600``) and rotates at 10 MiB,
keeping three old files. To log somewhere else, such as
``/var/log/lwip-acm-bridge.log``, pass ``--log-file``. Your user needs write
access to that location.

How it works
------------

On the stock cable, the calculator is a USB CDC-ACM device (``16c0:05e1``).
lwIP-CE sends Ethernet frames over that serial link, each with a two-byte
big-endian length prefix, so the way the serial link splits data into reads
and writes doesn't matter.

The bridge answers the calculator's DHCP requests itself and hands everything
else to the computer's kernel. The kernel routes it and translates its
addresses (NAT) out of the uplink. IPv6 is not forwarded.

The bridge also lowers the maximum segment size (MSS) in the calculator's TCP
SYNs to 360 bytes, so frames coming back stay under 512 bytes. Larger frames
can be split across USB transfers, and the calculator would lose them.

The bridge runs as your user. It calls ``sudo`` only for the commands that
change host networking, and it refuses to start if you launch it with
``sudo``, so the packet loop never runs as root.

macOS
~~~~~

The bridge opens the calculator's ``/dev/cu.usbmodem*`` serial port and
asserts DTR, which brings the calculator's link up. It creates a
point-to-point ``utun`` interface between ``10.84.0.1`` (the computer) and
``10.84.0.10`` (the calculator). A ``utun`` carries IP packets, not Ethernet
frames, so the bridge answers ARP itself, strips the Ethernet header from
packets going out, and adds one to replies.

Changes to the computer, all undone on exit:

- **IP forwarding:** ``net.inet.ip.forwarding`` is set to ``1`` only if it
  was ``0``, and put back only if the bridge changed it.
- **PF NAT:** a rule such as ``nat on en0 from 10.84.0.10 to any -> (en0)`` is
  loaded into its own anchor under ``com.apple/*``. The bridge refuses to
  replace the main PF ruleset if that anchor point is missing. It enables PF
  with a reference token (``pfctl -E``) and releases only that reference
  (``pfctl -X``), so other programs that use PF are not affected.

Linux
~~~~~

The bridge talks to the calculator directly over libusb. It detaches the
``cdc_acm`` kernel driver while it runs and reattaches it on exit. If no udev
rule grants your user access to the device, the bridge uses ``sudo`` to add a
temporary access rule (ACL) for this USB device and removes it on exit.

Frames go through a TAP interface. TAP carries Ethernet frames, so the kernel
handles ARP itself. The bridge uses ``sudo`` to create a temporary TAP
interface named ``lwipceN``, owned by your user, and to make these changes:

- enables IPv4 forwarding on the TAP interface and the uplink only, not
  through the global ``ip_forward`` switch. The uplink's original setting is
  restored on exit.
- adds its own nftables table with a masquerade (NAT) rule for the
  calculator's address on the uplink.
- if firewalld is running, adds a runtime forwarding rule limited to the
  calculator's address, the TAP interface and the uplink.

All of these are undone on exit. Without firewalld, the bridge warns if any
forward chain has a drop policy, because that chain can still block the
calculator's traffic. Docker installs such a chain.

Linux without root
^^^^^^^^^^^^^^^^^^

To run the bridge with no ``sudo`` at all, do a one-time setup as root.
``--print-setup`` prints the commands. They create a persistent TAP interface
owned by your user, with its address, forwarding and the NAT rule, and add a
udev rule that gives the logged-in user access to the calculator:

.. code-block:: sh

   python3 tools/lwip-acm-bridge.py --print-setup   # review, then run the commands as root
   python3 tools/lwip-acm-bridge.py --tap lwipce0

The network part of this setup lasts until reboot. The udev rule is
permanent. With ``--tap`` pointing at an existing interface, the bridge uses it
as it is and changes nothing on the computer. It warns if the interface's
address doesn't match ``--host-ip`` or if the interface is down. The printed
output includes the commands to undo the setup.

Crypto offload and secrets
--------------------------

.. warning::

   ``--accelerate-crypto`` routes X25519 and P-256 operations through the
   host. Ephemeral private scalars and shared secrets pass through host
   process memory and are not guaranteed to be wiped (Python's immutable
   bytes/int objects and the interpreter's copying prevent this). Core dumps
   are disabled while the flag is active, but swap and a privileged local
   attacker are not mitigated. If your threat model includes a compromised or
   untrusted host, leave this flag off.

These values are never logged, written to disk, or forwarded to the network.
Without the flag, the bridge drops crypto requests and the calculator does all
key operations itself.

What the bridge does to limit exposure:

- zeroes its receive buffer once each frame has been taken out of it.
- on Linux, marks itself non-dumpable, so crash handlers such as
  ``systemd-coredump`` can't capture its memory, and other processes running
  as your user can't attach a debugger or read it.
- relies on ``python3-cryptography`` to clear the key material it holds
  itself. That doesn't cover the copies Python makes before the key reaches
  it.

The Wi-Fi bridge firmware (see :doc:`using-wifi`) offers the same offload
without these host-side limits.

If the bridge was killed
------------------------

Cleanup runs on normal exit, Ctrl+C, and bridge errors. A forced kill
(``SIGKILL``) or power loss skips it. To clean up by hand:

- **macOS:** look in ``sudo pfctl -s Anchors`` for a leftover
  ``com.apple/lwip-ce-bridge-*`` anchor and flush only that anchor. Then set
  ``net.inet.ip.forwarding`` back to its earlier value, which the log
  records.
- **Linux:** look in ``sudo nft list tables`` for a leftover
  ``lwip_ce_bridge_*`` table and delete only that table. Remove the matching
  ``lwipceN`` TAP interface and any matching runtime firewalld direct rule.
  Then set the uplink's forwarding back to its earlier value, which the log
  records.
