Using Wi-Fi
===========

lwIP-CE can reach a Wi-Fi network through the **lwIP-CE Wi-Fi bridge**, an
ESP32-S3 or ESP32-P4 board running the firmware in ``wifi_bridge/``. The calculator plugs
into the bridge with its stock USB cable and gets an ordinary Ethernet
interface. Everything that works over a USB Ethernet adapter (DHCP, TCP, UDP,
TLS, DNS) works the same way over the bridge.

On top of the link, the bridge exposes a control channel. Programs use it
through ``<lwip/wireless/wifi.h>`` to read the connection state, scan, and
manage saved networks. The lwIP-CE app uses the same API for its Wi-Fi screen.

.. code-block:: text

    ┌────────────┐   USB    ┌──────────────────┐   802.11   ┌──────────┐
    │ Calculator │─────────▶│ lwIP-CE Wi-Fi    │ ·  ·  ·  · │ Wi-Fi    │
    │ (device)   │  stock   │ bridge (host)    │            │ network  │
    └────────────┘  cable   └──────────────────┘            └──────────┘

Hardware
--------

One of these boards:

- **The lwIP-CE bridge board** (firmware target ``esp32s3``, the default). The design is in
  ``wifi_bridge/hardware``: KiCad project, BOM and placement files in ``fab/``,
  and a printable enclosure. It is built around an ESP32-S3-WROOM-1-N16R8. The
  USB-C port powers the board and carries the console through a CH340K, which
  also handles reset and boot for flashing. The S3's own USB drives the USB-A
  port for the calculator. The red LED is lit while the bridge is on Wi-Fi.
- **A Waveshare ESP32-P4 Module Dev Kit** (target ``esp32p4``), which reaches its
  ESP32-C6 Wi-Fi co-processor over SDIO. It works as is.

You also need:

- The cable that came with the calculator, plugged into the board's USB-A port.
  No OTG adapter is needed: the calculator is the USB device and the bridge is
  the USB host.
- A 5 V supply for the board. The bridge powers the calculator's USB port, so
  the calculator charges while it is connected.

Setting Up
----------

Flash the bridge once, then install lwIP-CE on the calculator as usual (see
:doc:`getting-started`). The firmware builds for the bridge board by default.
For the ESP32-P4 kit, switch the target once (this resets
``wifi_bridge/sdkconfig``; ``set-target esp32s3`` switches back):

.. code-block:: text

    idf.py -C wifi_bridge set-target esp32p4

The bridge board's console shows up as ``/dev/ttyUSB0`` (CH340K); the ESP32-P4
kit's as ``/dev/ttyACM0``.

.. code-block:: text

    make dylib                                           # lwIP-CE release in build/
    wifi_tools/push.sh --bridge /dev/ttyUSB0             # flash the bridge, then push
                                                         # lwIP and the examples
    wifi_tools/push.sh                                   # calculator only
    wifi_tools/push.sh --bridge /dev/ttyUSB0 --bridge-only
    idf.py -C wifi_bridge monitor                        # bridge log

``wifi_tools/push.sh`` needs libticalcs2 (it builds a small ``calclink``
helper) and, for ``--bridge``, ESP-IDF v6.1. Release builds of the firmware
are produced by the ``wifi_bridge.yml`` workflow for both targets as
``lwip_wifi_bridge-<target>-<version>-merged.bin``, which flashes at offset
``0x0``:

.. code-block:: text

    esptool.py --chip esp32s3 write_flash 0x0 lwip_wifi_bridge-esp32s3-<version>-merged.bin

The bridge starts with no saved networks. Open the lwIP-CE app on the
calculator, choose **Wi-Fi**, then **Scan for networks** or **Add a network**.
The bridge stores up to 8 networks and joins the best saved one in range on its
own. When a working connection drops it looks for a network right away; after a
failed join it retries every 15 seconds. A network typed in by name is marked
hidden, so the bridge also tries it when it does not show up in a scan.

How the Link Behaves
--------------------

- The calculator's interface comes up when the bridge attaches over USB, but
  its *link* is only up while the bridge is connected to Wi-Fi. When Wi-Fi drops,
  the link goes down and DHCP runs again once Wi-Fi is back, exactly like
  unplugging an Ethernet cable.
- The calculator is directly on the Wi-Fi network: it gets its address from the
  network's DHCP server and is reachable by other devices on that network. There
  is no NAT on the bridge, so a server running on the calculator can be reached
  at the calculator's address.
- The calculator uses the bridge's Wi-Fi MAC address, because a Wi-Fi station
  may only send frames from its own address. As a result, the calculator usually
  gets the same address every time from the same network.

Crypto Offload
--------------

The bridge can also take over the slow parts of TLS. Two settings in the
lwIP-CE app's **Security** section control it, and both are on by default:

**Crypto offload**
    The bridge computes the X25519 key exchange and checks the RSA signatures
    on the server's certificate chain and CertificateVerify, using its hardware
    accelerators. The calculator still runs the rest of TLS (key schedule,
    record encryption, certificate parsing and policy) itself.

**Bridge TRNG**
    The bridge's hardware random number generator becomes the entropy source.
    As soon as the bridge answers, its output replaces the calculator's random
    generator state outright, and each new TLS handshake reseeds it with fresh
    bridge output. The calculator stops collecting its own entropy in the
    background meanwhile. Until the bridge answers (and whenever it is
    unplugged) the calculator's own source is used.

Offloading never changes a verdict. Signature checks run in parallel with the
rest of the handshake, and the handshake waits for all of them before it sends
its Finished message or hands any data to the program. If the bridge does not
answer within two seconds, or cannot decide (for example, an unusual key), the
calculator runs that operation itself. With an older bridge firmware, or with
another USB Ethernet adapter, nothing is offloaded.

The key exchange's ephemeral private key and the random bytes cross the USB
cable to and from the bridge, so the bridge is part of the trusted hardware.

Programs can use the same operations directly: ``lwip_wifi_x25519()``,
``lwip_wifi_rsa_verify()`` and ``lwip_wifi_random()`` wait for the bridge's
answer, and ``lwip_wifi_crypto_caps()`` reports which ones are available. Call
them from the main loop, not from a socket callback.

Wi-Fi Control API
-----------------

Include the header:

.. code-block:: c

    #include <lwip/wireless/wifi.h>

The calls work while ``lwip_network_up()`` is active. Each one sends a
request to the bridge, keeps servicing USB and lwIP timers while it waits, and
returns once the bridge answers or the call times out. They can be called from
your main loop like any other blocking helper; do not call them from inside an
lwIP or USB callback.

Requests never reach the wireless network and work while Wi-Fi is down, so
they are also how a program gets the calculator online in the first place.
Saved passwords stay on the bridge: no call can read one back. Do not call
them from the event callback either: a call made while another one is waiting
returns ``LWIP_WIFI_ERR_BUSY``.

.. list-table::
   :header-rows: 1
   :widths: 38 62

   * - Function
     - Purpose
   * - ``lwip_wifi_available()``
     - ``true`` once a bridge is attached over USB. Returns immediately.
   * - ``lwip_wifi_get_state(&state)``
     - Connection state: connected or not, SSID, RSSI, channel, BSSID, the
       slot of the joined network and how many networks are saved.
   * - ``lwip_wifi_list_profiles(profiles, max, &count)``
     - Saved networks in preference order: slot, SSID, security, flags.
   * - ``lwip_wifi_scan(networks, max, &count)``
     - Networks in range: SSID, RSSI, channel, security. Takes a few seconds.
   * - ``lwip_wifi_save_profile(slot, ssid, password, security, flags, &saved)``
     - Adds a network (``slot = LWIP_WIFI_SLOT_NONE``) or edits the one in
       ``slot``. When editing, ``NULL`` or ``""`` keeps the stored password.
       Saving a name that is already stored updates that entry.
   * - ``lwip_wifi_forget_profile(slot)``
     - Deletes a saved network.
   * - ``lwip_wifi_enable_profile(slot, enabled)``
     - A disabled network is skipped when the bridge picks one to join.
   * - ``lwip_wifi_prefer_profile(slot)``
     - Moves a saved network to the top of the preference order.
   * - ``lwip_wifi_connect(slot)``
     - Joins a saved network now. ``LWIP_WIFI_SLOT_NONE`` resumes automatic
       joining after a disconnect.
   * - ``lwip_wifi_disconnect()``
     - Leaves the current network and stops automatic joining until the next
       ``lwip_wifi_connect()``.
   * - ``lwip_wifi_set_event_cb(fn, arg)``
     - Registers a callback that receives the new state whenever the bridge
       joins or leaves a network. Pass ``NULL`` to remove it.

``lwip_wifi_connect()`` returns once the bridge has started joining. Joining
takes a few seconds; wait for the event callback (or poll
``lwip_wifi_get_state()``) to learn whether it worked. A wrong password shows
up as the bridge never reporting ``connected``.

Return codes:

.. list-table::
   :header-rows: 1
   :widths: 38 62

   * - Code
     - Meaning
   * - ``LWIP_WIFI_OK``
     - The bridge carried out the request.
   * - ``LWIP_WIFI_ERR_NO_BRIDGE``
     - No bridge is attached (for example, a USB Ethernet adapter is in use, or
       nothing is plugged in).
   * - ``LWIP_WIFI_ERR_TIMEOUT``
     - The bridge did not answer in time. Requests that change the connection
       wait up to 6 seconds, a scan up to 10 seconds, others 2 seconds.
   * - ``LWIP_WIFI_ERR_BAD_REQUEST``
     - The request was malformed, for example an empty or over-long SSID.
   * - ``LWIP_WIFI_ERR_NOT_FOUND``
     - The slot does not hold a saved network.
   * - ``LWIP_WIFI_ERR_FULL``
     - All 8 slots are in use.
   * - ``LWIP_WIFI_ERR_MEM``
     - lwIP could not allocate a buffer for the request.
   * - ``LWIP_WIFI_ERR_BUSY``
     - Another request is still waiting, or the bridge cannot scan right now
       (for example while it is joining a network). Try again shortly.

Security values are the ``LWIP_WIFI_SEC_*`` constants: open, WEP, WPA, WPA2,
WPA3 and WPA2/WPA3. Enterprise (802.1X) networks are not supported and are
left out of scan results. Profile flags are
``LWIP_WIFI_PROFILE_ENABLED``, ``LWIP_WIFI_PROFILE_HIDDEN`` (tried even when a
scan does not see it) and ``LWIP_WIFI_PROFILE_ACTIVE`` (the network the bridge
is joined to). A profile saved without ``LWIP_WIFI_PROFILE_ENABLED`` is stored
disabled.

Example
~~~~~~~

Join a network if the bridge is offline, then wait for it to connect:

.. code-block:: c

    #include <lwip.h>
    #include <lwip/wireless/wifi.h>

    static volatile bool online;

    static void on_wifi(const lwip_wifi_state_t *state, void *arg)
    {
        (void)arg;
        online = state->connected;
    }

    static bool go_online(const char *ssid, const char *password)
    {
        lwip_wifi_state_t state;
        uint8_t slot;
        uint32_t start;

        while (!lwip_wifi_available())
            lwip_service_events();

        lwip_wifi_set_event_cb(on_wifi, NULL);
        if (lwip_wifi_get_state(&state) == LWIP_WIFI_OK && state.connected)
            return true;

        if (lwip_wifi_save_profile(LWIP_WIFI_SLOT_NONE, ssid, password, LWIP_WIFI_SEC_WPA2,
                                   LWIP_WIFI_PROFILE_ENABLED, &slot) != LWIP_WIFI_OK)
            return false;
        if (lwip_wifi_connect(slot) != LWIP_WIFI_OK)
            return false;

        start = lwip_now_ms();
        while (!online && lwip_now_ms() - start < 15000)
            lwip_service_events();
        return online;
    }

Once the bridge is connected, the interface behaves like any other: wait for a
DHCP lease and use sockets as described in :doc:`using-the-network`.

``examples/wifi_ping`` (``LWPING``) waits for a lease, pings the gateway and
then stays reachable for 60 seconds. ``examples/wifi_api`` (``LWWIFI``) calls
every function above and writes the results to the ``WIFILOG`` AppVar.

The Wi-Fi Screen
----------------

Running the lwIP-CE app directly opens its settings; **Wi-Fi** shows the
bridge's state at the top and the saved networks below, followed by **Scan for
networks**, **Add a network** and **Join automatically** / **Disconnect**. Opening
a saved network offers connect, change password, rename, change security,
skip or use when joining, move to top, and forget. The screen updates on its
own when the bridge joins or leaves a network.

Text entry cycles through four key sets with **alpha**: lower case, upper case,
digits, and symbols. In password fields, **mode** shows or hides the text.
