wireless.h and lwip/wireless/
=============================

``wireless.h`` is the root-level umbrella for ``lwip/wireless/wifi.h``, the
control API for the lwIP-CE Wi-Fi bridge. It reads the bridge's connection
state, scans, manages saved networks and reports when the bridge joins or
leaves a network. Calls block while they service USB and lwIP timers, and
saved passwords never leave the bridge. See :doc:`../using-wifi` for setup,
the function reference and an example.

.. list-table::
   :header-rows: 1
   :widths: 28 72

   * - Header
     - Purpose
   * - :doc:`wifi.h <wireless/wifi>`
     - ``lwip_wifi_*`` functions, state/profile/network types, error codes.

.. toctree::
   :hidden:

   wireless/wifi
