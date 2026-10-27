Flashing the Bridge
===================

This page flashes a release of the Wi-Fi bridge firmware from the browser. It
needs Web Serial, which Chrome, Edge and Opera have on desktop.

Plug the bridge board into this computer through its USB-C port. Choose a
release and the board, then press **Flash** and pick the board's serial port.
Flashing replaces everything on the board, saved networks included.

.. raw:: html

   <link rel="stylesheet" href="_static/flasher.css">
   <div id="flasher" class="tool">
     <div class="tool-fields">
       <label>Release<select id="fw-release"></select></label>
       <label>Board<select id="fw-board"></select></label>
       <label>Baud rate<select id="fw-baud">
         <option>115200</option>
         <option>460800</option>
         <option selected>921600</option>
       </select></label>
     </div>
     <div class="tool-row">
       <button id="fw-flash" class="btn" disabled>Flash</button>
       <progress id="fw-progress" max="1" value="0" hidden></progress>
     </div>
     <p id="fw-status" class="tool-status"></p>
     <details id="fw-details">
       <summary>Log</summary>
       <pre id="fw-log"></pre>
     </details>
   </div>
   <script type="module" src="_static/flasher.js"></script>

If flashing fails at 921600 baud, try a lower rate. To flash from the command
line instead, see :doc:`using-wifi`.

Setting Up Wi-Fi
----------------

The bridge can also be given its networks from here, so they do not have to be
typed on the calculator. This needs bridge firmware 3.0.0 or newer. Plug the
bridge in and press **Connect**; right after flashing, the page connects on its
own. A network saved here is joined right away, and the page reports whether
the bridge got on.

.. raw:: html

   <div id="wifi" class="tool">
     <div class="tool-row">
       <p id="wifi-status" class="tool-status">Not connected to the bridge.</p>
       <button id="wifi-connect" class="btn btn-neutral" disabled>Connect</button>
     </div>
     <fieldset id="wifi-panel" disabled>
       <h4>Saved networks</h4>
       <table class="tool-table"><tbody id="wifi-saved"></tbody></table>
       <h4>Add a network</h4>
       <form id="wifi-form">
         <div class="tool-fields">
           <label>Networks in range<span class="tool-row">
             <select id="wifi-nearby"><option value="">Scan to list networks</option></select>
             <button type="button" id="wifi-scan" class="btn btn-neutral">Scan</button>
           </span></label>
           <label>Network name<input id="wifi-ssid" required autocomplete="off"></label>
           <label>Security<select id="wifi-security">
             <option value="0">Open</option>
             <option value="1">WEP</option>
             <option value="2">WPA</option>
             <option value="3" selected>WPA2</option>
             <option value="4">WPA3</option>
             <option value="5">WPA2/WPA3</option>
             <option value="6">Enterprise</option>
           </select></label>
           <label id="wifi-username-row" hidden>Username<input id="wifi-username" autocomplete="off"></label>
           <label id="wifi-password-row">Password<input id="wifi-password" type="password" autocomplete="off"></label>
         </div>
         <div class="tool-checks">
           <label><input id="wifi-show" type="checkbox"> Show password</label>
           <label><input id="wifi-hidden" type="checkbox"> Hidden network</label>
           <label id="wifi-check-row" hidden><input id="wifi-check" type="checkbox" checked> Check the server certificate</label>
         </div>
         <div class="tool-row">
           <button id="wifi-save" class="btn">Save and join</button>
         </div>
         <p id="wifi-result" class="tool-status"></p>
       </form>
     </fieldset>
   </div>
