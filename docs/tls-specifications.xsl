<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="html" encoding="UTF-8" indent="yes"
              doctype-system="about:legacy-compat"/>

  <xsl:key name="by-ref" match="requirement" use="ref"/>
  <xsl:key name="by-grade" match="requirement" use="grade"/>

  <xsl:template match="/tls-specifications">
    <html lang="en">
      <head>
        <meta charset="utf-8"/>
        <meta name="viewport" content="width=device-width, initial-scale=1"/>
        <title>lwIP-CE TLS Specification Compliance</title>
        <style>
          :root {
            --bg: #ffffff; --fg: #1f2328; --muted: #59636e; --line: #d1d9e0;
            --panel: #f6f8fa; --link: #0969da;
            --ok-bg: #dafbe1; --ok-fg: #116329;
            --dev-bg: #ffebe9; --dev-fg: #82071e;
            --ev-bg: #fff8c5; --ev-fg: #7d4e00;
            --part-bg: #ddf4ff; --part-fg: #0550ae;
            --na-bg: #eaeef2; --na-fg: #424a53;
          }
          @media (prefers-color-scheme: dark) {
            :root {
              --bg: #0d1117; --fg: #e6edf3; --muted: #9198a1; --line: #30363d;
              --panel: #151b23; --link: #4493f8;
              --ok-bg: #12261e; --ok-fg: #56d364;
              --dev-bg: #2d1216; --dev-fg: #ff7b72;
              --ev-bg: #2b2108; --ev-fg: #e3b341;
              --part-bg: #0c2d6b; --part-fg: #79c0ff;
              --na-bg: #21262d; --na-fg: #9198a1;
            }
          }
          * { box-sizing: border-box; }
          body {
            margin: 0; background: var(--bg); color: var(--fg);
            font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
          }
          main { max-width: 1100px; margin: 0 auto; padding: 24px 16px 64px; }
          h1 { font-size: 1.6rem; margin: 0 0 4px; }
          h2 { font-size: 1.15rem; margin: 32px 0 8px; padding-top: 8px;
               border-top: 1px solid var(--line); }
          p.lead { color: var(--muted); margin: 0 0 16px; }
          .summary { display: flex; flex-wrap: wrap; gap: 8px; margin: 16px 0; }
          .badge {
            display: inline-block; padding: 1px 8px; border-radius: 999px;
            font-size: 12px; font-weight: 600; white-space: nowrap;
          }
          .COMPLIANT { background: var(--ok-bg); color: var(--ok-fg); }
          .DEVIANT { background: var(--dev-bg); color: var(--dev-fg); }
          .NEEDS-EVIDENCE { background: var(--ev-bg); color: var(--ev-fg); }
          .PARTIAL { background: var(--part-bg); color: var(--part-fg); }
          .NOT-APPLICABLE { background: var(--na-bg); color: var(--na-fg); }
          .stat { padding: 8px 14px; border-radius: 8px; background: var(--panel);
                  border: 1px solid var(--line); }
          .stat b { font-size: 1.3rem; display: block; line-height: 1.2; }
          .stat span { color: var(--muted); font-size: 12px; }
          .filters {
            display: flex; align-items: end; flex-wrap: wrap; gap: 8px 16px;
            margin: 18px 0; padding: 12px 14px; border: 1px solid var(--line);
            border-radius: 8px; background: var(--panel);
          }
          .filter-field { display: grid; gap: 4px; }
          .filter-field label { color: var(--muted); font-size: 12px; font-weight: 600; }
          .filter-field select {
            min-width: 190px; padding: 7px 30px 7px 9px; border: 1px solid var(--line);
            border-radius: 6px; background: var(--bg); color: var(--fg); font: inherit;
          }
          .filter-status { color: var(--muted); padding-bottom: 7px; }
          .policy {
            margin: 12px 0 18px; padding: 10px 14px; border-left: 4px solid var(--dev-fg);
            border-radius: 4px; background: var(--panel);
          }
          td.justification { color: var(--muted); }
          .missing-justification { color: var(--dev-fg); font-style: italic; }
          nav.toc { display: flex; flex-wrap: wrap; gap: 6px 14px; font-size: 13px; }
          nav.toc a, .back a { color: var(--link); text-decoration: none; }
          nav.toc a:hover { text-decoration: underline; }
          table { width: 100%; border-collapse: collapse; table-layout: fixed; }
          th, td { text-align: left; vertical-align: top; padding: 8px 10px;
                   border-bottom: 1px solid var(--line); overflow-wrap: anywhere; }
          th { color: var(--muted); font-size: 12px; text-transform: uppercase;
               letter-spacing: .04em; }
          td.sec { width: 70px; white-space: nowrap; }
          td.grade { width: 130px; }
          td.loc { font: 12.5px/1.45 ui-monospace, SFMono-Regular, Menlo, monospace; width: 32%; }
          td.note { color: var(--fg); }
          [hidden] { display: none !important; }
          @media (max-width: 720px) {
            table, thead, tbody, tr, td { display: block; }
            thead { display: none; }
            tr { border-bottom: 1px solid var(--line); padding: 8px 0; }
            td { border: 0; padding: 2px 0; width: auto !important; }
          }
        </style>
      </head>
      <body>
        <main>
          <h1>lwIP-CE TLS Specification Compliance</h1>
          <p class="lead">
            Clause-by-clause ledger mapping the standards this TLS implementation
            targets (RFC, NIST SP, FIPS) to the code that satisfies or deviates
            from them. <xsl:value-of select="count(requirement)"/> entries.
          </p>

          <div class="summary">
            <xsl:for-each select="requirement[generate-id() = generate-id(key('by-grade', grade)[1])]">
              <xsl:sort select="grade"/>
              <div class="stat">
                <b><xsl:value-of select="count(key('by-grade', grade))"/></b>
                <span class="badge {grade}"><xsl:value-of select="grade"/></span>
              </div>
            </xsl:for-each>
          </div>

          <div class="filters">
            <div class="filter-field">
              <label for="grade-filter">Filter by grade</label>
              <select id="grade-filter">
                <option value="ALL">All grades</option>
                <xsl:for-each select="requirement[generate-id() = generate-id(key('by-grade', grade)[1])]">
                  <xsl:sort select="grade"/>
                  <option value="{grade}"><xsl:value-of select="grade"/></option>
                </xsl:for-each>
              </select>
            </div>
            <div id="filter-status" class="filter-status" aria-live="polite">
              Showing all <xsl:value-of select="count(requirement)"/> entries
            </div>
          </div>

          <p class="policy">
            <strong>Deviation policy:</strong>
            Every <span class="badge DEVIANT">DEVIANT</span> result is expected
            to be fixed. If a deviation is intentionally retained because of
            platform constraints, its audit entry must include a specific
            <code>&lt;justification&gt;...&lt;/justification&gt;</code> explaining why.
            The grade is the current status; a compliant entry's note may retain
            the original audit finding for traceability.
          </p>

          <nav class="toc">
            <xsl:for-each select="requirement[generate-id() = generate-id(key('by-ref', ref)[1])]">
              <xsl:sort select="ref"/>
              <a href="#{translate(ref, ' ', '-')}" data-audit-link="true">
                <xsl:value-of select="ref"/>
                (<xsl:value-of select="count(key('by-ref', ref))"/>)
              </a>
            </xsl:for-each>
          </nav>

          <xsl:for-each select="requirement[generate-id() = generate-id(key('by-ref', ref)[1])]">
            <xsl:sort select="ref"/>
            <section class="audit-group">
              <h2 id="{translate(ref, ' ', '-')}"><xsl:value-of select="ref"/></h2>
              <table>
                <thead>
                  <tr><th>Section</th><th>Location</th><th>Grade</th><th>Note</th><th>Justification</th></tr>
                </thead>
                <tbody>
                  <xsl:for-each select="key('by-ref', ref)">
                    <tr data-grade="{grade}">
                      <td class="sec"><xsl:value-of select="section"/></td>
                      <td class="loc"><xsl:value-of select="location"/></td>
                      <td class="grade">
                        <span class="badge {grade}"><xsl:value-of select="grade"/></span>
                      </td>
                      <td class="note"><xsl:value-of select="note"/></td>
                      <td class="justification">
                        <xsl:choose>
                          <xsl:when test="normalize-space(justification)">
                            <xsl:value-of select="justification"/>
                          </xsl:when>
                          <xsl:when test="grade = 'DEVIANT'">
                            <span class="missing-justification">Not yet documented.</span>
                          </xsl:when>
                        </xsl:choose>
                      </td>
                    </tr>
                  </xsl:for-each>
                </tbody>
              </table>
            </section>
          </xsl:for-each>
        </main>
        <script>
          (function () {
            var filter = document.getElementById("grade-filter");
            var status = document.getElementById("filter-status");
            var groups = document.querySelectorAll(".audit-group");
            var tocLinks = document.querySelectorAll("[data-audit-link]");
            var total = document.querySelectorAll("tr[data-grade]").length;

            function applyGradeFilter() {
              var selected = filter.value;
              var visibleTotal = 0;
              var i;
              for (i = 0; i &lt; groups.length; i++) {
                var rows = groups[i].querySelectorAll("tr[data-grade]");
                var visibleInGroup = 0;
                var j;
                for (j = 0; j &lt; rows.length; j++) {
                  var show = selected === "ALL" ||
                             rows[j].getAttribute("data-grade") === selected;
                  rows[j].hidden = !show;
                  if (show) {
                    visibleInGroup++;
                    visibleTotal++;
                  }
                }
                groups[i].hidden = visibleInGroup === 0;
                if (tocLinks[i]) tocLinks[i].hidden = visibleInGroup === 0;
              }
              status.textContent = selected === "ALL"
                ? "Showing all " + total + " entries"
                : "Showing " + visibleTotal + " of " + total + " entries";
            }

            filter.addEventListener("change", applyGradeFilter);
            applyGradeFilter();
          }());
        </script>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>
