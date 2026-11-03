/*
 * Semantic chart colours. One place for every threshold on the site.
 *
 * A row is scored on how good the outcome is for that metric, not on how big
 * the number is. Every site chart is now higher-is-better; data-better="lower"
 * stays supported for any metric where a smaller number wins.
 *
 *   <div data-verdict="percent" data-better="higher" data-value="96.4"> ... </div>
 *   <div data-verdict="percent" data-better="lower"  data-value="10"> ... </div>
 *   <div data-verdict="latency" data-ms="17300"> ... </div>   (a range uses its slower end)
 *   <p data-verdict-legend="percent"></p>                      (renders the thresholds)
 */
(function () {
  "use strict";

  var THRESHOLDS = {
    // score = rate when higher is better, 100 - rate when lower is better
    percent: { good: 85, bad: 35 },
    // gate latency in milliseconds, lower is better
    latency: { good: 1000, bad: 10000 },
  };

  function verdictFor(kind, el) {
    if (kind === "percent") {
      var v = parseFloat(el.getAttribute("data-value"));
      var score = el.getAttribute("data-better") === "lower" ? 100 - v : v;
      if (score >= THRESHOLDS.percent.good) return "good";
      if (score < THRESHOLDS.percent.bad) return "bad";
      return "mid";
    }
    if (kind === "latency") {
      var ms = parseFloat(el.getAttribute("data-ms"));
      if (ms < THRESHOLDS.latency.good) return "good";
      if (ms > THRESHOLDS.latency.bad) return "bad";
      return "mid";
    }
    return null;
  }

  var ICONS = {
    good: '<svg viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="8" r="7.5" fill="currentColor"/><path d="M4.6 8.3l2.2 2.2 4.6-4.8" fill="none" stroke="#fff" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    mid: '<svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 1.2L15.2 14.4H.8z" fill="currentColor" stroke="currentColor" stroke-width="1" stroke-linejoin="round"/><path d="M8 6v4" stroke="#fff" stroke-width="1.8" stroke-linecap="round"/><circle cx="8" cy="12.2" r="1" fill="#fff"/></svg>',
    bad: '<svg viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="8" r="7.5" fill="currentColor"/><path d="M8 4v5" stroke="#fff" stroke-width="1.9" stroke-linecap="round"/><circle cx="8" cy="11.6" r="1.1" fill="#fff"/></svg>',
  };
  var WORDS = { good: "good", mid: "middling", bad: "bad" };

  function icon(v) {
    return '<span class="v-icon" role="img" aria-label="' + WORDS[v] + '">' + ICONS[v] + "</span>";
  }

  function legendText(kind) {
    var t = THRESHOLDS[kind];
    var keys;
    if (kind === "percent") {
      keys =
        '<span class="v-good">' + icon("good") + " \u2265 " + t.good + "</span>" +
        '<span class="v-mid">' + icon("mid") + " " + t.bad + "\u2013" + (t.good - 1) + "</span>" +
        '<span class="v-bad">' + icon("bad") + " &lt; " + t.bad + "</span>";
    } else {
      keys =
        '<span class="v-good">' + icon("good") + " &lt; " + t.good / 1000 + " s</span>" +
        '<span class="v-mid">' + icon("mid") + " " + t.good / 1000 + "\u2013" + t.bad / 1000 + " s</span>" +
        '<span class="v-bad">' + icon("bad") + " &gt; " + t.bad / 1000 + " s</span>";
    }
    return '<span class="pg-legend-keys">' + keys + "</span>";
  }

  function apply() {
    document.querySelectorAll("[data-verdict]").forEach(function (row) {
      var v = verdictFor(row.getAttribute("data-verdict"), row);
      if (!v) return;
      row.classList.add("v-" + v);
      var num = row.querySelector("[data-verdict-num], .pg-bar-value");
      if (num && !num.querySelector(".v-icon")) num.insertAdjacentHTML("afterbegin", icon(v));
    });
    document.querySelectorAll("[data-verdict-legend]").forEach(function (el) {
      el.innerHTML = legendText(el.getAttribute("data-verdict-legend"));
    });
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", apply);
  else apply();
})();
