(function () {
  var button = document.querySelector(".mb-nav-hamburger-btn");
  var menu = document.getElementById("mobile-menu");
  if (button && menu) {
    button.addEventListener("click", function () {
      var open = menu.hasAttribute("hidden");
      if (open) menu.removeAttribute("hidden");
      else menu.setAttribute("hidden", "");
      button.setAttribute("aria-expanded", open ? "true" : "false");
    });
    menu.querySelectorAll("a").forEach(function (link) {
      link.addEventListener("click", function () {
        menu.setAttribute("hidden", "");
        button.setAttribute("aria-expanded", "false");
      });
    });
  }

  document.querySelectorAll("[data-tabs]").forEach(function (root) {
    var tabs = root.querySelectorAll("[data-tab]");
    function select(id) {
      tabs.forEach(function (tab) {
        tab.setAttribute("aria-selected", tab.getAttribute("data-tab") === id ? "true" : "false");
      });
      root.querySelectorAll("[data-panel]").forEach(function (panel) {
        panel.hidden = panel.getAttribute("data-panel") !== id;
      });
    }
    tabs.forEach(function (tab) {
      tab.addEventListener("click", function () { select(tab.getAttribute("data-tab")); });
    });
  });

  function copyText(value, button) {
    var done = function (ok) {
      var previous = button.getAttribute("data-label") || button.textContent;
      button.textContent = ok ? "Copied" : "Copy failed";
      setTimeout(function () { button.textContent = previous; }, 1400);
    };
    var fallback = function () {
      var area = document.createElement("textarea");
      area.value = value;
      area.setAttribute("readonly", "");
      area.style.position = "fixed";
      area.style.left = "-9999px";
      document.body.appendChild(area);
      area.select();
      var ok = false;
      try { ok = document.execCommand("copy"); } catch (err) { ok = false; }
      area.remove();
      done(ok);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(value).then(function () { done(true); }).catch(fallback);
    } else fallback();
  }

  document.querySelectorAll("[data-copy]").forEach(function (button) {
    button.setAttribute("data-label", button.textContent);
    button.addEventListener("click", function () {
      var node = document.getElementById(button.getAttribute("data-copy"));
      if (node) copyText(node.textContent, button);
    });
  });

  document.querySelectorAll("[data-swatch]").forEach(function (swatch) {
    swatch.addEventListener("click", function () {
      var hex = swatch.getAttribute("data-swatch");
      var label = swatch.querySelector("b");
      var previous = label.textContent;
      var finish = function (ok) {
        swatch.classList.toggle("is-copied", ok);
        label.textContent = ok ? "Copied" : previous;
        setTimeout(function () {
          label.textContent = previous;
          swatch.classList.remove("is-copied");
        }, 1200);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(hex).then(function () { finish(true); }).catch(function () { finish(false); });
      } else finish(false);
    });
  });

  var cases = {
    read: {
      ask: "cursor-agent asks for stripe · charges.read. The reason is a list of failed charges.",
      gate: "Inside the ceiling. The warden marks it low. You still decide.",
      out: '{ "status": "executed", "result": { "failed_charges": 3 } }\n// the key never enters the reply'
    },
    write: {
      ask: "codex asks for stripe · charges.write. The alias ceiling is charges.read.",
      gate: "Policy denies it before any model sees the request.",
      out: '{ "status": "denied" }\n// a write under a read ceiling dies first'
    },
    self: {
      ask: "The agent calls the approve route on 127.0.0.1, hoping to skip you.",
      gate: "That route wants the daemon token. The agent does not have it.",
      out: '{ "status": 401 }\n// there is no approve tool on MCP'
    }
  };
  var sim = document.getElementById("pitch-sim");
  if (sim) {
    var ask = document.getElementById("pitch-ask");
    var gate = document.getElementById("pitch-gate");
    var out = document.getElementById("pitch-out");
    function show(id) {
      sim.querySelectorAll("[data-case]").forEach(function (tab) {
        tab.setAttribute("aria-pressed", tab.getAttribute("data-case") === id ? "true" : "false");
      });
      ask.textContent = cases[id].ask;
      gate.textContent = cases[id].gate;
      out.textContent = cases[id].out;
    }
    sim.querySelectorAll("[data-case]").forEach(function (tab) {
      tab.addEventListener("click", function () { show(tab.getAttribute("data-case")); });
    });
    show("read");
  }
})();
