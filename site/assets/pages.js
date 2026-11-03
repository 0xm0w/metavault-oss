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
      try { ok = document.execCommand("copy"); } catch { ok = false; }
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

  var CODE_ESCAPES = { "&": "&amp;", "<": "&lt;", ">": "&gt;" };
  function escapeCode(value) {
    return value.replace(/[&<>]/g, function (ch) { return CODE_ESCAPES[ch]; });
  }
  function spanCode(cls, value) {
    return '<span class="' + cls + '">' + escapeCode(value) + "</span>";
  }
  function highlightJson(src) {
    var re = /("(?:[^"\\\n]|\\.)*")|(\/\/[^\n]*)|\b(true|false|null)\b|(-?\d[\d_]*(?:\.\d+)?(?:[eE][+-]?\d+)?)|([{}[\],:])/g;
    var out = "";
    var last = 0;
    var m;
    while ((m = re.exec(src))) {
      out += escapeCode(src.slice(last, m.index));
      if (m[1]) {
        var isKey = /^\s*:/.test(src.slice(re.lastIndex));
        out += spanCode(isKey ? "tok-key" : "tok-str", m[1]);
      } else if (m[2]) out += spanCode("tok-com", m[2]);
      else if (m[3]) out += spanCode("tok-bool", m[3]);
      else if (m[4]) out += spanCode("tok-num", m[4]);
      else out += spanCode("tok-punc", m[5]);
      last = re.lastIndex;
    }
    return out + escapeCode(src.slice(last));
  }
  function highlightToml(src) {
    var re = /(#[^\n]*)|("(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*')|(\[[^\]\n]*\])|\b(true|false)\b|(-?\d[\d_]*(?:\.\d+)?)|^([A-Za-z0-9_.-]+)(?=\s*=)|([=\[\],])/gm;
    var out = "";
    var last = 0;
    var m;
    while ((m = re.exec(src))) {
      out += escapeCode(src.slice(last, m.index));
      if (m[1]) out += spanCode("tok-com", m[1]);
      else if (m[2]) out += spanCode("tok-str", m[2]);
      else if (m[3]) out += spanCode("tok-sec", m[3]);
      else if (m[4]) out += spanCode("tok-bool", m[4]);
      else if (m[5]) out += spanCode("tok-num", m[5]);
      else if (m[6]) out += spanCode("tok-key", m[6]);
      else out += spanCode("tok-punc", m[7]);
      last = re.lastIndex;
    }
    return out + escapeCode(src.slice(last));
  }
  function highlightShell(src) {
    var re = /(#[^\n]*)|("(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*')|(-{1,2}[A-Za-z0-9][A-Za-z0-9_-]*)|^([^\s#][^\s]*)|([^\s#]+)/gm;
    var out = "";
    var last = 0;
    var m;
    while ((m = re.exec(src))) {
      out += escapeCode(src.slice(last, m.index));
      if (m[1]) out += spanCode("tok-com", m[1]);
      else if (m[2]) out += spanCode("tok-str", m[2]);
      else if (m[3]) out += spanCode("tok-flag", m[3]);
      else if (m[4]) out += spanCode("tok-cmd", m[4]);
      else out += spanCode("tok-arg", m[5]);
      last = re.lastIndex;
    }
    return out + escapeCode(src.slice(last));
  }
  function highlightLog(src) {
    var re = /("(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*')|\b([A-Za-z_][\w.-]*)(=)|\b(true|false|TRUE|FALSE|BLOCKED|ACCEPTED|MANDATORY)\b|\b(\d[\d_]*)\b/g;
    var out = "";
    var last = 0;
    var m;
    while ((m = re.exec(src))) {
      out += escapeCode(src.slice(last, m.index));
      if (m[1]) out += spanCode("tok-str", m[1]);
      else if (m[2]) out += spanCode("tok-key", m[2]) + spanCode("tok-punc", m[3]);
      else if (m[4]) out += spanCode("tok-bool", m[4]);
      else out += spanCode("tok-num", m[5]);
      last = re.lastIndex;
    }
    return out + escapeCode(src.slice(last));
  }
  function highlightPython(src) {
    var re = /(#[^\n]*)|("(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*')|\b(if|else|in|and|or|not|return|def|True|False|None)\b|\b(\d[\d_.]*)\b/g;
    var out = "";
    var last = 0;
    var m;
    while ((m = re.exec(src))) {
      out += escapeCode(src.slice(last, m.index));
      if (m[1]) out += spanCode("tok-com", m[1]);
      else if (m[2]) out += spanCode("tok-str", m[2]);
      else if (m[3]) out += spanCode("tok-bool", m[3]);
      else out += spanCode("tok-num", m[4]);
      last = re.lastIndex;
    }
    return out + escapeCode(src.slice(last));
  }
  function guessLang(text) {
    if (/^\s*\[[^\]\n]+\]\s*$/m.test(text)) return "toml";
    var head = text.replace(/^\s+/, "");
    if (head.charAt(0) === "{" || head.charAt(0) === "[") return "json";
    if (/^\s*(git|cd|npm|npx|node|metavault|ollama|docker|curl|ssh)\b/m.test(text)) return "shell";
    return "log";
  }
  function paintCode(pre, lang) {
    var painters = { json: highlightJson, toml: highlightToml, shell: highlightShell, log: highlightLog, python: highlightPython };
    var paint = painters[lang] || highlightLog;
    pre.innerHTML = paint(pre.textContent);
    pre.setAttribute("data-highlighted", "true");
  }
  document.querySelectorAll(".pg-snippet pre, .pg-trace-code, .pg-codeblock").forEach(function (pre) {
    if (pre.hasAttribute("data-highlighted")) return;
    paintCode(pre, pre.getAttribute("data-lang") || guessLang(pre.textContent));
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
      paintCode(out, out.getAttribute("data-lang") || "json");
    }
    sim.querySelectorAll("[data-case]").forEach(function (tab) {
      tab.addEventListener("click", function () { show(tab.getAttribute("data-case")); });
    });
    show("read");
  }

  var deck = document.querySelector(".hack-deck");
  if (deck) {
    var scroller = document.getElementById("hack-scroller");
    var slides = Array.prototype.slice.call(scroller.querySelectorAll(".hack-slide"));
    var dots = Array.prototype.slice.call(document.querySelectorAll(".hack-dot"));
    var up = document.getElementById("hack-up");
    var down = document.getElementById("hack-down");
    var reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    var index = 0;
    var frame = 0;
    var moving = false;
    var wheelUntil = 0;

    function paint() {
      dots.forEach(function (dot, i) {
        if (i === index) dot.setAttribute("aria-current", "true");
        else dot.removeAttribute("aria-current");
      });
      if (up) up.disabled = index <= 0;
      if (down) down.disabled = index >= slides.length - 1;
    }

    function go(next, instant) {
      var i = Math.max(0, Math.min(slides.length - 1, next));
      var same = i === index && Math.abs(scroller.scrollTop - slides[i].offsetTop) < 2;
      index = i;
      paint();
      if (same) return;
      moving = true;
      scroller.scrollTo({
        top: slides[i].offsetTop,
        behavior: instant || reduce ? "auto" : "smooth"
      });
      window.clearTimeout(go.timer);
      go.timer = window.setTimeout(function () { moving = false; }, instant || reduce ? 40 : 700);
    }

    dots.forEach(function (dot, i) {
      dot.addEventListener("click", function () { go(i); });
    });
    scroller.querySelectorAll('a[href^="#"]').forEach(function (link) {
      var target = slides.findIndex(function (slide) { return "#" + slide.id === link.getAttribute("href"); });
      if (target < 0) return;
      link.addEventListener("click", function (event) {
        event.preventDefault();
        go(target);
      });
    });
    if (up) up.addEventListener("click", function () { go(index - 1); });
    if (down) down.addEventListener("click", function () { go(index + 1); });

    function syncFromScroll() {
      var h = scroller.clientHeight || 1;
      var i = Math.round(scroller.scrollTop / h);
      i = Math.max(0, Math.min(slides.length - 1, i));
      if (i !== index) {
        index = i;
        paint();
      }
    }

    scroller.addEventListener("scroll", function () {
      if (moving || frame) return;
      frame = requestAnimationFrame(function () {
        frame = 0;
        if (!moving) syncFromScroll();
      });
    }, { passive: true });

    scroller.addEventListener("scrollend", function () {
      moving = false;
      syncFromScroll();
    });

    scroller.addEventListener("wheel", function (event) {
      if (!moving) syncFromScroll();
      if (Math.abs(event.deltaX) > Math.abs(event.deltaY)) return;
      var slide = slides[index];
      var extra = slide.scrollHeight - slide.clientHeight;
      if (extra > 2) {
        var atTop = slide.scrollTop <= 0;
        var atBottom = slide.scrollTop + slide.clientHeight >= slide.scrollHeight - 2;
        var goingDown = event.deltaY > 0;
        if ((goingDown && !atBottom) || (!goingDown && !atTop)) {
          event.preventDefault();
          slide.scrollTop += event.deltaY;
          return;
        }
      }
      event.preventDefault();
      if (Math.abs(event.deltaY) < 12) return;
      var now = Date.now();
      if (now < wheelUntil) return;
      wheelUntil = now + (reduce ? 0 : 680);
      go(index + (event.deltaY > 0 ? 1 : -1));
    }, { passive: false });

    document.addEventListener("keydown", function (event) {
      var target = event.target;
      var tag = target && target.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA" || (target && target.isContentEditable)) return;
      if (target && target.closest && target.closest("#pitch-sim, .mb-nav-mobile-menu")) return;
      if (event.key === "ArrowDown" || event.key === "PageDown") {
        event.preventDefault();
        go(index + 1);
      } else if (event.key === "ArrowUp" || event.key === "PageUp") {
        event.preventDefault();
        go(index - 1);
      } else if (event.key === "Home") {
        event.preventDefault();
        go(0);
      } else if (event.key === "End") {
        event.preventDefault();
        go(slides.length - 1);
      }
    });

    window.addEventListener("resize", function () {
      scroller.scrollTo({ top: slides[index].offsetTop, behavior: "auto" });
    });

    var start = 0;
    if (location.hash) {
      var found = slides.findIndex(function (slide) { return "#" + slide.id === location.hash; });
      if (found > 0) start = found;
    }
    if (start) go(start, true);
    else paint();
  }
})();
