(function () {
  const PAGE_ORDER = ["index.html", "overview.html", "alerts.html", "processes.html"];
  const LONG_BACK_MS = 700;

  function currentPage() {
    const path = window.location.pathname.split("/").pop() || "index.html";
    return PAGE_ORDER.includes(path) ? path : "index.html";
  }

  function goTo(page) {
    if (!page) return;
    const current = currentPage();
    if (current === page) return;
    window.location.href = page;
  }

  function cycleMode(step = 1) {
    const current = currentPage();
    const idx = PAGE_ORDER.indexOf(current);
    const nextIdx = (idx + step + PAGE_ORDER.length) % PAGE_ORDER.length;
    goTo(PAGE_ORDER[nextIdx]);
  }

  let backTimer = null;
  let longBackTriggered = false;

  function isBackKey(e) {
    return e.key === "Escape" || e.key === "Backspace";
  }

  function callHandler(name, event) {
    const nav = window.deviceNav;
    if (!nav || typeof nav[name] !== "function") return false;
    return nav[name](event) === true;
  }

  document.addEventListener("keydown", (e) => {
    if (e.repeat && !isBackKey(e)) {
      e.preventDefault();
      return;
    }

    if (e.key === "Tab" || e.key.toLowerCase() === "m") {
      e.preventDefault();
      cycleMode(1);
      return;
    }

    if (e.key === "ArrowUp") {
      if (callHandler("onUp", e)) e.preventDefault();
      return;
    }

    if (e.key === "ArrowDown") {
      if (callHandler("onDown", e)) e.preventDefault();
      return;
    }

    if (e.key === "Enter" || e.key === " ") {
      if (callHandler("onSelect", e)) e.preventDefault();
      return;
    }

    if (isBackKey(e)) {
      e.preventDefault();
      longBackTriggered = false;
      if (!backTimer) {
        backTimer = window.setTimeout(() => {
          longBackTriggered = true;
          goTo("index.html");
        }, LONG_BACK_MS);
      }
    }
  });

  document.addEventListener("keyup", (e) => {
    if (!isBackKey(e)) return;
    if (backTimer) {
      clearTimeout(backTimer);
      backTimer = null;
    }
    if (!longBackTriggered) {
      callHandler("onBack", e);
    }
    longBackTriggered = false;
  });
})();
