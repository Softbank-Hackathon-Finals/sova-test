// Layout preferences only. Does not change the response session or motion clock.
export function mountStudioView() {
  const toggle = document.getElementById("studio-view-toggle");
  const detail = document.getElementById("inspector-toggle");
  const inspector = document.getElementById("node-inspector");
  const supported = matchMedia("(min-width: 1180px) and (min-height: 700px)");
  let active = false;
  let detailsOpen = false;

  function setDetails(open) {
    detailsOpen = open;
    document.body.dataset.inspector = open ? "open" : "closed";
    detail.setAttribute("aria-expanded", String(open));
    inspector.inert = active && !open;
    if (active && !open) inspector.setAttribute("aria-hidden", "true");
    else inspector.removeAttribute("aria-hidden");
  }
  function setActive(value) {
    active = value && supported.matches;
    document.body.dataset.studioView = active ? "focused" : "overview";
    toggle.setAttribute("aria-pressed", String(active));
    toggle.textContent = active ? "전체 내용 보기" : "한 화면 보기";
    if (active && document.body.dataset.sidebar === "open")
      document.getElementById("sidebar-toggle").click();
    setDetails(false);
    window.scrollTo({ top: 0, behavior: "instant" });
  }
  toggle.onclick = () => setActive(!active);
  detail.onclick = () => setDetails(!detailsOpen);
  const resize = () => {
    toggle.hidden = !supported.matches;
    if (!supported.matches && active) setActive(false);
  };
  supported.addEventListener("change", resize);
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && active) {
      if (detailsOpen) {
        setDetails(false);
        detail.focus();
      } else {
        setActive(false);
        toggle.focus();
      }
    }
  });
  document
    .getElementById("workspace-sidebar")
    .addEventListener("click", (event) => {
      if (active && event.target.closest("[data-section], .brand"))
        setActive(false);
    });
  setDetails(false);
  resize();
}

export function mountSidebar() {
  const sidebar = document.getElementById("workspace-sidebar");
  const main = document.querySelector(".main-shell");
  const toggle = document.getElementById("sidebar-toggle");
  const close = document.getElementById("sidebar-close");
  const backdrop = document.getElementById("sidebar-backdrop");
  const compact = matchMedia("(max-width: 900px)");
  const preferenceKey = "sova.response.sidebar.v1";
  let desktopOpen = true,
    mobileOpen = false;
  try {
    desktopOpen = localStorage.getItem(preferenceKey) !== "closed";
  } catch {
    /* Storage may be disabled. */
  }

  function update({ focus = false } = {}) {
    const open = compact.matches ? mobileOpen : desktopOpen;
    document.body.dataset.sidebar = open ? "open" : "closed";
    document.body.dataset.sidebarMode = compact.matches ? "overlay" : "docked";
    sidebar.inert = !open;
    sidebar.setAttribute("aria-hidden", String(!open));
    if (compact.matches && open) {
      sidebar.setAttribute("role", "dialog");
      sidebar.setAttribute("aria-modal", "true");
    } else {
      sidebar.removeAttribute("role");
      sidebar.removeAttribute("aria-modal");
    }
    main.inert = compact.matches && open;
    backdrop.hidden = !compact.matches || !open;
    document.body.classList.toggle(
      "sidebar-overlay-open",
      compact.matches && open,
    );
    toggle.setAttribute("aria-expanded", String(open));
    const label = open ? "사이드바 접기" : "사이드바 펼치기";
    toggle.setAttribute("aria-label", label);
    toggle.title = label;
    if (focus)
      (compact.matches && open ? close : toggle).focus({ preventScroll: true });
  }
  function setOpen(open, { focus = true } = {}) {
    if (compact.matches) mobileOpen = open;
    else {
      desktopOpen = open;
      try {
        localStorage.setItem(preferenceKey, open ? "open" : "closed");
      } catch {
        /* Nonessential preference. */
      }
    }
    update({ focus });
  }
  toggle.onclick = () => setOpen(!(compact.matches ? mobileOpen : desktopOpen));
  close.onclick = () => setOpen(false);
  backdrop.onclick = () => setOpen(false);
  const onNavigate = (event) => {
    if (compact.matches && event.target.closest("[data-section], .brand"))
      setOpen(false);
  };
  sidebar.addEventListener("click", onNavigate);
  const onKeydown = (event) => {
    if (!compact.matches || !mobileOpen) return;
    if (event.key === "Escape") {
      event.preventDefault();
      setOpen(false);
      return;
    }
    if (event.key !== "Tab") return;
    const items = [
      ...sidebar.querySelectorAll(
        'a[href], button:not(:disabled), [tabindex="0"]',
      ),
    ].filter((node) => node.getClientRects().length);
    const first = items[0],
      last = items.at(-1);
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  };
  const onResize = () => {
    const focusWasInSidebar = sidebar.contains(document.activeElement);
    const wasOverlayOpen = mobileOpen;
    mobileOpen = false;
    update();
    if (wasOverlayOpen || (focusWasInSidebar && sidebar.inert))
      toggle.focus({ preventScroll: true });
  };
  document.addEventListener("keydown", onKeydown);
  compact.addEventListener("change", onResize);
  update();
  return () => {
    document.removeEventListener("keydown", onKeydown);
    compact.removeEventListener("change", onResize);
    sidebar.removeEventListener("click", onNavigate);
  };
}
