(() => {
  function boot() {
  const board = document.getElementById("oar-board");
  const nav = document.getElementById("oar-nav");
  if (!board || !nav || nav.dataset.ready) return;
  nav.dataset.ready = "1";

  const scenes = [
    ["01", "The problem"],
    ["02", "Inbound fails"],
    ["03", "Dials out"],
    ["04", "A real ssh"],
    ["05", "Revoke live"],
    ["06", "Use cases"],
  ];
  let i = 0;
  let timer;
  const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;

  function paint(n) {
    i = n;
    board.dataset.scene = String(i);
    nav.querySelectorAll("button.step").forEach((b, k) => {
      b.setAttribute("aria-current", k === i ? "true" : "false");
    });
    const bar = nav.querySelector(".bar i");
    if (bar) {
      bar.style.animation = "none";
      void bar.offsetWidth;
      bar.style.animation = "";
    }
  }

  scenes.forEach((s, k) => {
    const b = document.createElement("button");
    b.className = "step";
    b.type = "button";
    b.textContent = `${s[0]}  ${s[1]}`;
    b.addEventListener("click", () => {
      paint(k);
      arm();
    });
    nav.appendChild(b);
  });
  const wrap = document.createElement("div");
  wrap.className = "bar";
  wrap.innerHTML = "<i></i>";
  nav.appendChild(wrap);

  function arm() {
    clearInterval(timer);
    if (reduce) return;
    timer = setInterval(() => paint((i + 1) % scenes.length), 7000);
  }
  paint(0);
  arm();
  }
  boot();
  new MutationObserver(boot).observe(document.documentElement, { childList: true, subtree: true });
})();
