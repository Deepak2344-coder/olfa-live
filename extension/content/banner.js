// Olfa content script: listens for verdict messages from the background
// service worker and shows a dismissible red banner on pages flagged
// "dangerous". Reads nothing from the page beyond its own banner DOM.
(() => {
  const BANNER_ID = "olfa-banner";
  const dismissed = new Set(sessionMemory());

  function sessionMemory() {
    try {
      return JSON.parse(sessionStorage.getItem("olfa_dismissed") || "[]");
    } catch {
      return [];
    }
  }

  function rememberDismissal(url) {
    try {
      dismissed.add(url);
      sessionStorage.setItem("olfa_dismissed", JSON.stringify([...dismissed]));
    } catch {
      // sessionStorage unavailable: banner simply reappears on reload
    }
  }

  function showBanner(data) {
    if (document.getElementById(BANNER_ID) || dismissed.has(data?.url)) return;

    const banner = document.createElement("div");
    banner.id = BANNER_ID;
    banner.setAttribute("role", "alert");

    const face = document.createElement("img");
    face.src = chrome.runtime.getURL("assets/hachi.png");
    face.alt = "";
    face.id = "olfa-banner-face";
    banner.appendChild(face);

    const text = document.createElement("div");
    const title = `Woof! Hachi thinks this site is dangerous (safety score ${Math.round(Number(data.score) || 0)}/100)`;
    const strong = document.createElement("strong");
    strong.textContent = title;
    text.appendChild(strong);

    const list = document.createElement("ul");
    for (const reason of (data.reasons || []).slice(0, 2)) {
      const li = document.createElement("li");
      li.textContent = reason.text;
      list.appendChild(li);
    }
    text.appendChild(list);
    banner.appendChild(text);

    const dismiss = document.createElement("button");
    dismiss.id = "olfa-banner-dismiss";
    dismiss.textContent = "Got it";
    dismiss.addEventListener("click", () => {
      banner.remove();
      rememberDismissal(data.url);
    });
    banner.appendChild(dismiss);

    document.documentElement.prepend(banner);
  }

  chrome.runtime.onMessage.addListener((msg) => {
    if (msg?.type === "olfa:banner" && msg.data?.verdict === "dangerous") {
      showBanner(msg.data);
    }
  });
})();
