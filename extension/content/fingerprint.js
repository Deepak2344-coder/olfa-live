// Fingerprint probe. Runs in the page's own JS world (manifest "world": "MAIN")
// at document_start so it is installed before the page's first script.
//
// It records that a sensitive API was CALLED — never the data involved — and
// posts the API name to the isolated content agent, which listens on the same
// window's message channel. If "world": "MAIN" is unsupported this simply runs
// isolated and records nothing; the rest of the extension still works.
(() => {
  "use strict";

  const SOURCE = "olfa-fp";
  const reported = new Set();

  function report(api) {
    if (reported.has(api)) return;
    reported.add(api);
    try {
      window.postMessage({ source: SOURCE, api }, "*");
    } catch {
      /* page blocked postMessage: give up quietly */
    }
  }

  /** Wrap obj[key], keeping the original behaviour and properties. */
  function wrap(obj, key, label) {
    if (!obj) return;
    let original;
    try {
      original = obj[key];
    } catch {
      return;
    }
    if (typeof original !== "function" || original.__olfaWrapped) return;
    const wrapped = function wrapped(...args) {
      report(label);
      return original.apply(this, args);
    };
    wrapped.__olfaWrapped = true;
    try {
      obj[key] = wrapped;
    } catch {
      /* frozen object: not worth fighting */
    }
  }

  try {
    if (typeof HTMLCanvasElement !== "undefined") {
      wrap(HTMLCanvasElement.prototype, "toDataURL", "canvas.toDataURL");
      wrap(HTMLCanvasElement.prototype, "toBlob", "canvas.toBlob");
    }
    if (typeof CanvasRenderingContext2D !== "undefined") {
      wrap(CanvasRenderingContext2D.prototype, "getImageData", "canvas.getImageData");
    }
    if (typeof AudioContext !== "undefined") {
      wrap(AudioContext.prototype, "createOscillator", "audio.fingerprint");
    }
    if (typeof navigator !== "undefined") {
      if (navigator.permissions) wrap(navigator.permissions, "query", "permissions.query");
      if (navigator.clipboard) {
        wrap(navigator.clipboard, "readText", "clipboard.read");
        wrap(navigator.clipboard, "writeText", "clipboard.write");
      }
    }
    if (typeof document !== "undefined") {
      // Clipboard events the page listens for, recorded passively.
      document.addEventListener("copy", () => report("clipboard.copy"), true);
      document.addEventListener("paste", () => report("clipboard.paste"), true);
    }
  } catch {
    /* unusual page environment: keep whatever was recorded */
  }
})();
