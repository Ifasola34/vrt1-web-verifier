/* VERITAS page intro — a muted, autoplaying overview that crossfades to the page.
 *
 * Loaded as a classic <script> in <head> so it can hide the hero before first
 * paint (no flash-of-hero). CSP-safe by construction: external file, no inline
 * code anywhere, and every visual state is a class toggle (never an inline
 * style) — so the verifier's strict, no-'unsafe-inline' CSP needs no changes.
 *
 * Graceful degradation: if JS is disabled or this file fails to parse, the
 * `intro-pending` class is never added, so the overlay stays hidden and the
 * page renders and works exactly as before.
 */
(function () {
  "use strict";

  var de = document.documentElement;
  de.classList.add("intro-js"); // JS works → the footer "Replay the intro" control is usable

  var SEEN_KEY = "veritas_intro_seen";
  function seenThisSession() { try { return sessionStorage.getItem(SEEN_KEY) === "1"; } catch (e) { return false; } }
  function markSeen() { try { sessionStorage.setItem(SEEN_KEY, "1"); } catch (e) {} }
  function prefersReducedMotion() {
    try { return window.matchMedia("(prefers-reduced-motion: reduce)").matches; } catch (e) { return false; }
  }

  // Greet with the intro only on a fresh session, and only when motion is welcome.
  var autoOpen = !seenThisSession() && !prefersReducedMotion();
  if (autoOpen) de.classList.add("intro-pending"); // hide hero, show overlay, lock scroll — before first paint

  function onReady(fn) {
    if (document.readyState !== "loading") fn();
    else document.addEventListener("DOMContentLoaded", fn);
  }

  onReady(function () {
    var intro = document.getElementById("intro");
    var video = document.getElementById("intro-video");
    var unmuteBtn = document.getElementById("intro-unmute");
    var skipBtn = document.getElementById("intro-skip");
    var replayBtn = document.getElementById("intro-replay");
    var pageEls = [].slice.call(document.querySelectorAll(".hero, main, .site-footer"));

    // If the markup isn't there for any reason, never leave the page hidden.
    if (!intro || !video) { de.classList.remove("intro-pending"); return; }

    var closed = true;
    var started = false;

    function setInert(on) {
      for (var i = 0; i < pageEls.length; i++) {
        if (on) pageEls[i].setAttribute("inert", "");
        else pageEls[i].removeAttribute("inert");
      }
    }

    function syncUnmute() {
      if (!unmuteBtn) return;
      // textContent (not innerHTML) — XSS-safe; glyphs are literal code points (🔊 / 🔇).
      unmuteBtn.textContent = video.muted ? "🔊 Unmute" : "🔇 Mute";
      unmuteBtn.setAttribute("aria-pressed", video.muted ? "false" : "true");
    }

    function tryPlay() {
      var p;
      try { p = video.play(); } catch (e) { p = null; }
      if (p && typeof p.catch === "function") {
        p.catch(function () {
          // Autoplay refused: surface native controls so the visitor can start it
          // themselves rather than staring at a frozen frame. Skip/scroll still work.
          video.setAttribute("controls", "");
          intro.classList.add("autoplay-blocked");
        });
      }
    }

    function onKey(e) {
      if (e.key === "Escape" || e.key === "ArrowDown" || e.key === "PageDown") { e.preventDefault(); closeIntro(); }
    }
    function onWheel(e) { if (!e || (e.deltaY || 0) > 4) closeIntro(); }
    function onTouch() { closeIntro(); }
    function bindDismiss(on) {
      var m = on ? "addEventListener" : "removeEventListener";
      window[m]("keydown", onKey);
      window[m]("wheel", onWheel, { passive: true });
      window[m]("touchmove", onTouch, { passive: true });
    }

    function openIntro() {
      if (!closed) return;
      closed = false; started = false;
      intro.removeAttribute("hidden");
      intro.classList.remove("is-closing", "autoplay-blocked");
      video.removeAttribute("controls");
      de.classList.remove("intro-revealing");
      de.classList.add("intro-pending");
      setInert(true);
      try { video.currentTime = 0; } catch (e) {}
      video.muted = true; syncUnmute();
      tryPlay();
      bindDismiss(true);
      try { skipBtn.focus(); } catch (e) {}
      // Safety net: if it never starts (network stall / silent block) and we didn't
      // surface controls for an explicit block, reveal the page rather than trap it.
      window.setTimeout(function () {
        if (!closed && !started && !intro.classList.contains("autoplay-blocked")) closeIntro();
      }, 6000);
    }

    function closeIntro() {
      if (closed) return;
      closed = true;
      markSeen();
      bindDismiss(false);
      de.classList.add("intro-revealing");
      intro.classList.add("is-closing");
      var settled = false;
      function finish(e) {
        if (e && (e.target !== intro || e.propertyName !== "opacity")) return; // ignore bubbled/other transitions
        if (settled) return;
        settled = true;
        intro.removeEventListener("transitionend", finish);
        window.clearTimeout(t);
        intro.setAttribute("hidden", "");
        de.classList.remove("intro-pending", "intro-revealing");
        setInert(false);
        try { video.pause(); } catch (e2) {}
        // Move focus off the now-hidden overlay WITHOUT scrolling the page.
        // (Focusing the footer "Replay" button is what yanked the view to the bottom on close.)
        try { if (document.activeElement && document.activeElement.blur) document.activeElement.blur(); } catch (e3) {}
      }
      var t = window.setTimeout(finish, 900); // fallback if transitionend never fires
      intro.addEventListener("transitionend", finish);
    }

    if (skipBtn) skipBtn.addEventListener("click", closeIntro);
    if (unmuteBtn) unmuteBtn.addEventListener("click", function () { video.muted = !video.muted; syncUnmute(); });
    if (replayBtn) replayBtn.addEventListener("click", function (e) { e.preventDefault(); openIntro(); });
    video.addEventListener("playing", function () { started = true; });
    video.addEventListener("ended", closeIntro);
    video.addEventListener("error", function () { if (!closed) closeIntro(); });
    video.addEventListener("click", function () { if (video.paused) { tryPlay(); } else { video.pause(); } });

    syncUnmute();

    if (autoOpen) openIntro();
    else de.classList.remove("intro-pending"); // make sure the page is interactive
  });
})();
