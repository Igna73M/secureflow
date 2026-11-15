"use strict";

(() => {
    const storageKey = "secureflow-theme";
    const systemPreference = window.matchMedia?.("(prefers-color-scheme: dark)");
    let preference = "system";
    let transitionTimer = 0;

    try {
        const saved = window.localStorage.getItem(storageKey);
        if (saved === "light" || saved === "dark") preference = saved;
    } catch {
        // If storage is unavailable, follow the system preference for this visit.
    }

    function activeTheme() {
        return preference === "system"
            ? (systemPreference?.matches ? "dark" : "light")
            : preference;
    }

    function syncControls(theme = activeTheme()) {
        const label = theme === "dark" ? "Switch to light theme" : "Switch to dark theme";
        document.querySelectorAll("[data-theme-toggle]").forEach((button) => {
            button.setAttribute("aria-label", label);
            button.setAttribute("title", label);
            button.setAttribute("aria-pressed", String(theme === "dark"));
        });
    }

    function applyTheme(animate = false) {
        const theme = activeTheme();
        if (animate && !window.matchMedia?.("(prefers-reduced-motion: reduce)")?.matches) {
            document.documentElement.classList.add("theme-transition");
            window.clearTimeout(transitionTimer);
            transitionTimer = window.setTimeout(() => {
                document.documentElement.classList.remove("theme-transition");
            }, 260);
        }
        document.documentElement.dataset.theme = theme;
        document.documentElement.style.colorScheme = theme;
        syncControls(theme);

        const themeColor = document.querySelector('meta[name="theme-color"]');
        if (themeColor) themeColor.setAttribute("content", theme === "dark" ? "#0F172A" : "#F8FAFC");
    }

    applyTheme();

    const controlsObserver = new MutationObserver((mutations) => {
        if (mutations.some((mutation) => [...mutation.addedNodes].some((node) =>
            node.nodeType === Node.ELEMENT_NODE &&
            (node.matches?.("[data-theme-toggle]") || node.querySelector?.("[data-theme-toggle]"))))) {
            syncControls();
        }
    });
    controlsObserver.observe(document.documentElement, { childList: true, subtree: true });

    if (systemPreference?.addEventListener) {
        systemPreference.addEventListener("change", () => {
            if (preference === "system") applyTheme(true);
        });
    } else if (systemPreference?.addListener) {
        systemPreference.addListener(() => {
            if (preference === "system") applyTheme(true);
        });
    }

    document.addEventListener("click", (event) => {
        const button = event.target.closest("[data-theme-toggle]");
        if (!button) return;

        preference = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
        try {
            window.localStorage.setItem(storageKey, preference);
        } catch {
            // Keep the selection for this page even when persistence is unavailable.
        }
        applyTheme(true);
    });

    window.addEventListener("storage", (event) => {
        if (event.key !== storageKey && event.key !== null) return;
        preference = event.newValue === "light" || event.newValue === "dark" ? event.newValue : "system";
        applyTheme(true);
    });
})();
