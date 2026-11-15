"use strict";

const mobileNavToggle = document.querySelector(".mobile-nav-toggle");
const mobileNav = document.getElementById("primary-navigation");
const mobileNavHeader = mobileNavToggle?.closest(".site-header");

if (mobileNavToggle && mobileNav && mobileNavHeader) {
    const setMobileNavOpen = (open, restoreFocus = false) => {
        mobileNavHeader.classList.toggle("menu-open", open);
        mobileNavToggle.setAttribute("aria-expanded", String(open));
        mobileNavToggle.setAttribute("aria-label", open ? "Close main menu" : "Open main menu");
        if (open) window.requestAnimationFrame(() => mobileNav.querySelector("a:not([hidden])")?.focus());
        else if (restoreFocus) mobileNavToggle.focus();
    };

    mobileNavToggle.addEventListener("click", () => {
        setMobileNavOpen(mobileNavToggle.getAttribute("aria-expanded") !== "true");
    });
    mobileNav.querySelectorAll("a").forEach((link) => link.addEventListener("click", () => setMobileNavOpen(false)));
    mobileNav.querySelector("[data-auth-logout]")?.addEventListener("click", () => setMobileNavOpen(false));
    document.addEventListener("keydown", (event) => {
        if (event.key === "Escape" && mobileNavToggle.getAttribute("aria-expanded") === "true") setMobileNavOpen(false, true);
    });
    document.addEventListener("click", (event) => {
        if (!mobileNavHeader.contains(event.target)) setMobileNavOpen(false);
    });
    window.matchMedia("(min-width: 641px)").addEventListener("change", (event) => {
        if (event.matches) setMobileNavOpen(false);
    });
}

async function refreshAuthNavigation() {
    try {
        const response = await fetch("/api/auth/me", { credentials: "same-origin" });
        if (!response.ok) return;
        const auth = await response.json();
        for (const item of document.querySelectorAll("[data-auth-anon]")) {
            item.hidden = auth.authenticated;
        }
        for (const item of document.querySelectorAll("[data-auth-user]")) {
            item.hidden = !auth.authenticated;
        }
        const email = document.querySelector("[data-auth-email]");
        if (email && auth.authenticated) email.textContent = auth.user.email;
        for (const button of document.querySelectorAll("[data-auth-logout]")) {
            button.addEventListener("click", async () => {
                button.disabled = true;
                try {
                    const logout = await fetch("/api/auth/logout", {
                        method: "POST",
                        credentials: "same-origin",
                        headers: {
                            "Content-Type": "application/json",
                            "X-CSRF-Token": auth.csrfToken,
                        },
                        body: "{}",
                    });
                    if (!logout.ok) throw new Error("Logout failed.");
                    window.location.reload();
                } catch {
                    button.disabled = false;
                }
            }, { once: true });
        }
    } catch {
        return;
    }
}

refreshAuthNavigation();
