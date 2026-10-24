"use strict";

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
