"use strict";

const form         = document.getElementById("auth-form");
const errorEl      = document.getElementById("form-error");
const errorText    = errorEl.querySelector(".error-text");
const submitBtn    = form.querySelector("button[type=submit]");
const mode         = document.body.dataset.authMode;

const authFeatures = document.querySelector(".auth-feature-details");
const compactAuthViewport = window.matchMedia("(max-width: 640px)");
if (authFeatures) {
    const syncFeatureDisclosure = () => { authFeatures.open = !compactAuthViewport.matches; };
    syncFeatureDisclosure();
    compactAuthViewport.addEventListener("change", syncFeatureDisclosure);
}

/* ---------- Helpers ---------- */
function showError(msg) {
    errorText.textContent = msg;
    errorEl.hidden = false;
    // Move focus to error so screen readers announce it
    errorEl.setAttribute("tabindex", "-1");
    errorEl.focus();
}

function clearError() {
    errorText.textContent = "";
    errorEl.hidden = true;
    errorEl.removeAttribute("tabindex");
}

function setLoading(loading) {
    submitBtn.disabled = loading;
    submitBtn.classList.toggle("is-loading", loading);
    submitBtn.setAttribute("aria-busy", String(loading));
}

/* ---------- Password visibility toggle ---------- */
document.querySelectorAll(".toggle-password").forEach(btn => {
    btn.addEventListener("click", () => {
        const input = btn.closest(".input-wrapper").querySelector("input");
        const isHidden = input.type === "password";
        input.type = isHidden ? "text" : "password";
        btn.setAttribute("aria-pressed", String(isHidden));
        btn.setAttribute("aria-label", isHidden ? "Hide password" : "Show password");
        btn.querySelector(".icon-eye").style.display = isHidden ? "none" : "";
        btn.querySelector(".icon-eye-off").style.display = isHidden ? "" : "none";
    });
});

/* ---------- Password strength meter (register only) ---------- */
if (mode === "register") {
    const passwordInput   = document.getElementById("password");
    const strengthFill    = document.getElementById("strength-fill");
    const strengthLabel   = document.getElementById("password-strength-label");
    const strengthBar     = strengthFill?.closest("[role=progressbar]");

    if (passwordInput && strengthFill && strengthLabel) {
        passwordInput.addEventListener("input", () => {
            const val = passwordInput.value;
            const bytes = new TextEncoder().encode(val).length;
            let level = 0;

            const hasAlphanumeric = /[\p{L}\p{N}]/u.test(val);
            const hasSymbol = /[\p{P}\p{S}]/u.test(val);
            const meetsRequirements = [...val].length >= 8 && hasAlphanumeric && hasSymbol;

            if (bytes >= 8) level = 1;
            if (bytes >= 12 && hasAlphanumeric) level = 2;
            if (bytes >= 16 && hasSymbol) level = 3;
            if (bytes >= 20 && meetsRequirements) level = 4;

            const levels = ["", "strength-weak", "strength-fair", "strength-good", "strength-strong"];
            const labels = ["", "Weak", "Fair", "Good", "Strong"];
            const pct    = [0, 25, 50, 75, 100];

            strengthFill.className = "password-strength-fill " + (levels[level] || "");
            strengthLabel.textContent = level > 0 ? labels[level] : "";
            if (strengthBar) strengthBar.setAttribute("aria-valuenow", String(pct[level] || 0));

            // Colour the label text
            const colours = ["", "var(--color-fail)", "var(--color-error)", "var(--color-strength-good)", "var(--color-pass)"];
            strengthLabel.style.color = colours[level] || "";
        });
    }
}

/* ---------- Form submission ---------- */
form.addEventListener("submit", async event => {
    event.preventDefault();
    clearError();

    const email    = form.elements.email.value.trim();
    const password = form.elements.password.value;
    const encoded  = new TextEncoder().encode(password).length;

    // Client-side validation
    if (!email || !form.elements.email.validity.valid) {
        showError("Enter a valid email address.");
        form.elements.email.focus();
        return;
    }
    if (mode === "register") {
        const hasAlphanumeric = /[\p{L}\p{N}]/u.test(password);
        const hasSymbol = /[\p{P}\p{S}]/u.test(password);
        if ([...password].length < 8 || !hasAlphanumeric || !hasSymbol) {
            showError("Create a password with 8 to 128 characters. Include at least one letter or number, plus a symbol like ! or @.");
            form.elements.password.focus();
            return;
        }
    }
    if (encoded > 128) {
        showError("Password must not exceed 128 UTF-8 bytes.");
        form.elements.password.focus();
        return;
    }

    setLoading(true);

    try {
        // Fetch CSRF token
        const meRes = await fetch("/api/auth/me", { credentials: "same-origin" });
        const auth  = await meRes.json();

        if (auth.authenticated) {
            window.location.assign("/console/overview");
            return;
        }

        const res    = await fetch(`/api/auth/${mode}`, {
            method:      "POST",
            credentials: "same-origin",
            headers: {
                "Content-Type": "application/json",
                "Accept":        "application/json",
                "X-CSRF-Token":  auth.csrfToken,
            },
            body: JSON.stringify({ email, password }),
        });

        const result = res.status === 204 ? {} : await res.json().catch(() => ({}));

        if (!res.ok) {
            throw new Error(result.error || "Authentication could not be completed.");
        }

        window.location.assign("/console/overview");
    } catch (err) {
        showError(err.message || "Authentication could not be completed. Please try again.");
        setLoading(false);
    }
});
