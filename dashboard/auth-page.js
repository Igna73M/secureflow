"use strict";

const form = document.getElementById("auth-form");
const errorMessage = document.getElementById("form-error");
const submitButton = form.querySelector("button[type=submit]");
const mode = document.body.dataset.authMode;

function showError(message) {
    errorMessage.textContent = message;
    errorMessage.hidden = false;
}

form.addEventListener("submit", async event => {
    event.preventDefault();
    errorMessage.textContent = "";
    errorMessage.hidden = true;

    const email = form.elements.email.value.trim();
    const password = form.elements.password.value;
    if (!email || !form.elements.email.validity.valid) {
        showError("Enter a valid email address.");
        form.elements.email.focus();
        return;
    }
    if (mode === "register" && new TextEncoder().encode(password).length < 12) {
        showError("Password must be at least 12 UTF-8 bytes.");
        form.elements.password.focus();
        return;
    }
    if (new TextEncoder().encode(password).length > 128) {
        showError("Password must not exceed 128 UTF-8 bytes.");
        form.elements.password.focus();
        return;
    }

    submitButton.disabled = true;
    try {
        const current = await fetch("/api/auth/me", { credentials: "same-origin" });
        const auth = await current.json();
        if (auth.authenticated) {
            window.location.assign("/console.html");
            return;
        }
        const response = await fetch(`/api/auth/${mode}`, {
            method: "POST",
            credentials: "same-origin",
            headers: {
                "Content-Type": "application/json",
                Accept: "application/json",
                "X-CSRF-Token": auth.csrfToken,
            },
            body: JSON.stringify({ email, password }),
        });
        const result = response.status === 204 ? {} : await response.json();
        if (!response.ok) throw new Error(result.error || "Authentication could not be completed.");
        window.location.assign("/console.html");
    } catch (error) {
        showError(error.message || "Authentication could not be completed.");
        submitButton.disabled = false;
    }
});
