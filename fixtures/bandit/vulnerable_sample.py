"""Intentionally insecure sample used only for scanner testing."""

import subprocess


def run_user_command(user_input):
    # Intentionally unsafe: user-controlled input reaches a shell.
    subprocess.call(user_input, shell=True)
