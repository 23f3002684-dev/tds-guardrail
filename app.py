from flask import Flask, request, jsonify
from urllib.parse import urlparse
import os
import re
import shlex
import base64
import binascii

app = Flask(__name__)

HOME = "/home/agent"
WORKSPACE = "/home/agent/workspace"
SECRET = "/home/agent/.secrets"
OUTBOX = "/data/agent/outbox"

ALLOWED_HOSTS = {"pypi.org", "huggingface.co"}


def result(decision, reason):
    return jsonify({
        "decision": decision,
        "reason": reason
    })


def normalize_path(path, cwd=WORKSPACE):
    """Expand known agent paths and resolve relative traversal."""
    if not isinstance(path, str):
        return ""

    path = path.strip().strip("'\"")
    path = path.replace("\\", "/")
    # Shell-style home/environment expansion relevant to this agent.
    path = path.replace("${HOME}", HOME)
    path = path.replace("$HOME", HOME)

    if path == "~":
        path = HOME
    elif path.startswith("~/"):
        path = HOME + path[1:]

    if not path.startswith("/"):
        path = os.path.join(cwd, path)

    return os.path.normpath(path)


def is_secret_path(path):
    p = normalize_path(path)
    return p == SECRET or p.startswith(SECRET + "/")


def inside_outbox(path):
    p = normalize_path(path)
    return p == OUTBOX or p.startswith(OUTBOX + "/")


def decode_base64_candidates(text):
    """
    Find plausible base64 blobs and decode them so commands hidden inside
    base64 wrappers can still be inspected.
    """
    decoded = []

    if not isinstance(text, str):
        return decoded

    candidates = re.findall(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{8,}={0,2}", text)

    for candidate in candidates:
        try:
            padding = "=" * (-len(candidate) % 4)
            raw = base64.b64decode(candidate + padding, validate=True)
            value = raw.decode("utf-8")
            if value and all(c == "\n" or c == "\r" or c == "\t" or c.isprintable()
                             for c in value):
                decoded.append(value)
        except (binascii.Error, UnicodeDecodeError, ValueError):
            pass

    return decoded


def expanded_command(command):
    """Return original command plus recursively decoded base64 text."""
    pieces = [command]
    queue = [command]
    seen = {command}

    # A small fixed bound keeps the endpoint deterministic and fast.
    for _ in range(3):
        new_queue = []

        for text in queue:
            for decoded in decode_base64_candidates(text):
                if decoded not in seen:
                    seen.add(decoded)
                    pieces.append(decoded)
                    new_queue.append(decoded)

        if not new_queue:
            break

        queue = new_queue

    return "\n".join(pieces)


def command_tokens(command):
    """
    Tokenize shell text. Punctuation is separated so paths next to pipes,
    redirects, semicolons, etc. can still be examined.
    """
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars="|&;()<>")
        lexer.whitespace_split = True
        lexer.commenters = ""
        return list(lexer)
    except ValueError:
        # Malformed quoting: conservative fallback.
        return re.split(r"\s+", command)


def contains_secret_reference(command):
    """
    Detect direct and normalized references to the protected secret.
    """
    text = expanded_command(command)

    # Inspect the text after the expansions the assignment explicitly says
    # the shell may use.
    variants = {
        text,
        text.replace("${HOME}", HOME).replace("$HOME", HOME),
        text.replace("~/", HOME + "/")
    }

    for variant in variants:
        # Direct textual occurrence catches quoted/wrapped forms too.
        if SECRET in variant:
            return True

        for token in command_tokens(variant):
            token = token.strip().strip("'\"")

            # Remove common redirection prefixes.
            token = re.sub(r"^\d*(?:>>?|<<?)", "", token)

            if not token:
                continue

            # Only path-looking tokens need path normalization.
            if (
                token.startswith("/")
                or token.startswith("./")
                or token.startswith("../")
                or token.startswith("~/")
                or token.startswith("$HOME")
                or token.startswith("${HOME}")
                or "/../" in token
                or "/./" in token
            ):
                if is_secret_path(token):
                    return True

    return False


def check_bash(command):
    if not isinstance(command, str):
        return "block", "Invalid bash command."

    if contains_secret_reference(command):
        return "block", "Access to the agent's protected secrets is not permitted."

    return "allow", "Bash command does not access the protected secret."


def check_write(path):
    if not isinstance(path, str) or not path.strip():
        return "block", "Invalid write path."

    if not inside_outbox(path):
        return "block", "Files may only be written inside /data/agent/outbox/."

    return "allow", "Write target is inside the permitted outbox directory."


def check_http(url):
    if not isinstance(url, str):
        return "block", "Invalid HTTP URL."

    try:
        parsed = urlparse(url)
        host = parsed.hostname

        # Require an ordinary HTTP(S) URL with an exact allowed hostname.
        if parsed.scheme not in {"http", "https"} or not host:
            return "block", "Invalid or unsupported HTTP destination."

        host = host.rstrip(".").lower()

        if host not in ALLOWED_HOSTS:
            return "block", "HTTP requests are restricted to approved hosts."

        return "allow", "HTTP destination is an approved host."

    except (ValueError, TypeError):
        return "block", "Invalid HTTP URL."


@app.route("/check", methods=["POST"])
def check():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return result("block", "Request body must be a JSON object.")

    tool = data.get("tool")

    if tool == "bash":
        decision, reason = check_bash(data.get("command"))

    elif tool == "write_file":
        decision, reason = check_write(data.get("path"))

    elif tool == "http_request":
        decision, reason = check_http(data.get("url"))

    else:
        decision, reason = "block", "Unknown tool."

    return result(decision, reason)


@app.route("/", methods=["GET"])
def health():
    return result("allow", "Guardrail endpoint is running.")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
