"""Experiment v2: can Jev turn RAW evidence into the fields a deterministic rule needs?

v1 handed Jev pre-verified fields, which is the one situation where a rule (or the human who
verified them) doesn't need a model. v2 tests the step before that: a SAST finding arrives
with only raw evidence (file path, code snippet, route registration, deployment config), and
somebody has to work out

    attacker_controlled, reachable, sanitization, auth, internet, test_code, sensitive

before any priority can be computed. The true value of each field is known by construction.
Inventory metadata that a CMDB would supply (asset criticality, process privilege,
preconditions, compensating control) and the scanner's category severity are given as facts.

Every extraction pipeline feeds its fields into the SAME frozen v1 rubric (reference.sast_core),
so the only thing that differs between pipelines is how well they read the evidence.

All code is synthetic and harmless: it shows vulnerable *patterns* (string-built SQL, shell
string, unchecked path join, ...) with no payloads or exploit instructions.
"""

from __future__ import annotations

import hashlib
import json
import random
import re

from .reference import DISPOSITION_BY_EXPOSURE, sast_core

SEED = "20260924-v2-evidence"
N_FINDINGS = 300

CATEGORIES = {
    # category: (cwe, scanner severity)
    "SQL injection": ("CWE-89", "CRITICAL"),
    "OS command injection": ("CWE-78", "CRITICAL"),
    "Path traversal": ("CWE-22", "HIGH"),
    "Server-side request forgery": ("CWE-918", "HIGH"),
    "Cross-site scripting (reflected)": ("CWE-79", "MEDIUM"),
    "Insecure deserialization": ("CWE-502", "HIGH"),
}

SENSITIVE_MODELS = ["Invoice", "PaymentMethod", "PatientRecord", "ApiToken", "UserCredential"]
PLAIN_MODELS = ["ColorTheme", "BlogPost", "FeatureBanner", "PublicDoc", "EmojiPack"]
PARAMS = ["name", "report", "target", "file", "url", "query", "doc", "template", "path", "q"]
HANDLER_VERBS = ["export", "render", "fetch", "preview", "load", "convert", "search", "download"]

# ---------------------------------------------------------------------------
# Language fragments. {v} = variable holding the value, {M} = model, {p} = param
# ---------------------------------------------------------------------------

PY_SOURCE_ATTACKER = [
    'v = request.args.get("{p}", "")',
    'v = request.form["{p}"]',
    'v = (request.get_json() or {{}}).get("{p}", "")',
    'v = request.headers.get("X-{P}", "")',
]
PY_SOURCE_STORED = [  # second-order: value a user saved earlier, read back from storage
    "v = UserPreference.query.filter_by(user_id=current_user.id).one().{p}",
]
PY_SOURCE_INTERNAL = [
    'v = current_app.config["DEFAULT_{P}"]',
    'v = os.environ.get("{P}_NAME", "default")',
    'v = SERVER_SETTINGS["{p}"]',
]
JS_SOURCE_ATTACKER = [
    "let v = req.query.{p};",
    "let v = req.body.{p};",
    "let v = req.params.{p};",
    'let v = req.get("X-{P}");',
]
JS_SOURCE_STORED = [
    "let v = (await Preference.findOne({{ userId: req.user.id }})).{p};",
]
JS_SOURCE_INTERNAL = [
    "let v = process.env.{P}_NAME;",
    "let v = config.defaults.{p};",
    'let v = SERVER_SETTINGS["{p}"];',
]

# Per category and language: sink lines, inline sanitizers, and helper-function sanitizers.
# "effective" variants are ones that genuinely neutralize the pattern; "partial" ones filter
# something but are bypassable; "none" has nothing.
PY = {
    "SQL injection": {
        "sink": "rows = db.execute(f\"SELECT * FROM {T} WHERE name = '{{v}}'\")",
        "sink_effective": 'rows = db.execute("SELECT * FROM {T} WHERE name = %s", (v,))',
        "partial": ['v = v.replace(";", "")'],
        "helper_effective": ["if x not in ALLOWED_NAMES:", "    abort(400)", "return x"],
        "helper_partial": ['return x.replace("--", "").strip()'],
    },
    "OS command injection": {
        "sink": 'subprocess.run(f"convert {{v}} /tmp/out.png", shell=True)',
        "sink_effective": 'subprocess.run(["convert", v, "/tmp/out.png"], shell=False)',
        "effective_pre": ['if not re.fullmatch(r"[A-Za-z0-9_.-]{{1,64}}", v):', "    abort(400)"],
        "partial": ['v = v.replace(";", "").replace("&", "")'],
        "helper_effective": ["return shlex.quote(x)"],
        "helper_partial": ['return x.replace("|", "")'],
    },
    "Path traversal": {
        "sink": "data = open(os.path.join(BASE_DIR, v)).read()",
        "effective_pre": [
            "p = os.path.realpath(os.path.join(BASE_DIR, v))",
            "if not p.startswith(BASE_DIR + os.sep):",
            "    abort(403)",
        ],
        "sink_effective": "data = open(p).read()",
        "partial": ['v = v.replace("../", "")'],
        "helper_effective": [
            "p = os.path.realpath(os.path.join(BASE_DIR, x))",
            "if not p.startswith(BASE_DIR + os.sep):",
            "    abort(403)",
            "return os.path.relpath(p, BASE_DIR)",
        ],
        "helper_partial": ['return x.lstrip("/")'],
    },
    "Server-side request forgery": {
        "sink": "resp = requests.get(v, timeout=5)",
        "effective_pre": ["if urlparse(v).hostname not in ALLOWED_HOSTS:", "    abort(400)"],
        "partial": ['if "localhost" in v:', "    abort(400)"],
        "helper_effective": ["if urlparse(x).hostname not in ALLOWED_HOSTS:", "    abort(400)", "return x"],
        "helper_partial": ['if x.startswith("http://127."):', "    abort(400)", "return x"],
    },
    "Cross-site scripting (reflected)": {
        "sink": 'return f"<p>Results for {{v}}</p>"',
        "sink_effective": 'return render_template("results.html", q=v)',
        "partial": ['v = v.replace("<script>", "")'],
        "helper_effective": ["return markupsafe.escape(x)"],
        "helper_partial": ['return x.replace("<script>", "").replace("</script>", "")'],
    },
    "Insecure deserialization": {
        "sink": "obj = pickle.loads(base64.b64decode(v))",
        "effective_pre": [
            'raw, sig = v.rsplit(".", 1)',
            'if not hmac.compare_digest(sig, hmac.new(SIGNING_KEY, raw.encode(), "sha256").hexdigest()):',
            "    abort(403)",
            "v = raw",
        ],
        "partial": ["if len(v) > 4096:", "    abort(413)"],
        "helper_effective": [
            'raw, sig = x.rsplit(".", 1)',
            'if not hmac.compare_digest(sig, hmac.new(SIGNING_KEY, raw.encode(), "sha256").hexdigest()):',
            "    abort(403)",
            "return raw",
        ],
        "helper_partial": ["if len(x) > 4096:", "    abort(413)", "return x"],
    },
}
JS = {
    "SQL injection": {
        "sink": "const rows = await db.query(`SELECT * FROM {T} WHERE name = '${{v}}'`);",
        "sink_effective": 'const rows = await db.query("SELECT * FROM {T} WHERE name = ?", [v]);',
        "partial": ['v = v.replace(/;/g, "");'],
        "helper_effective": ["if (!ALLOWED_NAMES.has(x)) throw new HttpError(400);", "return x;"],
        "helper_partial": ['return x.replace(/--/g, "").trim();'],
    },
    "OS command injection": {
        "sink": "exec(`convert ${{v}} /tmp/out.png`);",
        "sink_effective": 'execFile("convert", [v, "/tmp/out.png"]);',
        "effective_pre": ["if (!/^[A-Za-z0-9_.-]{{1,64}}$/.test(v)) return res.status(400).end();"],
        "partial": ['v = v.replace(/;/g, "").replace(/&/g, "");'],
        "helper_effective": ["return shellEscape([x]);"],
        "helper_partial": ['return x.replace(/\\|/g, "");'],
    },
    "Path traversal": {
        "sink": "const data = fs.readFileSync(path.join(BASE_DIR, v));",
        "effective_pre": [
            "const p = path.resolve(BASE_DIR, v);",
            "if (!p.startsWith(BASE_DIR + path.sep)) return res.status(403).end();",
        ],
        "sink_effective": "const data = fs.readFileSync(p);",
        "partial": ['v = v.replace("../", "");'],
        "helper_effective": [
            "const p = path.resolve(BASE_DIR, x);",
            "if (!p.startsWith(BASE_DIR + path.sep)) throw new HttpError(403);",
            "return path.relative(BASE_DIR, p);",
        ],
        "helper_partial": ['return x.replace(/^\\/+/, "");'],
    },
    "Server-side request forgery": {
        "sink": "const resp = await fetch(v);",
        "effective_pre": ["if (!ALLOWED_HOSTS.has(new URL(v).hostname)) return res.status(400).end();"],
        "partial": ['if (v.includes("localhost")) return res.status(400).end();'],
        "helper_effective": [
            "if (!ALLOWED_HOSTS.has(new URL(x).hostname)) throw new HttpError(400);",
            "return x;",
        ],
        "helper_partial": ['if (x.startsWith("http://127.")) throw new HttpError(400);', "return x;"],
    },
    "Cross-site scripting (reflected)": {
        "sink": "return res.send(`<p>Results for ${{v}}</p>`);",
        "sink_effective": 'return res.render("results", {{ q: v }});',
        "partial": ['v = v.replace("<script>", "");'],
        "helper_effective": ["return escapeHtml(x);"],
        "helper_partial": ['return x.replace("<script>", "");'],
    },
    "Insecure deserialization": {
        "sink": 'const obj = serialize.unserialize(Buffer.from(v, "base64").toString());',
        "effective_pre": [
            'const [raw, sig] = v.split(".");',
            'if (sig !== crypto.createHmac("sha256", SIGNING_KEY).update(raw).digest("hex")) return res.status(403).end();',
            "v = raw;",
        ],
        "partial": ["if (v.length > 4096) return res.status(413).end();"],
        "helper_effective": [
            'const [raw, sig] = x.split(".");',
            'if (sig !== crypto.createHmac("sha256", SIGNING_KEY).update(raw).digest("hex")) throw new HttpError(403);',
            "return raw;",
        ],
        "helper_partial": ["if (x.length > 4096) throw new HttpError(413);", "return x;"],
    },
}

MISLEADING_NONE_COMMENT = {
    "py": "# input is sanitized upstream by the gateway",
    "js": "// input is validated upstream by the gateway",
}
MISLEADING_EFFECTIVE_COMMENT = {"py": "# TODO: add input validation", "js": "// TODO: add input validation"}

PUBLIC_DEPLOYMENTS = [
    "service:\n  type: LoadBalancer\n  annotations:\n    service.beta.kubernetes.io/aws-load-balancer-scheme: internet-facing",
    "ingress:\n  className: public-nginx\n  host: api.example.com\n  tls: true",
    "cloudrun:\n  ingress: all\n  allow_unauthenticated_invocations: true",
]
INTERNAL_DEPLOYMENTS = [
    "service:\n  type: ClusterIP\n  # only reachable from inside the cluster",
    "ingress:\n  className: internal-nginx\n  host: reports.corp.internal",
    "service:\n  type: LoadBalancer\n  annotations:\n    service.beta.kubernetes.io/aws-load-balancer-scheme: internal",
]
PROD_PATHS = {
    "py": ["app/api/{h}.py", "services/{h}/views.py", "src/web/routes/{h}.py"],
    "js": ["src/routes/{h}.js", "server/api/{h}.js", "app/controllers/{h}.js"],
}
TEST_PATHS = {
    "py": ["tests/test_{h}.py", "tests/fixtures/{h}_app.py", "scripts/dev_seed_{h}.py"],
    "js": ["test/{h}.spec.js", "spec/fixtures/{h}.js", "tools/local-debug-{h}.js"],
}


def _w(rng, pairs):
    vals, weights = zip(*pairs)
    return rng.choices(vals, weights=weights)[0]


def sample_truth(rng: random.Random) -> dict:
    return {
        "attacker_controlled": rng.random() < 0.70,
        "reachable": rng.random() < 0.80,
        "sanitization": _w(rng, [("none", 45), ("partial", 25), ("effective", 30)]),
        "auth": _w(rng, [("none", 45), ("user", 35), ("admin", 20)]),
        "internet": rng.random() < 0.60,
        "test_code": rng.random() < 0.15,
        "sensitive": rng.random() < 0.50,
    }


def sample_inventory(rng: random.Random) -> dict:
    return {
        "asset": _w(rng, [("low", 15), ("medium", 25), ("high", 35), ("critical", 25)]),
        "privilege": _w(rng, [("restricted", 20), ("standard", 65), ("elevated", 15)]),
        "preconditions": _w(rng, [("none", 80), ("moderate", 15), ("significant", 5)]),
        "control": _w(rng, [("none", 60), ("partial", 25), ("effective", 15)]),
    }


def _indent(lines, n):
    return [(" " * n + ln) if ln else ln for ln in lines]


def build_finding(i: int, rng: random.Random) -> dict:
    lang = "py" if i % 2 == 0 else "js"
    cat = rng.choice(list(CATEGORIES))
    cwe, severity = CATEGORIES[cat]
    t = sample_truth(rng)
    inv = sample_inventory(rng)
    p = rng.choice(PARAMS)
    handler = f"{rng.choice(HANDLER_VERBS)}_{p}_{rng.randint(10, 99)}"
    if lang == "js":
        handler = re.sub(r"_(\w)", lambda m: m.group(1).upper(), handler)
    model = rng.choice(SENSITIVE_MODELS if t["sensitive"] else PLAIN_MODELS)
    table = re.sub(r"(?<!^)([A-Z])", r"_\1", model).lower() + "s"
    frag = (PY if lang == "py" else JS)[cat]
    tricks = []

    # --- source ---------------------------------------------------------------
    if t["attacker_controlled"]:
        if rng.random() < 0.2:
            src = rng.choice(PY_SOURCE_STORED if lang == "py" else JS_SOURCE_STORED)
            tricks.append("second_order_source")
        else:
            src = rng.choice(PY_SOURCE_ATTACKER if lang == "py" else JS_SOURCE_ATTACKER)
    else:
        src = rng.choice(PY_SOURCE_INTERNAL if lang == "py" else JS_SOURCE_INTERNAL)
    src = src.format(p=p, P=p.upper())

    # --- sanitization -----------------------------------------------------------
    helper, pre, sink = [], [], frag["sink"]
    style = "inline"
    if t["sanitization"] != "none" and rng.random() < 0.4:
        style = "helper"
        tricks.append("opaque_helper")
        body = frag["helper_effective" if t["sanitization"] == "effective" else "helper_partial"]
        hname = (
            rng.choice(["clean_value", "normalize_input", "prepare_arg"])
            if lang == "py"
            else rng.choice(["cleanValue", "normalizeInput", "prepareArg"])
        )
        if lang == "py":
            helper = [f"def {hname}(x):"] + _indent(body, 4) + [""]
        else:
            helper = [f"function {hname}(x) {{"] + _indent(body, 2) + ["}", ""]
        pre = [f"v = {hname}(v)" if lang == "py" else f"v = {hname}(v);"]
    elif t["sanitization"] == "effective":
        pre = list(frag.get("effective_pre", []))
        sink = frag.get("sink_effective", sink)
    elif t["sanitization"] == "partial":
        pre = list(frag["partial"])
    if t["sanitization"] == "none" and rng.random() < 0.2:
        pre = [MISLEADING_NONE_COMMENT[lang]] + pre
        tricks.append("misleading_comment")
    if t["sanitization"] == "effective" and rng.random() < 0.15:
        pre = [MISLEADING_EFFECTIVE_COMMENT[lang]] + pre
        tricks.append("misleading_todo")
    sink = sink.format(T=table)
    pre = [ln.format() if "{{" in ln else ln for ln in pre]

    # --- data touched (sensitivity evidence) -------------------------------------
    if lang == "py":
        data_line = f"record = db.session.get({model}, request.view_args.get('id'))"
    else:
        data_line = f"const record = await {model}.findByPk(req.params.id);"

    # --- auth: decorator in code, middleware in route config, or nothing -----------
    auth_in_route = rng.random() < 0.5
    decorators = []
    if lang == "py" and t["auth"] != "none" and not auth_in_route:
        decorators = ["@login_required"] if t["auth"] == "user" else ['@roles_required("admin")']
    if lang == "py" and t["auth"] == "none" and rng.random() < 0.3:
        decorators = ["@cache.cached(timeout=60)"]
        tricks.append("non_auth_decorator")
    if lang == "js" and t["auth"] != "none":
        auth_in_route = True

    # --- snippet -------------------------------------------------------------------
    if lang == "py":
        body = [src, data_line] + pre + [sink]
        if not sink.lstrip().startswith("return"):
            body.append("return jsonify(ok=True)")
        code = helper + decorators + [f"def {handler}():"] + _indent(body, 4)
    else:
        body = [src, data_line] + pre + [sink]
        if not sink.lstrip().startswith("return"):
            body.append("return res.json({ ok: true });")
        code = helper + [f"async function {handler}(req, res) {{"] + _indent(body, 2) + ["}"]
    code_snippet = "\n".join(code)

    # --- route registration (reachability + route-level auth) ----------------------
    other = f"{rng.choice(HANDLER_VERBS)}_status" if lang == "py" else f"{rng.choice(HANDLER_VERBS)}Status"
    mw = {"user": "requireAuth", "admin": "requireAdmin"}.get(t["auth"])
    route = f"/{p}/{rng.randint(1, 9)}"
    if lang == "py":
        if t["auth"] != "none" and auth_in_route:
            bp = "admin_bp" if t["auth"] == "admin" else "account_bp"
            guard = "require_admin" if t["auth"] == "admin" else "require_login"
            reg = [f"{bp}.before_request({guard})", f'{bp}.add_url_rule("{route}", view_func={handler})']
        else:
            reg = [f'app.add_url_rule("{route}", view_func={handler})']
        others = [f'app.add_url_rule("/status", view_func={other})']
    else:
        if mw:
            reg = [f'router.get("{route}", {mw}, {handler});']
        else:
            reg = [f'router.get("{route}", {handler});']
        others = [f'router.get("/status", {other});']
    if not t["reachable"]:
        how = rng.choice(["commented", "flag", "absent"])
        tricks.append(f"unreachable_{how}")
        c = "#" if lang == "py" else "//"
        if how == "commented":
            reg = [f"{c} {ln}  {c} disabled after the 2025 migration" for ln in reg]
        elif how == "flag":
            if lang == "py":
                reg = ["ENABLE_LEGACY_ROUTES = False", "if ENABLE_LEGACY_ROUTES:"] + _indent(reg, 4)
            else:
                reg = (
                    ["const ENABLE_LEGACY_ROUTES = false;", "if (ENABLE_LEGACY_ROUTES) {"]
                    + _indent(reg, 2)
                    + ["}"]
                )
        else:
            reg = []
    route_config = "\n".join(others + reg)

    deployment = rng.choice(PUBLIC_DEPLOYMENTS if t["internet"] else INTERNAL_DEPLOYMENTS)
    file_path = rng.choice((TEST_PATHS if t["test_code"] else PROD_PATHS)[lang]).format(h=handler.lower())
    if t["test_code"] and file_path.startswith(("scripts/", "tools/")):
        tricks.append("test_path_without_test_word")

    facts = {
        "severity": severity,
        **inv,
        "attacker_controlled": t["attacker_controlled"],
        "reachable": t["reachable"],
        "sanitization": t["sanitization"],
        "auth": t["auth"],
        "internet": t["internet"],
        "sensitive": t["sensitive"],
        "environment": "test_code" if t["test_code"] else "production",
    }
    ref = sast_core(facts)
    state = {
        "finding": {
            "rule_id": f"R{rng.randint(1000, 9999)}",
            "category": cat,
            "cwe": cwe,
            "scanner_severity": severity,
            "message": f"Possible {cat.lower()}: data may reach a dangerous sink in {handler}.",
        },
        "file_path": file_path,
        "code_snippet": code_snippet,
        "route_config": route_config,
        "deployment": deployment,
    }
    return {
        "finding_id": f"V2-{i:04d}",
        "lang": lang,
        "category": cat,
        "truth": t,
        "inventory": inv,
        "severity": severity,
        "tricks": tricks,
        "sanitizer_style": style,
        "reference": {
            "exposure": ref["exposure"],
            "disposition": DISPOSITION_BY_EXPOSURE[ref["exposure"]],
            "urgent": ref["exposure"] >= 3,
        },
        "state": state,
    }


def build(n: int = N_FINDINGS) -> list[dict]:
    rng = random.Random(SEED)
    return [build_finding(i, rng) for i in range(n)]


def fields_to_facts(fields: dict, finding: dict) -> dict:
    """Combine extracted fields with inventory metadata for the frozen rubric."""
    return {
        "severity": finding["severity"],
        **finding["inventory"],
        "attacker_controlled": bool(fields["attacker_controlled"]),
        "reachable": bool(fields["reachable"]),
        "sanitization": fields["sanitization"],
        "auth": fields["auth"],
        "internet": bool(fields["internet"]),
        "sensitive": bool(fields["sensitive"]),
        "environment": "test_code" if fields["test_code"] else "production",
    }


def decide(fields: dict, finding: dict) -> dict:
    e = sast_core(fields_to_facts(fields, finding))["exposure"]
    return {"exposure": e, "disposition": DISPOSITION_BY_EXPOSURE[e], "urgent": e >= 3}


# ---------------------------------------------------------------------------
# Regex / keyword baseline: the rules a practitioner would write in an afternoon
# without a model. Written before any Jev or frontier output was seen.
# ---------------------------------------------------------------------------

SAFE_MARKERS = [
    r"%s",
    r"\?\"?,\s*\[",
    r"shlex\.quote",
    r"shellEscape",
    r"execFile\(",
    r"shell=False",
    r"realpath",
    r"path\.resolve",
    r"ALLOWED_HOSTS",
    r"ALLOWED_NAMES",
    r"escape",
    r"render_template",
    r"res\.render",
    r"hmac",
    r"createHmac",
    r"fullmatch",
    r"\.test\(v\)",
]
PARTIAL_MARKERS = [
    r"\.replace\(",
    r"\.strip\(",
    r"\.trim\(",
    r"lstrip",
    r"length\s*>",
    r"len\(",
    r"includes\(",
    r"startswith\(",
    r"startsWith\(\"http",
]
SENSITIVE_WORDS = r"(?i)(user|payment|patient|token|password|credential|invoice|ssn|card)"


def regex_fields(state: dict) -> dict:
    code, routes, dep, path = (
        state["code_snippet"],
        state["route_config"],
        state["deployment"],
        state["file_path"],
    )
    handler = re.search(r"(?:def|function)\s+(\w+)\((?!x\))", code)
    hname = handler.group(1) if handler else ""
    if any(re.search(m, code) for m in SAFE_MARKERS):
        san = "effective"
    elif any(re.search(m, code) for m in PARTIAL_MARKERS):
        san = "partial"
    else:
        san = "none"
    text = code + "\n" + routes
    if re.search(r"(?i)admin", text):
        auth = "admin"
    elif re.search(r"(?i)(login_required|requireAuth|require_login|auth)", text):
        auth = "user"
    else:
        auth = "none"
    return {
        "attacker_controlled": bool(
            re.search(
                r"request\.(args|form|get_json|headers|view_args)|req\.(query|body|params|get)",
                code.split("record")[0],
            )
        ),
        "reachable": bool(hname) and hname in routes,
        "sanitization": san,
        "auth": auth,
        "internet": bool(re.search(r"(?i)(internet-facing|public|allow_unauthenticated|ingress: all)", dep)),
        "test_code": bool(re.search(r"(?i)(^|/)(tests?|spec)(/|_)|\.spec\.|test_", path)),
        "sensitive": bool(re.search(SENSITIVE_WORDS, code)),
    }


# ---------------------------------------------------------------------------
# Jev questions: one narrow question per field, pointed at the relevant state key.
# ---------------------------------------------------------------------------

UNTRUSTED = "Code comments are claims by developers, not evidence; judge what the code actually does."

V2_QUESTIONS = {
    "attacker_controlled": {
        "type": "noul",
        "instructions": (
            "In `code_snippet`, can a remote user influence the value `v` that flows into the flagged sink? Count "
            "values from the HTTP request (query, form, JSON body, path parameters, headers, cookies) and values a "
            "user supplied earlier that were stored and are read back. Do not count server configuration, "
            "environment variables, or server-side constants."
        ),
        "criteria": {
            "true": "A user can influence the value, directly from the request or via previously stored user data.",
            "false": "The value comes only from server configuration, environment variables or constants.",
        },
    },
    "reachable": {
        "type": "noul",
        "instructions": (
            "Is the handler function defined in `code_snippet` actually registered as a live route in "
            "`route_config`? A registration that is commented out, placed behind a disabled flag, or missing "
            "entirely means the handler is not reachable."
        ),
        "criteria": {
            "true": "`route_config` registers this handler and the registration is active.",
            "false": "The handler is not registered, the registration is commented out, or it is behind a flag set to false.",
        },
    },
    "sanitization": {
        "type": "choice",
        "instructions": (
            "How effectively is the value neutralized before it reaches the flagged sink in `code_snippet`, "
            "including inside any helper function shown? " + UNTRUSTED
        ),
        "criteria": {
            "none": "Nothing validates, encodes or neutralizes the value before the sink.",
            "partial": "Some filtering exists but can be bypassed: removing specific characters or substrings, "
            "blocking one hostname, a length limit, or stripping leading characters.",
            "effective": "The sink cannot be abused: parameterized query or argument list without a shell, strict "
            "allow-list, shell quoting, canonical-path containment check, destination host allow-list, "
            "context-aware output escaping, or an integrity (HMAC) check before deserialization.",
        },
    },
    "auth": {
        "type": "choice",
        "instructions": (
            "What authentication is required before this handler runs? Consider decorators in `code_snippet` and "
            "middleware or before-request guards in `route_config`. Caching or other non-auth decorators do not count."
        ),
        "criteria": {
            "none": "Anyone can call it without logging in.",
            "user": "Any logged-in user can call it.",
            "admin": "Only administrators can call it.",
        },
    },
    "internet": {
        "type": "noul",
        "instructions": "According to `deployment`, can this service be reached from the public internet?",
        "criteria": {
            "true": "The deployment exposes the service publicly (internet-facing load balancer, public ingress, unauthenticated public invocation).",
            "false": "The deployment is internal only (cluster-internal service, internal ingress or internal load balancer).",
        },
    },
    "test_code": {
        "type": "noul",
        "instructions": (
            "Judging by `file_path`, is this test code, a test fixture, or a development-only script or "
            "tool that is not deployed to production?"
        ),
        "criteria": {
            "true": "Test, fixture, or local development/seed/debug code that does not run in production.",
            "false": "Application code that is deployed and runs in production.",
        },
    },
    "sensitive": {
        "type": "noul",
        "instructions": (
            "Does the handler in `code_snippet` read or write sensitive data, such as credentials, API "
            "tokens, payment details, invoices, personal or health records?"
        ),
        "criteria": {
            "true": "It touches sensitive records such as credentials, tokens, payment, invoice, personal or health data.",
            "false": "It only touches non-sensitive data such as themes, public posts, banners, public docs or emoji.",
        },
    },
}

FIELDS = list(V2_QUESTIONS)
CHOICE_FIELDS = {"sanitization": ["none", "partial", "effective"], "auth": ["none", "user", "admin"]}

# Pre-registered routing rule for "send to a human to verify"
NOUL_UNCERTAIN = (0.25, 0.75)
CHOICE_CONF_MIN = 0.40


def jev_fields(answers: dict) -> tuple[dict, bool]:
    """Fields from a Jev response + whether any answer falls in the pre-registered uncertainty band."""
    f, unsure = {}, False
    for k in FIELDS:
        a = answers[k]
        if a["type"] == "noul":
            f[k] = a["noul"] >= 0.5
            unsure |= NOUL_UNCERTAIN[0] <= a["noul"] <= NOUL_UNCERTAIN[1]
        else:
            f[k] = a["choice"]
            unsure |= (a.get("confidence") or 0) < CHOICE_CONF_MIN
    return f, unsure


def dataset_hash(findings: list[dict]) -> str:
    return hashlib.sha256(json.dumps(findings, sort_keys=True).encode()).hexdigest()
