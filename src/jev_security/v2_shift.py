"""Experiment v2, held-out set B: same fields and truth sampler, different frameworks and idioms.

Written AFTER the regex baseline and the Jev field questions were committed (git f309979), to
simulate rules meeting a codebase they were not written for: FastAPI (dependency-injected auth,
decorator routes included via include_router), NestJS (guards, controllers registered in a module),
Terraform / cloud deployment configs, pathlib/itsdangerous/TypeORM idioms, and test paths such as
__tests__/ or seed scripts.

Bias note: the author knew the regex rules while writing these templates, so set B is likely
biased against the regex, just as set A is biased toward it. Results are reported per set.
"""

from __future__ import annotations

import random

from .reference import DISPOSITION_BY_EXPOSURE, sast_core
from .v2_evidence import CATEGORIES, PARAMS, sample_inventory, sample_truth

SEED = "20260924-v2-shift"
N_FINDINGS = 150

SENSITIVE_MODELS_B = ["BillingAccount", "MedicalClaim", "SessionSecret", "KycDocument", "PayrollEntry"]
PLAIN_MODELS_B = ["Changelog", "Wallpaper", "ReleaseNote", "FaqEntry", "StickerSet"]
VERBS = ["export", "render", "fetch", "preview", "load", "convert", "lookup", "download"]

# FastAPI (py) and NestJS (ts) fragments per category.
FA = {
    "SQL injection": {
        "sink": "rows = (await db.execute(text(f\"SELECT * FROM {T} WHERE name = '{{v}}'\"))).all()",
        "eff_pre": [],
        "eff_sink": 'rows = (await db.execute(text("SELECT * FROM {T} WHERE name = :n").bindparams(n=v))).all()',
        "partial": ['v = re.sub(r"[;]", "", v)'],
    },
    "OS command injection": {
        "sink": 'subprocess.run(f"convert {{v}} /tmp/out.png", shell=True, check=True)',
        "eff_pre": [],
        "eff_sink": 'subprocess.run(["convert", v, "/tmp/out.png"], check=True)',
        "partial": ['v = v.translate(str.maketrans("", "", ";&"))'],
    },
    "Path traversal": {
        "sink": "data = (BASE / v).read_bytes()",
        "eff_pre": [
            "target = (BASE / v).resolve()",
            "if not target.is_relative_to(BASE.resolve()):",
            "    raise HTTPException(status_code=403)",
        ],
        "eff_sink": "data = target.read_bytes()",
        "partial": ['v = v.replace("..", "", 1)'],
    },
    "Server-side request forgery": {
        "sink": "resp = await client.get(v)",
        "eff_pre": [
            "if httpx.URL(v).host not in settings.partner_hosts:",
            "    raise HTTPException(status_code=400)",
        ],
        "partial": ['if v.startswith("http://169.254"):', "    raise HTTPException(status_code=400)"],
    },
    "Cross-site scripting (reflected)": {
        "sink": 'return HTMLResponse(f"<h2>{{v}}</h2>")',
        "eff_pre": [],
        "eff_sink": 'return templates.TemplateResponse("results.html", {{"request": request, "q": v}})',
        "partial": ['v = re.sub(r"(?i)<script.*?>", "", v)'],
    },
    "Insecure deserialization": {
        "sink": "obj = pickle.loads(base64.urlsafe_b64decode(v))",
        "eff_pre": ["v = signer.unsign(v, max_age=300)  # itsdangerous: raises if the signature is invalid"],
        "partial": ["if len(v) > 8192:", "    raise HTTPException(status_code=413)"],
    },
}
NE = {
    "SQL injection": {
        "sink": "const rows = await this.dataSource.query(`SELECT * FROM {T} WHERE name = '${{v}}'`);",
        "eff_pre": [],
        "eff_sink": 'const rows = await this.repo.createQueryBuilder("t").where("t.name = :name", {{ name: v }}).getMany();',
        "partial": ['v = v.replaceAll(";", "");'],
    },
    "OS command injection": {
        "sink": "execSync(`convert ${{v}} /tmp/out.png`);",
        "eff_pre": [],
        "eff_sink": 'spawnSync("convert", [v, "/tmp/out.png"]);',
        "partial": ['v = v.replaceAll("&", "");'],
    },
    "Path traversal": {
        "sink": "const data = await readFile(join(BASE_DIR, v));",
        "eff_pre": [
            "const target = resolve(BASE_DIR, v);",
            "if (!target.startsWith(BASE_DIR + sep)) throw new ForbiddenException();",
        ],
        "eff_sink": "const data = await readFile(target);",
        "partial": ['v = v.replaceAll("../", "");'],
    },
    "Server-side request forgery": {
        "sink": "const resp = await this.http.axiosRef.get(v);",
        "eff_pre": ["if (!this.allowedHosts.includes(new URL(v).hostname)) throw new BadRequestException();"],
        "partial": ['if (v.includes("169.254")) throw new BadRequestException();'],
    },
    "Cross-site scripting (reflected)": {
        "sink": "return `<h2>${{v}}</h2>`;",
        "eff_pre": [],
        "eff_sink": "return `<h2>${{sanitizeHtml(v, {{ allowedTags: [], allowedAttributes: {{}} }})}}</h2>`;",
        "partial": ['v = v.replace("<script>", "");'],
    },
    "Insecure deserialization": {
        "sink": 'const obj = unserialize(Buffer.from(v, "base64").toString());',
        "eff_pre": ["v = this.jwt.verify(v).data;  // throws if the signature is invalid"],
        "partial": ["if (v.length > 8192) throw new PayloadTooLargeException();"],
    },
}

FA_SRC_ATTACKER = [
    '{p}: str = Query("")',
    '{p}: str = Cookie("")',
    '{p}: str = Header("", alias="x-{p}")',
    "body: {C}Request = Body(...)",
]
NE_SRC_ATTACKER = [
    "@Query('{p}') v: string",
    "@Query('{p}') v: string",
    "@Headers('x-{p}') v: string",
    "@Body() dto: {C}Dto",
]

PUBLIC_B = [
    'resource "aws_lb" "api" {\n  internal           = false\n  load_balancer_type = "application"\n}',
    'resource "google_cloud_run_v2_service" "api" {\n  ingress = "INGRESS_TRAFFIC_ALL"\n}',
    'resource "azurerm_linux_web_app" "api" {\n  public_network_access_enabled = true\n}',
]
INTERNAL_B = [
    'resource "aws_lb" "api" {\n  internal           = true\n  load_balancer_type = "application"\n}',
    'resource "google_cloud_run_v2_service" "api" {\n  ingress = "INGRESS_TRAFFIC_INTERNAL_ONLY"\n}',
    'resource "azurerm_linux_web_app" "api" {\n  public_network_access_enabled = false\n}',
]
PROD_B = {
    "py": ["app/routers/{h}.py", "src/api/v2/{h}.py"],
    "ts": ["src/modules/{h}/{h}.controller.ts", "apps/api/src/{h}.controller.ts"],
}
TEST_B = {
    "py": ["tests/conftest_{h}.py", "benchmarks/load_{h}.py", "seed/dev_{h}.py"],
    "ts": ["src/__tests__/{h}.test.ts", "e2e/fixtures/{h}.ts", "stories/{h}.stories.ts"],
}


def _ind(lines, n):
    return [(" " * n + ln) if ln else ln for ln in lines]


def build_finding(i: int, rng: random.Random) -> dict:
    lang = "py" if i % 2 == 0 else "ts"
    cat = rng.choice(list(CATEGORIES))
    cwe, severity = CATEGORIES[cat]
    t, inv = sample_truth(rng), sample_inventory(rng)
    p = rng.choice(PARAMS)
    C = p.capitalize()
    verb = rng.choice(VERBS)
    model = rng.choice(SENSITIVE_MODELS_B if t["sensitive"] else PLAIN_MODELS_B)
    T = "".join("_" + c.lower() if c.isupper() else c for c in model).lstrip("_") + "s"
    frag = (FA if lang == "py" else NE)[cat]
    tricks = []

    # source
    stored = t["attacker_controlled"] and rng.random() < 0.2
    params, first = [], []
    if lang == "py":
        if t["attacker_controlled"] and not stored:
            s = rng.choice(FA_SRC_ATTACKER).format(p=p, C=C)
            params.append(s)
            first = [f"v = body.{p}" if s.startswith("body") else f"v = {p}"]
        elif stored:
            first = ["prefs = await repo.preferences_for(user.id)", f"v = prefs.{p}"]
            tricks.append("second_order_source")
        else:
            first = [f"v = settings.default_{p}"]
    else:
        if t["attacker_controlled"] and not stored:
            s = rng.choice(NE_SRC_ATTACKER).format(p=p, C=C)
            params.append(s)
            first = [f"let v = dto.{p};"] if s.startswith("@Body") else ["let v = v0;"]
            if not s.startswith("@Body"):
                params[-1] = s.replace(" v:", " v0:")
        elif stored:
            first = [f"let v = (await this.prefs.findOneBy({{ userId: user.id }})).{p};"]
            tricks.append("second_order_source")
        else:
            first = [f"let v = this.config.get<string>('DEFAULT_{p.upper()}');"]

    # sanitization
    pre, sink = [], frag["sink"]
    if t["sanitization"] == "effective":
        pre, sink = list(frag["eff_pre"]), frag.get("eff_sink", sink)
    elif t["sanitization"] == "partial":
        pre = list(frag["partial"])
    c = "#" if lang == "py" else "//"
    if t["sanitization"] == "none" and rng.random() < 0.2:
        pre = [f"{c} validated by the API gateway schema"] + pre
        tricks.append("misleading_comment")
    sink = sink.format(T=T)

    data = (
        f"record = await db.get({model}, item_id)"
        if lang == "py"
        else f"const record = await this.dataSource.getRepository({model}).findOneBy({{ id }});"
    )

    # auth
    auth_on_router = rng.random() < 0.5
    decos = []
    router = f"{verb}_router" if lang == "py" else f"{verb.capitalize()}{C}Controller"
    handler = f"{verb}_{p}" if lang == "py" else f"{verb}{C}"
    if lang == "py":
        if t["auth"] != "none" and not auth_on_router:
            params.append(
                "user: User = Depends(get_current_user)"
                if t["auth"] == "user"
                else "user: User = Depends(require_admin_user)"
            )
        elif stored:
            params.append("user: User = Depends(get_current_user_optional)")
        params = ["item_id: int"] + params + ["db: AsyncSession = Depends(get_db)"]
        decos = [f'@{router}.get("/{p}/{{item_id}}")']
        if t["auth"] == "none" and rng.random() < 0.3:
            decos.append("@cache(expire=60)")
            tricks.append("non_auth_decorator")
        code = (
            decos
            + [f"async def {handler}(" + ", ".join(params) + "):"]
            + _ind(
                first
                + [data]
                + pre
                + [sink]
                + ([] if sink.lstrip().startswith("return") else ['return {"ok": True}']),
                4,
            )
        )
    else:
        cls_guard = []
        if t["auth"] != "none" and auth_on_router:
            cls_guard = (
                ["@UseGuards(JwtAuthGuard, RolesGuard)", "@Roles('admin')"]
                if t["auth"] == "admin"
                else ["@UseGuards(JwtAuthGuard)"]
            )
        meth = [f"@Get('{p}/:id')"]
        if t["auth"] != "none" and not auth_on_router:
            meth += (
                ["@UseGuards(JwtAuthGuard, RolesGuard)", "@Roles('admin')"]
                if t["auth"] == "admin"
                else ["@UseGuards(JwtAuthGuard)"]
            )
        if t["auth"] == "none" and rng.random() < 0.3:
            meth.append("@UseInterceptors(CacheInterceptor)")
            tricks.append("non_auth_decorator")
        sig = (
            ["@Param('id') id: number"]
            + params
            + (["@CurrentUser() user: UserEntity"] if stored or t["auth"] != "none" else [])
        )
        body = (
            first
            + [data]
            + pre
            + [sink]
            + ([] if sink.lstrip().startswith("return") else ["return { ok: true };"])
        )
        code = (
            cls_guard
            + [f"@Controller('{verb}')", f"export class {router} {{"]
            + _ind(meth + [f"async {handler}(" + ", ".join(sig) + ") {"] + _ind(body, 2) + ["}"], 2)
            + ["}"]
        )
    code_snippet = "\n".join(code)

    # registration: FastAPI include_router / NestJS module controllers
    if lang == "py":
        deps = ""
        if t["auth"] != "none" and auth_on_router:
            deps = (
                ", dependencies=[Depends(get_current_user)]"
                if t["auth"] == "user"
                else ", dependencies=[Depends(require_admin_user)]"
            )
        reg = [f'app.include_router({router}, prefix="/api"{deps})']
        other = ['app.include_router(health_router, prefix="/health")']
    else:
        reg = [f"  controllers: [HealthController, {router}],"]
        other = []
    if not t["reachable"]:
        how = rng.choice(["commented", "flag", "absent"])
        tricks.append(f"unreachable_{how}")
        if how == "commented":
            reg = [f"{c} " + ln.strip() + f"  {c} removed from the public API in v3" for ln in reg]
        elif how == "flag":
            if lang == "py":
                reg = ["if settings.legacy_endpoints_enabled:  # false in every environment"] + _ind(reg, 4)
            else:
                reg = [
                    f"  controllers: [HealthController, ...(LEGACY_ENABLED ? [{router}] : [])],  // LEGACY_ENABLED = false"
                ]
        else:
            reg = [] if lang == "py" else ["  controllers: [HealthController],"]
    if lang == "py":
        route_config = "\n".join(other + reg)
    else:
        route_config = "\n".join(
            ["@Module({", "  imports: [TypeOrmModule.forFeature([])],"]
            + reg
            + ["})", "export class AppModule {}"]
        )

    deployment = rng.choice(PUBLIC_B if t["internet"] else INTERNAL_B)
    file_path = rng.choice((TEST_B if t["test_code"] else PROD_B)[lang]).format(
        h=f"{verb}_{p}" if lang == "py" else f"{verb}-{p}"
    )
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
    e = sast_core(facts)["exposure"]
    return {
        "finding_id": f"V2B-{i:04d}",
        "set": "B",
        "lang": lang,
        "category": cat,
        "truth": t,
        "inventory": inv,
        "severity": severity,
        "tricks": tricks,
        "reference": {"exposure": e, "disposition": DISPOSITION_BY_EXPOSURE[e], "urgent": e >= 3},
        "state": {
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
        },
    }


def build(n: int = N_FINDINGS) -> list[dict]:
    rng = random.Random(SEED)
    return [build_finding(i, rng) for i in range(n)]
