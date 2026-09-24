"""GATE 4: estimate request count, tokens and cost from the smoke-test's actual usage."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from jev_security.client import build_payload  # noqa: E402
from jev_security.experiment import PHASE_ORDER, plan_requests  # noqa: E402
from jev_security.questions import QUESTIONS  # noqa: E402

smoke = json.loads(next((ROOT / "results/raw/smoke/responses").glob("*.json")).read_text())
s_chars = len(json.dumps(smoke["request_payload"], ensure_ascii=False))
s_tok = smoke["response_body"]["usage"]["input_tokens"]
s_cost = smoke["response_body"]["usage"]["cost"]
tok_per_char = s_tok / s_chars
usd_per_tok = s_cost / s_tok
print(f"smoke calibration: {s_chars} payload chars -> {s_tok} input tokens, cost ${s_cost:.9f}")
print(f"  => {tok_per_char:.4f} tokens/char, ${usd_per_tok * 1e6:.4f} per 1M input tokens\n")
tot_n = tot_tok = 0
print(f"{'phase':<12}{'requests':>10}{'est. tokens':>14}{'est. cost USD':>16}")
out = {}
for ph in PHASE_ORDER:
    plan = plan_requests(ph)
    tok = (
        sum(
            len(json.dumps(build_payload(p["state"], QUESTIONS[p["domain"]]), ensure_ascii=False))
            for p in plan
        )
        * tok_per_char
    )
    tot_n += len(plan)
    tot_tok += tok
    out[ph] = {"requests": len(plan), "est_tokens": round(tok), "est_cost_usd": tok * usd_per_tok}
    print(f"{ph:<12}{len(plan):>10}{tok:>14,.0f}{tok * usd_per_tok:>16.4f}")
cost = tot_tok * usd_per_tok
print(f"{'TOTAL':<12}{tot_n:>10}{tot_tok:>14,.0f}{cost:>16.4f}")
print(f"\nWorst case incl. one retry per request: ${2 * cost:.4f}")
print(f"Cost gate ($1.00): {'PASS - proceed' if 2 * cost <= 1.0 else 'STOP - ask for approval'}")
Path(ROOT / "results/analysis").mkdir(parents=True, exist_ok=True)
(ROOT / "results/analysis/cost_estimate.json").write_text(
    json.dumps(
        {
            "smoke_input_tokens": s_tok,
            "smoke_cost": s_cost,
            "phases": out,
            "total_requests": tot_n,
            "total_est_tokens": round(tot_tok),
            "total_est_cost_usd": cost,
        },
        indent=1,
    )
)
