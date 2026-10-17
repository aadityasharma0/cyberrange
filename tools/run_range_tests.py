#!/usr/bin/env python3
"""CyberRange test harness.

Connects to the running backend over WebSocket, plays a scripted defensive run
for each scenario concurrently, and writes two artifacts into logs/:

  * test_log_<label>.txt            - timestamped test log: events, action
                                       results, PASS/FAIL assertions, summary.
  * blocked_traffic_<label>.csv     - per-tick traffic accounting: arriving vs
                                       passed attack traffic and what defenses
                                       blocked.

Usage:
  python tools/run_range_tests.py --label before --scenarios ddos brute
  python tools/run_range_tests.py --label after  --scenarios ddos brute sqli ransom mitm
"""
import argparse
import asyncio
import csv
import json
import sys
import time
from datetime import datetime
from pathlib import Path

try:
    import websockets
except ImportError:  # pragma: no cover
    sys.exit("websockets is required: pip install websockets")

FIRST_ACTION_AT = 3.0    # seconds into the run for the first mitigation
ACTION_SPACING = 8.0     # seconds between subsequent mitigations
ISOLATE_AT = 18.0
RECONNECT_AT = 24.0
REISOLATE_AT = 30.0
SURGE_AT = 40.0
BAD_ACTION_AT = 6.0


def now():
    return datetime.now().strftime("%H:%M:%S")


class Log:
    """Line-oriented test log (sync writes are atomic inside one event loop)."""

    def __init__(self, path: Path):
        self.f = open(path, "w", encoding="utf-8")
        self.passed = 0
        self.failed = 0

    def w(self, line=""):
        self.f.write(line + "\n")
        self.f.flush()
        print(line)

    def check(self, scope, desc, ok, detail=""):
        tag = "PASS" if ok else "FAIL"
        if ok:
            self.passed += 1
        else:
            self.failed += 1
        self.w(f"[{now()}] [{scope}] {tag}: {desc}" + (f" ({detail})" if detail else ""))
        return ok


class RowWriter:
    def __init__(self, path: Path):
        self.f = open(path, "w", newline="", encoding="utf-8")
        self.csv = csv.writer(self.f)
        self.csv.writerow([
            "scenario", "t", "phase", "legit_users", "attack_arriving",
            "attack_passed", "attack_blocked", "blocked_pct", "score", "events",
        ])
        self.total = {}

    def add(self, scenario, t, phase, legit, arriving, passed, score, events):
        blocked = max(0.0, arriving - passed)
        pct = (blocked / arriving * 100.0) if arriving > 0 else 0.0
        self.csv.writerow([
            scenario, f"{t:.1f}", phase, f"{legit:.0f}", f"{arriving:.0f}",
            f"{passed:.0f}", f"{blocked:.0f}", f"{pct:.1f}", score,
            "; ".join(events),
        ])
        self.f.flush()
        acc = self.total.setdefault(scenario, dict(arriving=0.0, passed=0.0, ticks=0))
        acc["arriving"] += arriving
        acc["passed"] += passed
        acc["ticks"] += 1


async def run_scenario(url, kind, log: Log, rows: RowWriter):
    scope = kind.upper()
    t_wall = time.time()
    state = {"t": 0.0, "init": None, "end": None, "events": [], "actions": {},
             "tick_keys_ok": True, "neg_blocked": 0, "ticks": 0}
    q = asyncio.Queue()
    res_q = asyncio.Queue()

    async with websockets.connect(url, max_size=None, open_timeout=10) as ws:
        async def reader():
            try:
                async for raw in ws:
                    m = json.loads(raw)
                    ty = m.get("type")
                    if ty == "tick":
                        state["t"] = m["t"]
                        chart = m.get("chart") or [0, 0, 0]
                        legit, arriving, passed = chart[0], chart[1], chart[2]
                        evs = m.get("events") or []
                        state["events"].extend(evs)
                        for e in evs:
                            log.w(f"[{now()}] [{scope}] EVENT t={m['t']:.1f}s {e}")
                        state["ticks"] += 1
                        if not all(k in m for k in
                                   ("phase", "loads", "status", "packets", "meters",
                                    "stats", "chart", "events", "score")):
                            state["tick_keys_ok"] = False
                        if arriving - passed < -1e-6:
                            state["neg_blocked"] += 1
                        rows.add(scope, m["t"], m["phase"], legit, arriving, passed,
                                 m["score"], evs)
                    elif ty == "init":
                        state["init"] = m
                        await q.put(m)
                    elif ty == "result":
                        await res_q.put(m)
                    elif ty == "end":
                        state["end"] = m
                        await q.put(m)
            except websockets.ConnectionClosed:
                pass

        reader_task = asyncio.create_task(reader())

        async def wait_t(target):
            while state["t"] < target and state["end"] is None:
                await asyncio.sleep(0.05)

        async def send_and_expect(msg, desc, expect_ok=True):
            await ws.send(json.dumps(msg))
            try:
                r = await asyncio.wait_for(res_q.get(), 8)
            except asyncio.TimeoutError:
                log.check(scope, desc, False, "no result from server")
                return None
            log.check(scope, desc, bool(r.get("ok")) == expect_ok, r.get("msg", ""))
            state["actions"][json.dumps(msg, sort_keys=True)] = r
            return r

        await ws.send(json.dumps({"type": "start", "kind": kind}))
        try:
            await asyncio.wait_for(q.get(), 10)
        except asyncio.TimeoutError:
            log.check(scope, "received init message", False, "timeout")
            reader_task.cancel()
            return state

        init = state["init"]
        log.w(f"[{now()}] [{scope}] START '{init['name']}' "
              f"nodes={len(init['nodes'])} edges={len(init['edges'])} "
              f"actions={len(init['actions'])} duration={init['duration']}s")
        log.check(scope, "init has nodes/edges/actions",
                  bool(init["nodes"]) and bool(init["edges"]) and bool(init["actions"]))
        log.check(scope, "every action carries id/label/desc/pts",
                  all(set(("id", "label", "desc", "pts")) <= set(a) for a in init["actions"]))
        log.check(scope, "negative-point trap action exists",
                  any(a["pts"] < 0 for a in init["actions"]))

        positive = [a for a in init["actions"] if a["pts"] > 0]
        isolate_node = next((n["id"] for n in init["nodes"]
                             if n.get("type") == "attacker"), None)

        async def plan():
            await wait_t(BAD_ACTION_AT)
            await send_and_expect({"type": "action", "id": "does_not_exist"},
                                  "unknown action rejected", expect_ok=False)
            for k, a in enumerate(positive):
                target = FIRST_ACTION_AT + k * ACTION_SPACING
                await wait_t(target)
                await send_and_expect({"type": "action", "id": a["id"]},
                                      f"apply '{a['label']}' (+{a['pts']})")
                r = state["actions"].get(json.dumps({"type": "action", "id": a["id"]},
                                                    sort_keys=True))
                if r and r.get("ok"):
                    again = await send_and_expect({"type": "action", "id": a["id"]},
                                                  f"re-apply '{a['label']}' is refused",
                                                  expect_ok=False)
                    if again is not None:
                        log.check(scope, "duplicate action reports already active",
                                  not again.get("ok") or "already" in again.get("msg", "").lower(),
                                  again.get("msg", ""))
            if isolate_node:
                await wait_t(ISOLATE_AT)
                r = await send_and_expect({"type": "isolate", "node": isolate_node},
                                          f"isolate attack source '{isolate_node}'")
                if r:
                    log.check(scope, "isolate message mentions isolation",
                              "isolat" in r.get("msg", "").lower(), r.get("msg", ""))
                await wait_t(RECONNECT_AT)
                r = await send_and_expect({"type": "isolate", "node": isolate_node},
                                          f"reconnect '{isolate_node}'")
                if r:
                    log.check(scope, "reconnect message mentions reconnection",
                              "reconnect" in r.get("msg", "").lower(), r.get("msg", ""))
                await wait_t(REISOLATE_AT)
                await send_and_expect({"type": "isolate", "node": isolate_node},
                                      f"isolate '{isolate_node}' again")
            await wait_t(SURGE_AT)
            await send_and_expect({"type": "trainer", "event": "surge"},
                                  "trainer injects surge")

        plan_task = asyncio.create_task(plan())
        end = await asyncio.wait_for(q.get(), 180)
        await plan_task
        reader_task.cancel()

    e = state["end"] or end
    log.check(scope, "end message has outcome/score/feedback",
              e.get("type") == "end" and "outcome" in e and "score" in e and "feedback" in e)
    log.check(scope, "outcome is a known value",
              e.get("outcome") in ("success", "partial", "failure"), str(e.get("outcome")))
    log.check(scope, "score within 0..max",
              isinstance(e.get("score"), int) and 0 <= e["score"] <= e.get("max", 0),
              f"{e.get('score')}/{e.get('max')}")
    log.check(scope, "feedback explains missed/mistaken actions",
              len(e.get("feedback") or []) >= 2, f"{len(e.get('feedback') or [])} items")
    log.check(scope, "events were emitted during the run", len(state["events"]) >= 1,
              f"{len(state['events'])} events")
    log.check(scope, "all ticks carried the full payload", state["tick_keys_ok"],
              f"{state['ticks']} ticks checked")
    log.check(scope, "attack_blocked never negative in any tick", state["neg_blocked"] == 0,
              f"{state['neg_blocked']} bad ticks")

    acc = rows.total.get(scope, dict(arriving=0.0, passed=0.0, ticks=0))
    blocked = acc["arriving"] - acc["passed"]
    pct = (blocked / acc["arriving"] * 100.0) if acc["arriving"] else 0.0
    log.w(f"[{now()}] [{scope}] END outcome={e.get('outcome')} "
          f"score={e.get('score')}/{e.get('max')} "
          f"attack_arriving={acc['arriving']:,.0f} attack_passed={acc['passed']:,.0f} "
          f"attack_blocked={blocked:,.0f} ({pct:.1f}%) ticks={acc['ticks']} "
          f"wall={time.time()-t_wall:.1f}s")
    for f in e.get("feedback") or []:
        log.w(f"[{now()}] [{scope}] FEEDBACK[{f.get('k')}] {f.get('text')}")
    state["summary"] = dict(outcome=e.get("outcome"), score=e.get("score"),
                            max=e.get("max"), arriving=acc["arriving"],
                            passed=acc["passed"], blocked=blocked, blocked_pct=pct,
                            ticks=acc["ticks"], events=len(state["events"]))
    return state


async def main_async(args):
    root = Path(__file__).resolve().parent.parent
    logs = root / "logs"
    logs.mkdir(exist_ok=True)
    log = Log(logs / f"test_log_{args.label}.txt")
    rows = RowWriter(logs / f"blocked_traffic_{args.label}.csv")
    log.w("=" * 78)
    log.w(f"Cyberrange test run - label={args.label} - url={args.url}")
    log.w(f"scenarios={','.join(args.scenarios)} - started {datetime.now().isoformat()}")
    log.w("=" * 78)

    results = await asyncio.gather(
        *[run_scenario(args.url, k, log, rows) for k in args.scenarios],
        return_exceptions=True,
    )
    summaries = []
    for kind, r in zip(args.scenarios, results):
        if isinstance(r, Exception):
            log.check(kind, "scenario run completed", False, repr(r))
        elif r and r.get("summary"):
            summaries.append((kind, r["summary"]))

    log.w("-" * 78)
    log.w("SUMMARY")
    for kind, s in summaries:
        log.w(f"  {kind:8s} outcome={s['outcome']:8s} score={s['score']:3d}/{s['max']} "
              f"blocked={s['blocked']:,.0f}/{s['arriving']:,.0f} "
              f"({s['blocked_pct']:.1f}%) events={s['events']} ticks={s['ticks']}")
    log.w(f"  assertions: {log.passed} passed, {log.failed} failed")
    log.w(f"  artifacts: {logs / ('test_log_' + args.label + '.txt')}")
    log.w(f"             {logs / ('blocked_traffic_' + args.label + '.csv')}")
    log.w(f"finished {datetime.now().isoformat()}")
    log.f.close()
    rows.f.close()
    return 1 if log.failed else 0


def main():
    p = argparse.ArgumentParser(description="CyberRange scripted test run")
    p.add_argument("--url", default="ws://127.0.0.1:8010/ws")
    p.add_argument("--label", required=True, help="before / after / ... (file suffix)")
    p.add_argument("--scenarios", nargs="+", required=True)
    args = p.parse_args()
    sys.exit(asyncio.run(main_async(args)))


if __name__ == "__main__":
    main()
