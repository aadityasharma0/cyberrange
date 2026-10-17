#!/usr/bin/env python3
"""Scripted test for session controls and the expanded instructor toolset.

Verifies over WebSocket:
  * pause freezes the clock (no ticks arrive) and resume restarts it,
  * restart re-inits the same scenario and resets the clock extras,
  * instructor: skip to next phase, +15s bonus time, injected alert, grade-now,
  * abort ends the session cleanly.

Exit code 0 = all checks pass.
"""
import asyncio
import json
import sys

import websockets

URL = "ws://127.0.0.1:8010/ws"
results = []


def check(name, cond, detail=""):
    results.append((name, bool(cond)))
    print(f"[{'PASS' if cond else 'FAIL'}] {name}" + (f"  ({detail})" if detail and not cond else ""))


async def recv(ws, want=None, tries=60, timeout=2.0):
    for _ in range(tries):
        m = json.loads(await asyncio.wait_for(ws.recv(), timeout))
        if want is None or m.get("type") == want:
            return m
    raise RuntimeError(f"never saw a {want} message")


async def recv_no_tick(ws, seconds=2.0):
    """Return (message, None) if anything arrives, (None, 'timeout') if silent."""
    try:
        return json.loads(await asyncio.wait_for(ws.recv(), seconds)), None
    except asyncio.TimeoutError:
        return None, "timeout"


async def main():
    async with websockets.connect(URL, max_size=None) as ws:
        await recv(ws, "scenarios")
        await recv(ws, "glossary")

        # --- start and pause ------------------------------------------
        await ws.send(json.dumps({"type": "start", "kind": "ddos"}))
        init = await recv(ws, "init")
        check("scenario starts with 70s duration", init["duration"] == 70, str(init.get("duration")))
        t0 = (await recv(ws, "tick"))["t"]

        await ws.send(json.dumps({"type": "pause"}))
        p = await recv(ws, "paused")
        check("pause acknowledged", p["paused"] is True)
        m, silence = await recv_no_tick(ws, 2.5)
        check("clock frozen while paused (no ticks)", silence == "timeout",
              f"got {m and m.get('type')} at t={m and m.get('t')}")

        await ws.send(json.dumps({"type": "resume"}))
        p = await recv(ws, "paused")
        check("resume acknowledged", p["paused"] is False)
        t1 = (await recv(ws, "tick"))["t"]
        check("clock runs again after resume", t1 > t0, f"t0={t0} t1={t1}")

        # --- instructor: skip phase -----------------------------------
        await ws.send(json.dumps({"type": "trainer", "event": "skip"}))
        r = await recv(ws, "result")
        check("skip reports a jump", "jumped" in r["msg"].lower(), r["msg"])
        t2 = (await recv(ws, "tick"))["t"]
        check("time jumped forward", t2 >= t1 + 4.5, f"t1={t1} t2={t2}")

        # --- instructor: +15s -----------------------------------------
        await ws.send(json.dumps({"type": "trainer", "event": "extra"}))
        r = await recv(ws, "result")
        check("+15s announced", "15s" in r["msg"], r["msg"])
        tick = await recv(ws, "tick")
        check("tick carries the extended duration", tick["dur"] == 85, str(tick.get("dur")))

        # --- instructor: injected alert --------------------------------
        await ws.send(json.dumps({"type": "trainer", "event": "alert"}))
        r = await recv(ws, "result")
        check("injected alert is CRITICAL", "CRITICAL" in r["msg"], r["msg"])

        # --- restart ----------------------------------------------------
        await ws.send(json.dumps({"type": "restart"}))
        init = await recv(ws, "init")
        check("restart re-inits the same scenario", init["kind"] == "ddos", init.get("kind"))
        tick = await recv(ws, "tick")
        check("restart resets duration extras", tick["dur"] == 70, str(tick.get("dur")))
        check("restart resets the clock", tick["t"] <= 1.0, str(tick.get("t")))

        # --- grade now --------------------------------------------------
        await ws.send(json.dumps({"type": "trainer", "event": "grade"}))
        r = await recv(ws, "result")
        check("grade-now announced", "grading" in r["msg"].lower(), r["msg"])
        end = await recv(ws, "end", timeout=5.0)
        check("early grade produces an end screen",
              end["outcome"] in ("success", "partial", "failure") and "max" in end, str(end.get("outcome")))

        # --- abort -------------------------------------------------------
        await ws.send(json.dumps({"type": "start", "kind": "mitm"}))
        await recv(ws, "init")
        await ws.send(json.dumps({"type": "abort"}))
        m = await recv(ws, "aborted")
        check("abort ends the session cleanly", m["type"] == "aborted")
        # after abort the connection still works: start another scenario
        await ws.send(json.dumps({"type": "start", "kind": "brute"}))
        init = await recv(ws, "init")
        check("can start a new scenario after abort", init["kind"] == "brute", init.get("kind"))
        await ws.send(json.dumps({"type": "abort"}))
        await recv(ws, "aborted")

    npass = sum(1 for _, ok in results if ok)
    print(f"\n{npass}/{len(results)} session-control checks PASS")
    return 0 if npass == len(results) else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
