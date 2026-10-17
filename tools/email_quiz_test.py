#!/usr/bin/env python3
"""Scripted test for the email training game and the plain-English metadata.

Connects over WebSocket, verifies:
  * scenarios arrive grouped by category with plain-English text,
  * the glossary (defensive chain + jargon buster) is served,
  * the 9-email Genuine/Phishing/Spam quiz: start, correct, wrong, drain to end,
  * every defensive action carries a plain-English explanation.

Exit code 0 = all checks pass.
"""
import asyncio
import json
import sys

import websockets

URL = "ws://127.0.0.1:8010/ws"
results = []


def check(name, cond, detail=""):
    results.append((name, bool(cond), detail))
    mark = "PASS" if cond else "FAIL"
    print(f"[{mark}] {name}" + (f"  ({detail})" if detail and not cond else ""))


async def recv(ws, want=None, tries=40):
    for _ in range(tries):
        m = json.loads(await asyncio.wait_for(ws.recv(), 10))
        if want is None or m.get("type") == want:
            return m
    raise RuntimeError(f"never saw a {want} message")


async def recv_quiz_or_end(ws):
    for _ in range(40):
        m = json.loads(await asyncio.wait_for(ws.recv(), 10))
        if m.get("type") in ("quiz", "end"):
            return m
    raise RuntimeError("quiz never finished")


async def main():
    async with websockets.connect(URL, max_size=None) as ws:
        # --- scenarios with categories + plain text -------------------
        s = await recv(ws, "scenarios")
        items = s["items"]
        ids = {i["id"] for i in items}
        check("6 training items served", len(items) == 6, f"got {len(items)}")
        check("email training present", "email" in ids)
        for want in ("ddos", "brute", "sqli", "ransom", "mitm"):
            check(f"{want} kept", want in ids)
        cats = {i["id"]: i.get("cat") for i in items}
        check("email is in Email category", cats.get("email") == "Email", cats.get("email"))
        check("ddos is in Network category", cats.get("ddos") == "Network")
        check("brute is in Identity category", cats.get("brute") == "Identity")
        check("sqli is in Data category", cats.get("sqli") == "Data")
        check("ransom is in Endpoint category", cats.get("ransom") == "Endpoint", cats.get("ransom"))
        check("mitm is in Network category", cats.get("mitm") == "Network")
        missing = [i["id"] for i in items if not i.get("plain") or not i.get("desc")]
        check("every item has plain + desc text", not missing, str(missing))

        # --- glossary --------------------------------------------------
        g = await recv(ws, "glossary")
        chain_terms = [c["term"] for c in g["chain"]]
        check("defensive chain has 7 entries", len(g["chain"]) == 7, str(chain_terms))
        check("chain starts at Router", chain_terms[0] == "Router")
        check("SIEM is the 6th gate", chain_terms[5] == "SIEM", str(chain_terms))
        check("EPP/EDR closes the chain", chain_terms[6] == "Endpoint - EPP / EDR")
        check("glossary has >= 14 terms", len(g["terms"]) >= 14, f"got {len(g['terms'])}")
        check("glossary explains SIEM in plain words",
              any(t["term"] == "SIEM" and "alarm panel" in t["defn"] for t in g["terms"]))

        # --- play the email quiz --------------------------------------
        await ws.send(json.dumps({"type": "start", "kind": "email"}))
        q = await recv(ws, "quiz_start")
        total = q["total"]
        check("quiz starts at email 1", q["index"] == 0)
        check("quiz has 9 emails", total == 9, f"got {total}")
        check("email has sender/subject/body",
              all(q["item"].get(k) for k in ("frm", "subj", "body")))

        # answer 1 correctly
        await ws.send(json.dumps({"type": "quiz_answer", "answer": "genuine"}))
        c = await recv(ws, "quiz_check")
        check("correct answer scored", c["correct"] is True and c["score"] == 1)

        # answer 2 wrongly (email 2 is the genuine standup note)
        await ws.send(json.dumps({"type": "quiz_next"}))
        q = await recv(ws, "quiz")
        check("quiz advances to email 2", q["index"] == 1)
        await ws.send(json.dumps({"type": "quiz_answer", "answer": "phishing"}))
        c = await recv(ws, "quiz_check")
        check("wrong answer flagged", c["correct"] is False and c["answer"] == "genuine")
        check("wrong answer explains the tell", len(c.get("clue", "")) > 30)

        # drain the rest with correct answers
        answered = 2
        while True:
            await ws.send(json.dumps({"type": "quiz_next"}))
            m = await recv_quiz_or_end(ws)
            if m["type"] == "end":
                break
            await ws.send(json.dumps({"type": "quiz_answer", "answer": "spam"}))
            answered += 1
            c = await recv(ws, "quiz_check")
            check(f"email {m['index'] + 1} answers and scores", c["correct"] is (c["answer"] == "spam"))
        check("all 9 emails answered", answered == 9, f"got {answered}")
        check("end screen uses graded verdict",
              m["outcome"] in ("success", "partial", "failure"), m.get("outcome"))
        check("quiz end reports score / 300",
              m.get("max") == 300 and 0 <= m["score"] <= 300, str(m))
        check("quiz end lists missed emails as feedback",
              any(f["k"] == "missed" for f in m["feedback"]))

        # --- plain-English defensive actions on a live scenario ---------
        await ws.send(json.dumps({"type": "start", "kind": "sqli"}))
        init = await recv(ws, "init")
        check("scenario actions all carry plain text",
              all(a.get("plain") for a in init["actions"]),
              str([a["id"] for a in init["actions"] if not a.get("plain")]))
        check("sqli scenario name is served", "SQL injection" in init.get("name", ""), init.get("name", ""))

    npass = sum(1 for _, ok, _ in results if ok)
    print(f"\n{npass}/{len(results)} email-quiz checks PASS")
    return 0 if npass == len(results) else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
