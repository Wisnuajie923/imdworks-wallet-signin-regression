#!/usr/bin/env python3
"""Deterministic, offline acceptance runner for bounty #8."""
import json, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from signin import (Wallet, SecureVerifier, VulnerableNoNonce, VulnerableOrigin,
                    ConcurrentSigninService, VerifyError, build_message,
                    canonicalize_evidence_results)

NOW = 1000
ALICE = Wallet.from_seed("bounty-8-alice")
BOB = Wallet.from_seed("bounty-8-bob")
ORIGIN = "https://app.local"

def signed(wallet=ALICE, nonce="nonce-001", origin=ORIGIN, expires=2000):
    msg=build_message(wallet.address,nonce,origin,expires)
    return msg,wallet.sign_personal(msg)
def outcome(verifier,msg,sig,origin=ORIGIN):
    try: verifier.verify(msg,sig,origin); return "accepted"
    except VerifyError as e: return "rejected:"+str(e)

def main():
    msg,sig=signed()
    cases=[]
    def add(name, expected, actual): cases.append({"name":name,"expected":expected,"actual":actual,"pass":expected==actual})
    add("valid_signature", "accepted", outcome(SecureVerifier(lambda:NOW),msg,sig))
    v=SecureVerifier(lambda:NOW); v.verify(msg,sig,ORIGIN); add("nonce_replay", "rejected:nonce-consumed", outcome(v,msg,sig))
    v=SecureVerifier(lambda:NOW); v.verify(msg,sig,ORIGIN); add("nonce_replay_explicit", "rejected:nonce-consumed", outcome(v,msg,sig))
    add("wrong_signer", "rejected:wrong-signer", outcome(SecureVerifier(lambda:NOW),msg,BOB.sign_personal(msg)))
    for origin in ["https://evil.local","https://app.local.evil","http://app.local","", "HTTPS://app.local"]:
        m,s=signed(origin=origin); expected="rejected:malformed-message" if (not origin or not origin.startswith("https://")) else "rejected:origin-mismatch"; add("origin_"+(origin or "empty"), expected, outcome(SecureVerifier(lambda:NOW),m,s))
    m,s=signed(expires=NOW); add("expiry_equal_boundary", "accepted", outcome(SecureVerifier(lambda:NOW),m,s))
    m,s=signed(expires=NOW-1); add("expiry_one_second_past", "rejected:expired", outcome(SecureVerifier(lambda:NOW),m,s))
    for label, candidate in [("empty",b""),("short",b"x"*64),("long",sig+b"x"),("bad_v",sig[:64]+b"\xff"),("zero_r",b"\0"*32+sig[32:]),("zero_s",sig[:32]+b"\0"*32+sig[64:]),("high_s",sig[:32]+(int.from_bytes(sig[32:64],'big')*2).to_bytes(32,'big')+sig[64:])]:
        add("malformed_"+label,"rejected:"+ ("wrong-signer" if label=="high_s" else "malformed-signature"),outcome(SecureVerifier(lambda:NOW),msg,candidate))
    for label, altered in [("message_address",msg.replace(ALICE.address,BOB.address)),("message_nonce",msg.replace("nonce-001","nonce-002")),("message_origin",msg.replace(ORIGIN,"https://evil.local")),("message_expiry",msg.replace("2000","1999"))]:
        add("tampered_"+label,"rejected:"+ ("origin-mismatch" if label=="message_origin" else "wrong-signer"),outcome(SecureVerifier(lambda:NOW),altered,sig))
    for nonce in ["a","nonce.with.dot","nonce:colon","nonce_underscore","nonce-64-"+"x"*50]:
        m,s=signed(nonce=nonce); add("nonce_format_"+nonce[:12],"accepted",outcome(SecureVerifier(lambda:NOW),m,s))
    # Vulnerable controls: these must demonstrate a security failure, not pass the secure policy.
    vv=VulnerableNoNonce(lambda:NOW); vv.verify(msg,sig,ORIGIN); add("baseline_no_nonce_replay", "accepted", outcome(vv,msg,sig))
    m2,s2=signed(origin="https://evil.local"); vo=VulnerableOrigin(lambda:NOW); add("baseline_origin_bypass", "accepted", outcome(vo,m2,s2,ORIGIN))
    cs=ConcurrentSigninService(lambda:NOW); raw_results=cs.concurrent_attempts(msg,sig,ORIGIN,32)
    raw_counts={x:raw_results.count(x) for x in sorted(set(raw_results))}
    if raw_counts != {"accepted":1,"rejected:nonce-consumed":31}:
        raise AssertionError(f"concurrency invariant violated: {raw_counts}")
    results=canonicalize_evidence_results(raw_results)
    add("concurrency_32_one_success", {"accepted":1,"rejected:nonce-consumed":31}, {x:results.count(x) for x in sorted(set(results))})
    report={"bounty":"#8","uuid":"80c238e8-dd8c-4d0a-8f60-711142f1a496","mode":"local-only","wallets":{"alice":ALICE.address,"bob":BOB.address},"case_count":len(cases),"cases":cases,"all_cases_pass":all(x["pass"] for x in cases),"concurrency_results":results}
    out=Path(__file__).parent/"reports"/"final-report.json"; out.write_text(json.dumps(report,sort_keys=True,indent=2)+"\n")
    trace=Path(__file__).parent/"traces"/"final-trace.json"; trace.write_text(json.dumps({"case_count":len(cases),"cases":[{k:c[k] for k in ("name","actual","pass")} for c in cases],"concurrency":results},sort_keys=True,indent=2)+"\n")
    print(json.dumps({"case_count":len(cases),"all_cases_pass":report["all_cases_pass"],"concurrency":{"accepted":results.count("accepted"),"nonce_consumed":results.count("rejected:nonce-consumed")},"report":str(out),"trace":str(trace)},sort_keys=True))
    return 0 if report["all_cases_pass"] else 1
if __name__=="__main__": raise SystemExit(main())
