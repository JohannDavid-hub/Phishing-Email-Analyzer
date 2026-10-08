import re
import json
import os
import csv
import difflib
from datetime import datetime
from email import message_from_string

# ---------------------------------------------------------
# Block 1: External Config & Threat Intelligence Ingestion
# ---------------------------------------------------------
def load_threat_rules():
    """Loads trusted domains and regex patterns from an external JSON file."""
    try:
        with open("threat_rules.json", "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {
            "trusted_domains": ["cfr.org", "csis.org", "google.com", "paypal.com", "microsoft.com", "state.gov"],
            "suspicious_regex_patterns": [
                r"(?:v[e3]rify|p[a@]ss|l[0o]g[i1]n|acc[0o]unt|s[u1]spend)",
                r"https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
                r"click\s+(?:here|now|below|link)"
            ]
        }

# ---------------------------------------------------------
# Block 2: Dynamic Detection Engines
# ---------------------------------------------------------
def check_domain_similarity(sender_email, trusted_domains):
    """Detects typosquatted / lookalike domains using fuzzy string matching."""
    if "@" not in sender_email:
        return None, 0.0
    
    sender_domain = sender_email.split("@")[-1].strip("> ").lower()
    
    if sender_domain in trusted_domains:
        return None, 0.0
        
    for target in trusted_domains:
        similarity = difflib.SequenceMatcher(None, sender_domain, target).ratio()
        if 0.75 <= similarity < 1.0:
            return f"Lookalike domain detected! '{sender_domain}' resembles legitimate '{target}' ({similarity*100:.0f}% match)", similarity
            
    return None, 0.0

def scan_regex_patterns(text, patterns):
    """Uses Regular Expressions to catch character substitutions and obfuscated links."""
    text_lower = text.lower()
    matches = []
    for pattern in patterns:
        found = re.findall(pattern, text_lower, re.IGNORECASE)
        if found:
            matches.extend(set(found))
    return list(set(matches))

def evaluate_sentiment_urgency(text):
    """Evaluates psychological pressure, coercion, and threat of suspension."""
    urgency_signals = ["urgent", "immediately", "suspended", "terminate", "24 hours", "penalty", "unauthorized"]
    text_lower = text.lower()
    return sum(1 for word in urgency_signals if word in text_lower)

def run_signature_rules(domain_alert, regex_matches, urgency_score, has_link):
    """Multi-condition Signature Engine: Combines weak signals into correlated threats."""
    signatures = []
    if domain_alert and (urgency_score > 0 or has_link):
        signatures.append("SIGNATURE-01: Lookalike Sender Domain paired with Urgent Call-to-Action")
    if len(regex_matches) >= 2 and has_link:
        signatures.append("SIGNATURE-02: Multiple Character Substitutions / Patterns with Embedded Link")
    if urgency_score >= 2:
        signatures.append("SIGNATURE-03: High Coercion / Stress-Inducing Tone Detected")
    return signatures

# ---------------------------------------------------------
# Block 3: CSV Reporting Engine for Trend & Stat Analysis
# ---------------------------------------------------------
def export_results_to_csv(analysis_records, filename="phishing_threat_report.csv"):
    """Collates and appends threat analysis records to a CSV file for trend tracking."""
    file_exists = os.path.exists(filename)
    fieldnames = [
        "Timestamp", "Source_Label", "Sender", "Subject", 
        "Verdict", "Risk_Score", "Domain_Alert", 
        "Regex_Triggers", "Urgency_Score", "Correlated_Signatures"
    ]
    
    with open(filename, mode="a", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        if not file_exists:
            writer.writeheader()
        writer.writerows(analysis_records)
        
    print(f"[✓] Successfully exported {len(analysis_records)} record(s) to '{filename}'.")

# ---------------------------------------------------------
# Block 4: Core Ingestion & Analysis Engine
# ---------------------------------------------------------
def analyze_raw_email(raw_email_str, source_label="Input Email"):
    """Parses raw email text or headers, executes checks, and returns a structured record."""
    config = load_threat_rules()
    
    # Parse RFC 5322 structure
    msg = message_from_string(raw_email_str)
    sender = msg.get("From", "Unknown Sender")
    subject = msg.get("Subject", "No Subject")
    
    # Extract body content automatically
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body += part.get_payload(decode=True).decode(errors="ignore")
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            body = payload.decode(errors="ignore")
        else:
            body = msg.get_payload() or ""
            
    combined_text = f"{subject} {body}"
    has_link = bool(re.search(r"https?://|www\.", combined_text, re.IGNORECASE))
    
    # Execute Modules
    domain_alert, similarity = check_domain_similarity(sender, config["trusted_domains"])
    regex_matches = scan_regex_patterns(combined_text, config["suspicious_regex_patterns"])
    urgency_score = evaluate_sentiment_urgency(combined_text)
    signatures = run_signature_rules(domain_alert, regex_matches, urgency_score, has_link)
    
    # Calculate Risk Score
    risk_score = 0
    if domain_alert: risk_score += 40
    risk_score += len(regex_matches) * 15
    risk_score += urgency_score * 10
    if signatures: risk_score += len(signatures) * 20
    
    # Assign Verdict
    if risk_score >= 50:
        verdict = "🔴 HIGH RISK PHISHING"
    elif risk_score >= 25:
        verdict = "🟡 SUSPICIOUS"
    else:
        verdict = "🟢 CLEAN / LOW RISK"
        
    # Terminal Display
    print("==========================================================")
    print(f"  ANALYZING: {source_label}")
    print("==========================================================")
    print(f"From       : {sender}")
    print(f"Subject    : {subject}")
    print(f"Verdict    : {verdict} (Risk Score: {risk_score}/100)")
    
    if domain_alert:
        print(f"  [!] Domain Alert : {domain_alert}")
    if regex_matches:
        print(f"  [!] Regex Triggers: {', '.join(regex_matches)}")
    if urgency_score > 0:
        print(f"  [!] Urgency Score : {urgency_score} psychological pressure signal(s)")
    if signatures:
        print("  [!] Correlated Signatures:")
        for sig in signatures:
            print(f"      - {sig}")
            
    print("==========================================================\n")

    # Structured Record for CSV Export
    return {
        "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Source_Label": source_label,
        "Sender": sender,
        "Subject": subject,
        "Verdict": verdict,
        "Risk_Score": risk_score,
        "Domain_Alert": domain_alert if domain_alert else "None",
        "Regex_Triggers": "; ".join(regex_matches) if regex_matches else "None",
        "Urgency_Score": urgency_score,
        "Correlated_Signatures": "; ".join(signatures) if signatures else "None"
    }

# ---------------------------------------------------------
# Block 5: Main Execution Workflow
# ---------------------------------------------------------
def main():
    print("\n==========================================================")
    print("  DIPLOMATIC PHISHING EMAIL ANALYZER (PRO EDITION)        ")
    print("==========================================================\n")
    
    sample_1 = """From: Security Team <alerts@service-g00gle.com>
Subject: URGENT: Account verification required
Content-Type: text/plain

Dear User, your account will be suspended within 24 hours unless you click here to verify credentials: https://verify-login-portal.com
"""
    
    sample_2 = """From: Research Desk <research@cfr.org>
Subject: Weekly Global Cyber Policy Digest
Content-Type: text/plain

Here is the latest analysis on state-sponsored cyber operations in Eastern Europe.
"""

    my_real_email = """Delivered-To: arcillajohanndavid@gmail.com
Received: by 2002:a05:7022:c91:b0:144:e5d0:516a with SMTP id ek17csp4022983dlb; Thu, 24 Sep 2026 13:54:00 -0700 (PDT)
X-Received: by 2002:a05:6102:1627:b0:7a5:673f:9a37 with SMTP id ada2fe7eead31-7af1eef5929mr1454175137.15.1790283240376; Thu, 24 Sep 2026 13:54:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1790283240; cv=pass; d=google.com; s=arc-20260327; b=OEfHGD6lNTmQHUpQ+rbv5ssPnH447tgcjlDUrnXDoUHnN6dm29Qb32+FwzhRGoqD/k fFJCbg39q+ogb42J50G+HetrrjYnFQAMavKoYyE9yP845lcU0Ja2cV63bOGpLMPV8cfM 4bNgeljvFr2qgOmcv1xFYvqSdZT5CRtX+q1R+p1f0gvygT/6sfrniNoauXhDGuF+Fd1A naiCQ7uGNoSE+l9VSUTP86QmahzYkWyFt/8+4A/Be9UJX76fqPfn1nc7n9k9Hio7CVcN swV841rg5M4hLdBKTM4k3AioaGY3ShdWHvTirduMhpY668eM6/YssssgA1x1Kc512AaQ 3Afw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20260327; h=to:subject:message-id:date:mime-version:from:dkim-signature; bh=feZ3SjJcaTa04O2EOYZg0KHd9vZxhltNQhTRq8uN8rk=; fh=fkGFyEMCuFmcsvFyh5dsWU7xDejpG9pxwdzcLuEYsuk=; b=pgZzveZu3ulfMxJaUOupxCiPVJRSUY1WDCA8REHXDSDlTKz5JDNS2mALZyIIyCu8kg plHQ07Aldj/rxPHBQulqUnPQgpkCboyjpydawtFXGdNAiK/Pme+KGC5+Rp+W7dvoqYBn 70iw/eoj6nYRCFUMKGrBz5VBQqKXKA+7ymQPHuD8w0sowPw4Tpx4KpE1uIue5PXWUWTt 7gB5MCGP4mT2/+ozCyqk4n/jvc6LwNMTvxzGMtx7m1ie0P6oeSkiHJzEKwYIL7pfQfLp H/VBYCuM0qcOVsgXiGLeyPqRWYqn8m/3LE/44UzQgrwvoc47Yv/lr5RkVSnoBWhac4l9 XETw==; dara=google.com
ARC-Authentication-Results: i=2; mx.google.com; dkim=pass header.i=@raffoenterprise-com.20251104.gappssmtp.com header.s=20251104 header.b=LcRfpQZl; arc=pass (i=1); spf=none (google.com: hr@raffoenterprise.com does not designate permitted sender hosts) smtp.mailfrom=hr@raffoenterprise.com; dara=pass header.i=@gmail.com
Return-Path: <hr@raffoenterprise.com>
Received: from mail-sor-f41.google.com (mail-sor-f41.google.com. [209.85.220.41]) by mx.google.com with SMTPS id ada2fe7eead31-7b0be2a90f1sor186098137.3.2026.09.24.13.54.00 for <arcillajohanndavid@gmail.com> (Google Transport Security); Thu, 24 Sep 2026 13:54:00 -0700 (PDT)
Received-SPF: none (google.com: hr@raffoenterprise.com does not designate permitted sender hosts) client-ip=209.85.220.41;
Authentication-Results: mx.google.com; dkim=pass header.i=@raffoenterprise-com.20251104.gappssmtp.com header.s=20251104 header.b=LcRfpQZl; arc=pass (i=1); spf=none (google.com: hr@raffoenterprise.com does not designate permitted sender hosts) smtp.mailfrom=hr@raffoenterprise.com; dara=pass header.i=@gmail.com
ARC-Seal: i=1; a=rsa-sha256; t=1790283240; cv=none; d=google.com; s=arc-20260327; b=HBvApltgY8odrLbKoYz+cxUuBZXDuczvQVCYFeWxdKN8OejU558c3pfdUelXLTDYvN CxkdasjNL+FldlLeOAvbkMhWSOcVDkGMfyeKbv1e8rQAbQyfkkvYkPqXnl5MJTh/pyAb gfRwA++Qyc06kpTj5nE3P3kppnxQJH5FcE2TC9DLwuckoeRgI99p4BHnVqJVuIdod/9n Si1s5x42zenJR5kMQxwbTlxNkb+q/r17hC8/b5DOtRrvV8w7JjHTw47RHEjENNS6s+YF VPMhmB3iBOOvNJTkrv7i9Pkfoju7kQYkZdhaW9PtHlIVjkOLTdv3uQIYirAlkY2aeYak IIDg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20260327; h=to:subject:message-id:date:mime-version:from:dkim-signature; bh=feZ3SjJcaTa04O2EOYZg0KHd9vZxhltNQhTRq8uN8rk=; fh=fkGFyEMCuFmcsvFyh5dsWU7xDejpG9pxwdzcLuEYsuk=; b=VYQmyPn7UtHje9/opSwTzGZGXbCOqSefiUHWwlJyrkJVe77TkfMlxmRQ1ljDzzGb4U 8x9jmxdDjhMJfMqum4CEGSnF/klvt8+Ld7Clm0NxnydggmAzLodGIhxD5+kj+EN7JuJJ 5iM06hRraLIL+zEBmnp5Zlu6uCTqEnift5Bt88HotlEWTczXinVajywLfPLg5Bm6Vu0U g6j6Z152x//q05JSF67LBPHNQ+wr2/iyDZIZ6/uwexn7PBrDB7OnZnyNOmga0YW/4eni 0vf/IoMdKaqwDf/0NaGt1+CHwGZExSbTmIOiYp1J9XwnVvRzj+7inedA6WSO00BniGmg kJ6Q==; dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=raffoenterprise-com.20251104.gappssmtp.com; s=20251104; t=1790283240; x=1790888040; dara=google.com; h=content-type:to:subject:message-id:date:mime-version:from:from:to :cc:subject:date:message-id:reply-to:content-type; bh=feZ3SjJcaTa04O2EOYZg0KHd9vZxhltNQhTRq8uN8rk=; b=LcRfpQZlsBCOLCw6c7eEa1kuphimqCO/zQXbL26SMwJz6cruYak7H5WsbZsqi3v16w /XpGrdpgJ5GPEnIx8pxrHbH7rxlPFzOolwuWaz0WRFNe8JH0NJiffvYq3XfPqKrNjMR5 Y/z8qGxyENNMYAKDA9sfxjzkBRYKPAysTD139mIUxMZiCJCfSqXEqFST6vsZJitisQiv 8QTEefDZBCyxKBLQvOeJH+YovL8R/Zih5TDhayEjoeJ+Two/XwMDzgQGoYEvrnUgKEeO fNiXaXjzLvO4zTFpU245WpHfAyztYsYo0PsugIAi+tNjiGtSBEnDuswBcBCJDgDrNKor C8zQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=1e100.net; s=20260707; t=1790283240; x=1790888040; h=content-type:to:subject:message-id:date:mime-version:from:x-gm-gg :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to :content-type; bh=feZ3SjJcaTa04O2EOYZg0KHd9vZxhltNQhTRq8uN8rk=; b=2K8vi7j/lNaYdnhm0PfB4iM6VgNEQm5bkV8z8icp5ZbFhjqUFrDIm0SEMt7AWmRFfP 3uBYVkuug6GMARPgHb3wxOSNNMf/L0XoVbyTAnhvrqHM1BX/sXIeLQD3zwTS5JUv5vpZ bnALsUNFiL281opeUfOBkllJF3aN6J5SZlgASs5WfUBX/hoZH847j9z3fzAJm74UwzUI 8ImCo0Zfc/oTHsE+iY/n/bFHjvYlUwO7nSUay33MJmN2/xElYksA/9P18eOqZjZWHnwi vfD8Oqq6I6xpN0Y29eOzzfmI8og23x3sf9JnnvbRmpSQdy+86LjWVyY+ajqPjb3CKbx+ R+YQ==
X-Gm-Message-State: AFuF++mvK74qFtv0X6v39xdTSUROxzocbRQy5jjOKilxWuqaRz7gWMJc g6JYsBB1rRSxc0ywm8sXssOiXdd1saeZv6A7PNaJx4qBU1n3aL4Th8rte2C5znnwOlJMTHtHK8y bnMT32hPjEQ0UpGgyAN1u0etA74l+F9xzK6FXCa4MywlCyJGOUpdGpA2B
X-Gm-Gg: AYBFou3yGRiZgunzYpvvKDL14Vtfj+J9uFcRd806loTcwN+0wYkWphZyXtmDL6rx4o+ swHbLyRn8c69UGEjK1AXRrUxghUCr+YEcUoBdu6XWRfFR3nagR7FIcTGD2MEvhGTQksbXX6VQvt FAePEKZWACEjHARKOwGjjz4D6Z804aQu/5LMpMHLFYdgx6m04l8KBq3t5W3NJ2zUlXn8lnkoK0o 7AAkw915IPp7AVNGQIoGA+AjbMEg7uSiYEH3WRUCt5IEEKikabsh6xfmI89/uZctG4+Ze3d6wOF L0wyYs9Hlg9v54nIYZCawwpiCcEgKsc5haiFwWMujyq3fqBhk+LjCUhHz5S29Y27aQuqYawd4GM Sos0Ro3tsnEY=
X-Received: by 2002:a05:6102:8696:20b0:7a1:f2b5:645b with SMTP id ada2fe7eead31-7af1eaea993mr1098300137.24.1790283239740; Thu, 24 Sep 2026 13:53:59 -0700 (PDT)
Received: from 48063349265 named unknown by gmailapi.google.com with HTTPREST; Thu, 24 Sep 2026 13:53:59 -0700
Received: from 48063349265 named unknown by gmailapi.google.com with HTTPREST; Thu, 24 Sep 2026 13:53:59 -0700
From: HR Team <hr@raffoenterprise.com>
MIME-Version: 1.0
Date: Thu, 24 Sep 2026 13:53:59 -0700
X-Gm-Features: AclHuK904I-4UnVt_14M4vHEc2Wi3R46PeL9NqJCYqYGkSGhFoEmRfKfvnKM55w
Message-ID: <CAMmjfV2eC3obFJiT-ESZecpZZgAA5S2ApTYHnjtYT-i3Z-6hKw@mail.gmail.com>
Subject: Final Chance to Connect! Don't Miss Out!
To: arcillajohanndavid@gmail.com
Content-Type: multipart/alternative; boundary="0000000000008d666a065c40cc65"

--0000000000008d666a065c40cc65
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Hi Johann,

I wanted to reach out one last time because we=E2=80=99re wrapping up our i=
nterview
schedule and I don=E2=80=99t want you to miss this opportunity. I=E2=80=99l=
l need to hear
from you no later than the end of business day today to move forward.

We=E2=80=99ve had an overwhelming response, and interview slots are filling=
 fast.
If you=E2=80=99re motivated to take on a new challenge and interested in ex=
ploring
this position, please reply with your availability today so we can secure a
time to connect. Or feel free to call me directly at 203-312-1926.

This is my final attempt to connect, and I=E2=80=99d love the chance to cha=
t with
you before our hiring decisions are finalized.

Looking forward to hearing from you today,

Kind Regards,



Talent Acquisition

Office. 203-312-1926

Email. hr@raffoenterprise.com

2 Corporate Drive, Suite 365, Shelton, CT 06484

--0000000000008d666a065c40cc65
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<p dir=3D"ltr">Hi Johann,</p>
<p>I wanted to reach out one last time because we=E2=80=99re wrapping up ou=
r interview schedule and I don=E2=80=99t want you to miss this opportunity.=
 I=E2=80=99ll need to hear from you no later than the end of business day t=
oday to move forward.</p>
<p>We=E2=80=99ve had an overwhelming response, and interview slots are fill=
ing fast. If you=E2=80=99re motivated to take on a new challenge and intere=
sted in exploring this position, please reply with your availability today =
so we can secure a time to connect. Or feel free to call me directly at 203=
-312-1926.=C2=A0</p>
<p>This is my final attempt to connect, and I=E2=80=99d love the chance to =
chat with you before our hiring decisions are finalized.</p>
<p>Looking forward to hearing from you today,</p>
<p><table role=3D"presentation" cellpadding=3D"0" cellspacing=3D"0" border=
=3D"0" width=3D"100%" style=3D"width:100%;max-width:600px;border-collapse:c=
ollapse;margin:0;padding:0">
            <tr>
                <td style=3D"padding:0;margin:0">
                <style>
        table[data-signature-wrapper=3D"1"]{
            width: 100% !important;
            max-width: 600px;
        }
        table[data-signature-wrapper=3D"1"] table{
            width: auto !important;
            table-layout: auto !important;
            border-collapse: collapse !important;
        }
        table[data-signature-wrapper=3D"1"] td.column{
            width: auto !important;
            max-width: none !important;
            white-space: normal;
            vertical-align: top;
        }
        table[data-signature-wrapper=3D"1"] img{
            width: auto !important;
            max-width: 100% !important;
            height: auto !important;
            display: block;
        }
        </style>
                <div><table id=3D"zs-output-sig" style=3D"font-family:Arial=
,Helvetica,sans-serif;line-height:0px;font-size:1px;padding:0px!important;b=
order-spacing:0px;margin:0px;border-collapse:collapse;width:500px" role=3D"=
presentation" border=3D"0" cellspacing=3D"0" cellpadding=3D"0">
<tbody>
<tr>
<td style=3D"padding:0px!important;width:inherit;height:inherit">
<table id=3D"inner-table" style=3D"font-family:Arial,Helvetica,sans-serif;l=
ine-height:0px;font-size:1px;padding:0px!important;border-spacing:0px;margi=
n:0px;border-collapse:collapse" role=3D"presentation" border=3D"0" cellspac=
ing=3D"0" cellpadding=3D"0">
<tbody>
<tr>
<td style=3D"border-collapse:collapse;font-family:Georgia,serif;font-size:1=
3px;font-style:normal;line-height:15px;font-weight:400;padding-bottom:14px;=
width:inherit;height:inherit">
<p style=3D"margin:0.04px"><span style=3D"font-family:Georgia,serif;font-si=
ze:13px;font-style:normal;line-height:15px;font-weight:400;color:#535353;di=
splay:inline">Kind Regards,</span></p>
</td>
</tr>
</tbody>
</table>
</td>
</tr>
<tr>
<td style=3D"padding:0px!important;width:inherit;height:inherit">
<table id=3D"inner-table" style=3D"font-family:Arial,Helvetica,sans-serif;l=
ine-height:0px;font-size:1px;padding:0px!important;border-spacing:0px;margi=
n:0px;border-collapse:collapse" role=3D"presentation" border=3D"0" cellspac=
ing=3D"0" cellpadding=3D"0">
<tbody>
<tr>
<td style=3D"padding-right:22px;width:inherit;height:inherit" width=3D"145"=
>
<table style=3D"font-family:Arial,Helvetica,sans-serif;line-height:0px;font=
-size:1px;padding:0px!important;border-spacing:0px;margin:0px;border-collap=
se:collapse" role=3D"presentation" border=3D"0" cellspacing=3D"0" cellpaddi=
ng=3D"0">
<tbody>
<tr>
<td style=3D"border-collapse:collapse;line-height:0px;padding-right:1px;wid=
th:inherit;height:inherit">
<p style=3D"margin:0.04px"><img src=3D"https://img2.gimm.io/1ba06306-963c-4=
404-8f38-1cf6c000cba0/image.png" alt=3D"" width=3D"145" height=3D"145" bord=
er=3D"0"></p>
</td>
</tr>
</tbody>
</table>
</td>
<td style=3D"padding:0px!important;width:inherit;height:inherit">
<table style=3D"font-family:Arial,Helvetica,sans-serif;line-height:0px;font=
-size:1px;padding:0px!important;border-spacing:0px;margin:0px;border-collap=
se:collapse" role=3D"presentation" border=3D"0" cellspacing=3D"0" cellpaddi=
ng=3D"0">
<tbody>
<tr>
<td style=3D"border-collapse:collapse;font-family:Georgia,serif;font-size:2=
7px;font-style:italic;line-height:29px;font-weight:400;padding-bottom:6px;w=
idth:inherit;height:inherit">
<p style=3D"margin:0.04px">=C2=A0</p>
</td>
</tr>
</tbody>
</table>
<table style=3D"font-family:Arial,Helvetica,sans-serif;line-height:0px;font=
-size:1px;padding:0px!important;border-spacing:0px;margin:0px;border-collap=
se:collapse" role=3D"presentation" border=3D"0" cellspacing=3D"0" cellpaddi=
ng=3D"0">
<tbody>
<tr>
<td style=3D"border-collapse:collapse;line-height:0px;padding-bottom:6px;pa=
dding-right:1px;width:inherit;height:inherit">
<p style=3D"margin:0.04px"><img src=3D"https://img2.gimm.io/895cbdd4-e3d8-4=
72f-af2f-bf731783a445/image.png" alt=3D"" width=3D"274" height=3D"1" border=
=3D"0"></p>
</td>
</tr>
</tbody>
</table>
<table style=3D"font-family:Arial,Helvetica,sans-serif;line-height:0px;font=
-size:1px;border-spacing:0px;margin:0px;border-collapse:collapse;padding:0p=
x!important;width:76.897%" role=3D"presentation" border=3D"0" cellspacing=
=3D"0" cellpadding=3D"0">
<tbody>
<tr>
<td style=3D"border-collapse:collapse;font-family:Georgia,serif;font-size:1=
6px;font-style:normal;line-height:18px;font-weight:bold;padding-bottom:8px;=
width:100%;height:inherit">
<p style=3D"margin:0.04px"><span style=3D"font-family:Georgia,serif;font-si=
ze:16px;font-style:normal;line-height:18px;font-weight:bold;color:#8d7933;d=
isplay:inline">Talent Acquisition</span></p>
</td>
</tr>
<tr>
<td style=3D"border-collapse:collapse;font-family:Georgia,serif;font-size:1=
3px;font-style:normal;line-height:15px;font-weight:400;padding-bottom:4px;w=
idth:100%;height:inherit">
<p style=3D"margin:0.04px"><span style=3D"font-family:Georgia,serif;font-si=
ze:13px;font-style:italic;line-height:15px;font-weight:400;color:#335f8d;di=
splay:inline">Office.</span> <span style=3D"font-family:Georgia,serif;font-=
size:13px;font-style:normal;line-height:15px;font-weight:400;color:#535353;=
display:inline">203-312-1926</span></p>
</td>
</tr>
<tr>
<td style=3D"border-collapse:collapse;font-family:Georgia,serif;font-size:1=
3px;font-style:normal;line-height:15px;font-weight:400;padding-bottom:4px;w=
idth:100%;height:inherit">
<p style=3D"margin:0.04px"><span style=3D"font-family:Georgia,serif;font-si=
ze:13px;font-style:italic;line-height:15px;font-weight:400;color:#335f8d;di=
splay:inline">Email.</span> <a style=3D"font-family:Georgia,serif;font-size=
:13px;font-style:normal;line-height:15px;font-weight:400;color:#535353;disp=
lay:inline;text-decoration:none" href=3D"mailto:hr@raffoenterprise.com" tar=
get=3D"_blank" rel=3D"nofollow noopener"> hr@raffoenterprise.com </a></p>
</td>
</tr>
<tr>
<td style=3D"border-collapse:collapse;font-family:Georgia,serif;font-size:1=
3px;font-style:normal;line-height:15px;font-weight:400;padding-bottom:6px;w=
idth:100%;height:inherit">
<p style=3D"margin:0.04px"><span style=3D"color:#535353">2 Corporate Drive,=
 Suite 365, Shelton, CT 06484=C2=A0</span></p>
</td>
</tr>
</tbody>
</table>
</td>
</tr>
</tbody>
</table>
</td>
</tr>
<tr>
<td style=3D"border-collapse:collapse;padding-bottom:16px;width:inherit;hei=
ght:inherit">=C2=A0</td>
</tr>
</tbody>
</table></div>
                </td>
            </tr>
        </table></p>

--0000000000008d666a065c40cc65-- """
    # Run the analysis on your real email
    real_record = analyze_raw_email(my_real_email, source_label="My Real Email Test")
    
    # Export the result straight to your CSV report
    export_results_to_csv([real_record], filename="phishing_threat_report.csv")

    record_1 = analyze_raw_email(sample_1, source_label="Sample #1 (Lookalike Domain Test)")
    record_2 = analyze_raw_email(sample_2, source_label="Sample #2 (Legitimate Research Email)")
    
    # Export records to CSV
    export_results_to_csv([record_1, record_2], filename="phishing_threat_report.csv")

if __name__ == "__main__":
    main()