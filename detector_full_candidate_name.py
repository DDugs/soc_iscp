import sys, csv, json, re
from typing import Dict, Any, Tuple, List

PHONE_RE    = re.compile(r"(?<!\d)(?:\+?91[-\s]*)?((\d){10})(?!\d)")
AADHAR_RE   = re.compile(r"(?<!\d)(?:\d{4}\s?\d{4}\s?\d{4})(?!\d)")
PASSPORT_RE = re.compile(r"\b([A-PR-WYa-pr-wy])[0-9]{7}\b")
UPI_RE      = re.compile(r"\b[a-zA-Z0-9._-]{2,}@([a-z]{2,20})\b")
EMAIL_RE    = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,}\b")
IPV4_RE     = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b")
PIN_RE      = re.compile(r"(?<!\d)(\d{6})(?!\d)")

ADDRESS_KWS = {
    "street","st","road","rd","lane","ln","avenue","ave","block","sector","phase",
    "layout","plot","house","hno","apartment","apt","society","near","behind","opp",
    "village","taluk","district"
}

def mask_phone(s: str) -> str:
    return s[:2] + "XXXXXX" + s[-2:]

def mask_aadhar(s: str) -> str:
    digits = re.sub(r"\D","", s)
    return digits[:4] + " XXXX XXXX"

def mask_passport(s: str) -> str:
    return s[0] + "XXXXXXX"

def mask_upi(s: str) -> str:
    local, handle = s.split("@",1)
    if len(local) <= 2:
        local_masked = "XX"
    else:
        local_masked = local[0] + "X"*(len(local)-2) + local[-1]
    return f"{local_masked}@{handle}"

def mask_email(s: str) -> str:
    local, domain = s.split("@",1)
    if len(local) <= 2:
        local_masked = "XX"
    else:
        local_masked = local[0] + "X"*(len(local)-2) + local[-1]
    return f"{local_masked}@{domain}"

def mask_ip(s: str) -> str:
    parts = s.split(".")
    return ".".join(parts[:2] + ["XXX","XXX"]) if len(parts) == 4 else "0.0.0.0"

def mask_name(fullname: str) -> str:
    return " ".join(
        t[0] + "X"*(len(t)-1) if len(t) > 1 else "X"
        for t in fullname.split()
    )

def mask_address(s: str) -> str:
    return re.sub(r"\d", "X", s)

def mask_generic_digits(s: str) -> str:
    return re.sub(r"\d", "X", s)

def is_full_name(value: str) -> bool:
    tokens = [t for t in re.split(r"[\s,]+", value.strip()) if t]
    alpha_tokens = [t for t in tokens if re.search(r"[A-Za-z]", t)]
    return len(alpha_tokens) >= 2

def looks_like_address(value: str) -> bool:
    v = value.lower()
    return any(kw in v for kw in ADDRESS_KWS) or bool(PIN_RE.search(value))

def redact_text_value(value: str) -> Tuple[str, bool]:
    original = value
    value = PHONE_RE.sub(lambda m: mask_phone(m.group(1)), value)
    value = AADHAR_RE.sub(lambda m: mask_aadhar(m.group(0)), value)
    value = PASSPORT_RE.sub(lambda m: mask_passport(m.group(0)), value)
    value = UPI_RE.sub(lambda m: mask_upi(m.group(0)), value)
    value = EMAIL_RE.sub(lambda m: mask_email(m.group(0)), value)
    return value, (value != original)

def process_record(obj: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:
    has_email = has_full_name = has_address = has_device_or_ip = False
    pii_found = False
    redacted = {}

    for k, v in obj.items():
        if not isinstance(v, str):
            redacted[k] = v
            continue
        val = v
        if k in ("phone","contact") and PHONE_RE.search(val):
            val = mask_phone(PHONE_RE.search(val).group(1))
            pii_found = True
        elif k == "aadhar" and AADHAR_RE.search(val):
            val = mask_aadhar(val); pii_found = True
        elif k == "passport" and PASSPORT_RE.search(val):
            val = mask_passport(val); pii_found = True
        elif k in ("upi_id","upi") and UPI_RE.search(val):
            val = mask_upi(val); pii_found = True
        elif k in ("email","username") and EMAIL_RE.search(val):
            has_email = True; val = mask_email(val)
        elif k in ("name","full_name") and is_full_name(val):
            has_full_name = True; val = mask_name(val)
        elif k in ("first_name","last_name") and val:
            val = val[0] + "X"*(len(val)-1)
        elif k in ("address","address_proof") and val.strip():
            has_address = looks_like_address(val); val = mask_address(val)
        elif k == "ip_address" and IPV4_RE.search(val):
            has_device_or_ip = True; val = mask_ip(val)
        elif k == "device_id" and len(re.sub(r"\W","", val)) >= 12:
            has_device_or_ip = True; val = mask_generic_digits(val)
        else:
            val2, found = redact_text_value(val)
            if found: pii_found = True; val = val2

        redacted[k] = val
    combinatorial_count = int(has_full_name) + int(has_email) + int(has_address) + int(has_device_or_ip)
    pii_flag = pii_found or (combinatorial_count >= 2)
    return redacted, pii_flag

def main():
    if len(sys.argv) < 2:
        print("to use - python3 detector_full_candidate_name.py iscp_pii_dataset.csv")
        sys.exit(1)

    input_csv = sys.argv[1]
    output_csv = "redacted_output_candidate_full_name.csv"

    with open(input_csv, newline="", encoding="utf-8") as f_in, \
         open(output_csv, "w", newline="", encoding="utf-8") as f_out:

        reader = csv.DictReader(f_in)
        writer = csv.DictWriter(f_out, fieldnames=["record_id","redacted_data_json","is_pii"])
        writer.writeheader()

        for row in reader:
            rid = row.get("record_id") or row.get("Record_ID") or row.get("id") or ""
            raw_json = row.get("Data_json") or row.get("data_json") or "{}"
            try:
                data_obj = json.loads(raw_json)
            except:
                fixed = raw_json.replace("''", '"').replace('""','"')
                try: data_obj = json.loads(fixed)
                except: data_obj = {}

            redacted_obj, is_pii = process_record(data_obj)
            writer.writerow({
                "record_id": rid,
                "redacted_data_json": json.dumps(redacted_obj, ensure_ascii=False),
                "is_pii": str(is_pii)
            })
    print(f"output - {output_csv}")
if __name__ == "__main__":
    main()
