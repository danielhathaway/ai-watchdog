import http.client
import json
import statistics

FLOORS = {"rx": 250_000, "tx": 125_000, "connections": 20}
OLLAMA_SCHEMA = {
    "type": "object", "required": ["summary"], "additionalProperties": False,
    "properties": {"summary": {"type": "string", "maxLength": 700}},
}


def deviations(sample, histories):
    flags = []
    for metric, floor in FLOORS.items():
        values = histories[metric]
        observed = sample[metric]
        if len(values) < 30 or observed is None:
            continue
        median = statistics.median(values)
        mad = statistics.median(abs(value - median) for value in values)
        threshold = median + max(floor, 8 * 1.4826 * mad, median * 0.75)
        if observed > threshold:
            flags.append({"metric": metric, "observed": round(observed), "threshold": round(threshold)})
    return flags


def vulnerability_overview(context):
    vulnerabilities = context.get("vulnerabilities", {})
    unresolved = vulnerabilities.get("unresolved")
    exploited = vulnerabilities.get("known_exploited")
    if unresolved is None or exploited is None:
        return "Vulnerability findings are unavailable."
    return (
        f"{unresolved} unresolved vulnerability findings, including "
        f"{exploited} known-exploited findings."
    )


def compact_facts(context):
    facts = {
        key: sentence.format(context[key])
        for key, sentence in (
            ("risk", "Watchdog recorded a risk score of {}."),
            ("failed_ssh", "The recent failed SSH attempt count was {}."),
            ("block_candidates", "The temporary block candidate count was {}."),
        )
        if context.get(key) is not None
    }
    if "deviations" in context:
        facts["deviations"] = f'The baseline deviation count was {len(context["deviations"])}.'
    if context.get("containment_requested"):
        facts["containment"] = "Watchdog requested containment."
    for name, source in context.get("vulnerabilities", {}).get("sources", {}).items():
        if name.startswith("Ubuntu:"):
            key, label = "ubuntu_osv", "Ubuntu OSV"
        elif name == "kev":
            key, label = "cisa_kev", "CISA KEV"
        else:
            continue
        status = source.get("status")
        state = source.get("freshness") if status == "ready" else status
        if state:
            facts[key] = f"Watchdog reported the {label} feed status as {state}."
    return facts


def local_review(model, context, *, prompt_mode="full"):
    if prompt_mode == "compact":
        findings = vulnerability_overview(context)
        facts = compact_facts(context) or {"none": ""}
        instruction = "Choose the most useful supporting fact. Return only its key in the detail field."
        evidence = f"{findings}\n{json.dumps(facts, separators=(',', ':'))}"
        schema = {
            "type": "object", "required": ["detail"], "additionalProperties": False,
            "properties": {"detail": {"type": "string", "enum": list(facts)}},
        }
        output_tokens = 32
    else:
        instruction = ("Summarize this host security assessment in two short sentences. "
                       "Use only supplied evidence. Explain uncertainty. Emit a JSON object with a summary string.")
        evidence = json.dumps(context)
        schema = OLLAMA_SCHEMA
        output_tokens = 200

    request = {
        "model": model, "stream": False, "think": False, "format": schema,
        "options": {"temperature": 0, "num_predict": output_tokens},
        "messages": [
            {"role": "system", "content": instruction},
            {"role": "user", "content": evidence},
        ],
    }
    with_http = http.client.HTTPConnection("127.0.0.1", 11434, timeout=15)
    try:
        with_http.request("POST", "/api/chat", json.dumps(request), {"Content-Type": "application/json"})
        response = with_http.getresponse()
        if response.status != 200:
            raise ValueError("Local model returned an error")
        result = json.loads(response.read(32769))
        if result.get("remote_model") or result.get("remote_host"):
            raise ValueError("Expected a local model")
        data = json.loads(result["message"]["content"])
        if prompt_mode == "compact":
            if (not isinstance(data, dict) or data.keys() != {"detail"}
                    or not isinstance(data["detail"], str) or data["detail"] not in facts):
                raise ValueError("Unexpected compact model output")
            return f'{findings} {facts[data["detail"]]}'.rstrip()
        if set(data) != {"summary"} or not isinstance(data["summary"], str) or not 0 < len(data["summary"]) <= 700:
            raise ValueError("Unexpected model output")
        return data["summary"]
    finally:
        with_http.close()
