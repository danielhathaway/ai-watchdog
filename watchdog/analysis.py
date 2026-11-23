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


def local_review(model, context):
    request = {
        "model": model, "stream": False, "think": False, "format": OLLAMA_SCHEMA,
        "options": {"temperature": 0, "num_predict": 200},
        "messages": [
            {"role": "system", "content": "Summarize this host security assessment in two short sentences. "
             "Use only supplied evidence. Explain uncertainty. Emit a JSON object with a summary string."},
            {"role": "user", "content": json.dumps(context)},
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
        if set(data) != {"summary"} or not isinstance(data["summary"], str) or not 0 < len(data["summary"]) <= 700:
            raise ValueError("Unexpected model output")
        return data["summary"]
    finally:
        with_http.close()
