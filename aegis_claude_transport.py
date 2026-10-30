"""Fixed HTTPS transport; launched by the trusted runner with bounded private stdin."""
import base64
import http.client
import json
import ssl
import sys


def main():
    # This process has no tools, redirects, proxy configuration, or target URLs.
    try:
        request = json.loads(sys.stdin.buffer.read(262145))
        body = request["body"].encode("utf-8")
        if len(body) > 196608 or not 1 <= request["response_limit"] <= 65536:
            raise ValueError()
        conn = http.client.HTTPSConnection("api.anthropic.com", 443,
            timeout=request["timeout_seconds"], context=ssl.create_default_context())
        try:
            conn.request("POST", "/v1/messages", body=body, headers={
                "content-type": "application/json", "anthropic-version": "2023-06-01",
                "x-api-key": request["api_key"]})
            response = conn.getresponse()
            if response.status != 200:
                retry = response.getheader("retry-after", "5")
                delay = min(300, max(1, int(retry))) if retry.isascii() and retry.isdigit() else 5
                result = {"status": "RATE_LIMIT" if response.status == 429 else "PROVIDER_ERROR",
                          "retry_after_seconds": delay}
            else:
                raw = response.read(request["response_limit"] + 1)
                if len(raw) > request["response_limit"]:
                    raise ValueError()
                result = {"status": "OK", "response_b64": base64.b64encode(raw).decode("ascii")}
        finally:
            conn.close()
    except Exception:
        # Neither HTTP bodies nor exception text may disclose a credential.
        result = {"status": "TRANSPORT_UNCERTAIN", "retry_after_seconds": 5}
    print(json.dumps(result, separators=(",", ":")))


if __name__ == "__main__":
    main()
