"""Analyze a synthetic HTTP response without contacting an external service."""

import httpx
from shensec import analyze_response, analyze_jwt


def main():
    response = httpx.Response(
        200,
        headers={
            "Access-Control-Allow-Origin": "*",
            "Set-Cookie": "session=example; Path=/",
        },
    )
    result = analyze_response(response, url="https://example.test")
    # analyze_response collects findings; it does not aggregate a risk summary.
    for finding in result.findings:
        print(f"{finding.rule_id}: {finding.severity.value} - {finding.title}")

    token = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjMifQ."
    for finding in analyze_jwt(token):
        print(f"{finding.rule_id}: {finding.severity.value} - {finding.title}")


if __name__ == "__main__":
    main()
