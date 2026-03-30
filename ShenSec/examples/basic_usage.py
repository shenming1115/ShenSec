import asyncio
import httpx
from shensec import scan_target, analyze_response, generate_report

async def main():
    target_url = "https://httpbin.org/get"
    print(f"Scanning target: {target_url}...")

    # Method 1: Using scan_target directly
    # result = scan_target(target_url, timeout=5.0)

    # Method 2: Handling your own HTTP request and then analyzing the response
    async with httpx.AsyncClient(verify=True) as client:
        try:
            response = await client.get(target_url, timeout=5.0)
            
            # Use ShenSec's public API to analyze an existing response
            result = analyze_response(response, url=target_url)
            
            print(f"Scan complete! Finding risk rating: {result.risk_rating.value}")
            print(f"Total findings: {len(result.findings)}")
            
            # Generate a Markdown report
            report = generate_report(result, "markdown")
            print("\n--- Report ---\n")
            print(report)

        except httpx.RequestError as e:
            print(f"Failed to fetch {target_url}: {e}")

if __name__ == "__main__":
    asyncio.run(main())