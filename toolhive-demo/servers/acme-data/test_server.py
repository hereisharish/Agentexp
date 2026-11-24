"""Smoke test: talk to the server over stdio exactly as ToolHive would."""

import asyncio
import json
import os
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

HERE = os.path.dirname(os.path.abspath(__file__))


async def main() -> None:
    params = StdioServerParameters(command=sys.executable, args=[os.path.join(HERE, "server.py")])
    async with stdio_client(params) as (r, w), ClientSession(r, w) as s:
        await s.initialize()
        tools = sorted(t.name for t in (await s.list_tools()).tools)
        assert tools == sorted(
            ["list_customers", "get_customer", "update_ticket", "delete_customer", "export_report", "reset_demo_data"]
        ), tools

        def text(res):
            return json.loads(res.content[0].text)

        c = text(await s.call_tool("get_customer", {"customer_id": "42"}))
        assert c["email"].endswith(".example") and "customer_note" in c["ticket"]
        assert text(await s.call_tool("update_ticket", {"customer_id": "41", "status": "resolved"}))["ok"]
        assert text(await s.call_tool("export_report", {"destination": "s3://x", "include_pii": True}))["included_pii"]
        assert text(await s.call_tool("delete_customer", {"customer_id": "40"}))["ok"]
        assert len(text(await s.call_tool("list_customers", {}))) == 2
        assert text(await s.call_tool("reset_demo_data", {}))["customers"] == 3
    print("acme-data smoke test: OK")


if __name__ == "__main__":
    asyncio.run(main())
