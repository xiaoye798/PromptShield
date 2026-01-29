import asyncio
import os
from dotenv import dotenv_values
import openai
from mcp_client import HoneypotMCPClient

config = dotenv_values(".env")
openai.api_key = config["OPENAI_API_KEY"]
client = openai.OpenAI(api_key=config["OPENAI_API_KEY"])

async def test():
    print("Testing OpenAI...")
    try:
        resp = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": "hi"}],
            max_tokens=5
        )
        print(f"OpenAI OK: {resp.choices[0].message.content}")
    except Exception as e:
        print(f"OpenAI Failed: {e}")

    print("Testing MCP...")
    try:
        mcp = HoneypotMCPClient(storage_path="./ablation_memory", global_singleton_mode=True)
        await mcp.connect()
        print("MCP Connect OK")
        await mcp.close()
        print("MCP Close OK")
    except Exception as e:
        print(f"MCP Failed: {e}")

if __name__ == "__main__":
    asyncio.run(test())
