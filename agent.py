# agent.py

import asyncio
import yaml
from core.loop import AgentLoop
from core.session import MultiMCP
from core.context import MemoryItem, AgentContext
import datetime
from pathlib import Path
import json
import re
import os
from typing import List, Dict, Optional, Any
from modules.memory import load_conversation_history, search_historical_conversations, add_conversation_to_history
from core.heuristics import apply_input_heuristics, normalize_query

def log(stage: str, msg: str):
    """Simple timestamped console logger."""
    now = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{now}] [{stage}] {msg}")



async def main():
    print("🧠 Cortex-R Agent Ready")
    current_session = None

    with open("config/profiles.yaml", "r") as f:
        profile = yaml.safe_load(f)
        mcp_servers_list = profile.get("mcp_servers", [])
        mcp_servers = {server["id"]: server for server in mcp_servers_list}

    multi_mcp = MultiMCP(server_configs=list(mcp_servers.values()))
    await multi_mcp.initialize()

    try:
        while True:
            raw_user_input = input("🧑 What do you want to solve today? → ")
            if raw_user_input.lower() == 'exit':
                break
            if raw_user_input.lower() == 'new':
                current_session = None
                continue

            # Apply input heuristics to sanitize and improve the query
            user_input, input_messages = await apply_input_heuristics(raw_user_input)
            if input_messages:
                print(f"📝 Input processed: {', '.join(input_messages)}")
            
            # Use normalized query for history search (but keep original for agent)
            normalized_input = normalize_query(user_input)

            # Check history for similar queries
            history = load_conversation_history()
            match = search_historical_conversations(normalized_input, history)
            if match:
                answer = match.get("answer", "")
                final_answer = match.get("final_answer", answer.split("FINAL_ANSWER:")[1].strip() if "FINAL_ANSWER:" in answer else answer)
                
                print(f"\n🔍 Found answer in history.")
                cont = input("Do you want to see this answer? (y/n) → ")
                if cont.lower() == 'y':
                    print(f"\n💡 Previous Answer: {final_answer}")
                    continue
                else:
                    print("Running agent to get a fresh answer...")

            while True:
                context = AgentContext(
                    user_input=user_input,  # Using the processed input
                    session_id=current_session,
                    dispatcher=multi_mcp,
                    mcp_server_descriptions=mcp_servers,
                )
                agent = AgentLoop(context)
                if not current_session:
                    current_session = context.session_id

                result = await agent.run()

                if isinstance(result, dict):
                    answer = result["result"]
                    if "FINAL_ANSWER:" in answer:
                        final_answer = answer.split("FINAL_ANSWER:")[1].strip()
                        print(f"\n💡 Final Answer: {final_answer}")
                        
                        # Add this conversation to history
                        add_conversation_to_history(user_input, answer, history)
                        
                        # Reset for next query to avoid state contamination
                        current_session = None 
                        break
                    elif "FURTHER_PROCESSING_REQUIRED:" in answer:
                        user_input = answer.split("FURTHER_PROCESSING_REQUIRED:")[1].strip()
                        print(f"\n🔁 Further Processing Required: {user_input}")
                        continue  # 🧠 Re-run agent with updated input
                    else:
                        print(f"\n💡 Final Answer (raw): {answer}")
                        
                        # Add this conversation to history
                        add_conversation_to_history(user_input, answer, history)
                        
                        # Reset for next query to avoid state contamination
                        current_session = None
                        break
                else:
                    print(f"\n💡 Final Answer (unexpected): {result}")
                    
                    # Add this conversation to history
                    add_conversation_to_history(user_input, str(result), history)
                    
                    # Reset for next query to avoid state contamination
                    current_session = None
                    break
    except KeyboardInterrupt:
        print("\n👋 Received exit signal. Shutting down...")

if __name__ == "__main__":
    asyncio.run(main())



# Find the ASCII values of characters in INDIA and then return sum of exponentials of those values.
# How much Anmol singh paid for his DLF apartment via Capbridge? 
# What do you know about Don Tapscott and Anthony Williams?
# What is the relationship between Gensol and Go-Auto?
# which course are we teaching on Canvas LMS? "H:\DownloadsH\How to use Canvas LMS.pdf"
# Summarize this page: https://theschoolof.ai/
# What is the log value of the amount that Anmol singh paid for his DLF apartment via Capbridge?

#Which plastic-based product category had the highest compound annual growth rate (CAGR) in exports from India between 2009-10 and 2018-19, and what was that rate? Search local documents
#Summarize the key measures DLF has taken to mitigate the risks associated with physical impacts of climate change. Search local documents
#What is the fine for a Light Motor Vehicle (LMV) driver caught using a mobile phone while driving in Bengaluru, and how does it change for repeat offences? Search local documents