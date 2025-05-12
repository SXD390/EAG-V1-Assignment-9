# modules/tools.py

from typing import List, Dict, Optional, Any
import re
import asyncio
from modules.model_manager import ModelManager

model = ModelManager()

async def clean_text(raw_text):
    # Step 1: Remove irrelevant sections (e.g., company history, long unrelated paragraphs)
    prompt = f"Clean the below text, removing irrelevant sections, but ensuring to retain 100% of meaningful information and formatting it(do not use markdown) for readability:\n\n{raw_text}"
    final_text = (await model.generate_text(prompt)).strip()
    return final_text.strip()

def extract_json_block(text: str) -> str:
    match = re.search(r"```json\n(.*?)```", text, re.DOTALL)
    if match:
        return match.group(1).strip()
    return text.strip()


def summarize_tools(tools: List[Any] = None, dispatcher = None) -> str:
    """
    Generate a string summary of tools for LLM prompt injection.
    Format: "- tool_name: description"
    
    Parameters:
    - tools: Optional list of tools to summarize. If None and dispatcher is provided, all tools will be used.
    - dispatcher: Optional MultiMCP instance to fetch all tools when tools=None
    """
    if tools is None:
        if dispatcher is None:
            return "No tools available."
        
        # Get all tools from dispatcher - use servers property directly
        try:
            # Method 1: Try to get all tools from all servers
            all_tools = []
            for server_id in dispatcher.servers.keys():
                server_tools = dispatcher.get_tools_from_servers([server_id])
                if server_tools:
                    all_tools.extend(server_tools)
            
            if all_tools:
                tools = all_tools
            else:
                return "No tools available from dispatcher."
        except Exception as e:
            print(f"[tools] Error getting tools from dispatcher: {e}")
            return "Error getting tools from dispatcher."
    
    return "\n".join(
        f"- {tool.name}: {getattr(tool, 'description', 'No description provided.')}"
        for tool in tools
    )


def filter_tools_by_hint(tools: List[Any], hint: Optional[str] = None) -> List[Any]:
    """
    If tool_hint is provided (e.g., 'search_documents'),
    try to match it exactly or fuzzily with available tool names.
    """
    if not hint:
        return tools

    hint_lower = hint.lower()
    filtered = [tool for tool in tools if hint_lower in tool.name.lower()]
    return filtered if filtered else tools


def get_tool_map(tools: List[Any]) -> Dict[str, Any]:
    """
    Return a dict of tool_name → tool object for fast lookup
    """
    return {tool.name: tool for tool in tools}

def tool_expects_input(self, tool_name: str) -> bool:
    tool = next((t for t in self.tools if t.name == tool_name), None)
    if not tool or not hasattr(tool, 'parameters') or not isinstance(tool.parameters, dict):
        return False
    # If the top-level parameter is just 'input', we assume wrapping is required
    return list(tool.parameters.keys()) == ['input']


def load_prompt(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()