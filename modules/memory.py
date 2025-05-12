# modules/memory.py

import json
import os
import time
from typing import List, Optional
from pydantic import BaseModel
import os
from typing import List, Dict, Optional, Any

HISTORY_FILE = "C:\\Users\\DELL\\Desktop\\EAG\\Assignment - 9\\S9-bu2\\historical_conversation_store.json"

# Optional fallback logger
try:
    from agent import log
except ImportError:
    import datetime
    def log(stage: str, msg: str):
        now = datetime.datetime.now().strftime("%H:%M:%S")
        print(f"[{now}] [{stage}] {msg}")

class MemoryItem(BaseModel):
    """Represents a single memory entry for a session."""
    timestamp: float
    type: str  # run_metadata, tool_call, tool_output, final_answer
    text: str
    tool_name: Optional[str] = None
    tool_args: Optional[dict] = None
    tool_result: Optional[dict] = None
    final_answer: Optional[str] = None
    tags: Optional[List[str]] = []
    success: Optional[bool] = None
    metadata: Optional[dict] = {}  # ✅ ADD THIS LINE BACK

# File to store historical conversations


def load_conversation_history() -> List[Dict[str, Any]]:
    """Load the conversation history from the JSON file."""
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            log("history", f"⚠️ Error loading conversation history: {e}")
            return []
    else:
        log("history", f"Creating new conversation history file: {HISTORY_FILE}")
        return []

def save_conversation_history(history: List[Dict[str, Any]]) -> None:
    """Save the conversation history to the JSON file."""
    try:
        with open(HISTORY_FILE, 'w', encoding='utf-8') as f:
            json.dump(history, f, indent=2, ensure_ascii=False)
    except Exception as e:
        log("history", f"⚠️ Error saving conversation history: {e}")

def search_historical_conversations(query: str, history: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """
    Search for similar queries in conversation history.
    Returns the matched conversation or None if no match is found.
    Exact match for now, but could be enhanced with semantic search later.
    """
    normalized_query = query.lower().strip()
    
    # First pass: exact match
    for conversation in history:
        if conversation.get("query", "").lower().strip() == normalized_query:
            log("history", f"Found exact match in history")
            return conversation
    
    # Second pass: simple contains match (could be improved with better similarity)
    for conversation in history:
        if normalized_query in conversation.get("query", "").lower() or conversation.get("query", "").lower() in normalized_query:
            log("history", f"Found similar match in history")
            return conversation
    
    return None

def add_conversation_to_history(query: str, answer: str, history: List[Dict[str, Any]]) -> None:
    """Add a new conversation to the history."""
    conversation = {
        "timestamp": datetime.datetime.now().isoformat(),
        "query": query,
        "answer": answer,
        "final_answer": answer.split("FINAL_ANSWER:")[1].strip() if "FINAL_ANSWER:" in answer else answer
    }
    history.append(conversation)
    save_conversation_history(history)
    log("history", f"Added conversation to history: {query}")

class MemoryManager:
    """Manages session memory (read/write/append)."""

    def __init__(self, session_id: str, memory_dir: str = "memory"):
        self.session_id = session_id
        self.memory_dir = memory_dir
        self.memory_path = os.path.join('memory', session_id.split('-')[0], session_id.split('-')[1], session_id.split('-')[2], f'session-{session_id}.json')
        self.items: List[MemoryItem] = []

        if not os.path.exists(self.memory_dir):
            os.makedirs(self.memory_dir)

        self.load()

    def load(self):
        if os.path.exists(self.memory_path):
            with open(self.memory_path, "r", encoding="utf-8") as f:
                raw = json.load(f)
                self.items = [MemoryItem(**item) for item in raw]
        else:
            self.items = []

    def save(self):
        # Before opening the file for writing
        os.makedirs(os.path.dirname(self.memory_path), exist_ok=True)
        with open(self.memory_path, "w", encoding="utf-8") as f:
            raw = [item.dict() for item in self.items]
            json.dump(raw, f, indent=2)

    def add(self, item: MemoryItem):
        self.items.append(item)
        self.save()

    def add_tool_call(
        self, tool_name: str, tool_args: dict, tags: Optional[List[str]] = None
    ):
        item = MemoryItem(
            timestamp=time.time(),
            type="tool_call",
            text=f"Called {tool_name} with {tool_args}",
            tool_name=tool_name,
            tool_args=tool_args,
            tags=tags or [],
        )
        self.add(item)

    def add_tool_output(
        self, tool_name: str, tool_args: dict, tool_result: dict, success: bool, tags: Optional[List[str]] = None
    ):
        item = MemoryItem(
            timestamp=time.time(),
            type="tool_output",
            text=f"Output of {tool_name}: {tool_result}",
            tool_name=tool_name,
            tool_args=tool_args,
            tool_result=tool_result,
            success=success,  # 🆕 Track success!
            tags=tags or [],
        )
        self.add(item)

    def add_final_answer(self, text: str):
        item = MemoryItem(
            timestamp=time.time(),
            type="final_answer",
            text=text,
            final_answer=text,
        )
        self.add(item)

    def find_recent_successes(self, limit: int = 5) -> List[str]:
        """Find tool names which succeeded recently."""
        tool_successes = []

        # Search from newest to oldest
        for item in reversed(self.items):
            if item.type == "tool_output" and item.success:
                if item.tool_name and item.tool_name not in tool_successes:
                    tool_successes.append(item.tool_name)
            if len(tool_successes) >= limit:
                break

        return tool_successes

    def add_tool_success(self, tool_name: str, success: bool):
        """Patch last tool call or output for a given tool with success=True/False."""

        # Search backwards for latest matching tool call/output
        for item in reversed(self.items):
            if item.tool_name == tool_name and item.type in {"tool_call", "tool_output"}:
                item.success = success
                log("memory", f"✅ Marked {tool_name} as success={success}")
                self.save()
                return

        log("memory", f"⚠️ Tried to mark {tool_name} as success={success} but no matching memory found.")

    def get_session_items(self) -> List[MemoryItem]:
        """
        Return all memory items for current session.
        """
        return self.items
