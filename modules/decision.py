from typing import List, Optional
from modules.perception import PerceptionResult
from modules.memory import MemoryItem
from modules.model_manager import ModelManager
from modules.tools import load_prompt
from core.heuristics import apply_output_heuristics
import re

# Optional logging fallback
try:
    from agent import log
except ImportError:
    import datetime
    def log(stage: str, msg: str):
        now = datetime.datetime.now().strftime("%H:%M:%S")
        print(f"[{now}] [{stage}] {msg}")

model = ModelManager()

# prompt_path = "prompts/decision_prompt.txt"

async def generate_plan(
    user_input: str, 
    perception: PerceptionResult,
    memory_items: List[MemoryItem],
    tool_descriptions: Optional[str],
    prompt_path: str,
    step_num: int = 1,
    max_steps: int = 3,
) -> str:

    """Generates the full solve() function plan for the agent."""

    memory_texts = "\n".join(f"- {m.text}" for m in memory_items) or "None"

    prompt_template = load_prompt(prompt_path)

    prompt = prompt_template.format(
        tool_descriptions=tool_descriptions or "No tools needed for current step",
        user_input=user_input,
        memory_texts=memory_texts,
        step_num=step_num,
        max_steps=max_steps,
        perception = perception
    )

    try:
        # log("decision:", f"\n\nprompt: {prompt}\n\n")
        raw = (await model.generate_text(prompt)).strip()
        #log("plan", f"LLM output: {raw}")

        # Apply output heuristics to fix common issues in the LLM response
        fixed_raw, heuristic_messages = await apply_output_heuristics(raw)
        if heuristic_messages:
            log("heuristics", f"Applied plan fixes: {', '.join(heuristic_messages)}")
            if fixed_raw != raw:
                log("heuristics", "Plan was modified to fix issues")
                raw = fixed_raw

        # If fenced in ```python ... ```, extract
        if raw.startswith("```"):
            raw = raw.strip("`").strip()
            if raw.lower().startswith("python"):
                raw = raw[len("python"):].strip()

        if re.search(r"^\s*(async\s+)?def\s+solve\s*\(", raw, re.MULTILINE):
            return raw  # ✅ Correct, it's a full function
        else:
            log("plan", "⚠️ LLM did not return a valid solve(). Defaulting to FINAL_ANSWER")
            return "FINAL_ANSWER: [Could not generate valid solve()]"


    except Exception as e:
        log("plan", f"⚠️ Planning failed: {e}")
        return "FINAL_ANSWER: [unknown]"