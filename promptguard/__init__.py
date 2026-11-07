"""PROMPTGUARD: task-bounded evidence admission and recovery."""
__version__ = "0.1.0"

# Lazy export preserves V1's dependency set and avoids control-plane side effects.
def __getattr__(name):
    if name == "PromptGuard":
        from promptguard_v2.sdk import PromptGuard
        return PromptGuard
    raise AttributeError(name)
