"""Action execution and coordination for the hackbot agent."""

from actions.action1 import Action1


class ActionHandler:
    """Coordinates action execution."""

    def __init__(self):
        self.actions = {
            "action1": Action1(),
        }

    def execute(self, action_name: str, params: dict) -> dict:
        """Execute a registered action by name."""
        if action_name not in self.actions:
            raise ValueError(f"Unknown action: {action_name}")
        return self.actions[action_name].run(params)

    def register(self, name: str, action) -> None:
        """Register a new action."""
        self.actions[name] = action
