import os
import json
from pathlib import Path
import shutil

class ActionRecorder:
    def __init__(self):
        self.actions_dir = Path("actions")
        self.steps_file = self.actions_dir / "steps.json"
        self._clear_actions_directory()
        self._ensure_directory_exists()
        self._ensure_steps_file_exists()
        
    def _clear_actions_directory(self):
        if self.actions_dir.exists():
            shutil.rmtree(self.actions_dir)
            
    def _ensure_directory_exists(self):
        if not self.actions_dir.exists():
            os.makedirs(self.actions_dir)
            
    def _ensure_steps_file_exists(self):
        if not self.steps_file.exists():
            with open(self.steps_file, 'w', encoding='utf-8') as f:
                json.dump([], f)
                
    def record_action(self, action_type: str, activity_name: str):
        action_data = {
            "action_type": action_type,
            "activity_name": activity_name
        }
        
        self._ensure_steps_file_exists()
        
        with open(self.steps_file, 'r+', encoding='utf-8') as f:
            try:
                steps = json.load(f)
            except json.JSONDecodeError:
                steps = []
                
            steps.append(action_data)
            f.seek(0)
            json.dump(steps, f, indent=2, ensure_ascii=False)
            f.truncate()