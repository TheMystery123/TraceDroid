import json
from pathlib import Path
from llm_api import SiliconFlowAPI, DashScopeAPI, OpenAIAPI
from tqdm import tqdm

class AppDescriptionGenerator:
    def __init__(self, llm_api_key: str, model: str = "deepseek-ai/deepseek-vl2"):
        """Initialize the description generator
        
        Args:
            llm_api_key: LLM API key
        """
        siliconflow_api = SiliconFlowAPI(
            api_key=llm_api_key,
            model=model
        )

        dashscope_api = DashScopeAPI(
            api_key="xxx",
            model="xxx"
        )

        openai_api = OpenAIAPI(
            api_key="xxx",
            model="xxx"
        )

        self.llm_api = openai_api

    def generate_app_description(self, screenshot_path: str, activity_info: str, ui_tree_path: str) -> str:
        """Use GPT to generate APP page description
        
        Args:
            screenshot_path: Screenshot path
            activity_info: Activity information
            
        Returns:
            str: Generated description text
        """
        # Read ui_tree_content
        with open(ui_tree_path, 'r', encoding='utf-8') as f:
            ui_tree_content = f.read()

        messages = [
            ("user", [
                str(screenshot_path),
                f"This is a screenshot of an Android APP page. The Activity is {activity_info}. Activity may contain information related to the APP functions."
                "Here is the UI tree XML of the page:"
                f"{ui_tree_content}"
                "Please generate a detailed description for this app page, outlining the functionality of the app as well as the features available on this page."
            ])
        ]
        response = self.llm_api.chat_completion(messages, max_tokens=512)
        
        # Process response
        if "output" in response and "choices" in response["output"]:
            content = response["output"]["choices"][0]["message"]["content"]
            if isinstance(content, list):
                return content[0].get("text", "")
            return content
        return "Failed to generate description"

    def process_record(self, record_path: str):
        """Process record.json file, add description field
        
        Args:
            record_path: Path to record.json file
        """
        try:
            record_dir = Path(record_path).parent
            
            # Read record.json
            with open(record_path, 'r', encoding='utf-8') as f:
                record_data = json.load(f)
            
            # Check if field already exists
            if "gpt_app_description" in record_data:
                print(f"Skip {record_path}: Description field already exists")
                return
            
            # Get first step information
            first_step = record_data["steps"][0]
            screenshot_path = record_dir / "screenshots" / "step_0.png"
            ui_tree_path = record_dir / "ui_trees" / "step_0_ui.xml"
            activity_info = first_step.get("activity_info", "empty")
            
            # Generate description
            gpt_description = self.generate_app_description(
                str(screenshot_path), 
                activity_info,
                str(ui_tree_path)
            )

            print(gpt_description)
            
            # Add new field
            record_data["gpt_app_description"] = gpt_description
            
            # Save updated record.json
            with open(record_path, 'w', encoding='utf-8') as f:
                json.dump(record_data, f, indent=2, ensure_ascii=False)
            print(f"Successfully processed: {record_path}")
        except Exception as e:
            print(f"Error processing {record_path}: {str(e)}")

    def process_all_records(self, data_dir: str):
        """Process all record directories in the specified directory
        
        Args:
            data_dir: Root data directory path
        """
        data_path = Path(data_dir)
        # Find all directories starting with record_
        record_dirs = [d for d in data_path.glob("record_*") if d.is_dir()]
        
        print(f"Found {len(record_dirs)} record directories")
        # Add progress bar
        for record_dir in tqdm(record_dirs, desc="Processing records", unit="record"):
            record_path = record_dir / "record.json"
            if record_path.exists():
                self.process_record(str(record_path))
            else:
                print(f"Warning: record.json not found in {record_dir}")

if __name__ == "__main__":
    generator = AppDescriptionGenerator(
        llm_api_key="xxx",
        model="xxx"
    )
    
    # Process all record directories under real_data directory
    generator.process_all_records("real_data") 