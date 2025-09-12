import configparser
import os
import json
import time
import shutil
from PIL import Image
import base64
import cv2

from llm_api import OpenAIAPI
from record import Record
from logger import Log
from prompts import *
from utils import *
from actions import *
from action_recorder import ActionRecorder
from pipeline import run_pipeline


def initialize_config():
    """Initialize and return config parser"""
    config = configparser.ConfigParser()
    config.read('config.ini')
    return config


def initialize_llm_client(config):
    """Initialize and return LLM client"""
    print("Initialize LLM client")
    print("OpenAI API Key:", config['llm']['openai_api_key'])
    print("OpenAI Model:", config['llm']['openai_model'])
    print("OpenAI Base URL:", config['llm']['openai_base_url'])
    return OpenAIAPI(
        api_key=config['llm']['openai_api_key'],
        model=config['llm']['openai_model'],
        base_url=config['llm']['openai_base_url']
    )


def initialize_android_device(config):
    """Get android device from config"""
    return config['uiautomator2'].get('android_device', "") if 'uiautomator2' in config else ""


def get_current_page_info(record, logger):
    """Get and log current page information"""
    logger.debug(f"Current Page Info: {record.get_running_info()}")
    current_steps = record.get_current_steps()
    logger.info(f"Current Steps: {current_steps}")
    
    record.record()
    current_steps = record.get_current_steps()
    logger.info(f"Current Steps: {current_steps}")
    
    logger.info(f"Screenshot Path: {record.get_cur_screenshot_path()}")
    logger.info(f"Current Activity: {record.get_cur_activity()}")
    logger.info(f"Current Hierarchy Path: {record.get_cur_hierarchy_path()}")
    logger.info(f"Current Component Info: {record.get_cur_components_path()}")


def process_screenshot(current_screenshot_path, current_component_path):
    """Process screenshot with component bounds"""
    with open(current_component_path, 'r', encoding='utf-8') as f:
        current_component_info = json.load(f)
    
    processed_screenshot = cv2.imread(current_screenshot_path)
    components_bounds = [item['bound'] for item in current_component_info]
    processed_screenshot = draw_all_bounds(processed_screenshot, components_bounds)
    
    processed_screenshot_path = 'processed_current_screenshot.png'
    cv2.imwrite(processed_screenshot_path, processed_screenshot)
    return processed_screenshot_path


def execute_click_action(record, action_detail, current_component_path):
    """Execute click or press action"""
    click_item = {}
    with open(current_component_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
        for each in data:
            if each['id'] == int(action_detail):
                click_item = each

    bound = click_item['bound']
    draw_bounds(record.current_steps, bound)
    click_node(bound, record.device_name)


def execute_swipe_action(record, action_detail, current_component_path):
    """Execute swipe action"""
    begin_bound = None
    if 'begin_component_id' in action_detail:
        with open(current_component_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            for each in data:
                if each['id'] == int(action_detail['begin_component_id']):
                    begin_bound = each['bound']
                    break
    
    draw_swipe_action(record.current_steps, begin_bound, action_detail['direction'])
    swipe(record.device_name, 
          action_detail['direction'], 
          int(action_detail['distance']),
          begin_bound)


def execute_action(record: Record, json_next_steps, current_component_path):
    """Execute action based on action type"""
    action_type = json_next_steps["action_type"]
    action_detail = json_next_steps["action_detail"]

    action_recorder.record_action(action_type, record.get_cur_activity())

    if action_type == "click" or action_type == "press":
        execute_click_action(record, action_detail, current_component_path)
    elif action_type == "swipe":
        execute_swipe_action(record, action_detail, current_component_path)
    elif action_type == "keyboard_input":
        draw_text_action(record.current_steps, f"Input: {action_detail}")
        keyboard_input(action_detail, record.device_name)
    elif action_type == "special_action":
        draw_text_action(record.current_steps, f"Special Action: {action_detail}")
        special_action(action_detail, record.device_name)
    elif action_type == "next_path":
        # No physical action needed, just log the path transition
        print(f"Path transition: {action_detail}")
    elif action_type == "end":
        # No physical action needed, just log the end
        print(f"Testing ended: {action_detail}")
    else:
        raise ValueError(f"action type {action_type} not supported")


def test_gpt_api_call(llm_client: OpenAIAPI):
    """Test GPT API call with simple prompt"""
    test_prompt = [
        ("user", [
            # "./image.jpg",  # Local image path
            "hello"  # Text prompt
        ])
    ]
    try:
        response = llm_client.chat_completion(test_prompt, max_tokens=10)
        print("API call successful. Response:")
        print(response)
        return True
    except Exception as e:
        print(f"API call failed. Error: {str(e)}")
        return False


def main():
    global action_recorder

    action_history = []
    original_app = None
    
    # Initialize components
    config = initialize_config()
    llm_client = initialize_llm_client(config)
    action_recorder = ActionRecorder()
    
    # Test GPT API call (keep but do not exit if failed)
    # test_gpt_api_call(llm_client)

    # Run static pipeline to get potential paths for bug-driven testing
    pipeline_result = None
    try:
        android_repo_root = "/path/repo_root/xxxx"
        code_segment = None
        apk_path = os.path.join('apks', 'xx.apk')
        if os.path.exists(apk_path):
            pipeline_result = run_pipeline(llm_client, apk_path, android_repo_root, code_segment)
            print("\n=== Pipeline (Static) Result ===")
            print(json.dumps({
                'rough_paths': pipeline_result['rough_paths'],
                'potential_paths': pipeline_result['potential_paths']
            }, ensure_ascii=False, indent=2))
        else:
            print(f"APK file not found: {apk_path}")
    except Exception as e:
        print(f"Pipeline stage failed: {e}")
        pipeline_result = None


    print("Pipeline result: ", pipeline_result)
    # exit()
    
    logger = Log().logger
    android_device = initialize_android_device(config)
    
    
    record = Record(android_device)
    logger.info('Initializing ...')
    
    # Get initial page info
    get_current_page_info(record, logger)
    
    current_screenshot_path = record.get_cur_screenshot_path()
    current_component_path = record.get_cur_components_path()
    
    # Process initial screenshot
    process_screenshot(current_screenshot_path, current_component_path)
    
    # Initialize bug-driven testing variables
    chat_history = []
    monitor_feedback = None
    current_path_index = 0
    
    # Get app info for bug-driven testing
    app_info = None
    if pipeline_result:
        app_info = pipeline_result.get('app_info', {})
        potential_paths = pipeline_result.get('potential_paths', [])
    else:
        # Fallback: create dummy app info if pipeline failed
        app_info = {
            'package_name': 'com.example.app',
            'activities': ['MainActivity', 'SettingsActivity']
        }
        potential_paths = [
            {'path': ['MainActivity', 'SettingsActivity'], 'score': 0.8, 'reason': 'Default path for testing'}
        ]
    
    print(f"\n=== Starting Bug-Driven Testing ===")
    print(f"App: {app_info.get('package_name', 'Unknown')}")
    print(f"Total potential paths: {len(potential_paths)}")

    while True:
        if not original_app and record.get_running_info():
            original_app = record.get_running_info().get('app', '')
        
        # Process current screenshot
        process_screenshot(current_screenshot_path, current_component_path)
        
        # Get current activity
        current_activity = record.get_cur_activity() or "Unknown"
        
        # Prepare bug-driven prompt
        with open(current_component_path, 'r', encoding='utf-8') as f:
            component_info = json.load(f)
        
        prompt = get_bug_driven_action_prompt(
            package_name=app_info.get('package_name', 'Unknown'),
            activities=app_info.get('activities', []),
            potential_paths=potential_paths,
            current_activity=current_activity,
            component_info=json.dumps(component_info),
            action_history=json.dumps(action_history),
            current_path_index=current_path_index
        )
        
        # Print input information
        print("\n=== Bug-Driven Testing Info ===")
        print(f"Current Activity: {current_activity}")
        print(f"Current Path Index: {current_path_index + 1}/{len(potential_paths)}")
        if current_path_index < len(potential_paths):
            current_path = potential_paths[current_path_index]
            print(f"Target Path: {' -> '.join(current_path['path'])} (score: {current_path['score']})")
        print(f"Action History Length: {len(action_history)}")
        
        # Add prompt to chat history
        chat_history = [("user", [prompt])]
        
        # Call LLM to generate next action
        response = llm_client.chat_completion(chat_history, max_tokens=512)

        try:
            next_steps = response["choices"][0]["message"]["content"]
        except:
            next_steps = "LLM call failed"

        # Print output information
        print("\n=== LLM Response ===")
        print(f"Response: {next_steps}")
        
        json_next_steps = extract_json_from_str(next_steps)
        logger.info(f"LLM suggested next action: {str(json_next_steps)}")
        
        # Handle special actions for bug-driven testing
        if json_next_steps["action_type"] == "next_path":
            current_path_index += 1
            print(f"\n=== Moving to Next Path: {current_path_index + 1}/{len(potential_paths)} ===")
            if current_path_index >= len(potential_paths):
                print("All potential paths completed!")
                break
            continue
        elif json_next_steps["action_type"] == "end":
            logger.info("Bug-driven testing completed")
            break
        
        action_history.append(json_next_steps)

        # Execute action
        execute_action(record, json_next_steps, current_component_path)
        
        # Update page info after action
        time.sleep(5)

        record.record()
        current_screenshot_path = record.get_cur_screenshot_path()
        current_component_path = record.get_cur_components_path()
        logger.info(f"Updated page information - Screenshot path: {current_screenshot_path}")


if __name__ == "__main__":
    main()

