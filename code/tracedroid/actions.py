import os


def get_bounds(bound):
    a, b, c, d = [int(i) for i in bound]
    return a, b, c, d


def click_node(bound, device_name):
    pos_x_start, pos_y_start, pos_x_end, pos_y_end = get_bounds(bound)
    cmd = "adb shell input tap {} {}".format(str((pos_x_start + pos_x_end) // 2), str((pos_y_start + pos_y_end) // 2))
    if device_name:
        cmd = f"adb -s {device_name} " + cmd[4:]
    os.system(cmd)

def press_node(bound, device_name, duration = 1000):
    pos_x_start, pos_y_start, pos_x_end, pos_y_end = get_bounds(bound)
    pos_x = (pos_x_start + pos_x_end) // 2
    pos_y = (pos_y_start + pos_y_end) // 2
    cmd = "adb shell input swipe {} {} {} {} {}".format(pos_x, pos_y, pos_x, pos_y, duration)
    if device_name:
        cmd = f"adb -s {device_name} " + cmd[4:]
    os.system(cmd)


def get_screen_size(device_name):
    """Get screen dimensions"""
    cmd = "adb shell wm size"
    if device_name:
        cmd = f"adb -s {device_name} shell wm size"
    output = os.popen(cmd).read()
    width, height = map(int, output.split("\n")[0].split("Physical size:")[1].strip().split("x"))
    return width, height

def swipe(device_name: str, direction: str, distance: int, begin_bound=None, duration=500):
    """
    Execute swipe operation
    direction: 'up', 'down', 'left', 'right'
    distance: swipe distance (pixels)
    begin_component_id: component ID to start swipe from
    begin_bound: component boundary to start swipe from
    duration: swipe duration (milliseconds)
    """
    width, height = get_screen_size(device_name)
    
    if begin_bound:
        # If start component specified, swipe from component center
        pos_x_start, pos_y_start, pos_x_end, pos_y_end = get_bounds(begin_bound)
        start_x = (pos_x_start + pos_x_end) // 2
        start_y = (pos_y_start + pos_y_end) // 2
    else:
        # Otherwise swipe from screen center
        start_x = width // 2
        start_y = height // 2
    
    # Calculate endpoint based on direction
    if direction == 'up':
        end_x = start_x
        end_y = start_y - distance
    elif direction == 'down':
        end_x = start_x
        end_y = start_y + distance
    elif direction == 'left':
        end_x = start_x - distance
        end_y = start_y
    elif direction == 'right':
        end_x = start_x + distance
        end_y = start_y
    else:
        raise ValueError(f"Unsupported swipe direction: {direction}")

    # Ensure coordinates are within screen bounds
    start_x = max(0, min(start_x, width))
    start_y = max(0, min(start_y, height))
    end_x = max(0, min(end_x, width))
    end_y = max(0, min(end_y, height))

    cmd = f"adb shell input swipe {start_x} {start_y} {end_x} {end_y} {duration}"
    if device_name:
        cmd = f"adb -s {device_name} " + cmd[4:]
    os.system(cmd)
    

def go_back(device_name):
    cmd = "adb shell input keyevent 4"
    if device_name:
        cmd = f"adb -s {device_name} " + cmd[4:]
    os.system(cmd)


def change_orientation(device_name):
    raise NotImplementedError("You can implement this function by pyautogui.click(x, y) to click your Android Simulator.")

def keyboard_input(text, device_name):
    """Simulate keyboard text input"""
    cmd = f"adb shell input text '{text}'"
    if device_name:
        cmd = f"adb -s {device_name} " + cmd[4:]
    os.system(cmd)

def special_action(action_type, device_name):
    """
    action_type: 'KEY_BACK', 'KEY_HOME', 'KEY_ENTER'
    """
    action_map = {
        'KEY_BACK': 4,    # KEYCODE_BACK
        'KEY_HOME': 3,    # KEYCODE_HOME
        'KEY_ENTER': 66,  # KEYCODE_ENTER
    }
    
    if action_type not in action_map:
        raise ValueError(f"Unsupported special action: {action_type}")
        
    cmd = "adb shell input keyevent {action_map[action_type]}"
    if device_name:
        cmd = f"adb -s {device_name} " + cmd[4:]
    os.system(cmd)