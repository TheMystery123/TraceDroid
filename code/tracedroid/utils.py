import re
import os
import cv2
import json
from PIL import Image
from typing import List, Dict, Any
import os
from bs4 import BeautifulSoup


def list_all_files(root_dir: str) -> List[str]:
    all_files = []
    for base, _, files in os.walk(root_dir):
        for f in files:
            all_files.append(os.path.join(base, f))
    return all_files


def extract_android_widgets_from_xml(xml_path: str) -> List[Dict[str, Any]]:
    """Parse an Android XML layout and return widgets with id/text and tag name."""
    try:
        with open(xml_path, 'r', encoding='utf-8') as f:
            content = f.read()
        soup = BeautifulSoup(content, 'lxml-xml')
        widgets = []
        for node in soup.find_all(True):
            view_id = node.get('android:id') or node.get('id')
            text = node.get('android:text') or node.get('text')
            if view_id or text:
                widgets.append({
                    'tag': node.name,
                    'id': view_id.replace('@+id/', '').replace('@id/', '') if view_id else None,
                    'text': text,
                    'xml_path': xml_path
                })
        return widgets
    except Exception:
        return []

def combine_images_horizontally(image_dir, output_path=None):
    """
    Horizontally combine all images in the specified directory into a single image
    
    Args:
        image_dir (str): Directory path containing the images
        output_path (str, optional): Save path for the output image. If None, only display without saving
        
    Returns:
        PIL.Image: Combined image object. Returns None if no images are found
    """
    if not os.path.exists(image_dir):
        return None
        
    # Get all images in the directory
    image_files = [f for f in os.listdir(image_dir) 
                  if f.endswith(('.png', '.jpg', '.jpeg'))]
    image_files.sort()  # Ensure images are sorted in order
    
    if not image_files:
        return None
        
    # Open all images
    images = [Image.open(os.path.join(image_dir, img)) 
              for img in image_files]
    
    # Calculate total width and maximum height of the combined image
    total_width = sum(img.width for img in images)
    max_height = max(img.height for img in images)
    
    # Create new image
    combined_image = Image.new('RGB', (total_width, max_height))
    
    # Combine images
    x_offset = 0
    for img in images:
        combined_image.paste(img, (x_offset, 0))
        x_offset += img.width
    
    # Save image if output path is specified
    if output_path:
        combined_image.save(output_path)
    
    return combined_image


def extract_json_from_str(json_str):
    json_pattern = r'```json\s*([\s\S]*?)\s*```'

    matches = re.findall(json_pattern, json_str)

    target_json = json.loads(matches[0])

    return target_json


def draw_bounds(i, bounds):
    image_path = os.path.join("screenshots", f"{i}.jpg")
    image = cv2.imread(image_path)
    x1, y1, x2, y2 = bounds
    cv2.rectangle(image, (x1, y1), (x2, y2), (0, 0, 255), 2)  # Blue bounds
    os.makedirs("actions", exist_ok=True)
    output_path = os.path.join("actions", f"{i}.jpg") 
    cv2.imwrite(output_path, image)
    # img = Image.open(output_path)
    # img.show()

def draw_all_bounds(image, bounds_list):
    for i, bounds in enumerate(bounds_list, 1):
        x1, y1, x2, y2 = bounds
        cv2.rectangle(image, (x1, y1), (x2, y2), (0, 0, 255), 2)  # Red border
        # Add component number
        cv2.putText(image, str(i), (x1, y1-10), cv2.FONT_HERSHEY_SIMPLEX, 0.8, (0, 0, 255), 2)
    return image

def draw_swipe_action(i, bound, direction):
    """
    Mark the starting position and direction of the swipe action
    """
    image_path = os.path.join("screenshots", f"{i}.jpg")
    image = cv2.imread(image_path)
    
    if bound:
        x1, y1, x2, y2 = bound
        # Draw a box at the starting position
        cv2.rectangle(image, (x1, y1), (x2, y2), (0, 255, 0), 2)  # Green border indicates swipe start point
        
        # Add direction arrow at the starting position
        center_x = (x1 + x2) // 2
        center_y = (y1 + y2) // 2
        arrow_length = 50
        
        if direction == "up":
            end_y = center_y - arrow_length
            cv2.arrowedLine(image, (center_x, center_y), (center_x, end_y), (0, 255, 0), 2)
        elif direction == "down":
            end_y = center_y + arrow_length
            cv2.arrowedLine(image, (center_x, center_y), (center_x, end_y), (0, 255, 0), 2)
        elif direction == "left":
            end_x = center_x - arrow_length
            cv2.arrowedLine(image, (center_x, center_y), (end_x, center_y), (0, 255, 0), 2)
        elif direction == "right":
            end_x = center_x + arrow_length
            cv2.arrowedLine(image, (center_x, center_y), (end_x, center_y), (0, 255, 0), 2)
    
    # Add text description in the upper left corner
    cv2.putText(image, f"Swipe {direction}", (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 255, 0), 2)
    
    os.makedirs("actions", exist_ok=True)
    output_path = os.path.join("actions", f"{i}.jpg") 
    cv2.imwrite(output_path, image)
    # img = Image.open(output_path)
    # img.show()

def draw_text_action(i, text):
    """
    Add text description in the upper left corner of the image
    """
    image_path = os.path.join("screenshots", f"{i}.jpg")
    image = cv2.imread(image_path)
    
    # Add text in the upper left corner
    cv2.putText(image, text, (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 0, 255), 2)
    
    os.makedirs("actions", exist_ok=True)
    output_path = os.path.join("actions", f"{i}.jpg") 
    cv2.imwrite(output_path, image)
    # img = Image.open(output_path)
    # img.show()