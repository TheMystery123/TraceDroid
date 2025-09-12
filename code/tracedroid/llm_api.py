from abc import ABC, abstractmethod
import requests
from typing import List, Dict, Any, Optional, Union
import base64
from pathlib import Path
import re
from openai import OpenAI
import json

class BaseLLMAPI(ABC):
    """Base class for LLM API"""
    
    @abstractmethod
    def chat_completion(self, messages: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        pass

    @staticmethod
    def encode_image_to_base64(image_path: Union[str, Path]) -> str:
        with open(image_path, "rb") as image_file:
            return base64.b64encode(image_file.read()).decode('utf-8')

    @staticmethod
    def is_base64(s: str) -> bool:
        try:
            return base64.b64encode(base64.b64decode(s)).decode('utf-8') == s
        except Exception:
            return False

    @staticmethod
    def is_url(s: str) -> bool:
        url_pattern = re.compile(
            r'^https?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain
            r'localhost|'  # localhost
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        return bool(url_pattern.match(s))


class OpenAIAPI(BaseLLMAPI):
    """OpenAI API Implementation"""
    
    def __init__(self, api_key: str, model: str = "gpt-4o", base_url: Optional[str] = None):
        """
        Initialize OpenAI API client
        
        Args:
            api_key: OpenAI API key
            model: Model name, default is gpt-4o
            base_url: Base API URL for custom endpoints
        """
        self.model = model
        self.client = OpenAI(
            api_key=api_key,
            base_url=base_url
        )
        
    def process_image(self, image: Union[str, Path]) -> Dict[str, Any]:
        if isinstance(image, str):
            if self.is_url(image):
                return {
                    "type": "image_url",
                    "image_url": image
                }
            elif self.is_base64(image):
                return {
                    "type": "image_url",
                    "image_url": f"data:image/jpeg;base64,{image}"
                }
            else:
                image_base64 = self.encode_image_to_base64(image)
                return {
                    "type": "image_url",
                    "image_url": f"data:image/jpeg;base64,{image_base64}"
                }
        else:
            image_base64 = self.encode_image_to_base64(image)
            return {
                "type": "image_url",
                "image_url": f"data:image/jpeg;base64,{image_base64}"
            }

    def format_message(self, role: str, content: Union[str, List[Union[str, Dict, Path]]], **kwargs) -> Dict[str, Any]:
        if isinstance(content, str):
            return {"role": role, "content": content}
        
        formatted_content = []
        for item in content:
            if isinstance(item, str):
                if any(item.lower().endswith(ext) for ext in ['.jpg', '.jpeg', '.png', '.gif']):
                    formatted_content.append(self.process_image(item))
                else:
                    formatted_content.append({
                        "type": "text",
                        "text": item
                    })
            elif isinstance(item, Path) and any(str(item).lower().endswith(ext) for ext in ['.jpg', '.jpeg', '.png', '.gif']):
                formatted_content.append(self.process_image(item))
            elif isinstance(item, dict):
                formatted_content.append(item)
                
        return {"role": role, "content": formatted_content}

    def chat_completion(
        self, 
        messages: List[Union[Dict[str, Any], tuple]],
        stream: bool = False,
        max_tokens: int = 4096,
        temperature: float = 0.7,
        top_p: float = 0.7,
        frequency_penalty: float = 0.5,
        presence_penalty: float = 0.0,
        stop: Optional[List[str]] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Send chat request to OpenAI API
        
        Args:
            messages: List of messages
            stream: Whether to use streaming response
            max_tokens: Maximum number of tokens to generate
            temperature: Temperature parameter
            top_p: Top-p sampling parameter
            frequency_penalty: Frequency penalty parameter
            presence_penalty: Presence penalty parameter
            stop: Stop sequences
            **kwargs: Additional parameters
        """
        formatted_messages = []
        for message in messages:
            if isinstance(message, dict):
                formatted_messages.append(message)
            elif isinstance(message, tuple):
                role, content = message
                formatted_messages.append(self.format_message(role, content))

        response = self.client.chat.completions.create(
            model=self.model,
            messages=formatted_messages,
            stream=stream,
            max_tokens=max_tokens,
            temperature=temperature,
            top_p=top_p,
            frequency_penalty=frequency_penalty,
            presence_penalty=presence_penalty,
            stop=stop,
        )
        
        if stream:
            return response
        
        return {
            "choices": [{
                "message": {
                    "role": response.choices[0].message.role,
                    "content": response.choices[0].message.content
                }
            }]
        }

    def rank_potential_paths(self, prompt: str) -> List[Dict[str, Any]]:
        resp = self.chat_completion([("user", [prompt])], max_tokens=1024)
        content = resp["choices"][0]["message"]["content"]
        try:
            data = json.loads(re.search(r"```json\s*([\s\S]*?)\s*```", content).group(1))
        except Exception:
            data = {"potential_paths": []}
        return data.get("potential_paths", [])
