import requests
import json
from typing import List, Dict, Any, Optional
from datetime import datetime

class DeepSeekClient:
    """
    DeepSeek API client class for interacting with DeepSeek services
    """
    
    def __init__(self, api_key: str, base_url: str = "https://api.deepseek.com"):
        """
        Initialize DeepSeek client
        
        Args:
            api_key: DeepSeek API key
            base_url: API base URL
        """
        self.api_key = api_key
        self.base_url = base_url.rstrip('/')
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
    
    def chat_completion(self, 
                       messages: List[Dict[str, str]], 
                       model: str = "deepseek-chat",
                       temperature: float = 0.0,
                       max_tokens: int = 800,
                       stream: bool = False) -> Dict[str, Any]:
        """
        Create chat completion request
        
        Args:
            messages: Message list, format is [{"role": "user/assistant/system", "content": "message content"}]
            model: Model name to use
            temperature: Temperature parameter, controls output randomness
            max_tokens: Maximum token count
            stream: Whether to use streaming output
            
        Returns:
            API response result
        """
        url = f"{self.base_url}/v1/chat/completions"
        
        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": stream
        }
        
        try:
            response = requests.post(url, headers=self.headers, json=payload, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            raise Exception(f"DeepSeek API request failed: {str(e)}")
        except json.JSONDecodeError as e:
            raise Exception(f"DeepSeek API response parsing failed: {str(e)}")
    
    def get_models(self) -> List[Dict[str, Any]]:
        """
        Get list of available models
        
        Returns:
            Model list
        """
        url = f"{self.base_url}/v1/models"
        
        try:
            response = requests.get(url, headers=self.headers, timeout=10)
            response.raise_for_status()
            return response.json().get('data', [])
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to get DeepSeek model list: {str(e)}")
    
    def validate_connection(self) -> bool:
        """
        Validate if API connection is normal
        
        Returns:
            Whether connection is successful
        """
        try:
            self.get_models()
            return True
        except Exception:
            return False

class DeepSeekChatCompletion:
    """
    DeepSeek chat completion class compatible with OpenAI interface format
    """
    
    def __init__(self, client: DeepSeekClient):
        self.client = client
    
    def create(self, 
               model: str = "deepseek-chat",
               messages: List[Dict[str, str]] = None,
               temperature: float = 0.0,
               max_tokens: int = 800,
               **kwargs) -> 'DeepSeekResponse':
        """
        Create chat completion, compatible with OpenAI interface format
        """
        if messages is None:
            messages = []
            
        response_data = self.client.chat_completion(
            messages=messages,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens
        )
        
        return DeepSeekResponse(response_data)

class DeepSeekResponse:
    """
    DeepSeek API response class, compatible with OpenAI response format
    """
    
    def __init__(self, response_data: Dict[str, Any]):
        self.response_data = response_data
        self.choices = [DeepSeekChoice(choice) for choice in response_data.get('choices', [])]
        self.usage = response_data.get('usage', {})
        self.id = response_data.get('id', '')
        self.object = response_data.get('object', 'chat.completion')
        self.created = response_data.get('created', int(datetime.now().timestamp()))
        self.model = response_data.get('model', 'deepseek-chat')

class DeepSeekChoice:
    """
    DeepSeek choice class, compatible with OpenAI format
    """
    
    def __init__(self, choice_data: Dict[str, Any]):
        self.choice_data = choice_data
        self.message = DeepSeekMessage(choice_data.get('message', {}))
        self.finish_reason = choice_data.get('finish_reason', 'stop')
        self.index = choice_data.get('index', 0)

class DeepSeekMessage:
    """
    DeepSeek message class, compatible with OpenAI format
    """
    
    def __init__(self, message_data: Dict[str, Any]):
        self.message_data = message_data
        self.content = message_data.get('content', '')
        self.role = message_data.get('role', 'assistant')
        self.function_call = message_data.get('function_call')
        self.tool_calls = message_data.get('tool_calls')
