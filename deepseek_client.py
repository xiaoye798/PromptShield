import requests
import json
from typing import List, Dict, Any, Optional
from datetime import datetime

class DeepSeekClient:
    """
    DeepSeek API客户端类，用于与DeepSeek服务进行交互
    """
    
    def __init__(self, api_key: str, base_url: str = "https://api.deepseek.com"):
        """
        初始化DeepSeek客户端
        
        Args:
            api_key: DeepSeek API密钥
            base_url: API基础URL
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
        创建聊天完成请求
        
        Args:
            messages: 消息列表，格式为[{"role": "user/assistant/system", "content": "消息内容"}]
            model: 使用的模型名称
            temperature: 温度参数，控制输出的随机性
            max_tokens: 最大token数量
            stream: 是否使用流式输出
            
        Returns:
            API响应结果
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
            raise Exception(f"DeepSeek API请求失败: {str(e)}")
        except json.JSONDecodeError as e:
            raise Exception(f"DeepSeek API响应解析失败: {str(e)}")
    
    def get_models(self) -> List[Dict[str, Any]]:
        """
        获取可用的模型列表
        
        Returns:
            模型列表
        """
        url = f"{self.base_url}/v1/models"
        
        try:
            response = requests.get(url, headers=self.headers, timeout=10)
            response.raise_for_status()
            return response.json().get('data', [])
        except requests.exceptions.RequestException as e:
            raise Exception(f"获取DeepSeek模型列表失败: {str(e)}")
    
    def validate_connection(self) -> bool:
        """
        验证API连接是否正常
        
        Returns:
            连接是否成功
        """
        try:
            self.get_models()
            return True
        except Exception:
            return False

class DeepSeekChatCompletion:
    """
    兼容OpenAI接口格式的DeepSeek聊天完成类
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
        创建聊天完成，兼容OpenAI接口格式
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
    DeepSeek API响应类，兼容OpenAI响应格式
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
    DeepSeek选择项类，兼容OpenAI格式
    """
    
    def __init__(self, choice_data: Dict[str, Any]):
        self.choice_data = choice_data
        self.message = DeepSeekMessage(choice_data.get('message', {}))
        self.finish_reason = choice_data.get('finish_reason', 'stop')
        self.index = choice_data.get('index', 0)

class DeepSeekMessage:
    """
    DeepSeek消息类，兼容OpenAI格式
    """
    
    def __init__(self, message_data: Dict[str, Any]):
        self.message_data = message_data
        self.content = message_data.get('content', '')
        self.role = message_data.get('role', 'assistant')
        self.function_call = message_data.get('function_call')
        self.tool_calls = message_data.get('tool_calls')