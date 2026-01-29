#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
API选择器脚本
用于在OpenAI和DeepSeek API之间切换配置
"""

import os
import sys
from dotenv import dotenv_values, set_key
from deepseek_client import DeepSeekClient
import openai

def load_config():
    """加载当前配置"""
    if not os.path.exists('.env'):
        print("错误：未找到.env文件，请先从env_TEMPLATE创建.env文件")
        return None
    return dotenv_values('.env')

def test_openai_connection(api_key):
    """测试OpenAI API连接"""
    try:
        openai.api_key = api_key
        # 尝试创建一个简单的聊天完成请求来测试连接
        response = openai.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": "Hello"}],
            max_tokens=5
        )
        return True
    except Exception as e:
        print(f"OpenAI API连接测试失败: {str(e)}")
        return False

def test_deepseek_connection(api_key, base_url):
    """测试DeepSeek API连接"""
    try:
        client = DeepSeekClient(api_key, base_url)
        return client.validate_connection()
    except Exception as e:
        print(f"DeepSeek API连接测试失败: {str(e)}")
        return False

def switch_to_openai():
    """切换到OpenAI API"""
    config = load_config()
    if not config:
        return False
    
    if not config.get('OPENAI_API_KEY'):
        print("错误：未配置OPENAI_API_KEY")
        return False
    
    print("正在测试OpenAI API连接...")
    if not test_openai_connection(config['OPENAI_API_KEY']):
        print("OpenAI API连接失败，请检查API密钥")
        return False
    
    set_key('.env', 'API_PROVIDER', 'openai')
    print("✅ 已成功切换到OpenAI API")
    return True

def switch_to_deepseek():
    """切换到DeepSeek API"""
    config = load_config()
    if not config:
        return False
    
    if not config.get('DEEPSEEK_API_KEY'):
        print("错误：未配置DEEPSEEK_API_KEY")
        return False
    
    base_url = config.get('DEEPSEEK_BASE_URL', 'https://api.deepseek.com')
    
    print("正在测试DeepSeek API连接...")
    if not test_deepseek_connection(config['DEEPSEEK_API_KEY'], base_url):
        print("DeepSeek API连接失败，请检查API密钥和基础URL")
        return False
    
    set_key('.env', 'API_PROVIDER', 'deepseek')
    print("✅ 已成功切换到DeepSeek API")
    return True

def show_current_config():
    """显示当前配置"""
    config = load_config()
    if not config:
        return
    
    provider = config.get('API_PROVIDER', 'openai')
    print(f"\n当前API提供商: {provider.upper()}")
    
    if provider == 'openai':
        api_key = config.get('OPENAI_API_KEY', '')
        masked_key = api_key[:8] + '*' * (len(api_key) - 12) + api_key[-4:] if len(api_key) > 12 else '*' * len(api_key)
        print(f"OpenAI API密钥: {masked_key}")
    elif provider == 'deepseek':
        api_key = config.get('DEEPSEEK_API_KEY', '')
        masked_key = api_key[:8] + '*' * (len(api_key) - 12) + api_key[-4:] if len(api_key) > 12 else '*' * len(api_key)
        print(f"DeepSeek API密钥: {masked_key}")
        print(f"DeepSeek 基础URL: {config.get('DEEPSEEK_BASE_URL', 'https://api.deepseek.com')}")
        print(f"DeepSeek 模型: {config.get('DEEPSEEK_MODEL', 'deepseek-chat')}")

def main():
    """主函数"""
    if len(sys.argv) < 2:
        print("API选择器 - shelLM项目")
        print("\n用法:")
        print("  python api_selector.py status    - 显示当前配置")
        print("  python api_selector.py openai    - 切换到OpenAI API")
        print("  python api_selector.py deepseek  - 切换到DeepSeek API")
        return
    
    command = sys.argv[1].lower()
    
    if command == 'status':
        show_current_config()
    elif command == 'openai':
        switch_to_openai()
    elif command == 'deepseek':
        switch_to_deepseek()
    else:
        print(f"未知命令: {command}")
        print("支持的命令: status, openai, deepseek")

if __name__ == '__main__':
    main()