#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
API Selector Script
Used to switch configuration between OpenAI and DeepSeek APIs
"""

import os
import sys
from dotenv import dotenv_values, set_key
from deepseek_client import DeepSeekClient
import openai

def load_config():
    """Load current configuration"""
    if not os.path.exists('.env'):
        print("Error: .env file not found, please create .env from env_TEMPLATE first")
        return None
    return dotenv_values('.env')

def test_openai_connection(api_key):
    """Test OpenAI API connection"""
    try:
        openai.api_key = api_key
        # Attempt to create a simple chat completion request to test connection
        response = openai.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": "Hello"}],
            max_tokens=5
        )
        return True
    except Exception as e:
        print(f"OpenAI API connection test failed: {str(e)}")
        return False

def test_deepseek_connection(api_key, base_url):
    """Test DeepSeek API connection"""
    try:
        client = DeepSeekClient(api_key, base_url)
        return client.validate_connection()
    except Exception as e:
        print(f"DeepSeek API connection test failed: {str(e)}")
        return False

def switch_to_openai():
    """Switch to OpenAI API"""
    config = load_config()
    if not config:
        return False
    
    if not config.get('OPENAI_API_KEY'):
        print("Error: OPENAI_API_KEY not configured")
        return False
    
    print("Testing OpenAI API connection...")
    if not test_openai_connection(config['OPENAI_API_KEY']):
        print("OpenAI API connection failed, please check API key")
        return False
    
    set_key('.env', 'API_PROVIDER', 'openai')
    print("✅ Successfully switched to OpenAI API")
    return True

def switch_to_deepseek():
    """Switch to DeepSeek API"""
    config = load_config()
    if not config:
        return False
    
    if not config.get('DEEPSEEK_API_KEY'):
        print("Error: DEEPSEEK_API_KEY not configured")
        return False
    
    base_url = config.get('DEEPSEEK_BASE_URL', 'https://api.deepseek.com')
    
    print("Testing DeepSeek API connection...")
    if not test_deepseek_connection(config['DEEPSEEK_API_KEY'], base_url):
        print("DeepSeek API connection failed, please check API key and base URL")
        return False
    
    set_key('.env', 'API_PROVIDER', 'deepseek')
    print("✅ Successfully switched to DeepSeek API")
    return True

def show_current_config():
    """Show current configuration"""
    config = load_config()
    if not config:
        return
    
    provider = config.get('API_PROVIDER', 'openai')
    print(f"\nCurrent API Provider: {provider.upper()}")
    
    if provider == 'openai':
        api_key = config.get('OPENAI_API_KEY', '')
        masked_key = api_key[:8] + '*' * (len(api_key) - 12) + api_key[-4:] if len(api_key) > 12 else '*' * len(api_key)
        print(f"OpenAI API Key: {masked_key}")
    elif provider == 'deepseek':
        api_key = config.get('DEEPSEEK_API_KEY', '')
        masked_key = api_key[:8] + '*' * (len(api_key) - 12) + api_key[-4:] if len(api_key) > 12 else '*' * len(api_key)
        print(f"DeepSeek API Key: {masked_key}")
        print(f"DeepSeek Base URL: {config.get('DEEPSEEK_BASE_URL', 'https://api.deepseek.com')}")
        print(f"DeepSeek Model: {config.get('DEEPSEEK_MODEL', 'deepseek-chat')}")

def main():
    """Main function"""
    if len(sys.argv) < 2:
        print("API Selector - shelLM Project")
        print("\nUsage:")
        print("  python api_selector.py status    - Show current configuration")
        print("  python api_selector.py openai    - Switch to OpenAI API")
        print("  python api_selector.py deepseek  - Switch to DeepSeek API")
        return
    
    command = sys.argv[1].lower()
    
    if command == 'status':
        show_current_config()
    elif command == 'openai':
        switch_to_openai()
    elif command == 'deepseek':
        switch_to_deepseek()
    else:
        print(f"Unknown command: {command}")
        print("Supported commands: status, openai, deepseek")

if __name__ == '__main__':
    main()
