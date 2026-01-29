import openai
from dotenv import dotenv_values
import argparse
from datetime import datetime
import yaml
from time import sleep
import random
import os
import json

config = dotenv_values(".env")

# Support both OpenAI and DeepSeek APIs
api_provider = config.get("API_PROVIDER", "openai").lower()
if api_provider == "deepseek":
    openai.api_key = config["DEEPSEEK_API_KEY"]
    openai.base_url = config.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
    MODEL_NAME = config.get("DEEPSEEK_MODEL", "deepseek-chat")
else:
    openai.api_key = config["OPENAI_API_KEY"]
    MODEL_NAME = "gpt-3.5-turbo-16k"

today = datetime.now()

history = open("history.txt", "a+", encoding="utf-8")

if os.stat('history.txt').st_size == 0:
    with open('personalitySSH.yml', 'r', encoding="utf-8") as file:
        identity = yaml.safe_load(file)

    identity = identity['personality']

    prompt = identity['prompt']

else:
    history_content = open("history.txt", "r", encoding="utf-8").read()
    continuation_msg = "Here the session stopped. Now you will start it again from the beginning with the same user. You must respond just with starting message and nothing more. Make sure you use same file and folder names. Ignore date-time in <>. This is not your concern."
    
    if continuation_msg not in history_content:
        history.write(f"\n{continuation_msg}\n")
    
    history.seek(0)
    prompt = history.read()

def main():
    parser = argparse.ArgumentParser(description = "Simple command line with GPT-3.5-turbo")
    parser.add_argument("--personality", type=str, help="A brief summary of chatbot's personality", 
                        default= prompt + 
                        f"\nBased on these examples make something of your own (different username and hostname) to be a starting message. Always start the communication in this way and make sure your output ends with '$'. For the last login date use {today}\n" + 
                        "Ignore date-time in <> after user input. This is not your concern.\n")

    args = parser.parse_args()

    initial_prompt = f"You are Linux OS terminal. Your personality is: {args.personality}"
    messages = [{"role": "system", "content": initial_prompt}]
    if os.stat('history.txt').st_size == 0:
        for msg in messages:
                    history.write(msg["content"])
    else:
        history.write("The session continues in following lines.\n\n")
    
    history.close()

    while True:
        
        logs = open("history.txt", "a+", encoding="utf-8")
        try:
            res = openai.chat.completions.create(
                model=MODEL_NAME,
                messages = messages,
                temperature = 0.0,
                max_tokens = 800
            )

            msg = res.choices[0].message.content
            message = {"content": msg, "role": 'assistant'}
            
            # Track token consumption
            if hasattr(res, 'usage') and res.usage:
                token_data = {
                    "timestamp": datetime.now().isoformat(),
                    "prompt_tokens": res.usage.prompt_tokens,
                    "completion_tokens": res.usage.completion_tokens,
                    "total_tokens": res.usage.total_tokens
                }
                # Append to tokens.json
                tokens_file = "tokens.json"
                if os.path.exists(tokens_file):
                    with open(tokens_file, 'r', encoding='utf-8') as f:
                        try:
                            tokens_history = json.load(f)
                        except json.JSONDecodeError:
                            tokens_history = []
                else:
                    tokens_history = []
                
                tokens_history.append(token_data)
                
                with open(tokens_file, 'w', encoding='utf-8') as f:
                    json.dump(tokens_history, f, indent=2, ensure_ascii=False)


            if "$cd" in message["content"] or "$ cd" in message["content"]:
                message["content"] = message["content"].split("\n")[1]

            lines = []

            messages.append(message)

            logs.write(messages[len(messages) - 1]["content"])
            logs.close()

            logs = open("history.txt", "a+", encoding="utf-8")
            
            if "will be reported" in messages[len(messages) - 1]["content"]:
                print(messages[len(messages) - 1]["content"])
                raise KeyboardInterrupt 

            if "PING" in message["content"]:
                lines = message["content"].split("\n")
                print(lines[0])

                for i in range(1, len(lines)-5):
                    print(lines[i])
                    sleep(random.uniform(0.1, 0.5))
                
                for i in range(len(lines)-4, len(lines)-1):
                    print(lines[i])
                
                user_input = input(f'{lines[len(lines)-1]}'.strip() + " ")
                messages.append({"role": "user", "content": user_input + f"\t<{datetime.now()}>\n" })
                logs.write(" " + user_input + f"\t<{datetime.now()}>\n")

            else:
                #print("\n", messages[len(messages) - 1]["content"], " ")
                user_input = input(f'\n{messages[len(messages) - 1]["content"]}'.strip() + " ")
                messages.append({"role": "user", "content": " " + user_input + f"\t<{datetime.now()}>\n"})
                logs.write(" " + user_input + f"\t<{datetime.now()}>\n")
            
        except KeyboardInterrupt:
            messages.append({"role": "user", "content": "\n"})
            print("")
            break
        
        logs.close()
    # print(res)

if __name__ == "__main__":
    main()
