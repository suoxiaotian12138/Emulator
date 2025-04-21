import re
import time

from flask import Flask, render_template, request
import subprocess

app = Flask(__name__)

# 定义临时文件路径
stega_txt_path = r"D:\project\Oniverse\file_pre_to_send\client1\stega.txt"
received_txt_path = r"D:\project\Oniverse\file_received\client2\ST.txt"

# 定义一个函数来去除 ANSI 转义序列
def remove_ansi_escape(text):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

@app.route('/', methods=['GET', 'POST'])
def index():
    stega_text = None
    secret_message = None
    error_message = None
    user_input = request.form.get('secret_message')

    if request.method == 'POST':
        if 'generate_stega' in request.form:
            if re.match(r'^[01]{16}$', user_input):
                try:
                    # 将用户输入的秘密消息写入临时文件
                    with open('temp_secret_message.txt', 'w') as f:
                        f.write(user_input)
                    result = subprocess.run(['python', 'StegaEncoder.py'], capture_output=True, text=True)
                    time.sleep(1)
                    with open(stega_txt_path, 'r', encoding='utf-8') as file:
                        stega_text = file.read()
                except Exception as e:
                    stega_text = f"Error: {str(e)}"
            else:
                error_message = "请输入 16 位的 0/1 比特串。"    # 1001110110101101
        elif 'extract_secret' in request.form:
            try:
                result = subprocess.run(['python', 'StegaDecoder.py'], capture_output=True, text=True)
                output_lines = result.stdout.splitlines()
                secret_message = output_lines[-1].split(': ')[-1]
                secret_message = remove_ansi_escape(secret_message)
                # 读取隐写文本
                with open(received_txt_path, 'r', encoding='utf-8') as file:
                    stega_text = file.read()
            except Exception as e:
                secret_message = f"Error: {str(e)}"

    return render_template('index.html', stega_text=stega_text, secret_message=secret_message, error_message=error_message, user_input=user_input)

if __name__ == '__main__':
    app.run(debug=True)