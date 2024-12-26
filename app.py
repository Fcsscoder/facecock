import sys
import os
import re
import json
import bcrypt
import random
from jinja2 import Environment, FileSystemLoader
from PyQt5 import uic, QtWidgets
from PyQt5.QtWidgets import QMessageBox, QMainWindow, QStackedWidget, QWidget
import smtplib
from email.mime.text import MIMEText

valid_ddds = [
    "11", "12", "13", "14", "15", "16", "17", "18", "19","21",
    "22", "24","27", "28","31", "32", "33", "34", "35", "37",
    "38","41", "42", "43", "44", "45", "46","47", "48", "49",
    "51", "53", "54", "55","61","62", "64","63","65", "66","67"
    ,"68","69","71", "73", "74", "75", "77","79","81", "82", 
    "83", "84", "85", "86", "87", "88", "89","91", "92", "93", 
    "94", "95", "96", "97", "98", "99"
]

valid_domains = [
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "icloud.com", "live.com", "aol.com", "msn.com", "protonmail.com",
    "yahoo.co.uk", "uol.com.br", "bol.com.br", "terra.com.br"
]

# Templates

current_dir = os.path.dirname(__file__)
env = Environment(loader=FileSystemLoader(current_dir))

email_template = env.get_template('email_template.html')

# Banco de dados

def get_resource_path(relative_path):
    if hasattr(sys, '_MEIPASS'):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

# Windows paths

login_path = get_resource_path('pages/login.ui')
create_path = get_resource_path('pages/create.ui')
forgot_path = get_resource_path('pages/forgot_password.ui')
send_code_path = get_resource_path('pages/send_code.ui')
change_password_path = get_resource_path('pages/change_password.ui')
confirm_email_path = get_resource_path('pages/confirm_email.ui')

def get_db_path():
    return os.path.join(os.getcwd(), "db.json")

def initialize_db():
    with open(get_db_path(), 'w') as f:
        json.dump([], f)

def load_db():
    try:
        with open(get_db_path(), 'r') as f:
            data = json.load(f)
        if not isinstance(data, list):
            raise ValueError("Formato inválido no banco de dados.")
        return data
    except (FileNotFoundError, json.JSONDecodeError, ValueError):
        initialize_db()
        return []

def save_db(data):
    with open(get_db_path(), 'w') as f:
        json.dump(data, f, indent=4)

def save_user(email, password, username, phone_number, sec_code):
    data = load_db()
    new_user = {
        "id": len(data) + 1,
        "email": email,
        "password": hash_password(password),
        "username": username,
        "phone_number": phone_number,
        "sec_code": sec_code
    }
    data.append(new_user)
    save_db(data)

# --- Funções auxiliares ---

# Senha

def hash_password(password):
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def check_password(password, hashed_password):
    return bcrypt.checkpw(password.encode("utf-8"), hashed_password.encode("utf-8"))

# Numero aleatório

def gen_random_num(length=5):
    return random.randint(10**(length - 1), 10**length - 1)

# Envio de email

def send_email(recipient, username, sec_code, message, password="coonxrlxynkdaxxb", sender="caiotosousa43@gmail.com"):
    try:
        output = email_template.render(username=username, message=message, sec_code=sec_code)

        msg = MIMEText(output, "html")
        msg['Subject'] = "FaceCock"
        msg['From'] = sender
        msg['To'] = recipient
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp_server:
            smtp_server.login(sender, password)
            smtp_server.sendmail(sender, recipient, msg.as_string())
        return True
    except Exception as e:
        print(f"Erro ao enviar email: {e}")
        return False

def get_user_by_email(email):
    for user in load_db():
        if user['email'] == email:
            return user
    return None

def get_user_by_username(username):
    for user in load_db():
        if user['username'] == username:
            return user
    return None

# Validações

def is_valid_phone_number(phone_number):
    cleaned = re.sub(r'\D', '', phone_number)
    is_valid_format = re.match(r'^(\d{2})(\d{4,5}\d{4})$', cleaned)
    if not is_valid_format:
        return False
    ddd = cleaned[:2]
    return ddd in valid_ddds

# Interface gráfica
    
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.current_user_email = None
        self.current_user_password = None
        self.current_user_sec_code = None
        self.current_user_username = None
        self.current_user_phone_number = None
        self.setWindowTitle("FaceCock")

        self.stack = QStackedWidget()
        self.setCentralWidget(self.stack)

        self.window_login = uic.loadUi(login_path)
        self.window_create = uic.loadUi(create_path)
        self.window_forgot_password = uic.loadUi(forgot_path)
        self.window_get_sended_code = uic.loadUi(send_code_path)
        self.window_change_password = uic.loadUi(change_password_path)
        self.window_confirm_email = uic.loadUi(confirm_email_path)

        self.stack.addWidget(self.window_login) 
        self.stack.addWidget(self.window_create)
        self.stack.addWidget(self.window_forgot_password)
        self.stack.addWidget(self.window_get_sended_code)
        self.stack.addWidget(self.window_change_password)
        self.stack.addWidget(self.window_confirm_email)

        self.showMaximized()

        self.setup_connections()

    def setup_connections(self):
        # tela de criar conta

        self.window_create.create_button.clicked.connect(self.create_account)
        self.window_create.login_page_button.clicked.connect(lambda: self.switch_screen(self.window_login))
        self.window_create.input_password.setEchoMode(self.window_create.input_password.Password)

        # tela de login

        self.window_login.create_page_button.clicked.connect(lambda: self.switch_screen(self.window_create))
        self.window_login.login_button.clicked.connect(self.login_account)
        self.window_login.forgot_password_button.clicked.connect(lambda: self.switch_screen(self.window_forgot_password))

        self.window_login.login_password_input.setEchoMode(self.window_login.login_password_input.Password)

        # tela de esqueci a senha

        self.window_forgot_password.create_page_button.clicked.connect(lambda: self.switch_screen(self.window_create))
        self.window_forgot_password.create_page_button.clicked.connect(lambda: self.clear_inputs(self.window_get_sended_code.code_input, self.window_forgot_password.forgot_email_input))
        
        self.window_forgot_password.login_page_button.clicked.connect(lambda: self.switch_screen(self.window_login))
        self.window_forgot_password.login_page_button.clicked.connect(lambda: self.clear_inputs(self.window_get_sended_code.code_input, self.window_forgot_password.forgot_email_input))
        self.window_forgot_password.forgot_button.clicked.connect(self.recover_account)

        # tela de checar o código

        self.window_get_sended_code.send_code_button.clicked.connect(self.check_sec_code)
        self.window_get_sended_code.create_page_button.clicked.connect(lambda: self.switch_screen(self.window_create))
        self.window_get_sended_code.create_page_button.clicked.connect(lambda: self.clear_inputs(self.window_get_sended_code.code_input, self.window_forgot_password.forgot_email_input))
        self.window_get_sended_code.login_page_button.clicked.connect(lambda: self.switch_screen(self.window_login))
        self.window_get_sended_code.login_page_button.clicked.connect(lambda: self.clear_inputs(self.window_get_sended_code.code_input, self.window_forgot_password.forgot_email_input))

        # tela de alterar a senha

        self.window_change_password.change_password_button.clicked.connect(self.check_passwords)
        self.window_change_password.new_password_input.setEchoMode(self.window_change_password.new_password_input.Password)
        self.window_change_password.confirm_password_input.setEchoMode(self.window_change_password.confirm_password_input.Password)

        # tela de confirmar o email

        self.window_confirm_email.confirm_email_button.clicked.connect(self.confirm_email)

        self.window_confirm_email.create_page_button_2.clicked.connect(lambda: self.switch_screen(self.window_create))
        self.window_confirm_email.create_page_button_2.clicked.connect(lambda: self.clear_inputs(self.window_confirm_email.confirm_email_input))

        self.window_confirm_email.login_page_button_2.clicked.connect(lambda: self.switch_screen(self.window_login))
        self.window_confirm_email.login_page_button_2.clicked.connect(lambda: self.clear_inputs(self.window_confirm_email.confirm_email_input))

    # Funções auxiliares na interface gráfica

    def is_valid_email(self, email):
        email_pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        
        if not re.match(email_pattern, email):
            QMessageBox.about(self, "Mensagem do Sistema", "Apenas letras (a-z, A-Z), número (0-9), e caracteres (_ - ,) podem ser utilizados")
            return None

        domain = email.split('@')[-1]

        if domain not in valid_domains:
            QMessageBox.about(self, "Mensagem do Sistema", f"O domínio '{domain}' não é reconhecido. Por favor, use um domínio válido.")
            return None

        return email

    def clear_inputs(self, *inputs):
        for input_field in inputs:
            input_field.setText('')

    # Funções interface gráfica

    def create_account(self):
        self.current_user_email = self.window_create.input_email.text()
        self.current_user_password = self.window_create.input_password.text()
        self.current_username = self.window_create.input_username.text()
        self.current_phone_number = self.window_create.input_phone.text()
        self.current_user_sec_code = gen_random_num()

        [email, password, username, phone_number] = [self.current_user_email, self.current_user_password, self.current_username, self.current_phone_number]

        if not all([email, password, username, phone_number]):
            QMessageBox.about(self, "Mensagem do sistema", "Não deixe campos vazios.")
            self.clear_inputs(
                self.window_create.input_email,
                self.window_create.input_password,
                self.window_create.input_username,
                self.window_create.input_phone
            )
            return
        
        if not self.is_valid_email(email):
            return

        if get_user_by_username(username):
            return QMessageBox.about(self, "Mensagem do sistema", "Nome de usuário já existe.")
            
        user = get_user_by_email(email)

        if user:
            return QMessageBox.about(self, "Mensagem do sistema", "Esse email já está em uso.")
        
        if not is_valid_phone_number(phone_number):
            return QMessageBox.about(self, "Mensagem do sistema", "Informe um número de telefone válido.")

        send_email(email, username, self.current_user_sec_code, "Insira o seguinte código para confirmar seu email:") 

        QMessageBox.about(self, "Mensagem do sistema", "Um código foi enviado para o seu email.")
        self.switch_screen(self.window_confirm_email)

    def confirm_email(self):
        code_input = int(self.window_confirm_email.confirm_email_input.text())

        if not code_input:
            return QMessageBox.about(self, "Mensagem do sistema", "Não deixe o campo vazio.")
        
        if not code_input == self.current_user_sec_code:
            return QMessageBox.about(self, "Mensagem do sistema", "Código inválido.")

        save_user(self.current_user_email, self.current_user_password, self.current_username, self.current_phone_number, gen_random_num())
        QMessageBox.about(self, "Mensagem do sistema", "Conta criada com sucesso!")
        self.switch_screen(self.window_login)

        self.current_user_email = None
        self.current_user_password = None
        self.current_user_sec_code = None
        self.current_user_username = None
        self.current_user_phone_number = None
        self.window_confirm_email.confirm_email_input.setText("")

        return

    def login_account(self):
        email = self.window_login.login_email_input.text()
        password = self.window_login.login_password_input.text()

        if not email and not password:
            QMessageBox.about(self, "Mensagem do sistema", "Não deixe campos vazios.")
            self.clear_inputs(
            self.window_login.login_email_input,
            self.window_login.login_password_input
            )
            return 

        self.clear_inputs(
            self.window_login.login_email_input,
            self.window_login.login_password_input
        )

        user = get_user_by_email(email)
        if user and check_password(password, user['password']):
            QMessageBox.about(self, "Mensagem do sistema", "Login bem-sucedido!")
        else:
            QMessageBox.about(self, "Mensagem do sistema", "Email e/ou senha incorretos.")

    def recover_account(self):
        email = self.window_forgot_password.forgot_email_input.text()

        if not email:
            return QMessageBox.about(self, "Mensagem do sistema", "Não deixe campos vazios.")

        user = get_user_by_email(email)

        if user:
            send_email(user['email'], user['username'], user['sec_code'], "Insira o seguinte código para alterar sua senha:")
            QMessageBox.about(self, "Mensagem do sistema", "Um código foi enviado para o seu email.")
            self.switch_screen(self.window_get_sended_code)
        else: 
            return QMessageBox.about(self, "Mensagem do sistema", "Endereço de email não encontrado.")
        
    def check_sec_code(self):
        email = self.window_forgot_password.forgot_email_input.text()
        user = get_user_by_email(email)
        code = self.window_get_sended_code.code_input.text()

        if not code.isdigit() or not len(code) == 5:
            return QMessageBox.about(self, "Mensagem do sistema", "O código deve conter apenas 5 dígitos.")

        if user['sec_code'] == int(code):
            self.current_user_email = email
            self.switch_screen(self.window_change_password)
        else:
            return QMessageBox.about(self, "Mensagem do sistema", "Código inválido. Tente novamente.")
        
    def check_passwords(self):
        new_password = self.window_change_password.new_password_input.text()
        confirm_new_password = self.window_change_password.confirm_password_input.text()

        if not new_password and not confirm_new_password:
            return QMessageBox.about(self, "Mensagem do sistema", "Não deixe campos vazios.")

        if not new_password == confirm_new_password:
            return QMessageBox.about(self, "Mensagem do sistema", "Senhas não conferem.")

        self.change_password(new_password)
        
    def change_password(self, new_password):
        email = self.current_user_email
        user = get_user_by_email(email)

        if not email or not user: 
            QMessageBox.about(self, "Mensagem do sistema", "Houve algum erro. Tente novamente.")
            self.switch_screen(self.window_login)
            return 

        all_users = load_db()
        new_sec_code = gen_random_num()

        for user in all_users:
            if user['email'] == email:
                 user['password'] = hash_password(new_password)
                 user['sec_code'] = new_sec_code
                 break
            
        save_db(all_users)
        QMessageBox.about(self, "Mensagem do sistema", "Senha alterada com sucesso.")
        self.switch_screen(self.window_login)
        self.clear_inputs(
                self.window_forgot_password.forgot_email_input,
                self.window_get_sended_code.code_input,
                self.window_change_password.new_password_input,
                self.window_change_password.confirm_password_input
            )
        return

    def switch_screen(self, target_screen: QWidget):
        self.stack.setCurrentWidget(target_screen)
        
app = QtWidgets.QApplication([])
main_window = MainWindow()
main_window.show()
app.exec()