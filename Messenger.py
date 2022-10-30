import requests
import time
import datetime
import hashlib
from PyQt5 import QtCore, QtGui, QtWidgets
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES, PKCS1_OAEP


class Ui_Login(object):
    def setupUi(self, Dialog):
        Dialog.setObjectName("Dialog")
        Dialog.resize(315, 138)
        self.gridLayout = QtWidgets.QGridLayout(Dialog)
        self.gridLayout.setObjectName("gridLayout")
        self.label = QtWidgets.QLabel(Dialog)
        font = QtGui.QFont()
        font.setPointSize(20)
        self.label.setFont(font)
        self.label.setTextFormat(QtCore.Qt.RichText)
        self.label.setScaledContents(False)
        self.label.setAlignment(QtCore.Qt.AlignCenter)
        self.label.setTextInteractionFlags(QtCore.Qt.NoTextInteraction)
        self.label.setObjectName("label")
        self.gridLayout.addWidget(self.label, 0, 0, 1, 2)
        self.label_2 = QtWidgets.QLabel(Dialog)
        font = QtGui.QFont()
        font.setPointSize(14)
        self.label_2.setFont(font)
        self.label_2.setObjectName("label_2")
        self.gridLayout.addWidget(self.label_2, 1, 0, 1, 1)
        self.lineEditLogin = QtWidgets.QLineEdit(Dialog)
        self.lineEditLogin.setObjectName("lineEditLogin")
        self.gridLayout.addWidget(self.lineEditLogin, 1, 1, 1, 1)
        self.label_3 = QtWidgets.QLabel(Dialog)
        font = QtGui.QFont()
        font.setPointSize(14)
        self.label_3.setFont(font)
        self.label_3.setObjectName("label_3")
        self.gridLayout.addWidget(self.label_3, 2, 0, 1, 1)
        self.lineEditPassword = QtWidgets.QLineEdit(Dialog)
        self.lineEditPassword.setObjectName("lineEditPassword")
        self.gridLayout.addWidget(self.lineEditPassword, 2, 1, 1, 1)
        self.regbutton = QtWidgets.QPushButton(Dialog)
        self.regbutton.setObjectName("regbutton")
        self.gridLayout.addWidget(self.regbutton, 3, 0, 1, 1)
        self.loginbutton = QtWidgets.QPushButton(Dialog)
        self.loginbutton.setObjectName("loginbutton")
        self.gridLayout.addWidget(self.loginbutton, 3, 1, 1, 1)

        self.retranslateUi(Dialog)
        QtCore.QMetaObject.connectSlotsByName(Dialog)

    def retranslateUi(self, Dialog):
        _translate = QtCore.QCoreApplication.translate
        Dialog.setWindowTitle(_translate("Dialog", "Dialog"))
        self.label.setText(_translate("Dialog", 'Мессенджер "Константа"'))
        self.label_2.setText(_translate("Dialog", "Введите логин:"))
        self.label_3.setText(_translate("Dialog", "Введите пароль:"))
        self.regbutton.setText(_translate("Dialog", "Зарегистрироваться"))
        self.loginbutton.setText(_translate("Dialog", "Авторизоваться"))


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(489, 501)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.gridLayout = QtWidgets.QGridLayout(self.centralwidget)
        self.gridLayout.setObjectName("gridLayout")
        self.listWidget = QtWidgets.QListWidget(self.centralwidget)
        self.listWidget.setObjectName("listWidget")
        self.gridLayout.addWidget(self.listWidget, 1, 0, 3, 1)
        self.label_2 = QtWidgets.QLabel(self.centralwidget)
        self.label_2.setObjectName("label_2")
        self.gridLayout.addWidget(self.label_2, 0, 1, 1, 1)
        self.textBrowser = QtWidgets.QTextBrowser(self.centralwidget)
        font = QtGui.QFont()
        font.setStrikeOut(False)
        self.textBrowser.setFont(font)
        self.textBrowser.setObjectName("textBrowser")
        self.gridLayout.addWidget(self.textBrowser, 1, 1, 1, 1)
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setObjectName("label")
        self.gridLayout.addWidget(self.label, 0, 0, 1, 1)
        self.sendButton = QtWidgets.QPushButton(self.centralwidget)
        self.sendButton.setObjectName("sendButton")
        self.gridLayout.addWidget(self.sendButton, 3, 1, 1, 1)
        self.message = QtWidgets.QTextEdit(self.centralwidget)
        self.message.setObjectName("message")
        self.gridLayout.addWidget(self.message, 2, 1, 1, 1)
        MainWindow.setCentralWidget(self.centralwidget)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.label_2.setText(_translate("MainWindow",
                                        "<html><head/><body><p align=\"center\"><span style=\" font-size:14pt;\">Выберите пользователя или чат</span></p></body></html>"))
        self.label.setText(_translate("MainWindow",
                                      "<html><head/><body><p align=\"center\"><span style=\" font-size:14pt;\">Список диалогов</span></p></body></html>"))
        self.sendButton.setToolTip(_translate("MainWindow", "<html><head/><body><p>f</p></body></html>"))
        self.sendButton.setText(_translate("MainWindow", "Отправить"))


class Ui_Registration(object):
    def setupUi(self, Dialog):
        Dialog.setObjectName("Dialog")
        Dialog.resize(361, 296)
        self.verticalLayout = QtWidgets.QVBoxLayout(Dialog)
        self.verticalLayout.setObjectName("verticalLayout")
        self.label = QtWidgets.QLabel(Dialog)
        self.label.setObjectName("label")
        self.verticalLayout.addWidget(self.label)
        self.label_2 = QtWidgets.QLabel(Dialog)
        self.label_2.setObjectName("label_2")
        self.verticalLayout.addWidget(self.label_2)
        self.lineEdit = QtWidgets.QLineEdit(Dialog)
        self.lineEdit.setObjectName("lineEdit")
        self.verticalLayout.addWidget(self.lineEdit)
        self.label_5 = QtWidgets.QLabel(Dialog)
        self.label_5.setObjectName("label_5")
        self.verticalLayout.addWidget(self.label_5)
        self.lineEdit_4 = QtWidgets.QLineEdit(Dialog)
        self.lineEdit_4.setObjectName("lineEdit_4")
        self.verticalLayout.addWidget(self.lineEdit_4)
        self.label_3 = QtWidgets.QLabel(Dialog)
        self.label_3.setObjectName("label_3")
        self.verticalLayout.addWidget(self.label_3)
        self.lineEdit_2 = QtWidgets.QLineEdit(Dialog)
        self.lineEdit_2.setObjectName("lineEdit_2")
        self.verticalLayout.addWidget(self.lineEdit_2)
        self.label_4 = QtWidgets.QLabel(Dialog)
        self.label_4.setObjectName("label_4")
        self.verticalLayout.addWidget(self.label_4)
        self.lineEdit_3 = QtWidgets.QLineEdit(Dialog)
        self.lineEdit_3.setObjectName("lineEdit_3")
        self.verticalLayout.addWidget(self.lineEdit_3)
        self.pushButton = QtWidgets.QPushButton(Dialog)
        self.pushButton.setObjectName("pushButton")
        self.verticalLayout.addWidget(self.pushButton)

        self.retranslateUi(Dialog)
        QtCore.QMetaObject.connectSlotsByName(Dialog)

    def retranslateUi(self, Dialog):
        _translate = QtCore.QCoreApplication.translate
        Dialog.setWindowTitle(_translate("Dialog", "Dialog"))
        self.label.setText(_translate("Dialog",
                                      "<html><head/><body><p align=\"center\"><span style=\" font-size:18pt; font-weight:600;\">Регистрация пользователя</span></p></body></html>"))
        self.label_2.setText(_translate("Dialog",
                                        "<html><head/><body><p align=\"center\"><span style=\" font-size:14pt;\">Логин:</span></p></body></html>"))
        self.label_5.setText(_translate("Dialog",
                                        "<html><head/><body><p align=\"center\"><span style=\" font-size:14pt;\">ФИО:</span></p></body></html>"))
        self.label_3.setText(_translate("Dialog",
                                        "<html><head/><body><p align=\"center\"><span style=\" font-size:14pt;\">Пароль:</span></p></body></html>"))
        self.label_4.setText(_translate("Dialog",
                                        "<html><head/><body><p align=\"center\"><span style=\" font-size:14pt;\">Повтор пароля:</span></p></body></html>"))
        self.pushButton.setText(_translate("Dialog", "Зарегистрироваться"))


class Login(QtWidgets.QDialog, Ui_Login):
    def __init__(self):
        super().__init__()
        self.setupUi(self)


class MainWindow(QtWidgets.QDialog, Ui_MainWindow):
    def __init__(self):
        super().__init__()
        self.setupUi(self)


class Registration(QtWidgets.QDialog, Ui_Registration):
    def __init__(self):
        super().__init__()
        self.setupUi(self)


class Messenger(QtWidgets.QMainWindow, Ui_MainWindow):
    def __init__(self):
        super().__init__()
        self.setupUi(self)

        self.userData = {}
        self.sender = str()
        self.receiver = str()
        self.code = str()
        self.drawn_users = []

        self.sendButton.clicked.connect(self.send_message)

        self.form_login = Login()
        self.form_login.show()
        self.form_login.loginbutton.clicked.connect(self.login)
        self.form_login.regbutton.clicked.connect(self._reg)

        self.form_registration = Registration()
        self.form_registration.pushButton.clicked.connect(self.registration)

        self.after = time.time() - 24 * 60 * 60

    def _date(self):
        self.form_date.show()

    def _reg(self):
        self.form_registration.show()

    def registration(self):
        login = self.form_registration.lineEdit.text()
        name = self.form_registration.lineEdit_4.text()
        pass1 = self.form_registration.lineEdit_2.text()
        pass2 = self.form_registration.lineEdit_3.text()

        if not login or not pass1 or not pass2:
            msg = QtWidgets.QMessageBox.information(
                self,
                "Ошибка!",
                "Введите данные."
            )
        # Генерация публичного ключа и отправка на сервер
        elif pass1 == pass2:
            self.sender = login
            self.code = str(pass1)
            data = {'login': login, 'password': hashlib.md5(pass1.encode('UTF-8')).hexdigest(),
                    'name': name, 'key': self.crypto()}

            if self.send_data(data) == 200:
                self.form_registration.hide()
                self.form_login.hide()

                self.response = requests.get(
                    'http://127.0.0.1:5000/users'
                )
                l = self.response.json()['logins']
                u = self.response.json()['users']
                self.users = dict(zip(l, u))
                self.all_users = dict(zip(l, u))
                l.remove(self.sender)
                u.remove(self.users[self.sender])
                self.drawn_users = l
                self.listWidget.addItems(u)

                self.show()

    def send_data(self, data):
        try:
            response = requests.post(
                'http://127.0.0.1:5000/reg',
                json=data
            )
        except:
            msg = QtWidgets.QMessageBox.information(
                self,
                "Внимание!",
                "Сервер недоступен, попробуйте позднее."
            )

        if response.status_code != 200:
            msg = QtWidgets.QMessageBox.information(
                self,
                "Ошибка!",
                "Что-то пошло не так. Попробуйте еще раз."
            )

        return response.status_code

    # Хеширование пароля
    def login(self):
        login = self.form_login.lineEditLogin.text()
        password = hashlib.md5(self.form_login.lineEditPassword.text().encode('UTF-8')).hexdigest()
        self.code = str(self.form_login.lineEditPassword.text())

        user_data = {'login': login, 'password': password}

        if not (login and password):
            msg = QtWidgets.QMessageBox.information(
                self,
                "Внимание!",
                "Введите данные"
            )
            return

        try:
            response = requests.post(
                'http://127.0.0.1:5000/login',
                json=user_data
            )
        except:
            msg = QtWidgets.QMessageBox.information(
                self,
                "Ошибка!",
                "Сервер недоступен, попробуйте позднее."
            )
            return

        if response.status_code == 401:
            msg = QtWidgets.QMessageBox.information(
                self,
                "Ошибка!",
                "Неверный логин или пароль."
            )

        elif response.status_code == 404:
            msg = QtWidgets.QMessageBox.information(
                self,
                "Ошибка!",
                "Такого пользователя не существует"
            )

        if response.status_code == 200:
            self.sender = login
            self.form_login.hide()
            self.show()
            self.timer = QtCore.QTimer()

            self.response = requests.get(
                'http://127.0.0.1:5000/users'
            )
            l = self.response.json()['logins']
            u = self.response.json()['users']
            self.users = dict(zip(l, u))
            self.all_users = dict(zip(l, u))
            l.remove(self.sender)
            u.remove(self.users[self.sender])
            self.drawn_users = l
            self.listWidget.addItems(u)

            self.timer.timeout.connect(self.get_messages)
            self.timer.timeout.connect(self.get_users)
            self.timer.start(3000)
            self.listWidget.itemSelectionChanged.connect(self.change_dialog)

    def get_users(self):
        self.response = requests.get(
            'http://127.0.0.1:5000/users'
        )
        l = self.response.json()['logins']  # Логины
        u = self.response.json()['users']  # ФИО
        self.users = dict(zip(l, u))

        for user in self.drawn_users:
            self.users.pop(user)
        self.users.pop(self.sender)
        self.listWidget.addItems(self.users.values())

    # Ключ
    def crypto(self):
        # Генерация ключа RSA
        RSA_key = RSA.generate(2048)

        # Генерация приватного ключа
        pr_key = RSA_key.exportKey(
            passphrase=self.code,
            pkcs=8,
            protection="scryptAndAES128-CBC"
        )

        with open('key.bin', 'wb') as f:
            f.write(pr_key)

        # Генерация публичного ключа с помощью приватного
        pu_key = RSA_key.public_key().exportKey()

        return pu_key.hex()

    # Шифрование
    def encrypt(self, item, receiver):
        # Получение ключа с сервера
        try:
            self.response = requests.get(
                'http://127.0.0.1:5000/send_key',
                params={'receiver': receiver}
            )
        except:
            msg = QtWidgets.QMessageBox.information(
                self,
                "Ошибка!",
                "Невозможно установить безопасное соединение с сервером"
            )
            return

        # Преобразование str ответа сервера в ключ RSA
        recipient_key = RSA.import_key(bytes.fromhex(self.response.json()['key']), passphrase=self.code)

        # Генерация ключа сессии
        session_key = get_random_bytes(16)

        # Генерация RSA ключа
        cipher_rsa = PKCS1_OAEP.new(recipient_key)

        # Шифровка данных
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(item)

        return [cipher_rsa.encrypt(session_key), cipher_aes.nonce, tag, ciphertext]

    def decrypt(self, enc_data):
        # Получение приватного ключа
        private_key = RSA.import_key(
            open(f'key.bin').read(),
            passphrase=self.code
        )

        # Считывание данных
        enc_session_key, nonce, tag, ciphertext = [
            bytes().fromhex(enc_data[x]) for x in range(0, 4)
        ]

        # Генерация ключа RSA
        cipher_rsa = PKCS1_OAEP.new(private_key)

        # Расшифровка данных
        session_key = cipher_rsa.decrypt(enc_session_key)
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        text = cipher_aes.decrypt_and_verify(ciphertext, tag)

        return text

    def format_message(self, message):
        sender = message['sender']
        if sender == self.sender:
            text = self.decrypt(message['msg_sender']).decode('UTF-8')
        else:
            text = self.decrypt(message['msg_receiver']).decode('UTF-8')
        dt = datetime.datetime.fromtimestamp(message['time'])
        time_format = dt.strftime('%Y.%m.%d - %H:%M')
        return f'{sender} {time_format}\n{text}\n'

    def get_key(self, d, value):
        for k, v in d.items():
            if v == value:
                return k

    def send_message(self):
        text = self.message.toPlainText()

        if not self.listWidget.currentItem():
            msg = QtWidgets.QMessageBox.information(
                self,
                "Ошибка!",
                "Выберите диалог для отправки"
            )
            return

        self.receiver = self.listWidget.currentItem().text()

        if not text:
            msg = QtWidgets.QMessageBox.information(
                self,
                "Ошибка!",
                "Поле ввода текста не может быть пустым."
            )
            return

        t1 = self.encrypt(text.encode('UTF-8'), self.sender)
        t2 = self.encrypt(text.encode('UTF-8'), self.get_key(self.all_users, self.receiver))
        text_sender = [t1[x].hex() for x in range(0, 4)]
        text_receiver = [t2[x].hex() for x in range(0, 4)]
        message = {'sender': self.sender, 'receiver': self.get_key(self.all_users, self.receiver), 'msg_sender': text_sender,
                   'msg_receiver': text_receiver}

        self.response = requests.post(
            'http://127.0.0.1:5000/send',
            json=message
        )

        if self.response.status_code == 200:
            self.message.setText('')
            self.message.repaint()

    def get_messages(self):
        try:
            self.response = requests.get(
                'http://127.0.0.1:5000/messages',
                params={'after': self.after, 'login': self.sender}
            )
        except:
            msg = QtWidgets.QMessageBox.information(
                self,
                "Внимание!",
                "Сервер недоступен, попробуйте позднее."
            )
            return

        messages = self.response.json()['messages']
        if messages:
            for message in messages:
                if not self.listWidget.currentItem():
                    return

                if self.get_key(self.all_users, self.listWidget.currentItem().text()) == message['sender'] or (
                        message['receiver'] == self.get_key(self.all_users, self.listWidget.currentItem().text())):
                    self.textBrowser.append(self.format_message(message))
                    self.after = message['time']

    def change_dialog(self):
        self.label_2.setText("<html><head/><body><p align=\"center\"><span style=\""
                             f"font-size:14pt;\">{self.listWidget.currentItem().text()}</span></p></body></html>")
        self.textBrowser.clear()
        try:
            response = requests.get(
                'http://127.0.0.1:5000/messages',
                params={'after': 0, 'login': self.sender}
            )
        except:
            return
        messages = response.json()['messages']
        for message in messages:
            # receiver = self.all_users[self.get_key(self.all_users, message['receiver'])]
            # sender = self.all_users[message['sender']]
            #
            # receiver - логин получателя
            # message['receiver'] - ФИО получателя
            # message['sender'] - ФИО отправителя
            # sender - логин отправителя
            # self.sender - логин текущего пользователя
            # self.listWidget.currentItem().text() - ФИО выделенного пользователя
            #
            #                           ОТПРАВИТЕЛЬ КТО-ТО ДРУГОЙ
            # receiver == self.sender -
            # Получатель - текущий пользователь (сравнивается по логинам)
            #
            # self.listWidget.currentItem().text() == message['sender'] -
            # Выделенный пользователь - отправитель сообщения (сравнивается по ФИО)
            #
            #
            #                       ОТПРАВИТЕЛЬ - ТЕКУЩИЙ ПОЛЬЗОВАТЕЛЬ
            #
            # message['receiver'] == self.listWidget.currentItem().text() -
            # Текущий пользователь выбрал пользователя, которому отправил сообщение (сравнивается по ФИО)
            #
            # self.sender == sender - Текущий пользователь - отправитель сообщения
            if self.get_key(self.all_users, self.listWidget.currentItem().text()) == message['receiver'] or self.get_key(self.all_users, self.listWidget.currentItem().text()) == message['sender']:
                self.textBrowser.append(self.format_message(message))

        self.after = time.time()


if __name__ == '__main__':
    import sys

    app = QtWidgets.QApplication(sys.argv)
    window = Messenger()
    sys.exit(app.exec_())
