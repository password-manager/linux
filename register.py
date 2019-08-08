import base64
import json
import os
import sys

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QMessageBox
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from PyQt5 import QtWidgets, uic

qt_creator_file = "guis/register.ui"
Ui_MainWindow, QtBaseClass = uic.loadUiType(qt_creator_file)


def create_key(master_password, salt):
    master_password_encode = master_password.encode()  # Convert to type bytes
    # salt = b'\x9c\x92&v\xb5\x10\xec\x14|\xa0\x0e\xd1\x1c\xdbE\xac'  # how to choose
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password_encode))


class MainWindow(QtWidgets.QMainWindow, Ui_MainWindow):
    def __init__(self):
        """Show main window. Connect cancelButton with onCancelButton function
        and registerButton with onRegisterButton function"""
        QtWidgets.QMainWindow.__init__(self)
        Ui_MainWindow.__init__(self)
        self.setupUi(self)
        self.cancelButton.pressed.connect(self.onCancelButton)
        self.registerButton.pressed.connect(self.onRegisterButton)
        self.master_password.setEchoMode(QtWidgets.QLineEdit.Password)
        self.checkBox.stateChanged.connect(self.changeCheckBox)

    def changeCheckBox(self, state):
        """If checkBox is checked - show password,
        if unchecked - hide it"""
        if state == Qt.Checked:
            self.master_password.setEchoMode(QtWidgets.QLineEdit.Normal)
        else:
            self.master_password.setEchoMode(QtWidgets.QLineEdit.Password)

    def onCancelButton(self):
        """Close registerWindow and run login.py"""
        window.close()
        os.system('python login.py')

    def onRegisterButton(self):
        email = self.email.text()
        master_password = self.master_password.text()
        salt = base64.urlsafe_b64encode(os.urandom(16))
        if not email or not master_password:
            QMessageBox.about(self, "No data", "Write password name and password, please")
        else:
            print(master_password)
            key = create_key(master_password, salt)
            print(key)
            f = Fernet(key)
            encrypted = f.encrypt(master_password.encode())
            print(encrypted.decode())
            with open('register.json', 'w+') as file:
                data = {'email': email, 'master_password': encrypted.decode(), 'salt': salt.decode(),
                        'key': key.decode()}
                json.dump(data, file)
            with open('key.txt', 'wb') as file:
                file.write(key)
            self.onCancelButton()


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    app.exec_()
