import base64
import binascii
import hashlib
import json
import os
import sys

from PyQt5 import QtWidgets, uic
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QMessageBox
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

qt_creator_file = "guis/login.ui"
Ui_MainWindow, QtBaseClass = uic.loadUiType(qt_creator_file)

def create_key(master_password, salt):
    master_password_encode = master_password.encode()  # Convert to type bytes
    #salt = b'\x9c\x92&v\xb5\x10\xec\x14|\xa0\x0e\xd1\x1c\xdbE\xac'  # how to choose
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password_encode))

def verify_password(stored_password, provided_password, salt):
    """Verify a stored password against one provided by user"""
    pwdhash = hashlib.pbkdf2_hmac('sha512',
                                  provided_password.encode('utf-8'),
                                  salt.encode('ascii'),
                                  100000, dklen=512)
    pwdhash = binascii.hexlify(pwdhash).decode('ascii')
    print(pwdhash)
    return pwdhash == stored_password


class MainWindow(QtWidgets.QMainWindow, Ui_MainWindow):
    def __init__(self):
        """Show main window. Connect loginButton with onLoginButton function
        and registerButton with onRegisterButton function"""
        QtWidgets.QMainWindow.__init__(self)
        Ui_MainWindow.__init__(self)
        self.setupUi(self)
        self.loginButton.pressed.connect(self.onLoginButton)
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

    def onLoginButton(self):
        """Close loginWindow and run showPasswords.py"""
        if os.path.exists('register.json'):
            with open('register.json', 'r') as file:
                email = self.email.text()
                master_password = self.master_password.text()
                data = json.load(file)
                print(data['salt'])
                if data['email'] == email and verify_password(data['master_password'], master_password, data['salt']):
                    window.close()
                    os.system('python showPasswords.py')
                else:
                    QMessageBox.about(self, "No user", "There is no such user! Try again, please")
                    self.email.setText("")
                    self.master_password.setText("")
        else:
            QMessageBox.about(self, "No user", "There is no such user! Try again, please")
            self.email.setText("")
            self.master_password.setText("")

    def onRegisterButton(self):
        """Close registerWindow and run register.py"""
        window.close()
        os.system('python register.py')


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    app.exec_()
