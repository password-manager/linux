import base64
import hashlib
import json
import os
import sys

import gnupg
import keyring
from PyQt5 import QtWidgets, uic
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QMessageBox

qt_creator_file = "guis/login.ui"
Ui_MainWindow, QtBaseClass = uic.loadUiType(qt_creator_file)
gpg = gnupg.GPG(gnupghome="/home/marina/gnupg")


def verify_password(stored_password, provided_password, salt):
    """Verify a stored password against one provided by user"""
    pwdhash = hashlib.pbkdf2_hmac('sha512',
                                  provided_password.encode('utf-8'),
                                  salt.encode(),
                                  100000, dklen=64)
    pwdhash = base64.b64encode(pwdhash).decode()
    return pwdhash == stored_password


class MainWindow(QtWidgets.QMainWindow, Ui_MainWindow):
    def __init__(self):
        """Show main window. Connect loginButton with on_login_button function
        and registerButton with on_register_button function"""
        QtWidgets.QMainWindow.__init__(self)
        Ui_MainWindow.__init__(self)
        self.setupUi(self)
        self.loginButton.pressed.connect(self.on_login_button)
        self.registerButton.pressed.connect(self.on_register_button)
        self.master_password.setEchoMode(QtWidgets.QLineEdit.Password)
        self.checkBox.stateChanged.connect(self.change_check_box_state)

    def change_check_box_state(self, state):
        """If checkBox is checked - show password,
        if unchecked - hide it
        """
        if state == Qt.Checked:
            self.master_password.setEchoMode(QtWidgets.QLineEdit.Normal)
        else:
            self.master_password.setEchoMode(QtWidgets.QLineEdit.Password)

    def on_login_button(self):
        """Check if mail and password match, then close loginWindow and run showPasswords.py"""
        if os.path.exists('register.json.gpg'):
            with open('register.json.gpg', 'rb') as file:
                gpg.decrypt_file(file, passphrase='passphrase', output='register.json')
            with open('register.json', 'r') as file:
                data = json.load(file)
                email = self.email.text()
                master_password = self.master_password.text()
                if data['email'] == email and verify_password(data['master_password'], master_password, data['salt']):
                    # os.remove('register.json')
                    keyring.set_password("system", "email", email)
                    keyring.set_password("system", "master_password", master_password)
                    keyring.set_password("system", "salt", data['salt'])
                    keyring.set_password("system", "directory", data['directory'])
                    window.close()
                    os.system('python3 showPasswords.py')
                else:
                    # os.remove('register.json')
                    self.show_message_box("There is no such user! Try again, please")
        else:
            self.show_message_box("Register first")

    def show_message_box(self, text):
        """Show MessageBox with error if there is no such user. Clear fields"""
        QMessageBox.about(self, "No user", text)
        self.email.setText("")
        self.master_password.setText("")

    def on_register_button(self):
        """Close registerWindow and run register.py"""
        window.close()
        os.system('python3 register.py')


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    app.exec_()
