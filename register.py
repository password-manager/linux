import base64
import hashlib
import json
import os
import socket
import sys

import gnupg

from PyQt5 import QtWidgets, uic
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QMessageBox

HOST = '127.0.0.1'
PORT = 8885

qt_creator_file = "guis/register.ui"
Ui_MainWindow, QtBaseClass = uic.loadUiType(qt_creator_file)
qt_creator_file = "guis/code.ui"
Ui_CodeWindow, QtCodeClass = uic.loadUiType(qt_creator_file)
gpg = gnupg.GPG(gnupghome="/home/marina/.gnupg")


def hash_password(password, salt):
    """Hash a password for storing."""
    pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'),
                                  salt, 100000, dklen=64)
    pwdhash = base64.b64encode(pwdhash)
    return pwdhash.decode()


class CodeWindow(QtWidgets.QMainWindow, Ui_CodeWindow):
    def __init__(self, registerWindow):
        QtWidgets.QMainWindow.__init__(self)
        Ui_CodeWindow.__init__(self)
        self.setupUi(self)
        self.verifyButton.pressed.connect(self.on_verify_button)
        self.registerWindow = registerWindow

    def on_verify_button(self):
        self.registerWindow.loginWindow.s.sendall(('1:' + self.registerWindow.email.text() + ':' + self.registerWindow.master_password.text() + ':' + self.code.text()).encode())
        data = self.registerWindow.loginWindow.s.recv(1024).decode()

        print(data)
        if data.split(':')[0] == '1' and data.split(':')[1] == 'ok':
            with open('register.json', 'x') as file:
                data = {'email': self.registerWindow.email.text(), 'master_password': self.registerWindow.hashed,
                        'salt': self.registerWindow.salt.decode(),
                        'directory': self.registerWindow.directory.text()}
                json.dump(data, file)
            input_data = gpg.gen_key_input(
                name_email=self.registerWindow.email.text(),
                passphrase=self.registerWindow.master_password.text())
            gpg.gen_key(input_data)
            with open('register.json', 'rb') as file:
                gpg.encrypt_file(file, recipients=[self.registerWindow.email.text()], output='register.json.gpg')
            os.remove('register.json')
            self.close()
            self.registerWindow.on_cancel_button()
        elif data.split(':')[0] == '1' and data.split(':')[1] == 'notOk':
            self.show_message_box(data.split(':')[2])

    def show_message_box(self, text):
        """Show MessageBox with error if there is no such user. Clear fields"""
        QMessageBox.about(self, "Error", text)
        self.on_cancel_button()


class RegisterWindow(QtWidgets.QMainWindow, Ui_MainWindow):
    def __init__(self, loginWindow):
        """Show main window. Connect buttons with appopciate functions."""
        QtWidgets.QMainWindow.__init__(self)
        Ui_MainWindow.__init__(self)
        self.setupUi(self)
        self.cancelButton.pressed.connect(self.on_cancel_button)
        self.registerButton.pressed.connect(self.on_register_button)
        self.master_password.setEchoMode(QtWidgets.QLineEdit.Password)
        self.checkBox.stateChanged.connect(self.change_check_box)
        self.loginWindow = loginWindow
        self.code_window = CodeWindow(self)

    def change_check_box(self, state):
        """If checkBox is checked - show password,
        if unchecked - hide it."""
        if state == Qt.Checked:
            self.master_password.setEchoMode(QtWidgets.QLineEdit.Normal)
        else:
            self.master_password.setEchoMode(QtWidgets.QLineEdit.Password)

    def on_cancel_button(self):
        """Close registerWindow and run login.py."""
        self.close()
        self.loginWindow.show()

    def on_register_button(self):
        """Check if there is already an user, if no - write email, master password and salt to password file"""
        if not self.email.text() or not self.master_password.text():
            QMessageBox.about(self, "No data", "Write password name and password, please")
        else:
            if os.path.exists('register.json.gpg'):
                self.show_message_box("Only one account is possible")
                self.on_cancel_button()
            else:
                self.salt = hashlib.sha256(os.urandom(64)).hexdigest().encode('ascii')
                self.hashed = hash_password(self.master_password.text(), self.salt)
                self.loginWindow.s.sendall(
                    ('0:' + self.email.text() + ':' + self.master_password.text() + ':' + self.salt.decode()).encode())
                data = self.loginWindow.s.recv(1024).decode()
                print(data)
                if data.split(':')[0] == '0' and data.split(':')[1] == 'ok':
                    self.code_window.show()
                elif data.split(':')[0] == '0' and data.split(':')[1] == 'notOk':
                    self.show_message_box(data.split(':')[2])
                    self.on_cancel_button()

    def show_message_box(self, text):
        """Show MessageBox with error if there is no such user. Clear fields"""
        QMessageBox.about(self, "Error", text)
        self.on_cancel_button()


if __name__ == '__main__':
    pass

