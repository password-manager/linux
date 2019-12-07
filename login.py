import base64
import hashlib
import json
import os
import socket
import sys

import gnupg
import keyring
from PyQt5 import QtWidgets, uic
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QMessageBox

from register import RegisterWindow

HOST = '127.0.0.1'
PORT = 8887

qt_creator_file = "guis/login.ui"
Ui_MainWindow, QtBaseClass = uic.loadUiType(qt_creator_file)
qt_creator_file = "guis/directory.ui"
Ui_DirWindow, QtDirClass = uic.loadUiType(qt_creator_file)
gpg = gnupg.GPG(gnupghome="/Users/jzawalska/.gnupg")


def verify_password(stored_password, provided_password, salt):
    """Verify a stored password against one provided by user"""
    return hash_password(provided_password, salt.encode()) == stored_password


def hash_password(password, salt):
    """Hash a password for storing."""
    pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'),
                                  salt, 100000, dklen=64)
    pwdhash = base64.b64encode(pwdhash)
    return pwdhash.decode()


class DirWindow(QtWidgets.QMainWindow, Ui_DirWindow):
    def __init__(self):
        QtWidgets.QMainWindow.__init__(self)
        Ui_DirWindow.__init__(self)
        self.setupUi(self)
        self.acceptButton.pressed.connect(self.on_accept_button)

    def on_accept_button(self):
        hashed = hash_password(window.master_password.text(), window.data.split(':')[2].encode())
        with open('register.json', 'x') as file:
            data = {'email': window.email.text(), 'master_password': hashed,
                    'salt': window.data.split(':')[2],
                    'directory': self.directory.text()}
            json.dump(data, file)
        input_data = gpg.gen_key_input(
            name_email=window.email.text(),
            passphrase=window.master_password.text())
        gpg.gen_key(input_data)
        with open('register.json', 'rb') as file:
            gpg.encrypt_file(file, recipients=[window.email.text()], output='register.json.gpg')
        os.remove('register.json')
        keyring.set_password("system", "email", window.email.text())
        keyring.set_password("system", "master_password", window.master_password.text())
        keyring.set_password("system", "salt", window.data.split(':')[2])
        keyring.set_password("system", "directory", self.directory.text())
        self.close()
        window.close()
        os.system('python3 showPasswords.py')


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
        try:
            self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.s.connect((HOST, PORT))
            self.online = True
        except ConnectionRefusedError:
            self.online = False

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
        if self.online:
            if os.path.exists('register.json.gpg'):
                self.s.sendall(('2:' + self.email.text() + ':' + self.master_password.text() + ':0').encode())
            else:
                self.s.sendall(('2:' + self.email.text() + ':' + self.master_password.text() + ':1').encode())
            self.data = self.s.recv(1024).decode()
            print(self.data)
            if self.data.split(':')[0] == '2' and self.data.split(':')[1] == 'ok':
                if self.data.split(':')[2] != 'Login successful':
                    dirWindow.show()
                else:
                    self.close()
                    self.set_keyrings()
                    os.system('python3 showPasswords.py')
            elif self.data.split(':')[0] == '2' and self.data.split(':')[1] == 'notOk':
                self.show_message_box("There is no such user! Try again, please")
        else:
            if os.path.exists('register.json.gpg'):
                self.set_keyrings()
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
        registerWindow.show()

    def set_keyrings(self):
        with open('register.json.gpg', 'rb') as file:
            gpg.decrypt_file(file, passphrase=self.master_password.text(), output='register.json')
        with open('register.json', 'r') as file:
            json_data = json.load(file)
            if json_data['email'] == self.email.text() and verify_password(json_data['master_password'],
                                                                           self.master_password.text(),
                                                                           json_data['salt']):
                os.remove('register.json')
                keyring.set_password("system", "email", self.email.text())
                keyring.set_password("system", "master_password", self.master_password.text())
                keyring.set_password("system", "salt", json_data['salt'])
                keyring.set_password("system", "directory", json_data['directory'])

                self.close()
                os.system('python3 showPasswords.py')
            else:
                os.remove('register.json')
                self.show_message_box("There is no such user! Try again, please")



if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    dirWindow = DirWindow()
    registerWindow = RegisterWindow(window)
    window.show()
    app.exec_()
