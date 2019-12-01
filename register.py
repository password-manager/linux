import base64
import hashlib
import json
import os
import sys

import gnupg
from PyQt5 import QtWidgets, uic
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QMessageBox

qt_creator_file = "guis/register.ui"
Ui_MainWindow, QtBaseClass = uic.loadUiType(qt_creator_file)
gpg = gnupg.GPG(gnupghome="/home/marina/.gnupg")


def hash_password(password, salt):
    """Hash a password for storing."""
    pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'),
                                  salt, 100000, dklen=64)
    pwdhash = base64.b64encode(pwdhash)
    return pwdhash.decode()


class MainWindow(QtWidgets.QMainWindow, Ui_MainWindow):
    def __init__(self):
        """Show main window. Connect buttons with appopciate functions."""
        QtWidgets.QMainWindow.__init__(self)
        Ui_MainWindow.__init__(self)
        self.setupUi(self)
        self.cancelButton.pressed.connect(self.on_cancel_button)
        self.registerButton.pressed.connect(self.on_register_button)
        self.master_password.setEchoMode(QtWidgets.QLineEdit.Password)
        self.checkBox.stateChanged.connect(self.change_check_box)

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
        os.system('python3 login.py')

    def on_register_button(self):
        """Check if there is already an user, if no - write email, master password and salt to password file"""
        if not self.email.text() or not self.master_password.text():
            QMessageBox.about(self, "No data", "Write password name and password, please")
        else:
            if os.path.exists('register.json.gpg'):
                self.show_message_box()
            else:
                salt = hashlib.sha256(os.urandom(64)).hexdigest().encode('ascii')
                hashed = hash_password(self.master_password.text(), salt)
                with open('register.json', 'x') as file:
                    data = {'email': self.email.text(), 'master_password': hashed, 'salt': salt.decode(),
                            'directory': self.directory.text()}
                    json.dump(data, file)
                input_data = gpg.gen_key_input(
                    name_email=self.email.text(),
                    passphrase=self.master_password.text())
                gpg.gen_key(input_data)
                with open('register.json', 'rb') as file:
                    gpg.encrypt_file(file, recipients=[self.email.text()], output='register.json.gpg')
                os.remove('register.json')
            self.on_cancel_button()

    def show_message_box(self):
        """Show MessageBox with error if there is no such user. Clear fields"""
        QMessageBox.about(self, "One account", "Only one account is possible")
        self.on_cancel_button()


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    app.exec_()
