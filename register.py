import base64
import binascii
import hashlib
import json
import os
import sys

from PyQt5 import QtWidgets, uic
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QMessageBox

qt_creator_file = "guis/register.ui"
Ui_MainWindow, QtBaseClass = uic.loadUiType(qt_creator_file)


def hash_password(password, salt):
    """Hash a password for storing."""
    pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'),
                                  salt, 100000, dklen=64)
    pwdhash = base64.b64encode(pwdhash)
    return pwdhash.decode()


class MainWindow(QtWidgets.QMainWindow, Ui_MainWindow):
    def __init__(self):
        """Show main window. Connect cancelButton with on_cancel_button function
        and registerButton with on_register_button function"""
        QtWidgets.QMainWindow.__init__(self)
        Ui_MainWindow.__init__(self)
        self.setupUi(self)
        self.cancelButton.pressed.connect(self.on_cancel_button)
        self.registerButton.pressed.connect(self.on_register_button)
        self.master_password.setEchoMode(QtWidgets.QLineEdit.Password)
        self.checkBox.stateChanged.connect(self.change_check_box)

    def change_check_box(self, state):
        """If checkBox is checked - show password,
        if unchecked - hide it"""
        if state == Qt.Checked:
            self.master_password.setEchoMode(QtWidgets.QLineEdit.Normal)
        else:
            self.master_password.setEchoMode(QtWidgets.QLineEdit.Password)

    def on_cancel_button(self):
        """Close registerWindow and run login.py"""
        window.close()
        os.system('python login.py')

    def on_register_button(self):
        """Write to register.json email, hashed password and salt"""
        email = self.email.text()
        master_password = self.master_password.text()
        # salt = hashlib.sha256(os.urandom(64)).hexdigest().encode('ascii')
        salt = b'7474e5091fbc195f486905019195e840e2a9feaea5e1723ba934039e4fe123aa'
        if not email or not master_password:
            QMessageBox.about(self, "No data", "Write password name and password, please")
        else:
            hashed = hash_password(master_password, salt)
            with open('register.json', 'w+') as file:
                data = {'email': email, 'master_password': hashed, 'salt': salt.decode()}
                json.dump(data, file)
            self.on_cancel_button()


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    app.exec_()
    