import os
import sys
from ast import literal_eval

from PyQt5 import QtWidgets, uic
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QMessageBox
from cryptography.fernet import Fernet

qt_creator_file = "guis/login.ui"
Ui_MainWindow, QtBaseClass = uic.loadUiType(qt_creator_file)

try:
    with open('key.txt', 'rb') as file:
        key = file.read()
except FileNotFoundError:
    key = None


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
        if key and os.path.exists('register.txt'):
            with open('register.txt', 'r') as file:
                data = file.read()
                fernet = Fernet(key)
                data = fernet.decrypt(str(data).encode())
                data = literal_eval(data.decode())
                if data['email'] == self.email.text() and data['master_password'] == self.master_password.text():
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
