import os
import sys

from PyQt5 import QtWidgets, uic
from PyQt5.QtWidgets import QMessageBox

qt_creator_file = "guis/login.ui"
Ui_MainWindow, QtBaseClass = uic.loadUiType(qt_creator_file)


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


    def onLoginButton(self):
        """Close loginWindow and run showPasswords.py"""
        try:
            with open('register.txt', 'r') as file:
                for line in file:
                    line = line.split(',')
                if line[0].split(':')[1] == self.email.text() and line[1].split(':')[1] == self.master_password.text():
                    window.close()
                    os.system('python showPasswords.py')
                else:
                    QMessageBox.about(self, "No user", "There is no such user! Try again, please")
                    self.email.setText("")
                    self.master_password.setText("")
        except FileNotFoundError:
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
