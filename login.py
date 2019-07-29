import os
import sys

from PyQt5 import QtWidgets, uic


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


    def onLoginButton(self):
        """Close loginWindow and run showPasswords.py"""
        window.close()
        os.system('python showPasswords.py')

    def onRegisterButton(self):
        """Close registerWindow and run register.py"""
        window.close()
        os.system('python register.py')


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    app.exec_()