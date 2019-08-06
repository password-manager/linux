import json
import os
import sys

from PyQt5.QtCore import Qt


from PyQt5 import QtWidgets, uic

qt_creator_file = "guis/register.ui"
Ui_MainWindow, QtBaseClass = uic.loadUiType(qt_creator_file)


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
        # with open('register.txt', 'w+') as file:
        #   file.write('login:{}, password:{}'.format(self.email.text(), self.master_password.text()))
        with open('register.json', 'w+') as file:
            data = {}
            data['email'] = self.email.text()
            data['master_password'] = self.master_password.text()
            json.dump(data, file)
        self.onCancelButton()


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    app.exec_()
