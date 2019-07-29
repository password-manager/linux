import os
import sys

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


    def onCancelButton(self):
        """Close registerWindow and run login.py"""
        window.close()
        os.system('python login.py')

    def onRegisterButton(self):
        pass


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    app.exec_()