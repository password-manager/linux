import os
import sys
import json

from PyQt5 import QtWidgets, uic

qt_creator_file = "guis/folder.ui"
Ui_MainWindow, QtBaseClass = uic.loadUiType(qt_creator_file)


class MainWindow(QtWidgets.QMainWindow, Ui_MainWindow):
    def __init__(self):
        """Show main window. Connect cancelButton with onCancelButton function
        and registerButton with onRegisterButton function"""
        QtWidgets.QMainWindow.__init__(self)
        Ui_MainWindow.__init__(self)
        self.setupUi(self)
        self.connect_components()

    def on_cancel_push_button(self):
        """Close folder window and run showPasswords.py"""
        window.close()
        os.system('python showPasswords.py')

    def on_ok_push_button(self):
        folder_name = self.folderNameLineEdit.text()  # get folder name
        if folder_name:
            with open('passwords.json', mode='r') as passwords:
                data = json.load(passwords)
                data.append({'directory': folder_name})
            with open('passwords.json', mode='w') as passwords:
                json.dump(data, passwords, indent=4)

    def connect_components(self):
        self.cancelPushButton.pressed.connect(self.on_cancel_push_button)
        self.okPushButton.pressed.connect(self.on_ok_push_button)


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    app.exec_()
