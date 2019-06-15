import os
import sys
from PyQt5 import QtWidgets, uic
import csv

qt_creator_file = "savePassword.ui"
Ui_MainWindow, QtBaseClass = uic.loadUiType(qt_creator_file)


class SavePasswordModel():

    def save(self, passwordName, password):
        with open('passwords.csv', mode='a+') as passwords:
            passwords = csv.writer(passwords, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            passwords.writerow([passwordName, password])


class MainWindow(QtWidgets.QMainWindow, Ui_MainWindow):
    def __init__(self, passwordName=None, password=None):
        QtWidgets.QMainWindow.__init__(self)
        Ui_MainWindow.__init__(self)
        self.setupUi(self)
        self.model = SavePasswordModel()
        self.passwordName.setText(passwordName)
        self.password.setText(password)
        self.saveButton.pressed.connect(self.onSaveButton)
        self.cancelButton.pressed.connect(self.onCancelButton)

    def onSaveButton(self):
        """
        Get input from passwordName and password,
        then save them to default file. Clear data.
        """
        passwordName = self.passwordName.text()
        password = self.password.text()
        if password and passwordName:  # Don't add empty strings.
            # Add 'passwordName' and 'password' to passwords.csv
            self.model.save(passwordName, password)

            #  Empty the input
            self.onClearButton()

    def onClearButton(self):
        """Empty inputs 'passwordName' and 'password'"""
        self.passwordName.setText("")
        self.password.setText("")

    def onCancelButton(self):
        """Empty inputs 'passwordName' and 'password'"""
        window.close()
        os.system('python showPasswords.py ')

if __name__=="__main__":
    app = QtWidgets.QApplication(sys.argv)
    if len(sys.argv) == 3:
        window = MainWindow(sys.argv[1], sys.argv[2])
    else:
        window = MainWindow()
    window.show()
    app.exec_()
