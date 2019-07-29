import json
import os
import sys
from PyQt5 import QtCore, QtWidgets, uic
from PyQt5.QtCore import Qt

qt_creator_file = "guis/passwordList.ui"
Ui_MainWindow, QtBaseClass = uic.loadUiType(qt_creator_file)


class PasswordsListModel(QtCore.QAbstractListModel): #think about better solution
    def __init__(self, *args, data=None, **kwargs):
        super(PasswordsListModel, self).__init__(*args, **kwargs)
        if data:
            self.data = data
        else:
            self.data = []

    def data(self, index, role):
        if role == Qt.DisplayRole:
            text, _ = self.data[index.row()]
            return text

    def rowCount(self, index):
        return len(self.data)


class MainWindow(QtWidgets.QMainWindow, Ui_MainWindow):
    def __init__(self):
        """Show main window. Load data.
        Connect createButton with onCreateButton function,
        deleteButton with onDeleteButton function,
        doubleClicked password with onEditClock function"""
        QtWidgets.QMainWindow.__init__(self)
        Ui_MainWindow.__init__(self)
        self.setupUi(self)
        self.model = PasswordsListModel()
        self.load()
        self.passwordsView.setModel(self.model)
        self.createButton.pressed.connect(self.onCreateButton)
        self.deleteButton.pressed.connect(self.onDeleteButton)
        self.passwordsView.doubleClicked.connect(self.onEditClick)

    def onCreateButton(self):
        """Close showPasswordsWindow and run savePassword.py"""
        window.close()
        os.system('python savePassword.py')

    def onEditClick(self, item):
        """Close showPasswordsWindow and
        run savePasswor.py with args:passwordName and encrypted password"""
        with open("passwords.json", "r") as f:
            data = list(json.load(f))
            for row in data:
                if row['password_name'] == item.data():
                    password = row['password']

        window.close()
        os.system('python savePassword.py ' + item.data() + " " + password)

    def onDeleteButton(self):
        """Delete selected password from View and from file"""
        indexes = self.passwordsView.selectedIndexes()
        if indexes:
            # Indexes is a list of a single item in single-select mode.
            index = indexes[0]
            data = self.model.data[index.row()]
            # Remove the item and refresh.
            del self.model.data[index.row()]
            self.model.layoutChanged.emit()
            # Clear the selection (as it is no longer valid).
            self.passwordsView.clearSelection()
            self.deleteFromFile(data[0])

    def load(self):
        """Load passwords from 'passwords.csv' to data to model"""
        try:
            with open('passwords.json', 'r') as file:
                json_data = json.load(file)
                for row in json_data:
                    self.model.data.append([row['password_name'], row['password']])
        except Exception:
            pass

    def deleteFromFile(self, name):
        """Delete selected password from file"""
        with open("passwords.json", "r") as f:
            data = json.load(f)
            for row in data:
                if row['password_name'] == name:
                    data.remove(row)


        with open("passwords.json", "w") as f:
            json.dump(data, f, indent=4)



if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()
    app.exec_()