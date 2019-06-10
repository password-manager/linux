import csv
import sys
from PyQt5 import QtCore, QtWidgets, uic
from PyQt5.QtCore import Qt

qt_creator_file = "passwordList.ui"
Ui_MainWindow, QtBaseClass = uic.loadUiType(qt_creator_file)


class PasswordsListModel(QtCore.QAbstractListModel):
    def __init__(self, *args, data=None, **kwargs):
        super(PasswordsListModel, self).__init__(*args, **kwargs)
        self.data = data or []

    def data(self, index, role):
        if role == Qt.DisplayRole:
            text, _ = self.data[index.row()]
            return text

    def rowCount(self, index):
        return len(self.data)


class MainWindow(QtWidgets.QMainWindow, Ui_MainWindow):
    def __init__(self):
        QtWidgets.QMainWindow.__init__(self)
        Ui_MainWindow.__init__(self)
        self.setupUi(self)
        self.model = PasswordsListModel()
        self.load()
        self.passwordsView.setModel(self.model)
        self.createButton.pressed.connect(self.create)
        self.deleteButton.pressed.connect(self.delete)


    def create(self):
        """
        Open window to create a new password
        """
        pass

    def delete(self):
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
            self.save(data[0])



    def load(self):
        try:
            with open('passwords.csv', 'r') as file:
                csv_data = csv.reader(file, delimiter=',')
                for row in csv_data:
                    self.model.data.append(row)
        except Exception:
            pass

    def save(self, name):
        with open("passwords.csv", "r") as f:
            data = list(csv.reader(f))

        with open("passwords.csv", "w", newline='') as f:
            writer = csv.writer(f)
            for row in data:
                if row[0] != name:
                    writer.writerow(row)





app = QtWidgets.QApplication(sys.argv)
window = MainWindow()
window.show()
app.exec_()

