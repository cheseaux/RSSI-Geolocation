"""
    ********************* VerySimpleWebBrowser ************************

    This is a Very Simple Web Browser implemented over Qt and QtWebKit.

    author: Juan Manuel Garcia <jmg.utn@gmail.com>

    *******************************************************************
"""

import sys
from PyQt4 import QtCore, QtGui, QtWebKit

class Browser(QtGui.QMainWindow):

    def __init__(self):
        """
            Initialize the browser GUI and connect the events
        """

        QtGui.QMainWindow.__init__(self)
        self.resize(800,600)
        self.centralwidget = QtGui.QWidget(self)

        self.mainLayout = QtGui.QHBoxLayout(self.centralwidget)
        self.mainLayout.setSpacing(0)

        self.html = QtWebKit.QWebView()
        self.mainLayout.addWidget(self.html)
        self.setCentralWidget(self.centralwidget)

        self.default_url = "http://www.jonathancheseaux.ch/"
        self.browse()

    def browse(self):
        """
            Make a web browse on a specific url and show the page on the
            Webview widget.
        """
        url = self.default_url
        self.html.load(QtCore.QUrl(url))
        self.html.show()

if __name__ == "__main__":

    app = QtGui.QApplication(sys.argv)
    main = Browser()
    main.show()
    sys.exit(app.exec_())
