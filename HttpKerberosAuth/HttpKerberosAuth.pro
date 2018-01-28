QT += core network
QT -= gui

CONFIG += c++11

TARGET = HttpKerberosAuth
CONFIG += console
CONFIG -= app_bundle

TEMPLATE = lib

SOURCES += main.cpp \
    httpkerberosauth.cpp

HEADERS += \
    httpkerberosauth.h

unix:!macx {
    LIBS += -lgssapi_krb5
}

win32 {
    LIBS += -lsecur32
}
