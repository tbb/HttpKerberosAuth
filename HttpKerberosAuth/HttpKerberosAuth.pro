QT += core network
QT -= gui

CONFIG += c++11

TARGET = HttpKerberosAuth
CONFIG += console
CONFIG -= app_bundle

TEMPLATE = app

SOURCES += main.cpp \
    httpkerberosauth.cpp

HEADERS += \
    httpkerberosauth.h
