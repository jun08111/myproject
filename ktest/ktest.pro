TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
        main.cpp
LIBS += -lpcap
LIBS += -lpthread
HEADERS += \
    main.h \
    kmeans.h
