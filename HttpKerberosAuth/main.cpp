#include <QCoreApplication>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>

#include "httpkerberosauth.h"

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);


    QNetworkAccessManager *manager = new QNetworkAccessManager();
    HttpKerberosAuth sender("SERVICENAME@domain",
                            manager);

    QNetworkRequest request(QUrl("https://address.domain"));
    QNetworkReply *reply = sender.makeRequest(request,
                                              QByteArray());

    qDebug() << "Status code" << reply->attribute(QNetworkRequest::HttpStatusCodeAttribute);
    qDebug() << "reply" << reply->readAll();

    return a.exec();
}
