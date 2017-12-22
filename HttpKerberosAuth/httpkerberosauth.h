#ifndef HTTPKERBEROSAUTH_H
#define HTTPKERBEROSAUTH_H

#include <QObject>

#ifdef Q_OS_WIN
#define SECURITY_WIN32
#include <windows.h>
#include <security.h>
typedef unsigned int OM_uint32;
#else
#include <gssapi.h>
#endif

class QNetworkRequest;
class QNetworkReply;
class QNetworkAccessManager;

class HttpKerberosAuth : public QObject
{
    Q_OBJECT
public:
    //! \brief Конструктор
    /*! \param _serviceName - имя сервиса,
     *  \param _manager - менеджер запросов
     */
    HttpKerberosAuth(QString _serviceName,
                     QNetworkAccessManager *_manager);
    //! \brief Деструктор
    ~HttpKerberosAuth();

private:
    char *serviceName; //!< Имя сервиса
    QNetworkAccessManager *manager; //!< Менеджер запросов

public:
    //! \brief выполнение post запроса request с телом body
    /*! \param request - заполненный запрос
     *  \param body - тело запроса
     *  \return результат запроса(синхронный)
     */
    QNetworkReply *makeRequest(QNetworkRequest request,
                               QByteArray body);

private:
    //! \brief вывод ошибки службы gssapi по коду
    /*! \param message - дополнительное сообщение
     *  \param majorStatus - главный код ошибки
     *  \param minorStatus - второстепенный код ошибки
     */
    void printStatus(const char *message,
                     OM_uint32 majorStatus,
                     OM_uint32 minorStatus);
    //! \brief внутренний обработчик ошибок
    /*! \param message - сообщение
     *  \param code - код ошибки
     *  \param type - тип ошибки
     */
    void printStatusInternal(const char *message,
                             OM_uint32 code,
                             int type);
};

#endif // HTTPKERBEROSAUTH_H
