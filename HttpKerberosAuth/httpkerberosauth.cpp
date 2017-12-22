#include "httpkerberosauth.h"

#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QEventLoop>

HttpKerberosAuth::HttpKerberosAuth(QString _serviceName,
                                   QNetworkAccessManager *_manager) :
    manager(_manager)
{
    serviceName = new char[_serviceName.size() + 1];
    memcpy(serviceName, _serviceName.toStdString().c_str(), _serviceName.length() + 1);
}

HttpKerberosAuth::~HttpKerberosAuth()
{
    delete [] serviceName;
}

QNetworkReply *HttpKerberosAuth::makeRequest(QNetworkRequest request,
                                             QByteArray body)
{
    QEventLoop eventLoop;
    QNetworkReply *reply = manager->post(request,
                                         body);
    connect(reply, SIGNAL(finished()), &eventLoop, SLOT(quit()));
    eventLoop.exec();
    if (reply->rawHeader("www-authenticate") == "Negotiate")
    {
#ifdef Q_OS_WIN
        CredHandle credHandle = {0};
        TimeStamp exp;
        qDebug() << "Acquire" << AcquireCredentialsHandleA(NULL,
                                                           (LPSTR)"Kerberos",
                                                           SECPKG_CRED_OUTBOUND,
                                                           NULL,
                                                           NULL,
                                                           NULL,
                                                           NULL,
                                                           &credHandle,
                                                           &exp);
        CtxtHandle context;
        SecBufferDesc outputBufferDesc;
        SecBuffer outputBuffers[1];
        outputBuffers[0].pvBuffer = NULL;
        outputBuffers[0].BufferType = SECBUFFER_TOKEN;
        outputBuffers[0].cbBuffer = 0;

        outputBufferDesc.ulVersion = SECBUFFER_VERSION;
        outputBufferDesc.cBuffers = 1;
        outputBufferDesc.pBuffers = outputBuffers;

        ulong contextAttr;

        SECURITY_STATUS status = InitializeSecurityContextA(&credHandle,
                                                            NULL,
                                                            (LPSTR)serviceName,
                                                            ISC_REQ_ALLOCATE_MEMORY,
                                                            0,
                                                            SECURITY_NATIVE_DREP,
                                                            NULL,
                                                            0,
                                                            &context,
                                                            &outputBufferDesc,
                                                            &contextAttr,
                                                            &exp);
        switch (status)
        {
        case SEC_E_OK:
            break;
        case SEC_E_INSUFFICIENT_MEMORY:
        case SEC_E_INTERNAL_ERROR:
        case SEC_E_INVALID_HANDLE:
        case SEC_E_INVALID_TOKEN:
        case SEC_E_LOGON_DENIED:
        case SEC_E_NO_AUTHENTICATING_AUTHORITY:
        case SEC_E_NO_CREDENTIALS:
        case SEC_E_TARGET_UNKNOWN:
        case SEC_E_UNSUPPORTED_FUNCTION:
        case SEC_E_WRONG_PRINCIPAL:
            qDebug() << "SSPI Error: Something goes wrong in initialize security context";
        default:
            qDebug() << "SSPI Error: Something goes wrong in initialize security context.";
        }

        SecBuffer pBuffer = outputBufferDesc.pBuffers[0];
        QByteArray ticket = QByteArray((const char *)pBuffer.pvBuffer, pBuffer.cbBuffer);

#else
        gss_ctx_id_t context;
        gss_ctx_id_t *gssContext = &context;
        gss_buffer_desc sendToken, receiveToken, *tokenPointer;
        gss_buffer_desc serviceNameBuffer;
        gss_name_t targetName;
        OM_uint32 majorStatus, minorStatus;
        gss_cred_id_t userCredential = GSS_C_NO_CREDENTIAL;

        // Конвертируем имя сервиса в формат kerberos'a
        serviceNameBuffer.value = (void *)serviceName;
        serviceNameBuffer.length = strlen(serviceName) + 1;
        majorStatus = gss_import_name(&minorStatus,
                                      &serviceNameBuffer,
                                      (gss_OID) GSS_C_NT_HOSTBASED_SERVICE,
                                      &targetName);
        if (majorStatus != GSS_S_COMPLETE)
        {
            printStatus("import service name", majorStatus, minorStatus);
            return reply;
        }

        // Начинаем цикл инициализации контекста
        tokenPointer = GSS_C_NO_BUFFER;
        *gssContext = GSS_C_NO_CONTEXT;

        do {
            gss_OID mech;
            OM_uint32 ret_flags;
            majorStatus = gss_init_sec_context(&minorStatus,
                                               userCredential,
                                               gssContext,
                                               targetName,
                                               GSS_C_NO_OID,
                                               GSS_C_DELEG_FLAG,
                                               0,
                                               NULL,
                                               tokenPointer,
                                               &mech,
                                               &sendToken,
                                               &ret_flags,
                                               NULL);

            if (gssContext == NULL)
            {
                (void) gss_release_name(&minorStatus, &targetName);
                return reply;
            }
            if (tokenPointer != GSS_C_NO_BUFFER)
            {
                receiveToken.value = NULL;
                receiveToken.length = 0;
            }
            if (majorStatus != GSS_S_COMPLETE && majorStatus != GSS_S_CONTINUE_NEEDED)
            {
                printStatus("init context", majorStatus, minorStatus);
                (void) gss_release_name(&minorStatus, &targetName);
                return reply;
            }
            if (sendToken.length != 0)
            {
                QByteArray ticket = QByteArray((const char *)sendToken.value, sendToken.length);
                QNetworkRequest newRequest = request;
                QEventLoop loop;

                newRequest.setRawHeader("Authorization", "Negotiate " + ticket.toBase64());

                reply->deleteLater();
                reply = manager->post(newRequest,
                                      body);
                connect(reply, SIGNAL(finished()), &loop, SLOT(quit()));
                loop.exec();
            }
            (void) gss_release_buffer(&minorStatus, &sendToken);

            if (majorStatus == GSS_S_CONTINUE_NEEDED)
            {
                QByteArray authHeader = reply->rawHeader("www-authenticate");
                int negotiateLength = 10;
                authHeader = authHeader.right(authHeader.size() - negotiateLength);
                authHeader = QByteArray::fromBase64(authHeader);
                receiveToken.value = authHeader.data();
                receiveToken.length = strlen(authHeader.data()) + 1;
                tokenPointer = &receiveToken;
            }
        } while (majorStatus == GSS_S_CONTINUE_NEEDED);
        (void) gss_release_name(&minorStatus, &targetName);
#endif
    }
    return reply;
}

void HttpKerberosAuth::printStatus(const char *message,
                                   OM_uint32 majorStatus,
                                   OM_uint32 minorStatus)
{
#ifdef Q_OS_LINUX
    printStatusInternal(message, majorStatus, GSS_C_GSS_CODE);
    printStatusInternal(message, minorStatus, GSS_C_MECH_CODE);
#else
    Q_UNUSED(message);
    Q_UNUSED(majorStatus);
    Q_UNUSED(minorStatus);
#endif
}

void HttpKerberosAuth::printStatusInternal(const char *message,
                                           OM_uint32 code,
                                           int type)
{
#ifdef Q_OS_LINUX
    OM_uint32 majorStatus, minorStatus;
    gss_buffer_desc messageBuffer = GSS_C_EMPTY_BUFFER;
    OM_uint32 messageContext = 0;

    while (1)
    {
        majorStatus = gss_display_status(&minorStatus,
                                         code,
                                         type,
                                         GSS_C_NULL_OID,
                                         &messageContext,
                                         &messageBuffer);
        if (majorStatus != GSS_S_COMPLETE)
            qDebug() << "error in gss_display_status" << message;
        else
            qDebug() << "GSS-API error" << message << ":" << (char *)messageBuffer.value;
        if (messageBuffer.length != 0)
            (void) gss_release_buffer(&minorStatus, &messageBuffer);
        if (!messageContext)
            break;
    }
#else
    Q_UNUSED(message);
    Q_UNUSED(code);
    Q_UNUSED(type);
#endif
}
