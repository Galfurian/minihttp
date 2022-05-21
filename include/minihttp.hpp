/// @file minihttp.hpp
/// @brief

#pragma once

#include <stdint.h>

#include <cctype>
#include <cstddef>
#include <cstring>
#include <algorithm>
#include <functional>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
#include <sstream>
#include <cstdarg>
#include <ctime>
#include <sys/time.h>

#if defined(_WIN32) || defined(__CYGWIN__)
#pragma push_macro("WIN32_LEAN_AND_MEAN")
#pragma push_macro("NOMINMAX")
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif // WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif // NOMINMAX
#include <winsock2.h>
#if _WIN32_WINNT < _WIN32_WINNT_WINXP
extern "C" char *_strdup(const char *strSource);
#define strdup _strdup
#include <wspiapi.h>
#endif // _WIN32_WINNT < _WIN32_WINNT_WINXP
#include <ws2tcpip.h>
#pragma pop_macro("WIN32_LEAN_AND_MEAN")
#pragma pop_macro("NOMINMAX")
#else
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif // defined(_WIN32) || defined(__CYGWIN__)

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/error.h>

namespace http
{
#define MINIHTTP_VERSION_MAJOR 1 ///< Major version.
#define MINIHTTP_VERSION_MINOR 0 ///< Minor version.
#define MINIHTTP_VERSION_PATCH 0 ///< Patch version.

/// @brief Logging functions.
namespace logging
{

#define CONSOLE_RST "\x1B[0m" ///< Reset: turn off all attributes.
#define CONSOLE_BLD "\x1B[1m" ///< Bold or bright.
#define CONSOLE_ITA "\x1B[2m" ///< Italic.
#define CONSOLE_UND "\x1B[4m" ///< Underlined.

#define CONSOLE_RED "\x1B[31m" ///< Sets color to RED.
#define CONSOLE_GRN "\x1B[32m" ///< Sets color to GREEN.
#define CONSOLE_YEL "\x1B[33m" ///< Sets color to YELLOW.
#define CONSOLE_BLU "\x1B[34m" ///< Sets color to BLUE.
#define CONSOLE_MAG "\x1B[35m" ///< Sets color to MAGENTA.
#define CONSOLE_CYN "\x1B[36m" ///< Sets color to CYAN.
#define CONSOLE_WHT "\x1B[37m" ///< Sets color to WHITE.

/// @brief Returns the current time.
inline const char *get_time()
{
    static char buffer[80];
    time_t now = time(0);
    struct tm tstruct;
    tstruct = *localtime(&now);
    strftime(buffer, sizeof(buffer), "%X", &tstruct);
    return buffer;
}

#ifndef NDEBUG
/// @brief Prints a debugging message.
inline void debug(const char *format, ...)
{
    va_list args;
    fputs(CONSOLE_CYN, stdout);
    fputs("[", stdout);
    fputs(logging::get_time(), stdout);
    fputs("] ", stdout);
    va_start(args, format);
    vfprintf(stdout, format, args);
    va_end(args);
    fputs(CONSOLE_RST, stdout);
}
#else
/// @brief Do not print debugging messages.
#define debug(...)
#endif

/// @brief Prints an generic message.
inline void info(const char *format, ...)
{
    va_list args;
    fputs(CONSOLE_WHT, stdout);
    fputs("[", stdout);
    fputs(logging::get_time(), stdout);
    fputs("] ", stdout);
    va_start(args, format);
    vfprintf(stdout, format, args);
    va_end(args);
    fputs(CONSOLE_RST, stdout);
}

/// @brief Prints a warning message.
inline void warning(const char *format, ...)
{
    va_list args;
    fputs(CONSOLE_YEL, stdout);
    fputs("[", stdout);
    fputs(logging::get_time(), stdout);
    fputs("] ", stdout);
    va_start(args, format);
    vfprintf(stdout, format, args);
    va_end(args);
    fputs(CONSOLE_RST, stdout);
}

/// @brief Prints an error message.
inline void error(const char *format, ...)
{
    va_list args;
    fputs(CONSOLE_RED, stderr);
    fputs("[", stdout);
    fputs(logging::get_time(), stdout);
    fputs("] ", stdout);
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    fputs(CONSOLE_RST, stderr);
}

} // namespace logging

namespace detail
{

/// @brief Returns the last error.
inline int getLastError()
{
#if defined(_WIN32) || defined(__CYGWIN__)
    return WSAGetLastError();
#else
    return errno;
#endif // defined(_WIN32) || defined(__CYGWIN__)
}

/// @brief Returns the string representing the error.
inline const char *getLastErrorStr(int error)
{
#ifdef _WIN32
    char *s = 0;
    ::FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, error, 0, (LPSTR)&s, 0, NULL);
    if (s) {
        ret = s;
        ::LocalFree(s);
    }
    return s;
#else
    return strerror(error);
#endif
}

} // namespace detail

/// @brief Represents a request error.
class RequestError : public std::logic_error {
public:
    /// @brief Construct a new request error.
    RequestError(const std::string &__arg)
        : std::logic_error::logic_error(__arg)
    {
        // Nothing to do.
    }
};

/// @brief Represents a response error.
class ResponseError : public std::runtime_error {
public:
    /// @brief Construct a new response error.
    ResponseError(const std::string &__arg)
        : std::runtime_error(__arg)
    {
        // Nothing to do.
    }
};

/// @brief Represents a system error.
class SystemError : public std::runtime_error {
public:
    /// @brief Construct a new system error.
    SystemError(int _error, const std::string &__arg)
        : std::runtime_error(__arg + " : " + detail::getLastErrorStr(_error))
    {
        // Nothing to do.
    }

    /// @brief Construct a new system error.
    SystemError(const std::string &_error, const std::string &__arg)
        : std::runtime_error(__arg + " : " + _error)
    {
        // Nothing to do.
    }
};

/// @brief Internet protocol.
struct InternetProtocol {
    /// @brief The internet protocol versions.
    enum Enum {
        V4, ///< Internet Protocol Version 4 (IPv4).
        V6  ///< Internet Protocol Version 6 (IPv6).
    };
    /// @brief The stored internet protocol version.
    Enum value;

    /// @brief Construct a new internet protocol object.
    /// @param _value the intialization value.
    InternetProtocol(Enum _value)
        : value(_value)
    {
        // Nothing to do.
    }

    /// @brief Checks equality between internet protocols.
    inline bool operator==(Enum _value) const
    {
        return value == _value;
    }

    /// @brief Returns the address family based on the internet protocol version.
    inline int getAddressFamily() const
    {
        if (value == InternetProtocol::V4)
            return AF_INET;
        if (value == InternetProtocol::V6)
            return AF_INET6;
        throw RequestError("Unsupported protocol");
    }
};

/// @brief Uniform Resource Identifier (URI).
/// @details
/// `URI = scheme ":" ["//" authority] path ["?" query] ["#" fragment]`
/// `authority = [userinfo "@"] host [":" port]`
struct Uri {
    /// @brief A non-empty scheme component followed by a colon (:).
    std::string scheme;
    /// @brief An optional authority component.
    struct {
        /// The *user* attribute of the userinfo.
        std::string user;
        /// The *password* attribute of the userinfo.
        std::string password;
        /// Can be either a registered name (including but not limited to a hostname) or an IP address.
        std::string host;
        /// The optional port.
        std::string port;
    } authority;
    /// A path consists of a sequence of path segments separated by a slash.
    std::string path;
    /// A query string of non-hierarchical data preceded by a question mark.
    std::string query;
    /// Fragment identifier providing direction to a secondary resource.
    std::string fragment;
};

/// @brief Stores an HTTP version.
struct HttpVersion {
    /// Major identifier.
    uint16_t ver_major;
    /// Minor identifier.
    uint16_t ver_minor;

    HttpVersion()
        : ver_major(),
          ver_minor()
    {
        // Nothing to do.
    }

    /// @brief Construct a new Http Version object based on input _ver_major and _ver_minor versions.
    HttpVersion(uint16_t _ver_major, uint16_t _ver_minor)
        : ver_major(_ver_major),
          ver_minor(_ver_minor)
    {
        // Nothing to do.
    }
};

/// @brief HTTP status information.
struct Status {
    /// RFC 7231, 6. Response Status Codes.
    enum Code {
        Continue          = 100,
        SwitchingProtocol = 101,
        Processing        = 102,
        EarlyHints        = 103,

        Ok                          = 200,
        Created                     = 201,
        Accepted                    = 202,
        NonAuthoritativeInformation = 203,
        NoContent                   = 204,
        ResetContent                = 205,
        PartialContent              = 206,
        MultiStatus                 = 207,
        AlreadyReported             = 208,
        ImUsed                      = 226,

        MultipleChoice    = 300,
        MovedPermanently  = 301,
        Found             = 302,
        SeeOther          = 303,
        NotModified       = 304,
        UseProxy          = 305,
        TemporaryRedirect = 307,
        PermanentRedirect = 308,

        BadRequest                  = 400,
        Unauthorized                = 401,
        PaymentRequired             = 402,
        Forbidden                   = 403,
        NotFound                    = 404,
        MethodNotAllowed            = 405,
        NotAcceptable               = 406,
        ProxyAuthenticationRequired = 407,
        RequestTimeout              = 408,
        Conflict                    = 409,
        Gone                        = 410,
        LengthRequired              = 411,
        PreconditionFailed          = 412,
        PayloadTooLarge             = 413,
        UriTooLong                  = 414,
        UnsupportedMediaType        = 415,
        RangeNotSatisfiable         = 416,
        ExpectationFailed           = 417,
        MisdirectedRequest          = 421,
        UnprocessableEntity         = 422,
        Locked                      = 423,
        FailedDependency            = 424,
        TooEarly                    = 425,
        UpgradeRequired             = 426,
        PreconditionRequired        = 428,
        TooManyRequests             = 429,
        RequestHeaderFieldsTooLarge = 431,
        UnavailableForLegalReasons  = 451,

        InternalServerError           = 500,
        NotImplemented                = 501,
        BadGateway                    = 502,
        ServiceUnavailable            = 503,
        GatewayTimeout                = 504,
        HttpVersionNotSupported       = 505,
        VariantAlsoNegotiates         = 506,
        InsufficientStorage           = 507,
        LoopDetected                  = 508,
        NotExtended                   = 510,
        NetworkAuthenticationRequired = 511
    };
    /// The HTTP version.
    HttpVersion http_version;
    /// The Status-Code element is a 3-digit integer result code of the attempt to understand and satisfy the request.
    uint16_t status_code;
    /// The Reason-Phrase is intended to give a short textual description of the Status-Code.
    std::string reason_phrase;

    Status()
        : http_version(),
          status_code(),
          reason_phrase()
    {
        // Nothing to do.
    }

    /// @brief Construct a new Status object.
    Status(HttpVersion _http_version, uint16_t _status_code, std::string _reason_phrase)
        : http_version(_http_version),
          status_code(_status_code),
          reason_phrase(_reason_phrase)
    {
        // Nothing to do.
    }
};

typedef std::vector<uint8_t> Data;
typedef std::vector<uint8_t>::iterator Iterator;
/// Stores a field of the header.
typedef std::pair<std::string, std::string> HeaderField;
/// Stores the list of fields inside a header.
typedef std::vector<HeaderField> HeaderFields;

/// @brief The structure of an HTTP response.
struct Response {
    /// The HTTP status of the response.
    Status status;
    /// The list of fields inside a header.
    HeaderFields header_fields;
    /// The body of the response.
    Data body;
};

namespace tls
{

inline const char *get_strerror(int err)
{
    static char error_text[256];
    mbedtls_strerror(err, error_text, sizeof(error_text));
    return error_text;
}

inline void print_trace(void *, int level, const char *file, int line, const char *str)
{
    printf("ssl(%s:%04d) [%d] %s\n", file, line, level, str);
}

class SSLContext {
public:
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_x509_crt cacert;
    mbedtls_ssl_config conf;

    SSLContext()
        : entropy(),
          ctr_drbg(),
          ssl(),
          cacert(),
          conf()
    {
        mbedtls_entropy_init(&entropy);
        mbedtls_x509_crt_init(&cacert);
        mbedtls_ssl_init(&ssl);
        mbedtls_ctr_drbg_init(&ctr_drbg);
        mbedtls_ssl_config_init(&conf);
    }

    ~SSLContext()
    {
        mbedtls_entropy_free(&entropy);
        mbedtls_x509_crt_free(&cacert);
        mbedtls_ssl_free(&ssl);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_ssl_config_free(&conf);
    }

    void init(const std::string &certs)
    {
        const char *pers = "minihttp";
        int err_code;

        // The CTR_DRBG context to seed.
        err_code = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, reinterpret_cast<const unsigned char *>(pers), strlen(pers) + 1);
        if (err_code != 0)
            throw SystemError(tls::get_strerror(err_code), "Failed to call ctr_drbg_seed");

        // Parse the certificates and add them to the chained list.
        if (!certs.empty()) {
            err_code = mbedtls_x509_crt_parse(&cacert, reinterpret_cast<const unsigned char *>(certs.c_str()), certs.size());
            if (err_code != 0)
                throw SystemError(tls::get_strerror(err_code), "Failed to call x509_crt_parse");
        }

        err_code = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
        if (err_code != 0)
            throw SystemError(tls::get_strerror(err_code), "Failed to call ssl_config_defaults");

        mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
        mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);

        // Set minimum to TLS 3.1
        mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_1);

        mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
        mbedtls_ssl_conf_dbg(&conf, tls::print_trace, NULL);

        err_code = mbedtls_ssl_setup(&ssl, &conf);
        if (err_code != 0)
            throw SystemError(tls::get_strerror(err_code), "Failed to call ssl_setup");
    }

    void reset()
    {
        mbedtls_ssl_session_reset(&ssl);
    }
};

} // namespace tls

namespace detail
{

#if defined(_WIN32) || defined(__CYGWIN__)
class WinSock {
public:
    WinSock()
        : started()
    {
        WSADATA wsaData;
        const auto error = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (error != 0)
            throw SystemError(error, "WSAStartup failed");

        if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
            WSACleanup();
            throw std::runtime_error("Invalid WinSock version");
        }
        started = true;
    }

    ~WinSock()
    {
        if (started)
            WSACleanup();
    }

    WinSock(WinSock &&other)
        : started{ other.started }
    {
        other.started = false;
    }

    WinSock &operator=(WinSock &&other)
    {
        if (&other == this)
            return *this;
        if (started)
            WSACleanup();
        started       = other.started;
        other.started = false;
        return *this;
    }

private:
    bool started = false;
};
#endif // defined(_WIN32) || defined(__CYGWIN__)

class Socket {
public:
#if defined(_WIN32) || defined(__CYGWIN__)
    typedef SOCKET Type;
    static const Type invalid = INVALID_SOCKET;
#else
    typedef int Type;
    static const Type invalid = -1;
#endif // defined(_WIN32) || defined(__CYGWIN__)

    Socket()
        : endpoint(invalid),
          internet_protocol(InternetProtocol::V4),
          sslctx(),
          certs(),
          use_ssl()
    {
        // Nothing to do.
    }

    Socket(const InternetProtocol _internet_protocol)
        : endpoint(),
          internet_protocol(_internet_protocol),
          sslctx(),
          certs(),
          use_ssl()
    {
        // Nothing to do.
    }

    ~Socket()
    {
        if (endpoint != invalid)
            this->close();
    }

    Socket(Socket &other)
        : endpoint(other.endpoint),
          internet_protocol(other.internet_protocol),
          sslctx(other.sslctx),
          certs(other.certs),
          use_ssl(other.use_ssl)
    {
        other.endpoint = invalid;
    }

    Socket &operator=(Socket &other)
    {
        if (&other == this)
            return *this;
        if (endpoint != invalid)
            this->close();
        endpoint          = other.endpoint;
        internet_protocol = other.internet_protocol;
        sslctx            = other.sslctx;
        certs             = other.certs;
        use_ssl           = other.use_ssl;
        other.endpoint    = invalid;
        return *this;
    }

    inline void setCerts(const std::string &_certs)
    {
        certs = _certs;
    }

    void connect(const Uri &uri, const struct sockaddr *address, const socklen_t addressSize, const int64_t timeout)
    {
        int err_code;
        if (uri.scheme == "http") {
            use_ssl = false;
        } else if (uri.scheme == "https") {
            use_ssl = true;
        } else {
            throw std::runtime_error("Unsupported scheme");
        }

#ifdef __APPLE__
        const int value = 1;
        if (setsockopt(endpoint, SOL_SOCKET, SO_NOSIGPIPE, &value, sizeof(value)) == -1) {
            this->close();
            throw SystemError(detail::getLastError(), "Failed to set socket option");
        }
#endif // __APPLE__

        if (use_ssl) {
            // Initialize a context.
            mbedtls_net_init((mbedtls_net_context *)&endpoint);

            sslctx.init(certs);

            //  Initiate a connection with host:port in the given protocol.
            err_code = mbedtls_net_connect(
                reinterpret_cast<mbedtls_net_context *>(&endpoint),
                uri.authority.host.c_str(), uri.authority.port.c_str(), MBEDTLS_NET_PROTO_TCP);
            if (err_code != 0)
                throw SystemError(tls::get_strerror(err_code), "Failed to create SSL socket");

            mbedtls_ssl_set_bio(&sslctx.ssl, (mbedtls_net_context *)&endpoint, mbedtls_net_send, mbedtls_net_recv, NULL);

            // Perform the SSL handshake.
            do {
                err_code = mbedtls_ssl_handshake(&sslctx.ssl);
            } while ((err_code != 0) && ((err_code == MBEDTLS_ERR_SSL_WANT_READ) || (err_code == MBEDTLS_ERR_SSL_WANT_WRITE)));

            if (err_code != 0)
                throw SystemError(tls::get_strerror(err_code), "Failed to call ssl_handshake");
        } else {
            // Open the endpoint.
            endpoint = socket(internet_protocol.getAddressFamily(), SOCK_STREAM, IPPROTO_TCP);

#if defined(_WIN32) || defined(__CYGWIN__)
            // Connect.
            do {
                err_code = ::connect(endpoint, address, addressSize);
            } while (err_code == -1 && WSAGetLastError() == WSAEINTR);
            // Check if we successfully connected.
            if (err_code == -1) {
                if (WSAGetLastError() == WSAEWOULDBLOCK) {
                    this->select(SelectType::write, timeout);
                    char socketErrorPointer[sizeof(int)];
                    socklen_t optionLength = sizeof(socketErrorPointer);
                    if (getsockopt(endpoint, SOL_SOCKET, SO_ERROR, socketErrorPointer, &optionLength) == -1)
                        throw SystemError(detail::getLastError(), "Failed to get socket option");
                    int socketError;
                    std::memcpy(&socketError, socketErrorPointer, sizeof(socketErrorPointer));
                    if (socketError != 0)
                        throw SystemError(socketError, "Failed to connect");
                } else {
                    throw SystemError(detail::getLastError(), "Failed to connect");
                }
            }
#else
            // Connect.
            do {
                err_code = ::connect(endpoint, address, addressSize);
            } while ((err_code == -1) && (errno == EINTR));
            // Check if we successfully connected.
            if (err_code == -1) {
                if (errno == EINPROGRESS) {
                    this->select(SelectType::write, timeout);
                    int socketError;
                    socklen_t optionLength = sizeof(socketError);
                    if (getsockopt(endpoint, SOL_SOCKET, SO_ERROR, &socketError, &optionLength) == -1)
                        throw SystemError(errno, "Failed to get socket option");
                    if (socketError != 0)
                        throw SystemError(socketError, "Failed to connect (getsockopt)");
                } else {
                    throw SystemError(errno, "Failed to connect");
                }
            }
#endif // defined(_WIN32) || defined(__CYGWIN__)
            if (endpoint == invalid)
                throw SystemError(detail::getLastError(), "Failed to create socket");
        }

        // ====================================================================
        // NON-BLOCKING
        // ====================================================================
        if (use_ssl) {
            // Set the socket non - blocking.
            err_code = mbedtls_net_set_nonblock((mbedtls_net_context *)&endpoint);
            if (err_code != 0) {
                this->close();
                throw SystemError(detail::getLastError(), "Failed to set socket non-blocking");
            }
        } else {
#if defined(_WIN32) || defined(__CYGWIN__)
            ULONG tmp = !!nonblock;
            if (::ioctlsocket(s, FIONBIO, &tmp) == SOCKET_ERROR) {
                this->close();
                throw SystemError(detail::getLastError(), "Failed to set socket non-blocking");
            }
#else
            int flags;
            if ((flags = ::fcntl(endpoint, F_GETFL)) < 0) {
                this->close();
                throw SystemError(detail::getLastError(), "Failed to set socket non-blocking");
            }
            if (::fcntl(endpoint, F_SETFL, flags | O_NONBLOCK) == -1) {
                this->close();
                throw SystemError(detail::getLastError(), "Failed to set socket non-blocking");
            }
#endif // defined(_WIN32) || defined(__CYGWIN__)
        }

        // ====================================================================
        // TIMEOUT
        // ====================================================================
        if (timeout > 0) {
            struct timeval timeval_timeout;
            timeval_timeout.tv_sec  = static_cast<time_t>(timeout / 1000);
            timeval_timeout.tv_usec = static_cast<suseconds_t>((timeout % 1000) * 1000);
            if (setsockopt(endpoint, SOL_SOCKET, SO_RCVTIMEO, &timeval_timeout, sizeof(timeval_timeout)) < 0)
                throw SystemError(errno, "Failed to set RCV timeout");
            if (setsockopt(endpoint, SOL_SOCKET, SO_SNDTIMEO, &timeval_timeout, sizeof(timeval_timeout)) < 0)
                throw SystemError(errno, "Failed to set SND timeout");
        }
    }

    std::size_t send(const void *buffer, const std::size_t length, const int64_t timeout)
    {
        ssize_t result;
        if (use_ssl) {
            do {
                result = mbedtls_ssl_write(&sslctx.ssl, reinterpret_cast<const unsigned char *>(buffer), length);
            } while (result == MBEDTLS_ERR_SSL_WANT_WRITE);
        } else {
            this->select(SelectType::write, timeout);
#if defined(_WIN32) || defined(__CYGWIN__)
            do {
                result = ::send(endpoint, reinterpret_cast<const char *>(buffer), static_cast<int>(length), 0);
            } while ((result == -1) && (detail::getLastError() == WSAEINTR));
#else
            do {
                result = ::send(endpoint, reinterpret_cast<const char *>(buffer), length, noSignal);
            } while ((result == -1) && (detail::getLastError() == EINTR));
#endif // defined(_WIN32) || defined(__CYGWIN__)
        }
        if (result < 0) {
            this->close();
            if (use_ssl) {
                throw SystemError(tls::get_strerror(static_cast<int>(result)), "Failed to send data");
            } else {
                throw SystemError(detail::getLastError(), "Failed to send data");
            }
        }
        return static_cast<std::size_t>(result);
    }

    std::size_t recv(void *buffer, const std::size_t length, const int64_t timeout)
    {
        ssize_t result;
        if (use_ssl) {
            do {
                result = mbedtls_ssl_read(&sslctx.ssl, reinterpret_cast<unsigned char *>(buffer), length);
            } while (result == MBEDTLS_ERR_SSL_WANT_READ);
        } else {
            this->select(SelectType::read, timeout);
#if defined(_WIN32) || defined(__CYGWIN__)
            do {
                result = ::recv(endpoint, reinterpret_cast<char *>(buffer), static_cast<int>(length), 0);
            } while (result == -1 && WSAGetLastError() == WSAEINTR);
#else
            do {
                result = ::recv(endpoint, reinterpret_cast<char *>(buffer), length, noSignal);
            } while ((result == -1) && (detail::getLastError() == EINTR));
#endif // defined(_WIN32) || defined(__CYGWIN__)
        }
        if (result < 0) {
            switch (result) {
            case EWOULDBLOCK:
#if defined(EAGAIN) && (EWOULDBLOCK != EAGAIN)
            case EAGAIN: // linux man pages say this can also happen instead of EWOULDBLOCK
#endif
                return 0;
            case ECONNRESET:
            case ENOTCONN:
            case ETIMEDOUT:
#ifdef _WIN32
            case WSAECONNABORTED:
            case WSAESHUTDOWN:
#endif
            default:
                this->close();
                if (use_ssl) {
                    throw SystemError(tls::get_strerror(static_cast<int>(result)), "Failed to read data");
                } else {
                    throw SystemError(detail::getLastError(), "Failed to read data");
                }
            }
        }
        return static_cast<std::size_t>(result);
    }

private:
    struct SelectType {
        enum Enum {
            read,
            write
        } value;
        SelectType(Enum _value)
            : value(_value)
        {
        }
        inline bool operator==(Enum _value) const
        {
            return value == _value;
        }
    };

    void select(const SelectType type, const int64_t timeout)
    {
        fd_set descriptorSet;
        FD_ZERO(&descriptorSet);
        FD_SET(endpoint, &descriptorSet);
        int count;

#if defined(_WIN32) || defined(__CYGWIN__)
        TIMEVAL select_timeout{
            static_cast<LONG>(timeout / 1000),
            static_cast<LONG>((timeout % 1000) * 1000)
        };
        do {
            count = ::select(0,
                             (type == SelectType::read) ? &descriptorSet : NULL,
                             (type == SelectType::write) ? &descriptorSet : NULL,
                             NULL,
                             (timeout >= 0) ? &select_timeout : NULL);
        } while ((count == -1) && (WSAGetLastError() == WSAEINTR));
        if (count == -1) {
            this->close();
            throw SystemError(detail::getLastError(), "Failed to select socket");
        }
        if (count == 0) {
            this->close();
            throw ResponseError("Request timed out");
        }
#else
        timeval select_timeout;
        select_timeout.tv_sec  = static_cast<time_t>(timeout / 1000);
        select_timeout.tv_usec = static_cast<suseconds_t>((timeout % 1000) * 1000);
        do {
            count = ::select(endpoint + 1,
                             (type == SelectType::read) ? &descriptorSet : NULL,
                             (type == SelectType::write) ? &descriptorSet : NULL,
                             NULL,
                             (timeout >= 0) ? &select_timeout : NULL);
        } while ((count == -1) && (errno == EINTR));
        if (count == -1) {
            this->close();
            throw SystemError(detail::getLastError(), "Failed to select socket");
        }
        if (count == 0) {
            this->close();
            throw ResponseError("Request timed out");
        }
#endif // defined(_WIN32) || defined(__CYGWIN__)
    }

    void close()
    {
        if (use_ssl) {
            sslctx.reset();
            mbedtls_net_free((mbedtls_net_context *)&endpoint);
        } else {
#if defined(_WIN32) || defined(__CYGWIN__)
            closesocket(endpoint);
#else
            ::close(endpoint);
#endif // defined(_WIN32) || defined(__CYGWIN__)
        }
    }

#if defined(__unix__) && !defined(__APPLE__) && !defined(__CYGWIN__)
    static const int noSignal = MSG_NOSIGNAL;
#else
    static const int noSignal = 0;
#endif // defined(__unix__) && !defined(__APPLE__)

    Type endpoint;
    InternetProtocol internet_protocol;
    tls::SSLContext sslctx;
    std::string certs;
    bool use_ssl;
};

// RFC 7230, 3.2.3. WhiteSpace
template <typename C>
inline bool isWhiteSpaceChar(const C c)
{
    return c == 0x20 || c == 0x09; // space or tab
}

// RFC 7230, 3.2.3. WhiteSpace
template <typename C>
inline bool isNotWhiteSpaceChar(const C c)
{
    return !isWhiteSpaceChar(c);
}

// RFC 5234, Appendix B.1. Core Rules
template <typename C>
inline bool isDigitChar(const C c)
{
    return c >= 0x30 && c <= 0x39; // 0 - 9
}

// RFC 5234, Appendix B.1. Core Rules
template <typename C>
inline bool isAlphaChar(const C c)
{
    return (c >= 0x61 && c <= 0x7A) || // a - z
           (c >= 0x41 && c <= 0x5A);   // A - Z
}

// RFC 7230, 3.2.6. Field Value Components
template <typename C>
inline bool isTokenChar(const C c)
{
    return c == 0x21 || // !
           c == 0x23 || // #
           c == 0x24 || // $
           c == 0x25 || // %
           c == 0x26 || // &
           c == 0x27 || // '
           c == 0x2A || // *
           c == 0x2B || // +
           c == 0x2D || // -
           c == 0x2E || // .
           c == 0x5E || // ^
           c == 0x5F || // _
           c == 0x60 || // `
           c == 0x7C || // |
           c == 0x7E || // ~
           isDigitChar(c) ||
           isAlphaChar(c);
}

// RFC 5234, Appendix B.1. Core Rules
template <typename C>
inline bool isVisibleChar(const C c)
{
    return c >= 0x21 && c <= 0x7E;
}

// RFC 7230, Appendix B. Collected ABNF
template <typename C>
inline bool isObsoleteTextChar(const C c)
{
    return static_cast<unsigned char>(c) >= 0x80 &&
           static_cast<unsigned char>(c) <= 0xFF;
}

inline Iterator skipWhiteSpaces(const Iterator begin, const Iterator end)
{
    Iterator it = begin;
    for (it = begin; it != end; ++it)
        if (!isWhiteSpaceChar(*it))
            break;
    return it;
}

// RFC 5234, Appendix B.1. Core Rules
template <typename T, typename C>
inline T digitToUint(const C c)
{
    // DIGIT (0 - 9)
    return (c >= 0x30 && c <= 0x39) ? static_cast<T>(c - 0x30) : throw ResponseError("Invalid digit");
}

template <typename T>
inline std::string numberToString(T Number)
{
    std::ostringstream ss;
    ss << Number;
    return ss.str();
}

// RFC 5234, Appendix B.1. Core Rules
template <typename T, typename C>
inline T hexDigitToUint(const C c)
{
    if (c >= 0x30 && c <= 0x39)
        return static_cast<T>(c - 0x30); // 0 - 9
    if (c >= 0x41 && c <= 0x46)
        return static_cast<T>(c - 0x41) + T(10); // A - Z
    if (c >= 0x61 && c <= 0x66)
        return static_cast<T>(c - 0x61) + T(10); // a - z, some services send lower-case hex digits
    throw ResponseError("Invalid hex digit");
}

inline char toLower(const char c)
{
    return (c >= 'A' && c <= 'Z') ? c - ('A' - 'a') : c;
}

inline std::string &strToLower(std::string &s)
{
    std::transform(s.begin(), s.end(), s.begin(), detail::toLower);
    return s;
}

// trim from start
inline std::string &ltrim(std::string &s)
{
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), std::not1(std::ptr_fun<int, int>(std::isspace))));
    return s;
}

// trim from end
inline std::string &rtrim(std::string &s)
{
    s.erase(std::find_if(s.rbegin(), s.rend(), std::not1(std::ptr_fun<int, int>(std::isspace))).base(), s.end());
    return s;
}

// trim from both ends
inline std::string &trim(std::string &s)
{
    return detail::ltrim(detail::rtrim(s));
}

/// @brief Searches the header field with the given name.
/// @param header_fields the list of fields.
/// @param field_name the name we are looking for.
/// @return an iterator to the field, if one is found.
inline HeaderFields::iterator findField(HeaderFields &header_fields, const std::string &field_name)
{
    HeaderFields::iterator field;
    for (field = header_fields.begin(); field != header_fields.end(); ++field)
        if (field->first == field_name)
            break;
    return field;
}

// RFC 3986, 3. Syntax Components
Uri parseUri(const std::string::const_iterator begin, const std::string::const_iterator end)
{
    Uri result;

    // RFC 3986, 3.1. Scheme
    std::string::const_iterator it = begin;
    if (it == end || !isAlphaChar(*begin))
        throw RequestError("Invalid scheme");

    result.scheme.push_back(*it++);

    for (; it != end && (isAlphaChar(*it) || isDigitChar(*it) || *it == '+' || *it == '-' || *it == '.'); ++it)
        result.scheme.push_back(*it);

    if (it == end || *it++ != ':')
        throw RequestError("Invalid scheme");
    if (it == end || *it++ != '/')
        throw RequestError("Invalid scheme");
    if (it == end || *it++ != '/')
        throw RequestError("Invalid scheme");

    // RFC 3986, 3.2. Authority
    std::string authority = std::string(it, end);

    // RFC 3986, 3.5. Fragment
    const std::string::size_type fragmentPosition = authority.find('#');
    if (fragmentPosition != std::string::npos) {
        result.fragment = authority.substr(fragmentPosition + 1);
        authority.resize(fragmentPosition); // remove the fragment part
    }

    // RFC 3986, 3.4. Query
    const std::string::size_type queryPosition = authority.find('?');
    if (queryPosition != std::string::npos) {
        result.query = authority.substr(queryPosition + 1);
        authority.resize(queryPosition); // remove the query part
    }

    // RFC 3986, 3.3. Path
    const std::string::size_type pathPosition = authority.find('/');
    if (pathPosition != std::string::npos) {
        // RFC 3986, 3.3. Path
        result.path = authority.substr(pathPosition);
        authority.resize(pathPosition);
    } else
        result.path = "/";

    // RFC 3986, 3.2.1. User Information
    std::string userinfo;
    const std::string::size_type hostPosition = authority.find('@');
    if (hostPosition != std::string::npos) {
        userinfo = authority.substr(0, hostPosition);

        const std::string::size_type passwordPosition = userinfo.find(':');
        if (passwordPosition != std::string::npos) {
            result.authority.user     = userinfo.substr(0, passwordPosition);
            result.authority.password = userinfo.substr(passwordPosition + 1);
        } else
            result.authority.user = userinfo;

        result.authority.host = authority.substr(hostPosition + 1);
    } else
        result.authority.host = authority;

    // RFC 3986, 3.2.2. Host
    const std::string::size_type portPosition = result.authority.host.find(':');
    if (portPosition != std::string::npos) {
        // RFC 3986, 3.2.3. Port
        result.authority.port = result.authority.host.substr(portPosition + 1);
        result.authority.host.resize(portPosition);
    } else if (result.scheme == "http") {
        result.authority.port = "80";
    } else if (result.scheme == "https") {
        result.authority.port = "443";
    }
    return result;
}

// RFC 7230, 2.6. Protocol Versioning

std::pair<Iterator, HttpVersion> parseHttpVersion(const Iterator begin, const Iterator end)
{
    Iterator it = begin;
    if (it == end || *it++ != 'H')
        throw ResponseError("Invalid HTTP version");
    if (it == end || *it++ != 'T')
        throw ResponseError("Invalid HTTP version");
    if (it == end || *it++ != 'T')
        throw ResponseError("Invalid HTTP version");
    if (it == end || *it++ != 'P')
        throw ResponseError("Invalid HTTP version");
    if (it == end || *it++ != '/')
        throw ResponseError("Invalid HTTP version");
    if (it == end)
        throw ResponseError("Invalid HTTP version");
    const uint16_t majorVersion = detail::digitToUint<uint16_t>(*it++);
    if (it == end || *it++ != '.')
        throw ResponseError("Invalid HTTP version");
    if (it == end)
        throw ResponseError("Invalid HTTP version");
    const uint16_t minorVersion = detail::digitToUint<uint16_t>(*it++);
    return std::make_pair(it, HttpVersion(majorVersion, minorVersion));
}

// RFC 7230, 3.1.2. Status Line

std::pair<Iterator, uint16_t> parseStatusCode(const Iterator begin, const Iterator end)
{
    uint16_t result = 0;
    Iterator it     = begin;
    while (it != end && isDigitChar(*it))
        result = static_cast<uint16_t>(result * 10U) + digitToUint<uint16_t>(*it++);
    if (std::distance(begin, it) != 3)
        throw ResponseError("Invalid status code");
    return std::make_pair(it, result);
}

// RFC 7230, 3.1.2. Status Line

std::pair<Iterator, std::string> parseReasonPhrase(const Iterator begin, const Iterator end)
{
    std::string result;
    Iterator it = begin;
    for (; it != end && (isWhiteSpaceChar(*it) || isVisibleChar(*it) || isObsoleteTextChar(*it)); ++it)
        result.push_back(static_cast<char>(*it));
    return std::make_pair(it, result);
}

// RFC 7230, 3.2.6. Field Value Components

std::pair<Iterator, std::string> parseToken(const Iterator begin, const Iterator end)
{
    std::string result;
    Iterator it = begin;
    for (; it != end && isTokenChar(*it); ++it)
        result.push_back(static_cast<char>(*it));
    if (result.empty())
        throw ResponseError("Invalid token");
    return std::make_pair(it, result);
}

// RFC 7230, 3.2. Header Fields

inline std::pair<Iterator, std::string> parseFieldValue(const Iterator begin, const Iterator end)
{
    std::string result;
    Iterator it = begin;
    for (; it != end && (detail::isWhiteSpaceChar(*it) || detail::isVisibleChar(*it) || detail::isObsoleteTextChar(*it)); ++it)
        result.push_back(static_cast<char>(*it));
    // Trim white spaces.
    return std::make_pair(it, trim(result));
}

// RFC 7230, 3.2. Header Fields

inline std::pair<Iterator, std::string> parseFieldContent(const Iterator begin, const Iterator end)
{
    std::pair<Iterator, std::string> field_value;
    Iterator it = begin, obsolete_fold_it;
    std::string result;
    for (;;) {
        field_value = detail::parseFieldValue(it, end);
        it          = field_value.first;
        result += field_value.second;
        // Handle obsolete fold as per RFC 7230, 3.2.4. Field Parsing
        // Obsolete folding is known as linear white space (LWS) in RFC 2616, 2.2 Basic Rules
        obsolete_fold_it = it;
        if (obsolete_fold_it == end || *obsolete_fold_it++ != '\r')
            break;
        if (obsolete_fold_it == end || *obsolete_fold_it++ != '\n')
            break;
        if (obsolete_fold_it == end || !isWhiteSpaceChar(*obsolete_fold_it++))
            break;
        result.push_back(' ');
        it = obsolete_fold_it;
    }
    return std::make_pair(it, result);
}

// RFC 7230, 3.2. Header Fields

std::pair<Iterator, HeaderField> parseHeaderField(const Iterator begin, const Iterator end)
{
    std::pair<Iterator, std::string> tokenResult = detail::parseToken(begin, end);
    Iterator it                                  = tokenResult.first;
    std::string field_name                       = tokenResult.second;

    if ((it == end) || *it++ != ':')
        throw ResponseError("Invalid header field = " + field_name);

    it = skipWhiteSpaces(it, end);

    std::pair<Iterator, std::string> valueResult = detail::parseFieldContent(it, end);
    it                                           = valueResult.first;
    std::string field_value                      = valueResult.second;

    if ((it == end) || *it++ != '\r')
        throw ResponseError("Invalid header field (missing \\r) = " + field_name + ":" + field_value);
    if ((it == end) || *it++ != '\n')
        throw ResponseError("Invalid header field (missing \\n) = " + field_name + ":" + field_value);

    // Transform the field name to lower-case letters.
    detail::strToLower(field_name);

    // Return the field name and value.
    return std::make_pair(it, HeaderField(field_name, field_value));
}

// RFC 7230, 3.1.2. Status Line

std::pair<Iterator, Status> parseStatusLine(const Iterator begin, const Iterator end)
{
    std::pair<Iterator, HttpVersion> http_version;
    std::pair<Iterator, uint16_t> status_code;
    std::pair<Iterator, std::string> reason_phrase;
    Iterator it = begin;
    // Read the http version.
    http_version = detail::parseHttpVersion(it, end);
    it           = http_version.first;
    if ((it == end) || (*it++ != ' '))
        throw ResponseError("Invalid status line");
    // Read the status code.
    status_code = detail::parseStatusCode(it, end);
    it          = status_code.first;
    if ((it == end) || (*it++ != ' '))
        throw ResponseError("Invalid status line");
    // Read the reason phrase.
    reason_phrase = detail::parseReasonPhrase(it, end);
    it            = reason_phrase.first;
    if (it == end || *it++ != '\r')
        throw ResponseError("Invalid status line");
    if (it == end || *it++ != '\n')
        throw ResponseError("Invalid status line");
    return std::make_pair(it, Status(http_version.second, status_code.second, reason_phrase.second));
}

// RFC 7230, 4.1. Chunked Transfer Coding
template <typename T, class Iterator>
T stringToUint(const Iterator begin, const Iterator end)
{
    T result = 0;
    for (Iterator it = begin; it != end; ++it)
        result = T(10U) * result + digitToUint<T>(*it);
    return result;
}

template <typename T, class Iterator>
T hexStringToUint(const Iterator begin, const Iterator end)
{
    T result = 0;
    for (Iterator it = begin; it != end; ++it)
        result = static_cast<T>(16 * result) + detail::hexDigitToUint<T>(*it);
    return result;
}

// RFC 7230, 3.1.1. Request Line
inline std::string encodeRequestLine(const std::string &method, const std::string &target)
{
    return method + " " + target + " HTTP/1.1\r\n";
}

// RFC 7230, 3.2. Header Fields
inline std::string encodeHeaderFields(const HeaderFields &header_fields)
{
    std::string result;
    for (HeaderFields::const_iterator field = header_fields.begin(); field != header_fields.end(); ++field) {
        if (field->first.empty())
            throw RequestError("Invalid header field name");
        for (std::string::const_iterator c = field->first.begin(); c != field->first.end(); ++c)
            if (!isTokenChar(*c))
                throw RequestError("Invalid header field name");
        for (std::string::const_iterator c = field->second.begin(); c != field->second.end(); ++c)
            if (!isWhiteSpaceChar(*c) && !isVisibleChar(*c) && !isObsoleteTextChar(*c))
                throw RequestError("Invalid header field value");
        result += field->first + ": " + field->second + "\r\n";
    }
    return result;
}

// RFC 4648, 4. Base 64 Encoding

std::string encodeBase64(const std::string::const_iterator begin, const std::string::const_iterator end)
{
    char chars[64] = {
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
        'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
        'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
    };

    std::string result;
    std::size_t c = 0;
    uint8_t charArray[3];

    for (std::string::const_iterator it = begin; it != end; ++it) {
        charArray[c++] = static_cast<uint8_t>(*it);
        if (c == 3) {
            result += chars[static_cast<uint8_t>((charArray[0] & 0xFC) >> 2)];
            result += chars[static_cast<uint8_t>(((charArray[0] & 0x03) << 4) + ((charArray[1] & 0xF0) >> 4))];
            result += chars[static_cast<uint8_t>(((charArray[1] & 0x0F) << 2) + ((charArray[2] & 0xC0) >> 6))];
            result += chars[static_cast<uint8_t>(charArray[2] & 0x3f)];
            c = 0;
        }
    }

    if (c) {
        result += chars[static_cast<uint8_t>((charArray[0] & 0xFC) >> 2)];

        if (c == 1)
            result += chars[static_cast<uint8_t>((charArray[0] & 0x03) << 4)];
        else // c == 2
        {
            result += chars[static_cast<uint8_t>(((charArray[0] & 0x03) << 4) + ((charArray[1] & 0xF0) >> 4))];
            result += chars[static_cast<uint8_t>((charArray[1] & 0x0F) << 2)];
        }

        while (++c < 4) result += '='; // padding
    }

    return result;
}

inline Data encodeHtml(const Uri &uri,
                       const std::string &method,
                       const Data &body,
                       HeaderFields header_fields)
{
    //if (uri.scheme != "http")
    //    throw RequestError("Only HTTP scheme is supported");

    // RFC 7230, 5.3. Request Target
    const std::string requestTarget = uri.path + (uri.query.empty() ? "" : '?' + uri.query);

    // RFC 7230, 5.4. Host
    header_fields.push_back(HeaderField("Host", uri.authority.host));

    // RFC 7230, 3.3.2. Content-Length
    header_fields.push_back(HeaderField("Content-Length", detail::numberToString(body.size())));

    // RFC 7617, 2. The 'Basic' Authentication Scheme
    if (!uri.authority.user.empty() || !uri.authority.password.empty()) {
        std::string userinfo = uri.authority.user + ':' + uri.authority.password;
        header_fields.push_back(HeaderField("Authorization", "Basic " + detail::encodeBase64(userinfo.begin(), userinfo.end())));
    }

    const std::string headerData = detail::encodeRequestLine(method, requestTarget) +
                                   detail::encodeHeaderFields(header_fields) +
                                   "\r\n";

    Data result(headerData.begin(), headerData.end());
    result.insert(result.end(), body.begin(), body.end());
    result.push_back(0);

    return result;
}

time_t getTimeNowMilliseconds()
{
    struct timeval time_now;
    gettimeofday(&time_now, NULL);
    return (time_now.tv_sec * 1000) + (time_now.tv_usec / 1000);
}

time_t getRemainingMilliseconds(const time_t time)
{
    const time_t remainingTime = (time - detail::getTimeNowMilliseconds());
    return (remainingTime > 0) ? remainingTime : 0;
}

} // namespace detail

class Request {
public:
    Request(const std::string &uriString,
            const InternetProtocol protocol = InternetProtocol::V4)
        : internet_protocol(protocol),
          uri(detail::parseUri(uriString.begin(), uriString.end()))
    {
    }

    Response send(const std::string &method         = "GET",
                  const std::string &body           = "",
                  const HeaderFields &header_fields = HeaderFields(),
                  const std::time_t timeout         = std::time_t(-1))
    {
        return this->send(
            method,
            Data(body.begin(), body.end()),
            header_fields,
            timeout);
    }

    Response send(const std::string &method,
                  const Data &body,
                  const HeaderFields &header_fields = HeaderFields(),
                  const std::time_t timeout         = std::time_t(-1))
    {
        const time_t stop_time = detail::getTimeNowMilliseconds() + timeout;
        ssize_t size;

        addrinfo hints    = {};
        hints.ai_family   = internet_protocol.getAddressFamily();
        hints.ai_socktype = SOCK_STREAM;
        // Translate name of a service location and/or a service name to set of socket addresses.
        addrinfo *_info;
        if (getaddrinfo(uri.authority.host.c_str(), uri.authority.port.c_str(), &hints, &_info) != 0)
            throw SystemError(detail::getLastError(), "Failed to get address info of " + uri.authority.host);
        // Make a copy and then free the other.
        addrinfo info = *_info;
        freeaddrinfo(_info);

        // Encode the request.
        const Data request_data = detail::encodeHtml(uri, method, body, header_fields);
        // Create the socket.
        detail::Socket socket(internet_protocol);
        // Take the first address from the list
        socket.connect(uri, info.ai_addr, info.ai_addrlen, (timeout >= 0) ? detail::getRemainingMilliseconds(stop_time) : -1);

        size_t remaining        = request_data.size();
        const uint8_t *sendData = request_data.data();

        // Send the request.
        logging::debug("Sending request...\n");
        while (remaining > 0) {
            logging::debug("REQUEST:\n%s\n", sendData);
            size = socket.send(sendData, remaining, (timeout >= 0) ? detail::getRemainingMilliseconds(stop_time) : -1);
            remaining -= size;
            sendData += size;
        }

        uint8_t buffer[BUFSIZ];
        Data crlf;
        crlf.push_back('\r');
        crlf.push_back('\n');
        Data header_end;
        header_end.push_back('\r');
        header_end.push_back('\n');
        header_end.push_back('\r');
        header_end.push_back('\n');

        Response response;
        Data response_data;
        bool parsing_header          = true;
        bool content_length_received = false;
        bool chunked_response        = false;
        bool remove_crlf_after_chunk = false;

        std::size_t expected_chunk_size = 0U;
        std::size_t content_length      = 0U;

        typedef Data::iterator Iterator;
        typedef std::pair<Iterator, Status> StatusLine;
        typedef std::pair<Iterator, HeaderField> HeaderFieldLine;

        Iterator begin_it, end_it, it;
        StatusLine status_line;
        HeaderFieldLine header_field_line;

        // read the response
        while (true) {
            size = socket.recv(buffer, sizeof(buffer), (timeout >= 0) ? detail::getRemainingMilliseconds(stop_time) : -1);
            logging::debug("We read %d bytes.\n", size);

            // Disconnected.
            if (size == 0) {
                logging::debug("Nothing to read\n");
                return response;
            }

            // Close the buffer.
            buffer[size] = 0;

            // Append the response.
            response_data.insert(response_data.end(), buffer, buffer + size);

            // We are still parsing the header.
            if (parsing_header) {
                // Save the beginning of the header.
                begin_it = response_data.begin();
                // RFC 7230, 3. Message Format
                // Empty line indicates the end of the header section (RFC 7230, 2.1. Client/Server Messaging)
                end_it = std::search(response_data.begin(), response_data.end(), header_end.begin(), header_end.end());

                // Cannot find the end of the header, keep reading.
                if (end_it == response_data.end()) {
                    continue;
                }
                // Include the first newline.
                end_it += 2;

                logging::debug("Parsig header...\n");

                // Parse the status line.
                status_line = detail::parseStatusLine(begin_it, end_it);
                // Get the iterator after the status line.
                it = status_line.first;
                // Save the status.
                response.status = status_line.second;

                for (;;) {
                    // Read the header field.
                    header_field_line = detail::parseHeaderField(it, end_it);
                    // Move the iterator after the field we just read.
                    it = header_field_line.first;
                    // Get the field name.
                    std::string field_name = header_field_line.second.first;
                    // Get the field value.
                    std::string field_value = header_field_line.second.second;
                    if (field_name == "transfer-encoding") {
                        // RFC 7230, 3.3.1. Transfer-Encoding
                        if (field_value == "chunked")
                            chunked_response = true;
                        else
                            throw ResponseError("Unsupported transfer encoding: " + field_value);
                    } else if (field_name == "content-length") {
                        // RFC 7230, 3.3.2. Content-Length
                        content_length          = detail::stringToUint<std::size_t>(field_value.begin(), field_value.end());
                        content_length_received = true;
                        response.body.reserve(content_length);
                        logging::debug("Reserving %d bytes for the body.\n", content_length);
                    }
                    response.header_fields.push_back(HeaderField(field_name, field_value));
                    if (it == end_it)
                        break;
                }
                // Include the second and last newline.
                end_it += 2;
                // Erease the header.
                response_data.erase(begin_it, end_it);
                // We finished parsing the header.
                parsing_header = false;

                logging::debug("Parsig body...\n");
            }

            if (!parsing_header) {
                // Content-Length must be ignored if Transfer-Encoding is received (RFC 7230, 3.2. Content-Length)
                if (chunked_response) {
                    logging::debug("Parsing chunked response...\n");
                    // RFC 7230, 4.1. Chunked Transfer Coding
                    for (;;) {
                        if (expected_chunk_size) {
                            // Get the amount of data that must be written.
                            const size_t to_write = std::min(expected_chunk_size, response_data.size());
                            // Save the beginning of the chunk.
                            begin_it = response_data.begin();
                            // Compute the end of the chunk.
                            end_it = response_data.begin() + static_cast<std::ptrdiff_t>(to_write);
                            // Insert the data inside the body.
                            response.body.insert(response.body.end(), begin_it, end_it);
                            // Clear the chunk from the response.
                            response_data.erase(begin_it, end_it);
                            // Decrease the chunk size.
                            expected_chunk_size -= to_write;
                            // If we have completely read the chunk, we must clear the CRLF after the chunk.
                            if (expected_chunk_size == 0)
                                remove_crlf_after_chunk = true;
                            // However, if there is no more data to parse, we must stop parsing and RECEIVE more data.
                            if (response_data.empty())
                                break;
                        } else {
                            if (remove_crlf_after_chunk) {
                                if (response_data.size() < 2) {
                                    logging::debug("There is no CRLF...\n");
                                    break;
                                }
                                // There must be a CRLF.
                                if (!std::equal(crlf.begin(), crlf.end(), response_data.begin()))
                                    throw ResponseError("Invalid chunk, no CRLF");
                                // Remove the CRLF.
                                response_data.erase(response_data.begin(), response_data.begin() + 2);
                                // We removed the CRLF.
                                remove_crlf_after_chunk = false;
                            }
                            // Search for CRLF.
                            it = std::search(response_data.begin(), response_data.end(), crlf.begin(), crlf.end());
                            if (it == response_data.end()) {
                                logging::debug("There is no CRLF stopping...\n");
                                break;
                            }
                            // Reading the expected chunk size.
                            expected_chunk_size = detail::hexStringToUint<std::size_t, Iterator>(response_data.begin(), it);
                            // Erasing the size.
                            response_data.erase(response_data.begin(), it + 2);
                            // If the expected_chunk_size is zero, terminate.
                            if (expected_chunk_size == 0) {
                                logging::debug("Terminating chunked response.\n");
                                return response;
                            }
                            logging::debug("Expected chunk size = %d\n", expected_chunk_size);
                        }
                    }
                } else {
                    logging::debug("Parsing whole response...\n");
                    response.body.insert(response.body.end(), response_data.begin(), response_data.end());
                    response_data.clear();
                    // got the whole content
                    if (content_length_received && (response.body.size() >= content_length)) {
                        logging::debug("We got the whole content.\n");
                        return response;
                    }
                    logging::debug("We still have content to read.\n");
                }
            }
        }

        return response;
    }

private:
#if defined(_WIN32) || defined(__CYGWIN__)
    WinSock winSock;
#endif // defined(_WIN32) || defined(__CYGWIN__)
    InternetProtocol internet_protocol;
    Uri uri;
};

} // namespace http