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

namespace http
{

namespace detail
{

inline int getLastError()
{
#if defined(_WIN32) || defined(__CYGWIN__)
    return WSAGetLastError();
#else
    return errno;
#endif // defined(_WIN32) || defined(__CYGWIN__)
}

inline const char *getLastErrorStr(int err)
{
#ifdef _WIN32
    char *s = 0;
    ::FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, err, 0, (LPSTR)&s, 0, NULL);
    if (s) {
        ret = s;
        ::LocalFree(s);
    }
    return s;
#else
    return strerror(err);
#endif
}

} // namespace detail

class RequestError : public std::logic_error {
public:
    RequestError(const std::string &__arg)
        : std::logic_error::logic_error(__arg)
    {
        // Nothing to do.
    }
};

class ResponseError : public std::runtime_error {
public:
    ResponseError(const std::string &__arg)
        : std::runtime_error(__arg)
    {
        // Nothing to do.
    }
};

class SystemError : public std::runtime_error {
public:
    SystemError(int _error, const std::string &__arg)
        : std::runtime_error(__arg + " : " + detail::getLastErrorStr(_error))
    {
        // Nothing to do.
    }
};

struct InternetProtocol {
    enum Enum {
        V4,
        V6
    } value;

    InternetProtocol(Enum _value)
        : value(_value)
    {
        // Nothing to do.
    }

    inline bool operator==(Enum _value) const
    {
        return value == _value;
    }

    inline int getAddressFamily() const
    {
        if (value == InternetProtocol::V4)
            return AF_INET;
        if (value == InternetProtocol::V6)
            return AF_INET6;
        throw RequestError("Unsupported protocol");
    }
};

struct Uri {
    std::string scheme;
    std::string user;
    std::string password;
    std::string host;
    std::string port;
    std::string path;
    std::string query;
    std::string fragment;
};

struct HttpVersion {
    uint16_t major;
    uint16_t minor;

    HttpVersion()
        : major(),
          minor()
    {
        // Nothing to do.
    }

    HttpVersion(uint16_t _major,
                uint16_t _minor)
        : major(_major),
          minor(_minor)
    {
        // Nothing to do.
    }
};

struct Status {
    // RFC 7231, 6. Response Status Codes
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

    HttpVersion httpVersion;
    uint16_t code;
    std::string reason;

    Status()
        : httpVersion(),
          code(),
          reason()
    {
        // Nothing to do.
    }

    Status(HttpVersion _httpVersion, uint16_t _code, std::string _reason)
        : httpVersion(_httpVersion),
          code(_code),
          reason(_reason)
    {
        // Nothing to do.
    }
};

typedef std::pair<std::string, std::string> HeaderField;
typedef std::vector<HeaderField> HeaderFields;

struct Response {
    Status status;
    HeaderFields headerFields;
    std::vector<uint8_t> body;
};

namespace detail
{
#if defined(_WIN32) || defined(__CYGWIN__)
class WinSock {
public:
    WinSock()
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
        : endpoint(invalid)
    {
        // Nothing to do.
    }

    Socket(const InternetProtocol internetProtocol)
        : endpoint(socket(internetProtocol.getAddressFamily(), SOCK_STREAM, IPPROTO_TCP))
    {
        if (endpoint == invalid)
            throw SystemError(getLastError(), "Failed to create socket");

#if defined(_WIN32) || defined(__CYGWIN__)
        ULONG mode = 1;
        if (ioctlsocket(endpoint, FIONBIO, &mode) != 0) {
            this->close();
            throw SystemError(detail::getLastError(), "Failed to get socket flags");
        }
#else
        const int flags = fcntl(endpoint, F_GETFL);
        if (flags == -1) {
            this->close();
            throw SystemError(detail::getLastError(), "Failed to get socket flags");
        }

        if (fcntl(endpoint, F_SETFL, flags | O_NONBLOCK) == -1) {
            this->close();
            throw SystemError(detail::getLastError(), "Failed to set socket flags");
        }
#endif // defined(_WIN32) || defined(__CYGWIN__)

#ifdef __APPLE__
        const int value = 1;
        if (setsockopt(endpoint, SOL_SOCKET, SO_NOSIGPIPE, &value, sizeof(value)) == -1) {
            this->close();
            throw SystemError(detail::getLastError(), "Failed to set socket option");
        }
#endif // __APPLE__
    }

    ~Socket()
    {
        if (endpoint != invalid)
            this->close();
    }

    Socket(Socket &other)
        : endpoint(other.endpoint)
    {
        other.endpoint = invalid;
    }

    Socket &operator=(Socket &other)
    {
        if (&other == this)
            return *this;
        if (endpoint != invalid)
            this->close();
        endpoint       = other.endpoint;
        other.endpoint = invalid;
        return *this;
    }

    void connect(const struct sockaddr *address, const socklen_t addressSize, const int64_t timeout)
    {
#if defined(_WIN32) || defined(__CYGWIN__)
        auto result = ::connect(endpoint, address, addressSize);
        while (result == -1 && WSAGetLastError() == WSAEINTR)
            result = ::connect(endpoint, address, addressSize);

        if (result == -1) {
            if (WSAGetLastError() == WSAEWOULDBLOCK) {
                select(SelectType::write, timeout);

                char socketErrorPointer[sizeof(int)];
                socklen_t optionLength = sizeof(socketErrorPointer);
                if (getsockopt(endpoint, SOL_SOCKET, SO_ERROR, socketErrorPointer, &optionLength) == -1)
                    throw SystemError(detail::getLastError(), "Failed to get socket option");

                int socketError;
                std::memcpy(&socketError, socketErrorPointer, sizeof(socketErrorPointer));

                if (socketError != 0)
                    throw SystemError(socketError, "Failed to connect");
            } else
                throw SystemError(detail::getLastError(), "Failed to connect");
        }
#else
        int result = ::connect(endpoint, address, addressSize);
        while (result == -1 && errno == EINTR)
            result = ::connect(endpoint, address, addressSize);

        if (result == -1) {
            if (errno == EINPROGRESS) {
                select(SelectType::write, timeout);
                int socketError;
                socklen_t optionLength = sizeof(socketError);
                if (getsockopt(endpoint, SOL_SOCKET, SO_ERROR, &socketError, &optionLength) == -1)
                    throw SystemError(errno, "Failed to get socket option");
                if (socketError != 0)
                    throw SystemError(socketError, "Failed to connect (getsockopt)");
            } else
                throw SystemError(errno, "Failed to connect (connect)");
        }
#endif // defined(_WIN32) || defined(__CYGWIN__)
    }

    std::size_t send(const void *buffer, const std::size_t length, const int64_t timeout)
    {
        select(SelectType::write, timeout);
#if defined(_WIN32) || defined(__CYGWIN__)
        auto result = ::send(endpoint, reinterpret_cast<const char *>(buffer),
                             static_cast<int>(length), 0);

        while (result == -1 && WSAGetLastError() == WSAEINTR)
            result = ::send(endpoint, reinterpret_cast<const char *>(buffer),
                            static_cast<int>(length), 0);

        if (result == -1)
            throw SystemError(detail::getLastError(), "Failed to send data");
#else
        ssize_t result = ::send(endpoint, reinterpret_cast<const char *>(buffer),
                                length, noSignal);

        while (result == -1 && errno == EINTR)
            result = ::send(endpoint, reinterpret_cast<const char *>(buffer),
                            length, noSignal);

        if (result == -1)
            throw SystemError(detail::getLastError(), "Failed to send data");
#endif // defined(_WIN32) || defined(__CYGWIN__)
        return static_cast<std::size_t>(result);
    }

    std::size_t recv(void *buffer, const std::size_t length, const int64_t timeout)
    {
        select(SelectType::read, timeout);
#if defined(_WIN32) || defined(__CYGWIN__)
        auto result = ::recv(endpoint, reinterpret_cast<char *>(buffer),
                             static_cast<int>(length), 0);

        while (result == -1 && WSAGetLastError() == WSAEINTR)
            result = ::recv(endpoint, reinterpret_cast<char *>(buffer),
                            static_cast<int>(length), 0);

        if (result == -1)
            throw SystemError(detail::getLastError(), "Failed to read data");
#else
        ssize_t result = ::recv(endpoint, reinterpret_cast<char *>(buffer),
                                length, noSignal);

        while (result == -1 && errno == EINTR)
            result = ::recv(endpoint, reinterpret_cast<char *>(buffer),
                            length, noSignal);

        if (result == -1)
            throw SystemError(detail::getLastError(), "Failed to read data");
#endif // defined(_WIN32) || defined(__CYGWIN__)
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

#if defined(_WIN32) || defined(__CYGWIN__)
        TIMEVAL selectTimeout{
            static_cast<LONG>(timeout / 1000),
            static_cast<LONG>((timeout % 1000) * 1000)
        };
        auto count = ::select(0,
                              (type == SelectType::read) ? &descriptorSet : NULL,
                              (type == SelectType::write) ? &descriptorSet : NULL,
                              NULL,
                              (timeout >= 0) ? &selectTimeout : NULL);

        while (count == -1 && WSAGetLastError() == WSAEINTR)
            count = ::select(0,
                             (type == SelectType::read) ? &descriptorSet : NULL,
                             (type == SelectType::write) ? &descriptorSet : NULL,
                             NULL,
                             (timeout >= 0) ? &selectTimeout : NULL);

        if (count == -1)
            throw SystemError(detail::getLastError(), "Failed to select socket");
        else if (count == 0)
            throw ResponseError("Request timed out");
#else
        timeval selectTimeout;
        selectTimeout.tv_sec  = static_cast<time_t>(timeout / 1000);
        selectTimeout.tv_usec = static_cast<suseconds_t>((timeout % 1000) * 1000);

        int count = ::select(endpoint + 1,
                             (type == SelectType::read) ? &descriptorSet : NULL,
                             (type == SelectType::write) ? &descriptorSet : NULL,
                             NULL,
                             (timeout >= 0) ? &selectTimeout : NULL);

        while (count == -1 && errno == EINTR)
            count = ::select(endpoint + 1,
                             (type == SelectType::read) ? &descriptorSet : NULL,
                             (type == SelectType::write) ? &descriptorSet : NULL,
                             NULL,
                             (timeout >= 0) ? &selectTimeout : NULL);

        if (count == -1)
            throw SystemError(detail::getLastError(), "Failed to select socket");
        else if (count == 0)
            throw ResponseError("Request timed out");
#endif // defined(_WIN32) || defined(__CYGWIN__)
    }

    void close()
    {
#if defined(_WIN32) || defined(__CYGWIN__)
        closesocket(endpoint);
#else
        ::close(endpoint);
#endif // defined(_WIN32) || defined(__CYGWIN__)
    }

#if defined(__unix__) && !defined(__APPLE__) && !defined(__CYGWIN__)
    static const int noSignal = MSG_NOSIGNAL;
#else
    static const int noSignal = 0;
#endif // defined(__unix__) && !defined(__APPLE__)

    Type endpoint;
};

// RFC 7230, 3.2.3. WhiteSpace
template <typename C>
bool isWhiteSpaceChar(const C c)
{
    return c == 0x20 || c == 0x09; // space or tab
}

// RFC 7230, 3.2.3. WhiteSpace
template <typename C>
bool isNotWhiteSpaceChar(const C c)
{
    return !isWhiteSpaceChar(c);
}

// RFC 5234, Appendix B.1. Core Rules
template <typename C>
bool isDigitChar(const C c)
{
    return c >= 0x30 && c <= 0x39; // 0 - 9
}

// RFC 5234, Appendix B.1. Core Rules
template <typename C>
bool isAlphaChar(const C c)
{
    return (c >= 0x61 && c <= 0x7A) || // a - z
           (c >= 0x41 && c <= 0x5A);   // A - Z
}

// RFC 7230, 3.2.6. Field Value Components
template <typename C>
bool isTokenChar(const C c)
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
bool isVisibleChar(const C c)
{
    return c >= 0x21 && c <= 0x7E;
}

// RFC 7230, Appendix B. Collected ABNF
template <typename C>
bool isObsoleteTextChar(const C c)
{
    return static_cast<unsigned char>(c) >= 0x80 &&
           static_cast<unsigned char>(c) <= 0xFF;
}

template <class Iterator>
Iterator skipWhiteSpaces(const Iterator begin, const Iterator end)
{
    Iterator i = begin;
    for (i = begin; i != end; ++i)
        if (!isWhiteSpaceChar(*i))
            break;

    return i;
}

// RFC 5234, Appendix B.1. Core Rules
template <typename T, typename C>
T digitToUint(const C c)
{
    // DIGIT (0 - 9)
    return (c >= 0x30 && c <= 0x39) ? static_cast<T>(c - 0x30) : throw ResponseError("Invalid digit");
}

template <typename T>
std::string numberToString(T Number)
{
    std::ostringstream ss;
    ss << Number;
    return ss.str();
}

// RFC 5234, Appendix B.1. Core Rules
template <typename T, typename C>
T hexDigitToUint(const C c)
{
    if (c >= 0x30 && c <= 0x39) 
        return static_cast<T>(c - 0x30); // 0 - 9
    if (c >= 0x41 && c <= 0x46) 
        return static_cast<T>(c - 0x41) + T(10); // A - Z
    if (c >= 0x61 && c <= 0x66) 
        return static_cast<T>(c - 0x61) + T(10); // a - z, some services send lower-case hex digits
    throw ResponseError("Invalid hex digit");
}

// RFC 3986, 3. Syntax Components
template <class Iterator>
Uri parseUri(const Iterator begin, const Iterator end)
{
    Uri result;

    // RFC 3986, 3.1. Scheme
    Iterator i = begin;
    if (i == end || !isAlphaChar(*begin))
        throw RequestError("Invalid scheme");

    result.scheme.push_back(*i++);

    for (; i != end && (isAlphaChar(*i) || isDigitChar(*i) || *i == '+' || *i == '-' || *i == '.'); ++i)
        result.scheme.push_back(*i);

    if (i == end || *i++ != ':')
        throw RequestError("Invalid scheme");
    if (i == end || *i++ != '/')
        throw RequestError("Invalid scheme");
    if (i == end || *i++ != '/')
        throw RequestError("Invalid scheme");

    // RFC 3986, 3.2. Authority
    std::string authority = std::string(i, end);

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
            result.user     = userinfo.substr(0, passwordPosition);
            result.password = userinfo.substr(passwordPosition + 1);
        } else
            result.user = userinfo;

        result.host = authority.substr(hostPosition + 1);
    } else
        result.host = authority;

    // RFC 3986, 3.2.2. Host
    const std::string::size_type portPosition = result.host.find(':');
    if (portPosition != std::string::npos) {
        // RFC 3986, 3.2.3. Port
        result.port = result.host.substr(portPosition + 1);
        result.host.resize(portPosition);
    }

    return result;
}

// RFC 7230, 2.6. Protocol Versioning
template <class Iterator>
std::pair<Iterator, HttpVersion> parseHttpVersion(const Iterator begin, const Iterator end)
{
    Iterator i = begin;

    if (i == end || *i++ != 'H')
        throw ResponseError("Invalid HTTP version");
    if (i == end || *i++ != 'T')
        throw ResponseError("Invalid HTTP version");
    if (i == end || *i++ != 'T')
        throw ResponseError("Invalid HTTP version");
    if (i == end || *i++ != 'P')
        throw ResponseError("Invalid HTTP version");
    if (i == end || *i++ != '/')
        throw ResponseError("Invalid HTTP version");
    if (i == end)
        throw ResponseError("Invalid HTTP version");
    const uint16_t majorVersion = digitToUint<uint16_t>(*i++);
    if (i == end || *i++ != '.')
        throw ResponseError("Invalid HTTP version");
    if (i == end)
        throw ResponseError("Invalid HTTP version");
    const uint16_t minorVersion = digitToUint<uint16_t>(*i++);
    return std::make_pair(i, HttpVersion(majorVersion, minorVersion));
}

// RFC 7230, 3.1.2. Status Line
template <class Iterator>
std::pair<Iterator, uint16_t> parseStatusCode(const Iterator begin, const Iterator end)
{
    uint16_t result = 0;
    Iterator i      = begin;
    while (i != end && isDigitChar(*i))
        result = static_cast<uint16_t>(result * 10U) + digitToUint<uint16_t>(*i++);
    if (std::distance(begin, i) != 3)
        throw ResponseError("Invalid status code");
    return std::make_pair(i, result);
}

// RFC 7230, 3.1.2. Status Line
template <class Iterator>
std::pair<Iterator, std::string> parseReasonPhrase(const Iterator begin, const Iterator end)
{
    std::string result;
    Iterator i = begin;
    for (; i != end && (isWhiteSpaceChar(*i) || isVisibleChar(*i) || isObsoleteTextChar(*i)); ++i)
        result.push_back(static_cast<char>(*i));
    return std::make_pair(i, result);
}

// RFC 7230, 3.2.6. Field Value Components
template <class Iterator>
std::pair<Iterator, std::string> parseToken(const Iterator begin, const Iterator end)
{
    std::string result;

    Iterator i = begin;
    for (; i != end && isTokenChar(*i); ++i)
        result.push_back(static_cast<char>(*i));

    if (result.empty())
        throw ResponseError("Invalid token");

    return std::make_pair(i, result);
}

// trim from start
static inline std::string &ltrim(std::string &s)
{
    s.erase(s.begin(), std::find_if(s.begin(), s.end(),
                                    std::not1(std::ptr_fun<int, int>(std::isspace))));
    return s;
}

// trim from end
static inline std::string &rtrim(std::string &s)
{
    s.erase(std::find_if(s.rbegin(), s.rend(),
                         std::not1(std::ptr_fun<int, int>(std::isspace)))
                .base(),
            s.end());
    return s;
}

// trim from both ends
static inline std::string &trim(std::string &s)
{
    return ltrim(rtrim(s));
}

// RFC 7230, 3.2. Header Fields
template <class Iterator>
std::pair<Iterator, std::string> parseFieldValue(const Iterator begin, const Iterator end)
{
    std::string result;
    Iterator i = begin;
    for (; i != end && (isWhiteSpaceChar(*i) || isVisibleChar(*i) || isObsoleteTextChar(*i)); ++i)
        result.push_back(static_cast<char>(*i));
    // trim white spaces
    return std::make_pair(i, trim(result));
}

// RFC 7230, 3.2. Header Fields
template <class Iterator>
std::pair<Iterator, std::string> parseFieldContent(const Iterator begin, const Iterator end)
{
    std::string result;

    Iterator i = begin;

    for (;;) {
        const std::pair<Iterator, std::string> fieldValueResult = parseFieldValue(i, end);
        i                                                       = fieldValueResult.first;
        result += fieldValueResult.second;

        // Handle obsolete fold as per RFC 7230, 3.2.4. Field Parsing
        // Obsolete folding is known as linear white space (LWS) in RFC 2616, 2.2 Basic Rules
        Iterator obsoleteFoldIterator = i;
        if (obsoleteFoldIterator == end || *obsoleteFoldIterator++ != '\r')
            break;

        if (obsoleteFoldIterator == end || *obsoleteFoldIterator++ != '\n')
            break;

        if (obsoleteFoldIterator == end || !isWhiteSpaceChar(*obsoleteFoldIterator++))
            break;

        result.push_back(' ');
        i = obsoleteFoldIterator;
    }

    return std::make_pair(i, result);
}

// RFC 7230, 3.2. Header Fields
template <class Iterator>
std::pair<Iterator, HeaderField> parseHeaderField(const Iterator begin, const Iterator end)
{
    std::pair<Iterator, std::string> tokenResult = parseToken(begin, end);
    Iterator i                                   = tokenResult.first;
    std::string fieldName                        = tokenResult.second;

    if (i == end || *i++ != ':')
        throw ResponseError("Invalid header");

    i = skipWhiteSpaces(i, end);

    std::pair<Iterator, std::string> valueResult = parseFieldContent(i, end);
    i                                            = valueResult.first;
    std::string fieldValue                       = valueResult.second;

    if (i == end || *i++ != '\r')
        throw ResponseError("Invalid header");

    if (i == end || *i++ != '\n')
        throw ResponseError("Invalid header");

    return std::make_pair(i, HeaderField(fieldName, fieldValue));
}

// RFC 7230, 3.1.2. Status Line
template <class Iterator>
std::pair<Iterator, Status> parseStatusLine(const Iterator begin, const Iterator end)
{
    const std::pair<Iterator, HttpVersion> httpVersionResult = parseHttpVersion(begin, end);
    Iterator i                                               = httpVersionResult.first;

    if (i == end || *i++ != ' ')
        throw ResponseError("Invalid status line");

    const std::pair<Iterator, uint16_t> statusCodeResult = parseStatusCode(i, end);
    i                                                    = statusCodeResult.first;

    if (i == end || *i++ != ' ')
        throw ResponseError("Invalid status line");

    std::pair<Iterator, std::string> reasonPhraseResult = parseReasonPhrase(i, end);
    i                                                   = reasonPhraseResult.first;

    if (i == end || *i++ != '\r')
        throw ResponseError("Invalid status line");

    if (i == end || *i++ != '\n')
        throw ResponseError("Invalid status line");

    return std::make_pair(i, Status(httpVersionResult.second, statusCodeResult.second, reasonPhraseResult.second));
}

// RFC 7230, 4.1. Chunked Transfer Coding
template <typename T, class Iterator>
T stringToUint(const Iterator begin, const Iterator end)
{
    T result = 0;
    for (Iterator i = begin; i != end; ++i)
        result = T(10U) * result + digitToUint<T>(*i);
    return result;
}

template <typename T, class Iterator>
T hexStringToUint(const Iterator begin, const Iterator end)
{
    T result = 0;
    for (Iterator i = begin; i != end; ++i)
        result = static_cast<T>(16 * result) + detail::hexDigitToUint<T>(*i);
    return result;
}

// RFC 7230, 3.1.1. Request Line
inline std::string encodeRequestLine(const std::string &method, const std::string &target)
{
    return method + " " + target + " HTTP/1.1\r\n";
}

// RFC 7230, 3.2. Header Fields
inline std::string encodeHeaderFields(const HeaderFields &headerFields)
{
    std::string result;
    for (HeaderFields::const_iterator field = headerFields.begin(); field != headerFields.end(); ++field) {
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
template <class Iterator>
std::string encodeBase64(const Iterator begin, const Iterator end)
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

    for (Iterator i = begin; i != end; ++i) {
        charArray[c++] = static_cast<uint8_t>(*i);
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

inline std::vector<uint8_t> encodeHtml(const Uri &uri,
                                       const std::string &method,
                                       const std::vector<uint8_t> &body,
                                       HeaderFields headerFields)
{
    if (uri.scheme != "http")
        throw RequestError("Only HTTP scheme is supported");

    // RFC 7230, 5.3. Request Target
    const std::string requestTarget = uri.path + (uri.query.empty() ? "" : '?' + uri.query);

    // RFC 7230, 5.4. Host
    headerFields.push_back(HeaderField("Host", uri.host));

    // RFC 7230, 3.3.2. Content-Length
    headerFields.push_back(HeaderField("Content-Length", detail::numberToString(body.size())));

    // RFC 7617, 2. The 'Basic' Authentication Scheme
    if (!uri.user.empty() || !uri.password.empty()) {
        std::string userinfo = uri.user + ':' + uri.password;
        headerFields.push_back(HeaderField("Authorization", "Basic " + encodeBase64(userinfo.begin(), userinfo.end())));
    }

    const std::string headerData = encodeRequestLine(method, requestTarget) +
                                   encodeHeaderFields(headerFields) +
                                   "\r\n";

    std::vector<uint8_t> result(headerData.begin(), headerData.end());
    result.insert(result.end(), body.begin(), body.end());

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

inline char toLower(const char c)
{
    return (c >= 'A' && c <= 'Z') ? c - ('A' - 'a') : c;
}

} // namespace detail

class Request {
public:
    Request(const std::string &uriString,
            const InternetProtocol protocol = InternetProtocol::V4)
        : internetProtocol(protocol),
          uri(detail::parseUri(uriString.begin(), uriString.end()))
    {
    }

    Response send(const std::string &method        = "GET",
                  const std::string &body          = "",
                  const HeaderFields &headerFields = HeaderFields(),
                  const std::time_t timeout        = std::time_t(-1))
    {
        return this->send(
            method,
            std::vector<uint8_t>(body.begin(), body.end()),
            headerFields,
            timeout);
    }

    Response send(const std::string &method,
                  const std::vector<uint8_t> &body,
                  const HeaderFields &headerFields = HeaderFields(),
                  const std::time_t timeout        = std::time_t(-1))
    {
        const time_t stopTime = detail::getTimeNowMilliseconds() + timeout;

        if (uri.scheme != "http")
            throw RequestError("Only HTTP scheme is supported");

        addrinfo hints    = {};
        hints.ai_family   = internetProtocol.getAddressFamily();
        hints.ai_socktype = SOCK_STREAM;

        const char *port = uri.port.empty() ? "80" : uri.port.c_str();

        addrinfo *_info;
        if (getaddrinfo(uri.host.c_str(), port, &hints, &_info) != 0)
            throw SystemError(detail::getLastError(), "Failed to get address info of " + uri.host);

        addrinfo info = *_info;
        freeaddrinfo(_info);

        const std::vector<uint8_t> requestData = detail::encodeHtml(uri, method, body, headerFields);

        detail::Socket socket(internetProtocol);

        // take the first address from the list
        socket.connect(
            info.ai_addr,
            static_cast<socklen_t>(info.ai_addrlen),
            (timeout >= 0) ? detail::getRemainingMilliseconds(stopTime) : -1);

        size_t remaining        = requestData.size();
        const uint8_t *sendData = requestData.data();

        // send the request
        while (remaining > 0) {
            const ssize_t size = socket.send(
                sendData,
                remaining,
                (timeout >= 0) ? detail::getRemainingMilliseconds(stopTime) : -1);
            remaining -= size;
            sendData += size;
        }

        uint8_t tempBuffer[4096];
        uint8_t crlf[2]      = { '\r', '\n' };
        uint8_t headerEnd[4] = { '\r', '\n', '\r', '\n' };
        Response response;
        std::vector<uint8_t> responseData;
        bool parsingBody              = false;
        bool contentLengthReceived    = false;
        std::size_t contentLength     = 0U;
        bool chunkedResponse          = false;
        std::size_t expectedChunkSize = 0U;
        bool removeCrlfAfterChunk     = false;

        typedef std::vector<uint8_t>::iterator Iterator;

        // read the response
        for (;;) {
            const ssize_t size = socket.recv(
                tempBuffer,
                4096,
                (timeout >= 0) ? detail::getRemainingMilliseconds(stopTime) : -1);
            if (size == 0) { // disconnected

                return response;
            }

            responseData.insert(
                responseData.end(),
                tempBuffer,
                tempBuffer + size);

            if (!parsingBody) {
                // RFC 7230, 3. Message Format
                // Empty line indicates the end of the header section (RFC 7230, 2.1. Client/Server Messaging)
                const Iterator endIterator =
                    std::search(
                        responseData.begin(), responseData.end(),
                        headerEnd, headerEnd + 4);
                if (endIterator == responseData.end())
                    break; // two consecutive CRLFs not found

                const Iterator headerBeginIterator = responseData.begin();
                const Iterator headerEndIterator   = endIterator + 2;

                std::pair<Iterator, Status> statusLineResult = detail::parseStatusLine(headerBeginIterator, headerEndIterator);
                Iterator i                                   = statusLineResult.first;

                response.status = statusLineResult.second;

                for (;;) {
                    std::pair<Iterator, HeaderField> headerFieldResult = detail::parseHeaderField(i, headerEndIterator);
                    i                                                  = headerFieldResult.first;

                    std::string fieldName = headerFieldResult.second.first;
                    std::transform(fieldName.begin(), fieldName.end(), fieldName.begin(), detail::toLower);

                    std::string fieldValue = headerFieldResult.second.second;

                    if (fieldName == "transfer-encoding") {
                        // RFC 7230, 3.3.1. Transfer-Encoding
                        if (fieldValue == "chunked")
                            chunkedResponse = true;
                        else
                            throw ResponseError("Unsupported transfer encoding: " + fieldValue);
                    } else if (fieldName == "content-length") {
                        // RFC 7230, 3.3.2. Content-Length
                        contentLength         = detail::stringToUint<std::size_t>(fieldValue.begin(), fieldValue.end());
                        contentLengthReceived = true;
                        response.body.reserve(contentLength);
                    }

                    response.headerFields.push_back(HeaderField(fieldName, fieldValue));

                    if (i == headerEndIterator)
                        break;
                }

                responseData.erase(responseData.begin(), headerEndIterator + 2);
                parsingBody = true;
            }

            if (parsingBody) {
                // Content-Length must be ignored if Transfer-Encoding is received (RFC 7230, 3.2. Content-Length)
                if (chunkedResponse) {
                    // RFC 7230, 4.1. Chunked Transfer Coding
                    for (;;) {
                        if (expectedChunkSize > 0) {
                            const size_t toWrite = std::min(expectedChunkSize, responseData.size());
                            response.body.insert(response.body.end(), responseData.begin(),
                                                 responseData.begin() + static_cast<std::ptrdiff_t>(toWrite));
                            responseData.erase(responseData.begin(),
                                               responseData.begin() + static_cast<std::ptrdiff_t>(toWrite));
                            expectedChunkSize -= toWrite;

                            if (expectedChunkSize == 0)
                                removeCrlfAfterChunk = true;
                            if (responseData.empty())
                                break;
                        } else {
                            if (removeCrlfAfterChunk) {
                                if (responseData.size() < 2)
                                    break;

                                if (!std::equal(crlf, crlf + 2, responseData.begin()))
                                    throw ResponseError("Invalid chunk");

                                removeCrlfAfterChunk = false;
                                responseData.erase(responseData.begin(), responseData.begin() + 2);
                            }

                            Iterator i = std::search(responseData.begin(), responseData.end(), crlf, crlf + 2);

                            if (i == responseData.end())
                                break;

                            expectedChunkSize = detail::hexStringToUint<uint8_t, Iterator>(responseData.begin(), i);

                            responseData.erase(responseData.begin(), i + 2);

                            if (expectedChunkSize == 0) {
                                return response;
                            }
                        }
                    }
                } else {
                    response.body.insert(response.body.end(), responseData.begin(), responseData.end());
                    responseData.clear();

                    // got the whole content
                    if (contentLengthReceived && response.body.size() >= contentLength) {
                        return response;
                    }
                }
            }
        }

        return response;
    }

private:
#if defined(_WIN32) || defined(__CYGWIN__)
    WinSock winSock;
#endif // defined(_WIN32) || defined(__CYGWIN__)
    InternetProtocol internetProtocol;
    Uri uri;
};

} // namespace http