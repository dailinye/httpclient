#pragma once

#include <string>
#include <xstring>
#include <memory>
#include <stdint.h>
#include <functional>
#include <list>

#ifdef HTTP_CLIENT_EXPORTS
#define HTTP_CLIENT_API __declspec(dllexport)
#else
#define HTTP_CLIENT_API
#endif

#ifdef WIN32
#pragma warning(push)
#pragma warning(disable: 4251)
struct HTTP_CLIENT_API AutoBuffer
{
	unsigned char *buffer;
	uint32_t length;
	uint32_t offset;

	AutoBuffer()
		:buffer(nullptr)
		,length(0)
		,offset(0)
	{

	}

	AutoBuffer(unsigned char *buf, const uint32_t len)
		:buffer(buf)
		,length(len)
		,offset(0)
	{

	}

	AutoBuffer(const uint32_t len)
	{
		if (len > 0)
		{
			buffer = new (std::nothrow)unsigned char[len];
			if (buffer != nullptr)
			{
				length = len;
				offset = 0;
			}
		}
	}

	AutoBuffer(const std::string& str)
		:buffer(nullptr)
		,length(0)
		,offset(0)
	{
		if (!str.empty())
		{
			buffer = new (std::nothrow)unsigned char[str.size()];
			if (buffer != nullptr)
			{
				memcpy(buffer, str.c_str(), str.size());
				length = str.size();
				offset = 0;
			}
		}
	}

	std::string AsString()
	{
		return std::string((char*)buffer, offset);
	}

	AutoBuffer& operator= (const AutoBuffer& rhs)
	{
		if (&rhs != this)
		{
			this->buffer = new (std::nothrow)unsigned char[rhs.length];
			if (nullptr != this->buffer)
			{
				memcpy(this->buffer, rhs.buffer, rhs.length);
				this->length = rhs.length;
				this->offset = rhs.offset;
			}
		}
		return *this;
	}

	AutoBuffer& operator= (AutoBuffer&& rhs)
	{
		if (&rhs != this)
		{
			this->buffer = rhs.buffer;
			this->length = rhs.length;
			this->offset = rhs.offset;
			rhs.buffer = nullptr;
			rhs.length = 0;
			rhs.offset = 0;
		}
		return *this;
	}

	AutoBuffer(const AutoBuffer& rhs)
	{
		this->buffer = rhs.buffer;
		this->length = rhs.length;
		this->offset = rhs.offset;
	}

	AutoBuffer(AutoBuffer&& rhs)
	{
		this->buffer = rhs.buffer;
		this->length = rhs.length;
		this->offset = rhs.offset;
		rhs.buffer = nullptr;
		rhs.length = 0;
	}

	~AutoBuffer()
	{
		if (buffer != nullptr)
		{
			delete buffer;
			length = 0;
			offset = 0;
		}
	}
};

enum HTTP_ERROR_CODE
{
	HTTP_OK = (0),
	HTTP_ERROR = (-1000),
	HTTP_CURL_ERROR = (-2000),
	HTTP_INVALID_PARAM = (HTTP_ERROR - 1),
	HTTP_OUT_OF_MEMORY = (HTTP_ERROR - 2),
	HTTP_NOT_IMPLEMENT = (HTTP_ERROR - 3),
	HTTP_INITIAL_REQUEST_FAILED = (HTTP_ERROR - 4)
};

/* common http header key*/
#ifndef HTTP_HEADER_AUTHORIZATION
#define HTTP_HEADER_AUTHORIZATION ("Authorization")
#endif

#ifndef HTTP_HEADER_AUTHORIZATION_TYPE
#define HTTP_HEADER_AUTHORIZATION_TYPE ("WWW-Authenticate")
#endif

#ifndef HTTP_HEADER_CONTENT_LENGTH
#define HTTP_HEADER_CONTENT_LENGTH ("Content-Length")
#endif

#ifndef HTTP_HEADER_CONTENT_TYPE
#define HTTP_HEADER_CONTENT_TYPE ("Content-Type")
#endif

#ifndef HTTP_HEADER_ACCEPT
#define HTTP_HEADER_ACCEPT ("Accept")
#endif

#ifndef HTTP_HEADER_USER_AGENT
#define HTTP_HEADER_USER_AGENT ("User-Agent")
#endif
/* common http header key*/

/*http status codes*/
#ifndef HTTP_STATUS_OK
#define HTTP_STATUS_OK (HTTP_ERROR-200)
#endif
#ifndef HTTP_CREATED
#define HTTP_CREATED (HTTP_ERROR-201)
#endif
#ifndef HTTP_BAD_REQUEST
#define HTTP_BAD_REQUEST (HTTP_ERROR-400)
#endif
#ifndef HTTP_UNAUTHORIZED
#define HTTP_UNAUTHORIZED (HTTP_ERROR-401)
#endif
#ifndef HTTP_FORBIDDEN
#define HTTP_FORBIDDEN (HTTP_ERROR-403)
#endif
#ifndef HTTP_NOT_FOUND
#define HTTP_NOT_FOUND (HTTP_ERROR-404)
#endif
#ifndef HTTP_NOT_ALLOWD
#define HTTP_NOT_ALLOWD (HTTP_ERROR-405)
#endif
#ifndef HTTP_CONFLICT
#define HTTP_CONFLICT (HTTP_ERROR-409)
#endif
#ifndef HTTP_PRECONDITION_FAILED
#define HTTP_PRECONDITION_FAILED (HTTP_ERROR-412)
#endif
#ifndef HTTP_EXCEPTATION_FAILED
#define HTTP_EXCEPTATION_FAILED (HTTP_ERROR-417)
#endif
#ifndef HTTP_LOCKED
#define HTTP_LOCKED (HTTP_ERROR-423)
#endif
#ifndef HTTP_INTERNAL_ERROR
#define HTTP_INTERNAL_ERROR (HTTP_ERROR-500)
#endif
#ifndef HTTP_SERVICE_UNVAILABLE
#define HTTP_SERVICE_UNVAILABLE (HTTP_ERROR-503)
#endif
#ifndef HTTP_INSUFFICIENT_STORAGE
#define HTTP_INSUFFICIENT_STORAGE (HTTP_ERROR-507)
#endif
/*http status codes*/

class HTTP_CLIENT_API HttpHeaders
{
public:
	typedef std::list<std::pair<std::string, std::string>> HeadersType;
public:
	HttpHeaders(const std::string& headerString = "");

	void setHeader(const std::string& key, const std::string& value);
	std::string getHeader(const std::string& key) const;
	void setHeaders(const HeadersType& headers);
	void setHeaders(const std::string& headers);
	HeadersType getHeaders() const;

private:
	class Impl;
	std::shared_ptr<Impl> impl_;
};

class HTTP_CLIENT_API HttpBody
{
public:
	typedef std::function<size_t(void*, size_t, size_t, void*)> HttpContentCallback;

public:
	HttpBody();
	HttpBody(AutoBuffer& content);

	void setContent(AutoBuffer& content);
	AutoBuffer& getContent();

	void setContentCallback(HttpContentCallback& callback, void *userData = nullptr);
	HttpContentCallback getContentCallback();
	void *getUserData();

private:
	class Impl;
	std::shared_ptr<Impl> impl_;
};

struct HTTP_CLIENT_API HttpProxy
{
	std::string ProxyServer;
	std::string ProxyPort;
	std::string ProxyUserName;
	std::string ProxyPassword;
};

typedef std::function<int32_t(HttpBody&)> HttpRequestCallback;

enum HTTP_SSLVERSION
{
	SSLVERSION_TLSv1, /* TLS 1.x */
	SSLVERSION_SSLv2,
	SSLVERSION_SSLv3,
	SSLVERSION_TLSv1_0,
	SSLVERSION_TLSv1_1,
	SSLVERSION_TLSv1_2,
	SSLVERSION_TLSv1_3,
	SSLVERSION_Invalid
};

enum HTTP_METHOD
{
	HTTP_GET,
	HTTP_POST,
	HTTP_PUT,
	HTTP_INVALID
};

class HTTP_CLIENT_API HttpClient
{
public:
	HttpClient();

	static int32_t init();
	static int32_t release();

	void setUri(const std::string& uri);
	std::string getUri() const;

	void setRequestHeaders(const HttpHeaders& httpHeaders);
	HttpHeaders& getRequestHeaders();
	void setResponseHeaders(const HttpHeaders& httpHeaders);
	HttpHeaders& getResponseHeaders();
	void setRequestBody(const HttpBody& httpBody);
	HttpBody& getRequestBody();
	void setResponseBody(const HttpBody& httpBody);
	HttpBody& getResponseBody();

	void setHttpMethod(const HTTP_METHOD method);
	HTTP_METHOD getHttpMethod() const;

	void setTimeout(const int64_t timeout);
	int64_t getTimeout() const;
	void setConnectionTimeout(const int64_t timeout);
	int64_t getConnectionTimeout() const;
	
	void setUseSSL(const bool useSSL);
	bool getUseSSL() const;
	void setSSLVersion(const HTTP_SSLVERSION sslVersion);
	HTTP_SSLVERSION getSSLVersion() const;
	void setVerifySSLHost(const bool verifyHost);
	bool getVerifySSLHost() const;
	void setVerifySSLPeer(const bool verifyPeer);
	bool getVerifySSLPeer() const;
	void setCertPath(const std::wstring& certPath);
	std::wstring getCertPath() const;

	void setUseProxy(const bool useProxy);
	bool getUseProxy() const;
	void setProxyInfo(const HttpProxy& proxy);
	HttpProxy getProxyInfo() const;

	int32_t sendRequest();

public:
	/* request content length*/
	void setContentLength(const int64_t length);
	int64_t getContentLength() const;


public:
	static std::string base64Encode(const std::string& value);
	static std::string base64Decode(const std::string& value);

private:
	class Impl;
	std::shared_ptr<Impl> impl_;
};
#pragma warning(pop)
#endif
