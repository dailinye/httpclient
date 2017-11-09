#include "HttpClient.h"
#include <mutex>
#include <curl/curl.h>
#include <locale>
#include <algorithm>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#pragma comment(lib, "libcurl.lib")
#pragma comment(lib, "libeay32.lib")
#pragma comment(lib, "ssleay32.lib")

#ifndef curl_easy_setopt_safe
#define curl_easy_setopt_safe(opt, val)                         \
    if (curl_easy_setopt(curl_, opt, val) != CURLE_OK)          \
    {                                                           \
        return HTTP_INITIAL_REQUEST_FAILED;                     \
    }
#endif

#ifndef DEFAULT_REQUEST_TIMEOUT
#define DEFAULT_REQUEST_TIMEOUT (60) // 60 seconds
#endif // !DEFAULT_REQUEST_TIMEOUT

#ifndef DEFAULT_CONNECTION_TIMEOUT
#define DEFAULT_CONNECTION_TIMEOUT (10) // 10 seconds
#endif // !DEFAULT_CONNECTION_TIMEOUT

#ifndef MAX_INT64_LEN
#define MAX_INT64_LEN (20)
#endif

class Utility
{
public:
	static std::string int64str(const int64_t value)
	{
		char buf[MAX_INT64_LEN + 1] = { 0 };
		snprintf(buf, MAX_INT64_LEN, "%I64d", value);
		return buf;
	}

	static std::string urlEncode(const std::string& url)
	{
		std::string out = "";
		for (std::string::size_type i = 0; i < url.size(); ++i)
		{
			unsigned char c = url[i];
			if (::isalnum(c) ||
				(c == '-') ||
				(c == '_') ||
				(c == '.') ||
				(c == '~'))
			{
				out += c;
			}
			else
			{
				char buf[4] = { 0 };
				snprintf(buf, 4, "%%%02X", c);
				out += buf;
			}
		}
		return out;
	}

	static std::string urlDecode(const std::string& url)
	{
		std::string out = "";
		std::string::size_type pos = 0;
		while (pos < url.size())
		{
			auto c = url[pos];
			if (c != '%' ||
				(pos + 2) >= url.size() ||
				!::isxdigit(url[pos + 1]) ||
				!::isxdigit(url[pos + 2]))
			{
				if (c == '+')
				{
					c = ' ';
				}
				out += c;
				++pos;
				continue;
			}
			auto c1 = url[++pos], c2 = url[++pos];
			c1 = c1 - '0' - ((c1 >= 'A') ? 7 : 0) - ((c1 >= 'a') ? 32 : 0);
			c2 = c2 - '0' - ((c2 >= 'A') ? 7 : 0) - ((c2 >= 'a') ? 32 : 0);
			out += (unsigned char)(c1 * 16 + c2);
			++pos;
		}
		return out;
	}
};

class HttpHeaders::Impl
{
public:
	Impl(const std::string& headerString)
	{
		setHeaders(headerString);
	}

	void setHeader(const std::string& key, const std::string& value)
	{
		headers_.push_back(std::make_pair(key, value));
	}

	std::string getHeader(const std::string& key) const
	{
		for each (const auto& item in headers_)
		{
			if (item.first == key)
			{
				return item.second;
			}
		}
		return "";
	}

	void setHeaders(const HeadersType& headers)
	{
		headers_ = headers;
	}

	void setHeaders(const std::string& headers)
	{
		headers_.clear();
		std::string::size_type begin = 0, end = 0;
		for (std::string::size_type i = 0; i < headers.size(); ++i)
		{
			if (headers[i] == '\r')
			{
				end = i - begin;
				std::string header = headers.substr(begin, end);
				for (std::string::size_type j = 0; j < header.size(); ++j)
				{
					if (header[j] == ':')
					{
						// trim space
						if (header[j + 1] == ' ')
						{
							headers_.push_back(std::make_pair(header.substr(0, j), header.substr(j + 2)));
						}
						else
						{
							headers_.push_back(std::make_pair(header.substr(0, j), header.substr(j + 1)));
						}						
						break;
					}
				}
				++i;
				begin = i + 1;
			}
		}
	}

	HeadersType getHeaders() const
	{
		return headers_;
	}

private:
	HeadersType headers_;
};

class HttpBody::Impl
{
public:
	Impl()
	{

	}

	Impl(AutoBuffer& content)
		:content_(content)
	{

	}

	void setContent(AutoBuffer& content)
	{
		content_ = content;
	}

	AutoBuffer& getContent()
	{
		return content_;
	}

	void setContentCallback(HttpContentCallback& callback, void *userData)
	{
		callback_ = callback;
		userData_ = userData;
	}

	HttpContentCallback getContentCallback()
	{
		return callback_;
	}	

	void *getUserData()
	{
		return userData_;
	}

private:
	AutoBuffer content_;
	HttpContentCallback callback_ = nullptr;
	void *userData_ = nullptr;
};

class HttpClient::Impl
{
public:
	Impl()
	{

	}

	static int32_t init()
	{
		return curl_global_init(CURL_GLOBAL_ALL);
	}

	static int32_t release()
	{
		curl_global_cleanup();
		return HTTP_OK;
	}

	void setUri(const std::string& uri)
	{
		uri_ = uri;
	}

	std::string getUri() const
	{
		return uri_;
	}

	void setRequestHeaders(const HttpHeaders& httpHeaders)
	{
		requestHeaders_ = httpHeaders;
	}

	HttpHeaders& getRequestHeaders()
	{
		return requestHeaders_;
	}

	void setResponseHeaders(const HttpHeaders& httpHeaders)
	{
		responseHeaders_ = httpHeaders;
	}

	HttpHeaders& getResponseHeaders()
	{
		return responseHeaders_;
	}

	void setRequestBody(const HttpBody& httpBody)
	{
		requestBody_ = httpBody;
	}

	HttpBody& getRequestBody()
	{
		return requestBody_;
	}

	void setResponseBody(const HttpBody& httpBody)
	{
		responseBody_ = httpBody;
	}

	HttpBody& getResponseBody()
	{
		return responseBody_;
	}

	void setHttpMethod(const HTTP_METHOD method)
	{
		method_ = method;
	}

	void setTimeout(const int64_t timeout)
	{
		timeout_ = timeout;
	}

	int64_t getTimeout() const
	{
		return timeout_;
	}

	void setConnectionTimeout(const int64_t timeout)
	{
		connectionTimeout_ = timeout;
	}

	int64_t getConnectionTimeout() const
	{
		return connectionTimeout_;
	}
	
	HTTP_METHOD getHttpMethod() const
	{
		return method_;
	}

	void setUseSSL(const bool useSSL)
	{
		useSSL_ = useSSL;
	}

	bool getUseSSL() const
	{
		return useSSL_;
	}

	void setSSLVersion(const HTTP_SSLVERSION sslVersion)
	{
		sslVersion_ = sslVersion;
	}

	HTTP_SSLVERSION getSSLVersion() const
	{
		return sslVersion_;
	}

	void setVerifySSLHost(const bool verifyHost)
	{
		verifySSLHost_ = verifyHost;
	}

	bool getVerifySSLHost() const
	{
		return verifySSLHost_;
	}

	void setVerifySSLPeer(const bool verifyPeer)
	{
		verifySSLPeer_ = verifyPeer;
	}

	bool getVerifySSLPeer() const
	{
		return verifySSLPeer_;
	}

	void setCertPath(const std::wstring& certPath)
	{
		certPath_ = certPath;
	}

	std::wstring getCertPath() const
	{
		return certPath_;
	}

	void setUseProxy(const bool useProxy)
	{
		useProxy_ = useProxy;
	}

	bool getUseProxy() const
	{
		return useProxy_;
	}

	void setProxyInfo(const HttpProxy& proxy)
	{
		proxy_ = proxy;
	}

	HttpProxy getProxyInfo() const
	{
		return proxy_;
	}
	
	int32_t sendRequest()
	{
		if (uri_.empty())
		{
			return HTTP_INVALID_PARAM;
		}

		curl_ = curl_easy_init();
		if (curl_ == nullptr)
		{
			return HTTP_INITIAL_REQUEST_FAILED;
		}

		if (HTTP_OK != initHeaders())
		{
			return HTTP_INITIAL_REQUEST_FAILED;
		}
		if (HTTP_OK != initRequest())
		{
			return HTTP_INITIAL_REQUEST_FAILED;
		}

		CURLcode ret = curl_easy_perform(curl_);
		if (ret != CURLE_OK)
		{
			curl_easy_cleanup(curl_);
			return (HTTP_CURL_ERROR - ret);
		}

		int32_t httpStatusCode = 0;
		ret = curl_easy_getinfo(curl_, CURLINFO_RESPONSE_CODE, &httpStatusCode);
		if (CURLE_OK != ret)
		{
			// set response headers
			responseHeaders_.setHeaders(rspHeaders_);
			curl_easy_cleanup(curl_);
			return (HTTP_CURL_ERROR - ret);
		}
		// convert http status code
		httpStatusCode = (HTTP_ERROR - httpStatusCode);
		if (HTTP_STATUS_OK != httpStatusCode)
		{
			// set response headers
			responseHeaders_.setHeaders(rspHeaders_);
			curl_easy_cleanup(curl_);
			return httpStatusCode;
		}

		// set response headers
		responseHeaders_.setHeaders(rspHeaders_);
		curl_easy_cleanup(curl_);

		return HTTP_OK;
	}

public:
	void setContentLength(const int64_t length)
	{
		contentLength_ = length;
	}

	int64_t getContentLength() const
	{
		return contentLength_;
	}

private:
	int32_t initRequest()
	{
		switch (method_)
		{
		case HTTP_GET:
			curl_easy_setopt_safe(CURLOPT_HTTPGET, 1L);
			break;
		case HTTP_POST:
			curl_easy_setopt_safe(CURLOPT_POST, 1L);
			break;
		case HTTP_PUT:
			curl_easy_setopt_safe(CURLOPT_PUT, 1L);
			curl_easy_setopt_safe(CURLOPT_UPLOAD, 1L);
			break;
		default:
			return HTTP_INITIAL_REQUEST_FAILED;
		}

		curl_easy_setopt_safe(CURLOPT_URL, uri_.c_str());

		curl_easy_setopt_safe(CURLOPT_NOSIGNAL, 1L);
		curl_easy_setopt_safe(CURLOPT_NOPROGRESS, 1L);
		curl_easy_setopt_safe(CURLOPT_TCP_NODELAY, 1L);
		curl_easy_setopt_safe(CURLOPT_NETRC, CURL_NETRC_IGNORED);
		curl_easy_setopt_safe(CURLOPT_FOLLOWLOCATION, 1L);
		curl_easy_setopt_safe(CURLOPT_MAXREDIRS, 10L);

		if (!useSSL_)
		{
			curl_easy_setopt_safe(CURLOPT_SSL_VERIFYPEER, 0L);
			curl_easy_setopt_safe(CURLOPT_SSL_VERIFYHOST, 0L);
		}
		else
		{
			if (verifySSLPeer_)
			{
				curl_easy_setopt_safe(CURLOPT_SSL_VERIFYPEER, 1L);
			}
			if (verifySSLHost_)
			{
				curl_easy_setopt_safe(CURLOPT_SSL_VERIFYHOST, 1L);
			}
			if (!certPath_.empty())
			{
				curl_easy_setopt_safe(CURLOPT_CAPATH, certPath_.c_str());
			}
		}

		if (timeout_ > 0)
		{
			curl_easy_setopt_safe(CURLOPT_TIMEOUT, timeout_);
		}
		if (connectionTimeout_ > 0)
		{
			curl_easy_setopt_safe(CURLOPT_CONNECTTIMEOUT, connectionTimeout_);
		}

		curl_easy_setopt_safe(CURLOPT_READDATA, &requestBody_);
		if (requestBody_.getContentCallback() != nullptr)
		{
			curl_easy_setopt_safe(CURLOPT_READFUNCTION, requestBody_.getContentCallback());
		}
		else
		{
			curl_easy_setopt_safe(CURLOPT_READFUNCTION, curlSendFunc);
		}
		curl_easy_setopt_safe(CURLOPT_INFILESIZE_LARGE, contentLength_);

		curl_easy_setopt_safe(CURLOPT_WRITEDATA, &responseBody_);
		if (responseBody_.getContentCallback() != nullptr)
		{
			curl_easy_setopt_safe(CURLOPT_WRITEFUNCTION, responseBody_.getContentCallback());
		}
		else
		{
			curl_easy_setopt_safe(CURLOPT_WRITEFUNCTION, curlRecieveFunc);
		}

		curl_easy_setopt_safe(CURLOPT_HEADERDATA, this);
		curl_easy_setopt_safe(CURLOPT_HEADERFUNCTION, curlHeaderFunc);

		if (useProxy_)
		{
			curl_easy_setopt_safe(CURLOPT_PROXYAUTH, CURLAUTH_ANY/*CURLAUTH_BASIC*/);
			std::string proxySrvAndPort = proxy_.ProxyServer + ":" + proxy_.ProxyPort;
			curl_easy_setopt_safe(CURLOPT_PROXY, proxySrvAndPort.c_str());
			if (!proxy_.ProxyUserName.empty() && !proxy_.ProxyPassword.empty())
			{
				std::string proxyUserNameAndPsw = proxy_.ProxyUserName + ":" + proxy_.ProxyPassword;
				curl_easy_setopt_safe(CURLOPT_PROXYUSERPWD, proxyUserNameAndPsw);
			}
		}

#ifdef _DEBUG
		curl_easy_setopt_safe(CURLOPT_VERBOSE, 1L);
#endif
		return HTTP_OK;
	}

	int32_t initHeaders()
	{
		static std::list<std::string> unUrlEncodeHeader = { 
			HTTP_HEADER_AUTHORIZATION,
			HTTP_HEADER_CONTENT_LENGTH,
			HTTP_HEADER_AUTHORIZATION_TYPE,
			HTTP_HEADER_CONTENT_TYPE,
			HTTP_HEADER_ACCEPT,
			HTTP_HEADER_USER_AGENT
		};

		curl_slist *headers = nullptr;
		for each (const auto& item in requestHeaders_.getHeaders())
		{
			std::string header;
			for each (auto i in unUrlEncodeHeader)
			{
				if (i == item.first)
				{
					header = item.first + ":" + item.second;
				}
			}
			header = !header.empty() ? header : Utility::urlEncode(item.first) + ":" +  Utility::urlEncode(item.second);
			headers = curl_slist_append(headers, header.c_str());
			if (nullptr == headers)
			{
				return HTTP_INITIAL_REQUEST_FAILED;
			}
		}
		if (contentLength_ == 0 && requestBody_.getContent().length != 0)
		{
			contentLength_ = requestBody_.getContent().length;
		}
		{
			// set the content length
			std::string header = HTTP_HEADER_CONTENT_LENGTH + std::string(":") + Utility::int64str(contentLength_);
			headers = curl_slist_append(headers, header.c_str());
			if (nullptr == headers)
			{
				return HTTP_INITIAL_REQUEST_FAILED;
			}
		}
		curl_easy_setopt_safe(CURLOPT_HTTPHEADER, headers);
		
		return HTTP_OK;
	}

public:
	std::string& getRspHeaders()
	{
		return rspHeaders_;
	}

private:
	static size_t curlHeaderFunc(void *ptr, size_t size, size_t nmemb, void *data)
	{
		if (ptr == nullptr || data == nullptr)
		{
			return 0;
		}
		if (size == 0 || nmemb == 0)
		{
			return 0;
		}
		size_t len = size * nmemb;
		char *buf = new (std::nothrow)char[len + 1];
		if (nullptr == buf)
		{
			return 0;
		}
		buf[len] = 0;
		::memcpy(buf, ptr, len);		
		HttpClient::Impl *httpClient = (HttpClient::Impl *)data;
		std::string& rspHeaders = httpClient->getRspHeaders();
		rspHeaders += buf;
		delete buf;
		return len;
	}

	static size_t curlSendFunc(void *ptr, size_t size, size_t nmemb, void *data)
	{
		if (ptr == nullptr || data == nullptr)
		{
			return 0;
		}
		if (size == 0 || nmemb == 0)
		{
			return 0;
		}

		HttpBody *body = (HttpBody *)data;
		AutoBuffer& buf = body->getContent();
		if (buf.length <= buf.offset)
		{
			return 0;
		}
		size_t copySize = std::min<size_t>(size * nmemb, buf.length - buf.offset);
		// copy the data
		::memcpy(ptr, buf.buffer + buf.offset, copySize);
		// update the offset
		buf.offset += copySize;

		return copySize;
	}

	static size_t curlRecieveFunc(void *ptr, size_t size, size_t nmemb, void *data)
	{
		if (ptr == nullptr || data == nullptr)
		{
			return 0;
		}
		if (size == 0 || nmemb == 0)
		{
			return 0;
		}
		HttpBody *body = (HttpBody *)data;
		AutoBuffer& buf = body->getContent();
		size_t copySize = size * nmemb;
		if ((buf.length - buf.offset) < copySize)
		{
			// realloc the memory
			// more 64KB every time
			int32_t memorySize = buf.length + copySize + (64 * 1024);
			unsigned char *memory = new (std::nothrow)unsigned char[memorySize];
			if (memory == nullptr)
			{
				return 0;
			}
			// swap the old memory
			::memcpy(memory, buf.buffer, buf.offset);
			delete buf.buffer;
			// update the length and memory
			buf.buffer = memory;
			buf.length = memorySize;
		}
		// copy the data
		::memcpy(buf.buffer + buf.offset, ptr, copySize);
		// update the offset
		buf.offset += copySize;
		return copySize;
	}

private:
	std::string uri_ = "";
	HttpHeaders requestHeaders_;
	HttpHeaders responseHeaders_;
	HttpBody requestBody_;
	HttpBody responseBody_;
	HTTP_METHOD method_ = HTTP_GET;
	int64_t timeout_ = DEFAULT_REQUEST_TIMEOUT;
	int64_t connectionTimeout_ = DEFAULT_CONNECTION_TIMEOUT;
	bool useSSL_ = false;
	HTTP_SSLVERSION sslVersion_ = SSLVERSION_TLSv1;
	bool verifySSLHost_ = false;
	bool verifySSLPeer_ = false;
	std::wstring certPath_ = L"";
	bool useProxy_ = false;
	HttpProxy proxy_;
	CURL *curl_ = nullptr;

private:
	int64_t contentLength_ = 0;

private:
	std::string rspHeaders_ = "";
};

HttpHeaders::HttpHeaders(const std::string & headerString)
	:impl_(new (std::nothrow)Impl(headerString))
{
}

void HttpHeaders::setHeader(const std::string & key, const std::string & value)
{
	if (!impl_)
	{
		return;
	}
	return impl_->setHeader(key, value);
}

std::string HttpHeaders::getHeader(const std::string & key) const
{
	if (!impl_)
	{
		return "";
	}
	return impl_->getHeader(key);
}

void HttpHeaders::setHeaders(const HeadersType& headers)
{
	if (!impl_)
	{
		return;
	}
	return impl_->setHeaders(headers);
}

void HttpHeaders::setHeaders(const std::string & headers)
{
	if (!impl_)
	{
		return;
	}
	return impl_->setHeaders(headers);
}

HttpHeaders::HeadersType HttpHeaders::getHeaders() const
{
	if (!impl_)
	{
		return HeadersType();
	}
	return impl_->getHeaders();
}

HttpBody::HttpBody()
	:impl_(new (std::nothrow)Impl())
{
}

HttpBody::HttpBody(AutoBuffer & content)
	:impl_(new (std::nothrow)Impl(content))
{
}

void HttpBody::setContent(AutoBuffer & content)
{
	if (!impl_)
	{
		return;
	}
	return impl_->setContent(content);
}

AutoBuffer & HttpBody::getContent()
{
	//if (!impl_)
	//{
	//	return AutoBuffer();
	//}
	return impl_->getContent();
}

void HttpBody::setContentCallback(HttpContentCallback & callback, void *userData)
{
	if (!impl_)
	{
		return;
	}
	return impl_->setContentCallback(callback, userData);
}

HttpBody::HttpContentCallback HttpBody::getContentCallback()
{
	//if (!impl_)
	//{
	//	return HttpContentCallback();
	//}
	return impl_->getContentCallback();
}

void * HttpBody::getUserData()
{
	if (!impl_)
	{
		return nullptr;
	}
	return impl_->getUserData();
}

HttpClient::HttpClient()
	:impl_(new (std::nothrow) Impl)
{

}

int32_t HttpClient::init()
{
	return int32_t();
}

int32_t HttpClient::release()
{
	return int32_t();
}

void HttpClient::setUri(const std::string & uri)
{
	if (!impl_)
	{
		return;
	}
	return impl_->setUri(uri);
}

std::string HttpClient::getUri() const
{
	if (!impl_)
	{
		return "";
	}
	return impl_->getUri();
}

void HttpClient::setRequestHeaders(const HttpHeaders & httpHeaders)
{
	if (!impl_)
	{
		return;
	}
	return impl_->setRequestHeaders(httpHeaders);
}

HttpHeaders& HttpClient::getRequestHeaders()
{
	//if (!impl_)
	//{
	//	return HttpHeaders();
	//}
	return impl_->getRequestHeaders();
}

void HttpClient::setResponseHeaders(const HttpHeaders & httpHeaders)
{
	if (!impl_)
	{
		return;
	}
	return impl_->setResponseHeaders(httpHeaders);
}

HttpHeaders& HttpClient::getResponseHeaders()
{
	//if (!impl_)
	//{
	//	return HttpHeaders();
	//}
	return impl_->getResponseHeaders();
}

void HttpClient::setRequestBody(const HttpBody & httpBody)
{
	if (!impl_)
	{
		return;
	}
	return impl_->setRequestBody(httpBody);
}

HttpBody& HttpClient::getRequestBody()
{
	//if (!impl_)
	//{
	//	return HttpBody(AutoBuffer());
	//}
	return impl_->getRequestBody();
}

void HttpClient::setResponseBody(const HttpBody & httpBody)
{
	if (!impl_)
	{
		return;
	}
	return impl_->setResponseBody(httpBody);
}

HttpBody& HttpClient::getResponseBody()
{
	//if (!impl_)
	//{
	//	return HttpBody(AutoBuffer());
	//}
	return impl_->getResponseBody();
}

void HttpClient::setHttpMethod(const HTTP_METHOD method)
{
	if (!impl_)
	{
		return;
	}
	return impl_->setHttpMethod(method);
}

HTTP_METHOD HttpClient::getHttpMethod() const
{
	if (!impl_)
	{
		return HTTP_INVALID;
	}
	return impl_->getHttpMethod();
}

void HttpClient::setTimeout(const int64_t timeout)
{
	if (!impl_)
	{
		return;
	}
	return impl_->setTimeout(timeout);
}

int64_t HttpClient::getTimeout() const
{
	if (!impl_)
	{
		return 0;
	}
	return impl_->getTimeout();
}

void HttpClient::setConnectionTimeout(const int64_t timeout)
{
	if (!impl_)
	{
		return;
	}
	return impl_->setConnectionTimeout(timeout);
}

int64_t HttpClient::getConnectionTimeout() const
{
	if (!impl_)
	{
		return 0;
	}
	return impl_->getConnectionTimeout();
}

void HttpClient::setUseSSL(const bool useSSL)
{
	if (!impl_)
	{
		return;
	}
	return impl_->setUseSSL(useSSL);
}

bool HttpClient::getUseSSL() const
{
	if (!impl_)
	{
		return false;
	}
	return impl_->getUseSSL();
}

void HttpClient::setSSLVersion(const HTTP_SSLVERSION sslVersion)
{
	if (!impl_)
	{
		return;
	}
	return impl_->setSSLVersion(sslVersion);
}

HTTP_SSLVERSION HttpClient::getSSLVersion() const
{
	if (!impl_)
	{
		return SSLVERSION_Invalid;
	}
	return impl_->getSSLVersion();
}

void HttpClient::setVerifySSLHost(const bool verifyHost)
{
	if (!impl_)
	{
		return;
	}
	return impl_->setVerifySSLHost(verifyHost);
}

bool HttpClient::getVerifySSLHost() const
{
	if (!impl_)
	{
		return false;
	}
	return impl_->getVerifySSLHost();
}

void HttpClient::setVerifySSLPeer(const bool verifyPeer)
{
	if (!impl_)
	{
		return;
	}
	return impl_->setVerifySSLPeer(verifyPeer);
}

bool HttpClient::getVerifySSLPeer() const
{
	if (!impl_)
	{
		return false;
	}
	return impl_->getVerifySSLPeer();
}

void HttpClient::setCertPath(const std::wstring & certPath)
{
	if (!impl_)
	{
		return;
	}
	return impl_->setCertPath(certPath);
}

std::wstring HttpClient::getCertPath() const
{
	if (!impl_)
	{
		return L"";
	}
	return impl_->getCertPath();
}

void HttpClient::setUseProxy(const bool useProxy)
{
	if (!impl_)
	{
		return;
	}
	return impl_->setUseProxy(useProxy);
}

bool HttpClient::getUseProxy() const
{
	if (!impl_)
	{
		return false;
	}
	return impl_->getUseProxy();
}

void HttpClient::setProxyInfo(const HttpProxy & proxy)
{
	if (!impl_)
	{
		return;
	}
	return impl_->setProxyInfo(proxy);
}

HttpProxy HttpClient::getProxyInfo() const
{
	if (!impl_)
	{
		return HttpProxy();
	}
	return impl_->getProxyInfo();
}

int32_t HttpClient::sendRequest()
{
	if (!impl_)
	{
		return HTTP_OUT_OF_MEMORY;
	}
	return impl_->sendRequest();
}

void HttpClient::setContentLength(const int64_t length)
{
	if (!impl_)
	{
		return;
	}
	return impl_->setContentLength(length);
}

int64_t HttpClient::getContentLength() const
{
	if (!impl_)
	{
		return 0;
	}
	return impl_->getContentLength();
}

std::string HttpClient::base64Encode(const std::string & value)
{
	if (value.empty())
	{
		return "";
	}

	BIO *b64, *bio;
	BUF_MEM *bptr = NULL;	

	b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);

	BIO_write(bio, value.c_str(), value.size());
	BIO_flush(bio);

	BIO_get_mem_ptr(bio, &bptr);
	std::string out(bptr->data, bptr->length);

	BIO_free_all(bio);
	return out;
}

std::string HttpClient::base64Decode(const std::string & value)
{
	if (value.empty())
	{
		return "";
	}

	BIO *b64, *bio;

	b64 = BIO_new(BIO_f_base64());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

	bio = BIO_new_mem_buf(value.c_str(), value.size());
	bio = BIO_push(b64, bio);

	char *buf = new (std::nothrow)char[value.size()];
	if (buf == nullptr)
	{
		BIO_free_all(bio);
		return "";
	}

	int size = BIO_read(bio, buf, value.size());
	std::string out(buf, size);
	BIO_free_all(bio);
	delete buf;
	return out;
}
