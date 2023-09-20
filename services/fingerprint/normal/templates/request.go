package templates

import "gitlab.example.com/zhangweijie/component/services/fingerprint/normal/operators"

// Request 从模板发出的 HTTP 请求
type Request struct {
	// Operators inline 将结构体字段内联展开，将其字段作为父结构体的直接成员，而不是在序列化为YAML时以嵌套的方式表示。这样可以使生成的YAML更加扁平，减少嵌套层次。在反序列化时，也会将嵌套的YAML字段展开为结构体的直接成员。
	operators.Operators `yaml:",inline" json:",inline"`
	// description: |
	//   Path contains the path/s for the HTTP requests. It supports variables
	//   as placeholders.
	// examples:
	//   - name: Some example path values
	//     value: >
	//       []string{"{{BaseURL}}", "{{BaseURL}}/+CSCOU+/../+CSCOE+/files/file_list.json?path=/sessions"}

	// description: |
	//    HTTP 请求方法
	Method HTTPMethodTypeHolder `yaml:"method,omitempty" json:"method,omitempty" jsonschema:"title=method is the http request method,description=Method is the HTTP Request Method,enum=GET,enum=HEAD,enum=POST,enum=PUT,enum=DELETE,enum=CONNECT,enum=OPTIONS,enum=TRACE,enum=PATCH,enum=PURGE"`
	// description: |
	//   路径包含 HTTP 请求的路径, 支持变量作为占位符
	// examples:
	//   - name: Some example path values
	//     value: >
	//       []string{"{{BaseURL}}", "{{BaseURL}}/+CSCOU+/../+CSCOE+/files/file_list.json?path=/sessions"}
	Path []string `yaml:"path,omitempty" json:"path,omitempty" jsonschema:"title=path(s) for the http request,description=Path(s) to send http requests to"`
	// description: |
	//   包含 Raw 格式的 HTTP 请求
	//   raw才能使用注解 @timeout @host @once @tls-sni
	// examples:
	//   - name: Some example raw requests
	//     value: |
	//       []string{"GET /etc/passwd HTTP/1.1\nHost:\nContent-Length: 4", "POST /.%0d./.%0d./.%0d./.%0d./bin/sh HTTP/1.1\nHost: {{Hostname}}\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:71.0) Gecko/20100101 Firefox/71.0\nContent-Length: 1\nConnection: close\n\necho\necho\ncat /etc/passwd 2>&1"}
	Raw []string `yaml:"raw,omitempty" json:"raw,omitempty" jsonschema:"http requests in raw format,description=HTTP Requests in Raw Format"`
	// description: |
	//   HTTP 请求正文
	// examples:
	//   - name: Same Body for a Login POST request
	//     value: "\"username=test&password=test\""
	Body string `yaml:"body,omitempty" json:"body,omitempty" jsonschema:"title=body is the http request body,description=Body is an optional parameter which contains HTTP Request body"`
	// description: |
	//   当前请求的任何有效负载,有效负载支持提供有效负载列表的键值组合，或者也可以选择将单个文件作为负载提供，该负载将在运行时读取
	Payloads map[string]interface{} `yaml:"payloads,omitempty" json:"payloads,omitempty" jsonschema:"title=payloads for the http request,description=Payloads contains any payloads for the current request"`
	// description: |
	//   随请求一起发送的 HTTP 标头
	// examples:
	//   - value: |
	//       map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Content-Length": "1", "Any-Header": "Any-Value"}
	Headers map[string]string `yaml:"headers,omitempty" json:"headers,omitempty" jsonschema:"title=headers to send with the http request,description=Headers contains HTTP Headers to send with the request"`
	// description: |
	//   读取的 http 响应正文的最大大小（以字节为单位）
	// examples:
	//   - name: Read max 2048 bytes of the response
	//     value: 2048
	MaxSize int `yaml:"max-size,omitempty" json:"max-size,omitempty" jsonschema:"title=maximum http response body size,description=Maximum size of http response body to read in bytes"`
	// description: |
	//   可为原始部分中定义的所有请求启用 Cookie 重用
	CookieReuse bool `yaml:"cookie-reuse,omitempty" json:"cookie-reuse,omitempty" jsonschema:"title=optional cookie reuse enable,description=Optional setting that enables cookie reuse"`
	// description: |
	//   启用强制读取整个原始不安全请求正文，忽略任何指定的内容长度标头
	ForceReadAllBody bool `yaml:"read-all,omitempty" json:"read-all,omitempty" jsonschema:"title=force read all body,description=Enables force reading of entire unsafe http request body"`
	// description: |
	//  指定重定向后是否应遵循 HTTP 客户端。这可以与“max-redirects”结合使用，以控制HTTP请求重定向
	Redirects bool `yaml:"redirects,omitempty" json:"redirects,omitempty" jsonschema:"title=follow http redirects,description=Specifies whether redirects should be followed by the HTTP Client"`
	// description: |
	//   指定 HTTP 客户端是否只应遵循重定向到同一主机。这可以与“max-redirects”结合使用，以控制HTTP请求重定向
	HostRedirects bool `yaml:"host-redirects,omitempty" json:"host-redirects,omitempty" jsonschema:"title=follow same host http redirects,description=Specifies whether redirects to the same host should be followed by the HTTP Client"`
	// description: |
	//   指定是否使用 raw http 引擎发送不符合 RFC 的请求
	//   This uses the [rawhttp](https://github.com/projectdiscovery/rawhttp) engine to achieve complete
	//   control over the request, with no normalization performed by the client.
	Unsafe bool `yaml:"unsafe,omitempty" json:"unsafe,omitempty" jsonschema:"title=use rawhttp non-strict-rfc client,description=Unsafe specifies whether to use rawhttp engine for sending Non RFC-Compliant requests"`
	// description: |
	//  跳过对请求中未解析变量的检查
	SkipVariablesCheck bool `yaml:"skip-variables-check,omitempty" json:"skip-variables-check,omitempty" jsonschema:"title=skip variable checks,description=Skips the check for unresolved variables in request"`
	// description: |
	//  从内部提取器中提取的所有值
	IterateAll bool `yaml:"iterate-all,omitempty" json:"iterate-all,omitempty" jsonschema:"title=iterate all the values,description=Iterates all the values extracted from internal extractors"`
	// description: |
	//   一旦找到匹配项，就会停止执行请求和模板
	StopAtFirstMatch bool `yaml:"stop-at-first-match,omitempty" json:"stop-at-first-match,omitempty" jsonschema:"title=stop at first match,description=Stop the execution after a match is found"`
}
