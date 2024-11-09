# Advanced Logger++ Filters 

Logger++ is a multithreaded logging extension for Burp Suite. Here is a list of custom filters to check for potential vulnerabilities.

## Table of Contents
- [PostMessage](#postmessage)
- [ClientSide_RaceCondition](#clientside_racecondition)
- [API_SOAP](#api_soap)
- [All_Access_Control](#all_access_control)
- [OpenRedirect](#openredirect)
- [SSRF](#ssrf)
- [HTTP_Headers_Manipulation](#http_headers_manipulation)
- [Telerik_CVE](#telerik_cve)
- [CSTI&SSTI](#cstissti)
- [JSONP](#jsonp)
- [CORS](#cors)
- [LFI](#lfi)
- [Web_Cache](#web_cache)
- [OpenRedirect_Params](#openredirect_params)
- [RCE_Params](#rce_params)
- [FDT&SSRF_Params](#fdtssrf_Params)

---

### **PostMessage**
Check for open communication between windows without restrictions on origin

**Filter:**  
`Response.Body CONTAINS "postMessage" OR Response.Body CONTAINS "addEventListener"`

---

### **ClientSide_RaceCondition**
*Identify risky usage of `setTimeout` and `setInterval` that could lead to race conditions (Check2Act)*

**Filter:**  
`Response.Body CONTAINS "setTimeout" OR Response.Body CONTAINS "setInterval"`

---

### **API_SOAP**
*Detect SOAP API usage*

**Filter:**  
`Request.Body CONTAINS "wsdl" OR Request.URL CONTAINS "wsdl OR Response.Body CONTAINS "wsdl" OR Response.Headers CONTAINS "wsdl"`

---

### **All_Access_Control**
*Check for potential All misconfigurations about Access-Control*

**Filter:**  
`Response.Headers CONTAINS "Access-Control"`

---

### **OpenRedirect**
*Check for open redirect vulnerabilities*

**Filter:**  
`(Request.Query MATCHES ".*(http%3A%2F%2F|https%3A%2F%2F)?(www.)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}.*" OR Request.Body MATCHES ".*(http%3A%2F%2F|https%3A%2F%2F)?(www.)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}.*") AND Response.Status IN [301, 302]`

---

### **SSRF**
*Detect potential SSRF vulnerabilities*

**Filter:**  
`(Request.Query MATCHES ".*(http%3A%2F%2F|https%3A%2F%2F)?(www.)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}.*" OR Request.Body MATCHES ".*(http%3A%2F%2F|https%3A%2F%2F)?(www.)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}.*")`

---

### **HTTP_Headers_Manipulation**
*Before running this check, use various tools to add headers to the request(https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/special-http-headers#headers-to-change-location), and then inspect the response for suspicious headers or content. this headers indicating potential misconfigurations.*

**Filter:**  
`Response.Body CONTAINS "h4ck3er.com" OR Response.Body CONTAINS "127.0.0.2" OR Response.Body CONTAINS "127.0.0.3" OR Response.Body CONTAINS "127.0.0.4" OR Response.Body CONTAINS "127.0.0.5" OR Response.Body CONTAINS "127.0.0.6" OR Response.Body CONTAINS "127.0.0.7" OR Response.Headers CONTAINS "h4ck3er.com" OR Response.Headers CONTAINS "127.0.0.2" OR Response.Headers CONTAINS "127.0.0.3" OR Response.Headers CONTAINS "127.0.0.4" OR Response.Headers CONTAINS "127.0.0.5" OR Response.Headers CONTAINS "127.0.0.6" OR Response.Headers CONTAINS "127.0.0.7" OR Response.Headers CONTAINS "localhost"`

---

### **Telerik_CVE**
*Detect potential vulnerabilities related to Telerik components*

**Filter:**  
`Request.URL CONTAINS "WebResource.axd" OR Request.URL CONTAINS "Telerik.Web.UI" OR Request.URL CONTAINS "ScriptResource.axd"`

---

### **CSTI&SSTI**
*First, use tools like AutoRepeater(https://github.com/nccgroup/AutoRepeater) to input for example `{{110*110}}` or ... in the fields, then check the response for the number 12100, which indicates a potential client-side or server-side template injection vulnerability.*

**Filter:**  
`Response.Body CONTAINS "12100"`

---

### **JSONP**
*Detect JSONP usage, which may indicate a potential XSS risk.*

**Filter:**  
`Request.URL CONTAINS "callback" OR Request.URL CONTAINS "jsonp" OR Response.Body CONTAINS "jsonp"`

---

### **CORS**
*Detect CORS headers usage, which may indicate a potential CORS vulnerability.*

**Filter:**  
`Response.Headers CONTAINS "Access-Control-Allow-Origin" OR Response.Headers CONTAINS "Access-Control-Allow-Credential"`

---

### **LFI**
*Detect Local File Inclusion vulnerabilities*

**Filter:**  
`Request.Query MATCHES ".*\.[a-z]{1,5}.*" OR Request.Body MATCHES ".*\.[a-z]{1,5}.*"`

---

### **Web_Cache**
*Detect cache pages to test all cache vulnerabilities.*

**Filter:**  
`Response.Headers CONTAINS "X-Cache"`

---

### **OpenRedirect_Params**
*Detect Open Redirects with suspicious URL parameters. (Based on OWASP Top 25 Parameters)*

**Filter:**  
`Request.Body CONTAINS "dir" OR Request.URL CONTAINS "dir" OR Request.Body CONTAINS "return" OR Request.URL CONTAINS "return" OR Request.Body CONTAINS "url" OR Request.URL CONTAINS "url" OR Request.Body CONTAINS "next" OR Request.URL CONTAINS "next" OR Request.Body CONTAINS "dest" OR Request.URL CONTAINS "dest" OR Request.Body CONTAINS "target" OR Request.URL CONTAINS "target" OR Request.Body CONTAINS "continue" OR Request.URL CONTAINS "continue" OR Request.Body CONTAINS "view" OR Request.URL CONTAINS "view"`

---

### **RCE_Params**
*Check for potential Remote Code Execution vulnerabilities. (Based on OWASP Top 25 Parameters)*

**Filter:**  
`Request.Query CONTAINS "cmd" OR Request.Query CONTAINS "exec" OR Request.Query CONTAINS "command" OR Request.Query CONTAINS "execute" OR Request.Query CONTAINS "ping" OR Request.Query CONTAINS "query" OR Request.Query CONTAINS "jump" OR Request.Query CONTAINS "code" OR Request.Query CONTAINS "reg" OR Request.Query CONTAINS "do" OR Request.Query CONTAINS "func" OR Request.Query CONTAINS "arg" OR Request.Query CONTAINS "option" OR Request.Query CONTAINS "load" OR Request.Query CONTAINS "process" OR Request.Query CONTAINS "step" OR Request.Query CONTAINS "read" OR Request.Query CONTAINS "function" OR Request.Query CONTAINS "req" OR Request.Query CONTAINS "feature" OR Request.Body CONTAINS "exe" OR Request.Body CONTAINS "run" OR Request.Body CONTAINS "print" OR Request.Body CONTAINS "payload" OR Request.Body CONTAINS "cmd" OR Request.Body CONTAINS "exec" OR Request.Body CONTAINS "command" OR Request.Body CONTAINS "execute" OR Request.Body CONTAINS "ping" OR Request.Body CONTAINS "Body" OR Request.Body CONTAINS "jump" OR Request.Body CONTAINS "code" OR Request.Body CONTAINS "reg" OR Request.Body CONTAINS "do" OR Request.Body CONTAINS "func" OR Request.Body CONTAINS "arg" OR Request.Body CONTAINS "option" OR Request.Body CONTAINS "load" OR Request.Body CONTAINS "process" OR Request.Body CONTAINS "step" OR Request.Body CONTAINS "read" OR Request.Body CONTAINS "function" OR Request.Body CONTAINS "req" OR Request.Body CONTAINS "feature" OR Request.Body CONTAINS "exe" OR Request.Body CONTAINS "run" OR Request.Body CONTAINS "print" OR Request.Body CONTAINS "payload"`

---

### **FDT&SSRF_Params**
*Detect Directory Traversal and SSRF vulnerabilities. (Based on OWASP Top 25 Parameters)*

**Filter:**  
`Request.Query CONTAINS "dir" OR Request.Query CONTAINS "date" OR Request.Query CONTAINS "detail" OR Request.Query CONTAINS "file" OR Request.Query CONTAINS "path" OR Request.Query CONTAINS "download" OR Request.Query CONTAINS "folder" OR Request.Query CONTAINS "include" OR Request.Query CONTAINS "require" OR Request.Query CONTAINS "show" OR Request.Query CONTAINS "doc" OR Request.Query CONTAINS "site" OR Request.Query CONTAINS "type" OR Request.Query CONTAINS "view" OR Request.Query CONTAINS "content" OR Request.Query CONTAINS "document" OR Request.Query CONTAINS "layout" OR Request.Query CONTAINS "conf" OR Request.Query CONTAINS "link" OR Request.Query CONTAINS "locate" OR Request.Body CONTAINS "dir" OR Request.Body CONTAINS "date" OR Request.Body CONTAINS "detail" OR Request.Body CONTAINS "file" OR Request.Body CONTAINS "path" OR Request.Body CONTAINS "download" OR Request.Body CONTAINS "folder" OR Request.Body CONTAINS "include" OR Request.Body CONTAINS "require" OR Request.Body CONTAINS "show" OR Request.Body CONTAINS "doc" OR Request.Body CONTAINS "site" OR Request.Body CONTAINS "type" OR Request.Body CONTAINS "view" OR Request.Body CONTAINS "content" OR Request.Body CONTAINS "document" OR Request.Body CONTAINS "layout" OR Request.Body CONTAINS "conf" OR Request.Body CONTAINS "link" OR Request.Body CONTAINS "locate" OR Request.Query CONTAINS "window" OR Request.Query CONTAINS "val" OR Request.Query CONTAINS "domain" OR Request.Query CONTAINS "host" OR Request.Query CONTAINS "html" OR Request.Query CONTAINS "data" OR Request.Body CONTAINS "window" OR Request.Body CONTAINS "val" OR Request.Body CONTAINS "domain" OR Request.Body CONTAINS "host" OR Request.Body CONTAINS "html" OR Request.Body CONTAINS "data"`

---

Each section includes a brief description and the exact filters used to detect these vulnerabilities in your codebase.
