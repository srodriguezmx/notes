---
share: "true"
---

# Intro

- API is Leading and simpler attack vector 
- Exposes data to Internet 
- 2023 API top ten update 

## Bugbounty Writeups 

- PentesterLand Writeups Compilation: [https://pentester.land/writeups/](https://pentester.land/writeups/) 
- HackerOne Hacktivity: [https://hackerone.com/hacktivity](https://hackerone.com/hacktivity) 
- Awesome Bugbounty Writeups Repo:[https://github.com/devanshbatham/Awesome-Bugbounty-Writeups](https://github.com/devanshbatham/Awesome-Bugbounty-Writeups)
## Incidente List

- [2018 USPS Data Leak](https://krebsonsecurity.com/2018/11/usps-site-exposed-data-on-60-million-users/%C2%A0)
- [2019 Venmo Public API Scraping](https://techcrunch.com/2019/06/16/millions-venmo-transactions-scraped/)
- [2021 Peloton API Data Leak](https://threatpost.com/pelotons-spilled-riders-data/165880/)
- [2021 Parler API Data Leak](https://www.wired.com/story/parler-hack-data-public-posts-images-video/)
- [2021 LinkedIn API Data Leak](https://restoreprivacy.com/linkedin-data-leak-700-million-users/)
- [2022 Coinbase Authorization Flaw](https://securityboulevard.com/2022/02/coinbase-fixes-vulnerable-api-that-let-you-sell-bitcoin-you-didnt-own/)
- [2022 Optus API Data Breach](https://www.bbc.com/news/world-australia-63056838)
- [2022 Toyota API Exposure](https://www.bleepingcomputer.com/news/security/researcher-breaches-toyota-supplier-portal-with-info-on-14-000-partners/)
- [2023 EatonWorks Toyota Research Disclosure](https://eaton-works.com/2023/02/06/toyota-gspims-hack/)
- [2023 T-mobile API Data Exposure](https://venturebeat.com/security/t-mobile-data-breach-shows-api-security-cant-be-ignored/)

## Mapped to External Sources

|                                                           |                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **OWASP Top 10**                                          | **External Reference**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| API1:2023 Broken Object Level Authorization               | - [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)<br>- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| API2:2023 Broken Authentication                           | - [CWE-204: Observable Response Discrepancy](https://cwe.mitre.org/data/definitions/204.html)<br>- [CWE-307: Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| API3:2023 Broken Object Property Level Authorization      | - [CWE-213: Exposure of Sensitive Information Due to Incompatible Policies](https://cwe.mitre.org/data/definitions/213.html)<br>- [CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)<br>- [API3:2019 Excessive Data Exposure - OWASP API Security Top 10 2019](https://github.com/OWASP/API-Security/blob/master/2019/en/src/0xa3-excessive-data-exposure.md)<br>- [API6:2019 - Mass Assignment - OWASP API Security Top 10 2019](https://github.com/OWASP/API-Security/blob/master/2019/en/src/0xa6-mass-assignment.md)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| API4:2023 Unrestricted Resource Consumption               | - [CWE-770: Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html)<br>- [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)<br>- [CWE-799: Improper Control of Interaction Frequency](https://cwe.mitre.org/data/definitions/799.html)<br>- [NIST Security Strategies for Microservices-based Application Systems](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-204.pdf)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| API5:2023 Broken Function Level Authorization             | - [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)<br>- [OWASP Top 10 2013: A7: Missing Function Level Access Control](https://github.com/OWASP/Top10/raw/master/2013/OWASP%20Top%2010%20-%202013.pdf)<br>- [OWASP Guidance: Forced Browsing](https://owasp.org/www-community/attacks/Forced_browsing)<br>- [OWASP Guidance: Access Control](https://owasp.org/www-community/Access_Control)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| API6:2023 Unrestricted Access to Sensitive Business Flows | - [API10:2019 Insufficient Logging & Monitoring](https://owasp.org/API-Security/editions/2019/en/0xaa-insufficient-logging-monitoring/)<br>- [OWASP Automated Threats to Web Applications](https://owasp.org/www-project-automated-threats-to-web-applications/)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| API6:2023 Server Side Request Forgery                     | - [CWE-918: Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)<br>- [URL confusion vulnerabilities in the wild: Exploring parser inconsistencies, Snyk](https://snyk.io/blog/url-confusion-vulnerabilities/)<br>- [Server Side Request Forgery](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)<br>- [Server-Side Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| API8:2023 Security Misconfiguration                       | - [CWE-2: Environmental Security Flaws](https://cwe.mitre.org/data/definitions/2.html)<br>- [CWE-16: Configuration](https://cwe.mitre.org/data/definitions/16.html)<br>- [CWE-209: Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html)<br>- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)<br>- [CWE-388: Error Handling](https://cwe.mitre.org/data/definitions/388.html)<br>- [CWE-444: Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')](https://cwe.mitre.org/data/definitions/444.html)<br>- [CWE-942: Permissive Cross-domain Policy with Untrusted Domains](https://cwe.mitre.org/data/definitions/942.html)<br>- [NIST Guide to General Server Security](https://csrc.nist.gov/publications/detail/sp/800-123/final)<br>- [Let's Encrypt: a free, automated, and open Certificate Authority](https://letsencrypt.org/)<br>- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)<br>- [Configuration and Deployment Management Testing - Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/README)<br>- [Testing for Error Handling - Web Securi](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/README) |
| API9:2023 Improper Inventory Management                   | - [CWE-1059: Incomplete Documentation](https://cwe.mitre.org/data/definitions/1059.html)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| API10:2023 Unsafe Consumption of APIs                     | - [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)<br>- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |

Understanding the external sources and how they are associated with the given OWASP[

![](https://kajabi-storefronts-production.kajabi-cdn.com/kajabi-storefronts-production/themes/2153183333/assets/text.png?168866273826087)

BBH_API_Writeups_JSON



](https://university.apisec.ai/courses/downloads/2154027563/bbh_api_dataset-txt)


## Risk Rating

- Review Guide to Risk Rating OWASP, find more info

https://web.archive.org/web/20190503095606/https://www.owasp.org/index.php/OWASP_Risk_Rating_Methodology

https://owasp.org/www-project-risk-assessment-framework/

![[Pasted image 20241220170448.png|Pasted image 20241220170448.png]]
## 2019 Risk Scores

|                                               |                    |                |                   |               |             |
| --------------------------------------------- | ------------------ | -------------- | ----------------- | ------------- | ----------- |
| **Risk**                                      | **Exploitability** | **Prevalence** | **Detectability** | **Technical** | **Overall** |
| API1:2019 Broken Object Level Authorization   | 3                  | 3              | 2                 | 3             | 11          |
| API2:2019 Broken User Authentication          | 3                  | 2              | 2                 | 3             | 10          |
| API3:2019 Excessive Data Exposure             | 3                  | 2              | 2                 | 2             | 9           |
| API4:2019 Lack of Resources & Rate Limiting   | 2                  | 3              | 3                 | 2             | 10          |
| API5:2019 Broken Function Level Authorization | 3                  | 2              | 1                 | 2             | 8           |
| API6:2019 - Mass Assignment                   | 2                  | 2              | 2                 | 2             | 8           |
| API7:2019 Security Misconfiguration           | 3                  | 3              | 3                 | 2             | 11          |
| API8:2019 Injection                           | 3                  | 2              | 3                 | 3             | 11          |
| API9:2019 Improper Assets Management          | 3                  | 3              | 2                 | 2             | 10          |
| API10:2019 Insufficient Logging & Monitoring  | 2                  | 3              | 1                 | 2             | 8           |

## 2023 Risk Scores

|                                                           |                    |                |                   |               |             |
| --------------------------------------------------------- | ------------------ | -------------- | ----------------- | ------------- | ----------- |
| **Risk**                                                  | **Exploitability** | **Prevalence** | **Detectability** | **Technical** | **Overall** |
| API1:2023 Broken Object Level Authorization               | 3                  | 3              | 3                 | 2             | 11          |
| API2:2023 Broken Authentication                           | 3                  | 2              | 3                 | 3             | 11          |
| API3:2023 Broken Object Property Level Authorization      | 3                  | 2              | 3                 | 2             | 10          |
| API4:2023 Unrestricted Resource Consumption               | 2                  | 3              | 3                 | 3             | 11          |
| API5:2023 Broken Function Level Authorization             | 3                  | 2              | 3                 | 3             | 11          |
| API6:2023 Unrestricted Access to Sensitive Business Flows | 3                  | 3              | 2                 | 2             | 10          |
| API7:2023 Server Side Request Forgery                     | 3                  | 2              | 3                 | 2             | 10          |
| API8:2023 Security Misconfiguration                       | 3                  | 3              | 3                 | 3             | 12          |
| API9:2023 Improper Inventory Management                   | 3                  | 3              | 2                 | 2             | 10          |
| API10:2023 Unsafe Consumption of APIs                     | 3                  | 2              | 2                 | 3             | 10          |


# OWASP API1:2023 Broken Object Level Authorization (BOLA)

## What is it ?


BOLA vulnerabilities occur when an API provider does not have sufficient controls in place to enforce authorization. In other words, API users should only have access to sensitive resources that belong to them. When BOLA is present an attacker will be able to access the sensitive data of other users.


![[Pasted image 20241220171524.png|Pasted image 20241220171524.png]]

## Impact 

Unauthorized access can result in data disclosure to unauthorized parties, data loss, or data manipulation. Unauthorized access to objects can also lead to full account takeover.


## Weakness Examples 

Attackers can exploit API endpoints that are vulnerable to broken object-level authorization by manipulating the ID of an object that is sent within the request. Object IDs can be anything from sequential integers, UUIDs, or generic strings. Regardless of the data type, they are easy to identify in the request target (path or query string parameters), request headers, or even as part of the request payload.


``` http
[https://herohospital.com/api/v3/users?id=2727](https://herohospital.com/api/v3/users?id=2727) and receives the following response:

`{`

`"id": "2727",`

`"fname": "Bruce",`

`"lname": "Wayne",`

 `"dob": "1975-02-19",`

`"username": "bman",`

`"diagnosis": "Depression",`

`}`

[https://herohospital.com/api/v3/users?id=2728](https://herohospital.com/api/v3/users?id=2728) and receives the following response:

`{`

`"id": "2728",`

`"fname": "Harvey",`

`"lname": "Dent",`

 `"dob": "1979-03-30",`

`"username": "twoface",`

`"diagnosis": "Dissociative Identity Disorder",`

`}`


```

``` http

- GET /api/user/**1**
- GET /user/account/find?**user_id=aE1230000token**
- POST /company/account/**Apple**/balance
- GET /admin/settings/account/**bman**

In these instances, you can probably guess other potential resources, like the following, by altering the bold values:

- GET /api/resource/**3**
- GET /user/account/find?user_id=**23**
- POST /company/account/**Google**/balance
- POST /admin/settings/account/**hdent**

```


![[Pasted image 20241220171849.png|Pasted image 20241220171849.png]]

## [OWASP Preventative Measures](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)


- Implement a proper authorization mechanism that relies on the user policies and hierarchy.
- Use the authorization mechanism to check if the logged-in user has access to perform the requested action on the record in every function that uses an input from the client to access a record in the database.
- Prefer the use of random and unpredictable values as GUIDs for records' IDs._
- Write tests to evaluate the vulnerability of the authorization mechanism. Do not deploy changes that make the tests fail.

## Additional Resources

- [CWE-284: Improper Access Control](https://cwe.mitre.org/data/definitions/284.html)
- [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
- [CWE-639: Authorization Bypass Through User-Controlled Key](https://cwe.mitre.org/data/definitions/639.html)
- [Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
- [Authorization Testing Automation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Testing_Automation_Cheat_Sheet.html)
- [Web Security Academy: Access Controls](https://portswigger.net/web-security/access-control)
- [APIsec What is BOLA?](https://www.apisec.ai/blog/broken-object-level-authorization)
- [BOLA Deep Dive by Inon Shkedy](https://inonst.medium.com/a-deep-dive-on-the-most-critical-api-vulnerability-bola-1342224ec3f2)


# OWASP API2:2023 Broken Authentication

## Whas si it 

 Refers to any weakness within the API authentication process. All APIs that contain sensitive information should have some mechanism to authenticate users. Authentication is the process that is used to verify the identity of an API user, whether that user is a person, device, or system.

## Impact

Attackers can gain complete control of other users’ accounts in the system, read their personal data, and perform sensitive actions on their behalf. Systems are unlikely to be able to distinguish attackers’ actions from legitimate user ones.

The authentication process is often one of the first lines of defense for APIs and when this mechanism is vulnerable, it can lead to a data breach.

## Weakness Examples 

- Weak password Policy 
	- Allows users to create simple passwords
	- Allows brute force attempts against user accounts
	- Allows users to change their password without asking for password confirmation
	- Allows users to change their account email without asking for password confirmation
	- Discloses token or password in the URL
	- GraphQL queries allow for many authentication attempts in a single request
	- Lacking authentication for sensitive requests
- Weak authentication mechanisms
	- Credential Stuffing (No account blocking)
		- Allows users to brute force many username and password combinations
	- Predictable tokens
		- - Using incremental or guessable token IDs
- Misconfiguration JSON Web Tokes  
	- API provider accepts unsigned JWT tokens
	- API provider does not check JWT expiration
	- API provider discloses sensitive information within the encoded JWT payload
	- JWT is signed with a weak key

## OWASP Preventative Measures


- Make sure you know all the possible flows to authenticate to the API (mobile/ web/deep links that implement one-click authentication/etc.). Ask your engineers what flows you missed.
- Read about your authentication mechanisms. Make sure you understand what and how they are used.==OAuth is not authentication, and neither are API keys.==
- Don't reinvent the wheel in authentication, token generation, or password storage. Use the standards.
- Credential recovery/forgot password endpoints should be treated as login endpoints in terms of brute force, rate limiting, and lockout protections.
- Require re-authentication for sensitive operations (e.g. changing the account owner email address/2FA phone number).
- Use the [OWASP Authentication Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html).
- Where possible, implement multi-factor authentication.
- Implement anti-brute force mechanisms to mitigate credential stuffing, dictionary attacks, and brute force attacks on your authentication endpoints. This mechanism should be stricter than the regular rate limiting mechanisms on your APIs.
- Implement [account lockout](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/03-Testing_for_Weak_Lock_Out_Mechanism(OTG-AUTHN-003))/captcha mechanisms to prevent brute force attacks against specific users. Implement weak-password checks.
- API keys should not be used for user authentication. They should only be used for [API clients](https://cloud.google.com/endpoints/docs/openapi/when-why-api-key) authentication.

## Additional Resources

- [CWE-204: Observable Response Discrepancy](https://cwe.mitre.org/data/definitions/204.html)
- [CWE-307: Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [Key Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html)
- [Credential Stuffing](https://owasp.org/www-community/attacks/Credential_stuffing)
- [Web Security Academy: Authentication](https://portswigger.net/web-security/authentication)
- [Web Security Academy: JWT Attacks](https://portswigger.net/web-security/jwt)


# API3:2023 Broken Object Property Level Autorization 


## What is it?

(BOPLA) is the combination of two items from the 2019 OWASP API Security Top Ten, excessive data exposure and mass assignment.

Excessive Data Exposure takes place when an API provider responds to a request with an entire data object. This is particularly valid for REST APIs. For other protocols such as GraphQL, it may require crafted requests to specify which properties should be returned.

Mass Assignment is a weakness that allows for user input to alter sensitive object properties. If, for example, an API uses a special property to create admin accounts only authorized users should be able to make requests that successfully alter those administrative properties. It could update his account balance.

## Impact

Unauthorized access to private/sensitive object properties may result in data disclosure, data loss, or data corruption. Under certain circumstances, unauthorized access to object properties can lead to privilege escalation or partial/full account takeover.

## Weakness Examples


- Excessive data exposure
	- if an API consumer requests information for their user account and receives information about other user accounts as well, the API is exposing excessive data.
	- All you need to do to detect excessive data exposure is test your target API endpoints and review the information sent in response.
- Mass assignment
	- an application might have ==account update== functionality that the user should use only to update their username, password, and address. If the consumer can include other parameters in a request related to their account, such as the account privilege level or sensitive information like account balances, and the application accepts those parameters without checking them against a whitelist of permitted actions, the consumer could take advantage of this weakness to change these values.


``` http
“Password”:

{

“User”: “hapi_hacker”,

“Password”: “GreatPassword123”

}
-------------------------------
{

“User”: “hapi_hacker”,

“Password”: “GreatPassword123”,

“isAdmin”: true

}
```


## [OWASP Preventative Measures](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/)

- When exposing an object using an API endpoint, always make sure that the user should have access to the object's properties you expose.
- Avoid using generic methods such as to_json() and to_string(). Instead, cherry-pick specific object properties you specifically want to return.
- If possible, avoid using functions that automatically bind a client's input into code variables, internal objects, or object properties ("Mass Assignment").
- Allow changes only to the object's properties that should be updated by the client.
- Implement a schema-based response validation mechanism as an extra layer of security. As part of this mechanism, define and enforce data returned by all API methods.
- Keep returned data structures to the bare minimum, according to the business/functional requirements for the endpoint.

## Additional Resources

- [API3:2019 Excessive Data Exposure - OWASP API Security Top 10 2019](https://github.com/OWASP/API-Security/blob/master/2019/en/src/0xa3-excessive-data-exposure.md)
- [API6:2019 - Mass Assignment - OWASP API Security Top 10 2019](https://github.com/OWASP/API-Security/blob/master/2019/en/src/0xa6-mass-assignment.md)
- [Mass Assignment Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html)
- [CWE-213: Exposure of Sensitive Information Due to Incompatible Policies](https://cwe.mitre.org/data/definitions/213.html)
- [CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes](https://cwe.mitre.org/data/definitions/915.html)


## API4:2023 Unrestricted Resource Consumption  

## Whats is it?

An API issue where the provider of the API does not have safeguards in place to prevent excessive use of their API. Exploitation requires simple API requests. Multiple concurrent requests can be performed from a single local computer or by using cloud computing resources.

## Impact

Exploitation can lead to DoS due to resource starvation, but it can also lead to operational costs increase such as those related to the infrastructure due to higher CPU demand, increasing cloud storage needs, etc.

Every API request has a technical and financial cost.

When API providers do not enforce limitations on resource consumption there is an increased risk of denial of service (DoS), distributed denial of service (DDoS), unnecessary financial costs, and degradation of the quality of service to other users. In addition, rate limiting plays an important role in the monetization and availability of APIs.
## Weakness Examples 

An API is vulnerable if at least one of the following limits is missing or set inappropriately (e.g. too low/high):

- Execution timeouts
- Maximum allocable memory
- Maximum number of file descriptors
- Maximum number of processes
- Maximum upload file size
- Number of operations to perform in a single API client request (e.g. GraphQL batching)
- Number of records per page to return in a single request-response
- Third-party service providers' spending limit

## [OWASP Preventative Measures](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/)

- Docker makes it easy to limit [memory](https://docs.docker.com/config/containers/resource_constraints/#memory), [CPU](https://docs.docker.com/config/containers/resource_constraints/#cpu), [number of restarts](https://docs.docker.com/engine/reference/commandline/run/#restart-policies---restart), [file descriptors, and processes](https://docs.docker.com/engine/reference/commandline/run/#set-ulimits-in-container---ulimit).
- Implement a limit on how often a client can call the API within a defined timeframe.
- Notify the client when the limit is exceeded by providing the limit number and the time at which the limit will be reset.
- Add proper server-side validation for query string and request body parameters, specifically the one that controls the number of records to be returned in the response.
- Define and enforce maximum size of data on all incoming parameters and payloads such as maximum length for strings and maximum number of elements in arrays.

## Additional Resources

- ["Availability" - Web Service Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Web_Service_Security_Cheat_Sheet.html#availability)
- ["DoS Prevention" - GraphQL Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html#dos-prevention)
- ["Mitigating Batching Attacks" - GraphQL Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html#mitigating-batching-attacks)
- [CWE-770: Allocation of Resources Without Limits or Throttling](https://cwe.mitre.org/data/definitions/770.html)
- [CWE-400: Uncontrolled Resource Consumption](https://cwe.mitre.org/data/definitions/400.html)
- [CWE-799: Improper Control of Interaction Frequency](https://cwe.mitre.org/data/definitions/799.html)
- "Rate Limiting (Throttling)" - [Security Strategies for Microservices-based Application Systems](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-204.pdf), NIST


## API5: Broken Function Level Authorization 

## Whats is It?

Is a vulnerability where API functions have insufficient access controls. BFLA is about altering or deleting data. In addition, a vulnerable API would allow an attacker to perform actions of other roles including administrative actions.

 An API susceptible to BOLA would allow an attacker the ability to see what is in the bank account of another user, while the same API vulnerable to BFLA would allow an attacker to transfer funds from other users' accounts to their own.

## Impact

Such flaws allow attackers to access unauthorized functionality. Administrative functions are key targets for this type of attack and may lead to data disclosure, data loss, or data corruption. Ultimately, it may lead to service disruption.


## Weakness Examples 

BFLA can be exploited for unauthorized use of lateral functions, or a similarly privileged group, or it could be exploited for privilege escalation, where an attacker can use the functions of a more privileged group.

If an API has different privilege levels, it may use different endpoints to perform privileged actions. For example, a bank may use the /{userid}/account/balance endpoint for a user wishing to access their account information and the /admin/account/{userid} endpoint for an administrator that needs to access user account information.

An API won’t always use administrative endpoints for administrative functionality. Instead, the functionality could be based on HTTP request methods like GET, POST, PUT, and DELETE. If a provider doesn’t restrict the HTTP methods an attacker can use, simply making an unauthorized request with a different method could indicate a BFLA vulnerability.

When testing for BFLA, look for any functionality that an attacker could use to their advantage. These functions include but are not limited to, altering user accounts, deleting user resources, and gaining access to restricted endpoints.

## [OWASP Preventative Measures](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/)

_Your application should have a consistent and easy-to-analyze authorization module that is invoked from all your business functions. Frequently, such protection is provided by one or more components external to the application code._

- The enforcement mechanism(s) should deny all access by default, requiring explicit grants to specific roles for access to every function.
- Review your API endpoints against function level authorization flaws, while keeping in mind the business logic of the application and groups hierarchy.
- Make sure that all of your administrative controllers inherit from an administrative abstract controller that implements authorization checks based on the user's group/role.
- Make sure that administrative functions inside a regular controller implement authorization checks based on the user's group and role.


## Additional Resources

- [CWE-285: Improper Authorization](https://cwe.mitre.org/data/definitions/285.html)
- [Forced Browsing](https://owasp.org/www-community/attacks/Forced_browsing)
- "A7: Missing Function Level Access Control", [OWASP Top 10 2013](https://github.com/OWASP/Top10/raw/master/2013/OWASP%20Top%2010%20-%202013.pdf)
- [OWASP Community Guide for Access Control](https://owasp.org/www-community/Access_Control)



# API6:2023 Unrestricted Access To Sensitive Business Flows 


## Keyword 

**Depleting Stock** 
 
Exploit API into attackers advantage, example buying all tickets from a concert as soon as they available.   

## What is It?

Represents the risk of an attacker being able to identify and exploit API-driven workflows. If vulnerable an attacker will be able to leverage an organization's API request structure to obstruct other users. This obstruction could come in the form of spamming other users, depleting the stock of highly sought-after items, or preventing other users from using expected application functionality.

## Impact 

In general technical impact is not expected. Exploitation might hurt the business in different ways, for example: prevent legitimate users from purchasing a product, or lead to inflation in the internal economy of a game.


## Weakness Examples 

- A purchase flow for a web application does not restrict access to a purchase process then a scalper could automate requests to instantly drain the stock of an item down to nothing.
- If a flow has a CAPTCHA mechanism that requires human interaction then the automated requests could be interrupted and slow down automated purchasing.

## [OWASP Preventative Measures](https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/)

The mitigation planning should be done in two layers:_

- Business - identify the business flows that might harm the business if they are excessively used.
- Engineering - choose the right protection mechanisms to mitigate the business risk.

Some of the protection mechanisms are more simple while others are more difficult to implement. The following methods are used to slow down automated threats:

- Device fingerprinting: denying service to unexpected client devices (e.g headless browsers) tends to make threat actors use more sophisticated solutions, thus more costly for them
- Human detection: using either captcha or more advanced biometric solutions (e.g. typing patterns)
- Non-human patterns: analyze the user flow to detect non-human patterns (e.g. the user accessed the "add to cart" and "complete purchase" functions in less than one second)_
- Consider blocking IP addresses of Tor exit nodes and well-known proxies

Secure and limit access to APIs that are consumed directly by machines (such as developer and B2B APIs). They tend to be an easy target for attackers because they often don't implement all the required protection mechanisms.

## Additional Resources

- [OWASP Automated Threats to Web Applications](https://owasp.org/www-project-automated-threats-to-web-applications/)
- [API10:2019 Insufficient Logging & Monitoring](https://github.com/OWASP/API-Security/blob/master/2019/en/src/0xaa-insufficient-logging-monitoring.md)



## API7:2023 **SSRF**

## Keyword

**An attacker could supply URLs** 

**SSRF**

## What is It?

Is a vulnerability that takes place when a user is able to control the remote resources retrieved by an application.  An attacker can use an API to supply their own input, in the form of a URL, to control the remote resources that are retrieved by the targeted server.

Exploitation requires the attacker to find an API endpoint that accesses a URI that’s provided by the client.

Lack of or improper validation of such URIs are common issues. Regular API requests and response analysis will be required to detect the issue.
## Impact

Successful exploitation might lead to internal services enumeration (e.g. port scanning), information disclosure, bypassing firewalls, or other security mechanisms. In some cases, it can lead to DoS or the server being used as a proxy to hide malicious activities.


## Weakness Examples 

```http

Intercepted Request:

POST api/v1/store/products
headers...
{
inventory":"http://store.com/api/v3/inventory/item/12345"
}

Attack:

POST api/v1/store/products
headers…
{
"inventory":"§http://localhost/secrets§"
 }

Response:

HTTP/1.1 200 OK  
headers...  
{
"secret_token":"SecretAdminToken123"
}
```

- Out-of-Band (or Blind) SSRF takes place when a vulnerable server performs a request from user input but does not send a response back to the attacker indicating a successful attack.

```http

**Intercepted Request:**

`_POST api/v1/store/products_`

`_headers…_`

`_{_`

`_"inventory":"http://store.com/api/v3/inventory/item/12345"_`

 }

**Attack**:

`_POST api/v1/store/products_`

`_headers…_`

`_{_`

`_"inventory:"_**_§_****_http://localhost/secrets_****_§"_**`

} 

**Response:**

HTTP/1.1 200 OK  
headers...  
{}
```

Burp Suite Pro has a great tool called Burp Suite Collaborator. Collaborator can be leveraged to set up a web server that will provide us with the details of any requests that are made to our random URL.

```http

**Attack**:

`_POST api/v1/store/products_`

`_headers…_`

`_{_`

`_"inventory":"_**_§[https://webhook.site/306b30f8-2c9e-4e5d-934d-48426d03f5c0](https://webhook.site/306b30f8-2c9e-4e5d-934d-48426d03f5c0)_****_§"_**`

 }

```
## [  OWASP Preventative Measures](https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/)

- Isolate the resource fetching mechanism in your network: usually, these features are aimed to retrieve remote resources and not internal ones.
- Whenever possible, use allow lists of:
    - Remote origins users are expected to download resources from (e.g. Google Drive, Gravatar, etc.)
    - URL schemes and ports_
    - Accepted media types for a given functionality
- Disable HTTP redirections.
- Use a well-tested and maintained URL parser to avoid issues caused by URL parsing inconsistencies.
- Validate and sanitize all client-supplied input data.
- Do not send raw responses to clients.

## Additional Resources

- [Server Side Request Forgery](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
- [Server-Side Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [CWE-918: Server-Side Request Forgery (SSRF)](https://cwe.mitre.org/data/definitions/918.html)
- [URL confusion vulnerabilities in the wild: Exploring parser inconsistencies, Snyk](https://snyk.io/blog/url-confusion-vulnerabilities/)
- [Web Security Academy: SSRF](https://portswigger.net/web-security/ssrf)


## API8:2023 Security Misconfiguration 

## Keywords

Unpatched Flaws in the s ystem that host API

## Whats is it?

Security Misconfiguration represents a catch-all for many vulnerabilities related to the systems that host APIs. Attackers will often attempt to find unpatched flaws, common endpoints, or unprotected files and directories to gain unauthorized access or knowledge of the system.

Automated tools are available to detect and exploit misconfigurations such as unnecessary services or legacy options.

## Impact

Security misconfigurations can not only expose sensitive user data, but also system details that can lead to full server compromise.


## Weakness Examples


Security misconfigurations are really a set of weaknesses that includes misconfigured headers, misconfigured transit encryption, the use of default accounts, the acceptance of unnecessary HTTP methods, a lack of input sanitization, and verbose error messaging.

if an upload endpoint was used to pass uploaded files to a web directory, then it could allow the upload of a script. Navigating to the URL where the file is located could launch the script resulting in direct shell access to the web server.

Misconfigured headers can result in sensitive information disclosure, downgrade attacks, and cross-site scripting attacks.


The X-Powered-By header reveals backend technology. Headers like this one will often advertise the exact supporting service and its version. You could use information like this to search for exploits published for that version of software.

X-XSS-Protection is exactly what it looks like: a header meant to prevent cross-site scripting (XSS) attacks. XSS is a common type of injection vulnerability where an attacker could insert scripts into a web page and trick end-users into clicking on malicious links. An X-XSS-Protection value of 0 indicates no protections in place and a value of 1 indicates that the protection is turned on. This header, and others like it, clearly reveals whether or not a security control is in place.

The X-Response-Time header is middleware that provides usage metrics. In the previous example, its value represents 566.43 milliseconds. But if the API isn’t configured properly, this header can function as a side-channel used to reveal existing resources. If the X-Response-Time header has a consistent response time for non-existing records, for example, but increases its response time for certain other records, this could be an indication that those records exist.

if an API provider allows unnecessary HTTP methods, there is an increased risk that the application won’t handle these methods properly or will result in sensitive information disclosure.


## [OWASP Preventative Measures](https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/)

The API life cycle should include:

- A repeatable hardening process leading to fast and easy deployment of a properly locked down environment
- A task to review and update configurations across the entire API stack. The review should include: orchestration files, API components, and cloud services (e.g. S3 bucket permissions)
- An automated process to continuously assess the effectiveness of the configuration and settings in all environments

Furthermore:

- Ensure that all API communications from the client to the API server and any downstream/upstream components happen over an encrypted communication channel (TLS), regardless of whether it is an internal or public-facing API.
- Be specific about which HTTP verbs each API can be accessed by: all other HTTP verbs should be disabled (e.g. HEAD)._
- APIs expecting to be accessed from browser-based clients (e.g., WebApp front-end) should, at least:
    - implement a proper Cross-Origin Resource Sharing (CORS) policy
    - include applicable Security Headers
- Restrict incoming content types/data formats to those that meet the business/ functional requirements.
- Ensure all servers in the HTTP server chain (e.g. load balancers, reverse and forward proxies, and back-end servers) process incoming requests in a uniform manner to avoid desync issues.
- Where applicable, define and enforce all API response payload schemas, including error responses, to prevent exception traces and other valuable information from being sent back to attackers.
## Additional Resources

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [Configuration and Deployment Management Testing - Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/README)
- [Testing for Error Handling - Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/README)
- [Testing for Cross Site Request Forgery - Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/05-Testing_for_Cross_Site_Request_Forgery)
- [CWE-2: Environmental Security Flaws](https://cwe.mitre.org/data/definitions/2.html)
- [CWE-16: Configuration](https://cwe.mitre.org/data/definitions/16.html)
- [CWE-209: Generation of Error Message Containing Sensitive Information](https://cwe.mitre.org/data/definitions/209.html)
- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
- [CWE-388: Error Handling](https://cwe.mitre.org/data/definitions/388.html)
- [CWE-444: Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')](https://cwe.mitre.org/data/definitions/444.html)
- [CWE-942: Permissive Cross-domain Policy with Untrusted Domains](https://cwe.mitre.org/data/definitions/942.html)
- [Guide to General Server Security](https://csrc.nist.gov/publications/detail/sp/800-123/final), NIST
- [Let's Encrypt: a free, automated, and open Certificate Authority](https://letsencrypt.org/)


## API9:2023 Improper Inventory Management
## Keewords

Old API versions or endpoints left running unpatched and using weaker security requirements

### What is it?

represents the risks involved with exposing non-production and unsupported API versions. When this is present the non-production and unsupported versions of the API are often not protected by the same security rigor as the production versions.
### Impact

Attackers can gain access to sensitive data, or even take over the server. Sometimes different API versions/deployments are connected to the same database with real data. Threat agents may exploit deprecated endpoints available in old API versions to get access to administrative functions or exploit known vulnerabilities.

Alternatively, they may get access to sensitive data through a 3rd party with whom there's no reason to share data with.

Outdated documentation makes it more difficult to find and/or fix vulnerabilities. Lack of assets inventory and retirement strategies leads to running unpatched systems, resulting in leakage of sensitive data.

## Weekness Examples 

APIs that are still being developed are typically not as secure as their production API counterparts.

Improper inventory management can lead to other vulnerabilities, such as excessive data exposure, information disclosure, mass assignment, improper rate-limiting, and API injection, this means that discovering an improper inventory management vulnerability is only the first step toward further exploitation of an API.

Detecting improper inventory management can be tested by using outdated API documentation, changelogs, and version history on repositories. For example, if an organization’s API documentation has not been updated along with the API’s endpoints, it could contain references to portions of the API that are no longer supported.


Organizations often include versioning information in their endpoint names to distinguish between older and newer versions, such as /v1/, /v2/, /v3/, and so on. APIs still in development often use paths such as /alpha/, /beta/, /test/, /uat/, and /demo/. If an attacker knows that an API is now using apiv3.org/admin but part of the API documentation refers to apiv1.org/admin, they could try testing different endpoints to see if apiv1 or apiv2 are still active. Additionally, the organization’s changelog may disclose the reasons why v1 was updated or retired. If an attacker has access to v1, you can test for those weaknesses.

Outside of using documentation, an attacker could discover improper inventory vulnerabilities through the use of guessing, fuzzing, or brute force requests.

```http

API providers will often update services and the newer version of the API will be available over a new path like the following:

- api.target.com/v3
- /api/v2/accounts
- /api/v3/accounts
- /v2/accounts

API versioning could also be maintained as a header:

- _Accept: version=2.0_
- _Accept api-version=3_

In addition versioning could also be set within a query parameter or request body.

- /api/accounts?ver=2
- POST /api/accounts  
      
    {  
    "ver":1.0,  
    "user":"hapihacker"  
    }

Non-production versions of an API include any version of the API that was not meant for end-user consumption. Non-production versions could include:

- api.test.target.com
- api.uat.target.com
- beta.api.com
- /api/private
- /api/partner
- /api/test

```


## [OWASP Preventative Measures](https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/)

- Inventory all API hosts and document important aspects of each one of them, focusing on the API environment (e.g., production, staging, test, development), who should have network access to the host (e.g., public, internal, partners) and the API version.
- Inventory integrated services and document important aspects such as their role in the system, what data is exchanged (data flow), and its sensitivity.
- Document all aspects of your API such as authentication, errors, redirects, rate limiting, cross-origin resource sharing (CORS) policy and endpoints, including their parameters, requests, and responses.
- Generate documentation automatically by adopting open standards. Include the documentation build in your CI/CD pipeline.
- Make API documentation available to those authorized to use the API.
- Use external protection measures such as API security firewalls for all exposed versions of your APIs, not just for the current production version.
- Avoid using production data with non-production API deployments. If this is unavoidable, these endpoints should get the same security treatment as the production ones.
- When newer versions of APIs include security improvements, perform risk analysis to make the decision of the mitigation actions required for the older version: for example, whether it is possible to backport the improvements without breaking API compatibility or you need to take the older version out quickly and force all clients to move to the latest version.

## Additional Resources

- [CWE-1059: Incomplete Documentation](https://cwe.mitre.org/data/definitions/1059.html)
- [OpenAPI Initiative](https://www.openapis.org/)

## API10:2023 Unsafe Consumption of APIs

## Keywords 

When an application is consuming the data of third-party APIs it should treat those with a similar trust to user input. By that, I mean, there should be little to no trust.


## What is it?

data consumed from third-party APIs should be treated with similar security standards as end-user-supplied input. If a third-party API provider is compromised then that insecure API connection back to the consumer becomes a new vector for the attacker to leverage.


Exploiting this issue requires attackers to identify and potentially compromise other APIs/services the target API integrated with. Usually, this information is not publicly available or the integrated API/service is not easily exploitable.

Developers tend to trust and not verify the endpoints that interact with external or third-party APIs, relying on weaker security requirements such as those regarding transport security, authentication/authorization, and input validation and sanitization.

## Impact 

The impact varies according to what the target API does with pulled data. Successful exploitation may lead to sensitive information exposure to unauthorized actors, many kinds of injections, or denial of service.


 if an attacker compromises a third-party API provider, then that third party's connections to other businesses can become an additional attack vector.

If that third-party API isn't held to similar security standards as an Internet-facing API then it could also be vulnerable to injection, authorization, and other compromising attacks.

## [OWASP Preventative Measures](https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/)

- When evaluating service providers, assess their API security posture.
- Ensure all API interactions happen over a secure communication channel (TLS).
- Always validate and properly sanitize data received from integrated APIs before using it.
- Maintain an allowlist of well-known locations integrated APIs may redirect yours to: do not blindly follow redirects.


## Additional Resources

- [Web Service Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Web_Service_Security_Cheat_Sheet.html)
- [Injection Flaws](https://www.owasp.org/index.php/Injection_Flaws)
- [Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html)
- [Transport Layer Protection Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html)
- [Unvalidated Redirects and Forwards Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)


## Injection 

## Keywords

Lack of validation Inputs 

## What is it?

They take place when an attacker is able to send commands that are executed by the systems that support the web application. The most common forms of injection attacks are SQL injection, Cross-site scripting (XSS), and operating system command injection.

Attackers will feed the API with malicious data through whatever injection vectors are available (e.g., direct input, parameters, integrated services, etc.), expecting it to be sent to an interpreter.

njection flaws are very common and are often found in SQL, LDAP, or NoSQL queries, OS commands, XML parsers, and ORM. These flaws are easy to discover when reviewing the source code. Attackers can use scanners and fuzzers.
## Impact

Injection can lead to information disclosure and data loss. It may also lead to DoS, or complete host takeover.


## Weekness Examples

In each of these injection attacks, the API delivers an unsanitized payload directly to the operating system running the application or its database. As a result, if an attacker sends a payload containing SQL commands to a vulnerable API that uses a SQL database, the API will pass the commands to the database, which will process and perform the commands.

Verbose error messaging, HTTP response codes, and unexpected API behavior can all be clues to an attacker and will be an indication that they have discovered an injection flaw.

An attacker were to send OR 1=0-- as an address in an account registration process. The API may pass that payload directly to the backend SQL database, where the OR 1=0 statement would fail (as 1 does not equal 0), causing some SQL error:

```http
POST /api/v1/register HTTP 1.1

Host: example.com

--snip--

{

“Fname”: “hAPI”,

“Lname”: “Hacker”,

“Address”: “' OR 1=0--”,

}

```

An error in the backend database could show up as a response to the consumer. In this case, the attacker might receive a response like “Error: You have an error in your SQL syntax…”, but any response directly from databases or the supporting system will serve as a clear indicator that there is likely an injection vulnerability.

Finding injection flaws requires diligently testing API endpoints and paying attention to how the API responds, then crafting requests that attempt to manipulate the backend systems.

## [OWASP 2019 Preventative Measures](https://owasp.org/API-Security/editions/2019/en/0xa8-injection/)

#### Preventing injection requires keeping data separate from commands and queries.

- Perform data validation using a single, trustworthy, and actively maintained library.
- Validate, filter, and sanitize all client-provided data, or other data coming from integrated systems.
- Special characters should be escaped using the specific syntax for the target interpreter.
- Prefer a safe API that provides a parameterized interface.
- Always limit the number of returned records to prevent mass disclosure in case of injection.
- Validate incoming data using sufficient filters to only allow valid values for each input parameter.
- Define data types and strict patterns for all string parameters.

## Additional Resources

- [OWASP Injection Flaws](https://www.owasp.org/index.php/Injection_Flaws)
- [SQL Injection](https://www.owasp.org/index.php/SQL_Injection)
- [NoSQL Injection Fun with Objects and Arrays](https://www.owasp.org/images/e/ed/GOD16-NOSQL.pdf)
- [Command Injection](https://www.owasp.org/index.php/Command_Injection)
- [CWE-20: Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)
- [CWE-319: Cleartext Transmission of Sensitive Information](https://cwe.mitre.org/data/definitions/319.html)
- [Web Security Academy: OS Injection](https://portswigger.net/web-security/os-command-injection)
- [Web Security Academy: SQL Injection](https://portswigger.net/web-security/sql-injection)
- [Web Security Academy: XML Injection](https://portswigger.net/web-security/xxe)


## Insufficient Logging and Monitoring


## Keywords

Visibility of logs
## What is it?

In order to detect an attack against an API an organization must have monitoring in place. Without sufficient logging and monitoring an API provider is operating in the dark and API attacks are guaranteed to go unnoticed until it is far too late.

Without logging and monitoring, or with insufficient logging and monitoring, it is almost impossible to track suspicious activities and respond to them in a timely fashion.

## Impact 

Without visibility over ongoing malicious activities, attackers have plenty of time to fully compromise systems.


## Weekness Examples 

Logs can reveal patterns in API usage and can be used as evidence to understand how an API is abused.

Logging and monitoring provide an audit trail of activities and are often required for compliance purposes. 

An important part of logging is to ensure that the logs have integrity and cannot be altered by an attacker

## [OWASP 2019 Preventative Measures](https://owasp.org/API-Security/editions/2019/en/0xaa-insufficient-logging-monitoring/)

- Log all failed authentication attempts, denied access, and input validation errors.
- Logs should be written using a format suited to be consumed by a log management solution and should include enough detail to identify the malicious actor.
- Logs should be handled as sensitive data, and their integrity should be guaranteed at rest and transit.
- Configure a monitoring system to continuously monitor the infrastructure, network, and API functioning.
- Use a Security Information and Event Management (SIEM) system to aggregate and manage logs from all components of the API stack and hosts.
- Configure custom dashboards and alerts, enabling suspicious activities to be detected and responded to earlier.

## Additional Resources

- [OWASP Logging Cheat Sheet](https://www.owasp.org/index.php/Logging_Cheat_Sheet)
- [OWASP Proactive Controls: Implement Logging and Intrusion Detection](https://www.owasp.org/index.php/OWASP_Proactive_Controls)
- [OWASP Application Security Verification Standard: V7: Error Handling and Logging Verification Requirements](https://github.com/OWASP/ASVS/blob/master/4.0/en/0x15-V7-Error-Logging.md)
- [CWE-223: Omission of Security-relevant Information](https://cwe.mitre.org/data/definitions/223.html)
- [CWE-778: Insufficient Logging](https://cwe.mitre.org/data/definitions/778.html)


## Business Logic Flaws


### What is it ?

Business logic vulnerabilities are weaknesses within applications that are unique to the policies and features of a given API provider.

Identifying business logic vulnerabilities can be challenging due to the unique nature of each business.

They often require specific knowledge of the application's functionality and the flow of transactions or data.

These weaknesses typically occur when developers fail to anticipate the various ways that an application's features can be misused or when they don't consider the wider context of the business rules. This is often due to a lack of comprehensive understanding of the application's business logic, a lack of input validation, or incomplete function-level authorization checks.

### Impact 

Business logic vulnerabilities can cause a variety of technical impacts, depending on the specific flaw and the systems involved. These impacts can range from unauthorized access to data or functionality to a total bypass of system controls.


### Weekness Examples

if an API has an upload feature that instructs users to only upload certain encoded payloads, but doesn’t validate the encoded payloads, a user could upload any file as long as it was encoded. This would allow end users to upload and potentially execute arbitrary code, including malicious payloads.

A certain Experian partner was authorized to use Experian’s API to perform credit checks, but the partner added the API’s credit check functionality to their web application and inadvertently exposed all partner-level requests to users. This request could be intercepted when using the partner’s web application, and if it included a name and address, the Experian API would respond with the individual’s credit score and credit risk factors. One of the leading causes of this business logic vulnerability was that Experian trusted the partner to not expose the API.


Another problem with trust is that credentials, like API keys, tokens, and passwords, are constantly being stolen and leaked. Without strong technical controls in place, business logic vulnerabilities can often have the most significant impact, leading to exploitation and compromise.


Examine an API's documentation for telltale signs of business logic vulnerabilities. Statements like the following should be indications of potential business logic flaws:

“Only use feature X to perform function Y.”

“Do not do X with endpoint Y.”

“Only admins should perform request X.”

These statements may indicate that the API provider is trusting that you won’t do any of the discouraged actions, as instructed. An attacker will easily disobey such requests to test for the presence of technical security controls.


Another business logic vulnerability comes about when developers assume that consumers will exclusively use a browser to interact with the web application and won’t capture API requests that take place behind the scenes.  This would allow the attacker to capture shared API keys or use parameters that could negatively impact the security of the application.

```http

POST /api/v1/login HTTP 1.1

Host: example.com

--snip--

UserId=hapihacker&password=arealpassword!&MFA=true

```

There is a chance that an attacker could bypass multifactor authentication by simply altering the parameter MFA to false.

One method of testing for business logic flaws is to study the application’s business logic with an adversarial mindset and try breaking any assumptions that have been made.

## Preventative Measures

- Use a Threat Modeling Approach: Understand the business processes and workflows your API supports. Identifying the potential threats, weaknesses, and risks during the design phase can help to uncover and mitigate business logic vulnerabilities.
    
- Reduce or remove trust relationships with users, systems, or components. Business logic vulnerabilities can be used to exploit these trust relationships, leading to broader impacts.
    
- Regular training can help developers to understand and avoid business logic vulnerabilities. Training should cover secure coding practices, common vulnerabilities, and how to identify potential issues during the design and coding phases.
- Implement a bug bounty program, third-party penetration testing, or a responsible disclosure policy. This allows security researchers, who are a step removed from the design and delivery of an application, to disclose vulnerabilities they discover in APIs.

## Additional Resources

- [OWASP A04 Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)
- [OWASP Business Logic Vulnerability](https://owasp.org/www-community/vulnerabilities/Business_logic_vulnerability)
- [CWE-840: Business Logic Errors](https://cwe.mitre.org/data/definitions/840.html)
- [Snyk Insecure Design](https://learn.snyk.io/lessons/insecure-design/javascript/)
- [Web Security Academy: Business Logic Vulnerabilities](https://portswigger.net/web-security/logic-flaws)
