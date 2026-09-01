<img width="1070" alt="Authsignal" src="https://raw.githubusercontent.com/authsignal/authsignal-java/main/.github/images/authsignal.png">

# Authsignal Java

Check out our [official Java SDK documentation](https://docs.authsignal.com/sdks/server/java).

## Installation

### Requirements

- Java 1.11 or later

### Gradle users

Add this dependency to your project's build file:

```groovy
implementation 'com.authsignal:authsignal-java:2.10.1'
```

### Maven users

Add this dependency to your project's POM:

```xml
<dependency>
  <groupId>com.authsignal</groupId>
  <artifactId>authsignal-java</artifactId>
  <version>2.10.1</version>
</dependency>
```

## Initialization

```java
import com.authsignal.AuthsignalClient;
...

AuthsignalClient client = new AuthsignalClient(secret, baseURL);
```

### Retry policy

Requests use a 3-second connect timeout, 10-second request timeout, and retry twice by default with exponential backoff and jitter. Transient network failures, `429`, and `5xx` responses are retried for `GET`, `HEAD`, and `OPTIONS`; writes are retried only when they carry an idempotency key. Pass a retry count to `new AuthsignalClient(secret, baseURL, retries)`; use `0` to disable retries.

You can find your tenant secret in the [Authsignal Portal](https://portal.authsignal.com/organisations/tenants/api).

You must specify the correct base URL for your tenant's region.

| Region      | Base URL                         |
| ----------- | -------------------------------- |
| US (Oregon) | https://api.authsignal.com/v1    |
| AU (Sydney) | https://au.api.authsignal.com/v1 |
| EU (Dublin) | https://eu.api.authsignal.com/v1 |

## Usage

For more detailed information on how use this library refer to the [official SDK documentation](https://docs.authsignal.com/sdks/server/overview).
