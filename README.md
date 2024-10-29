# Authsignal Java

Check out our [official Java SDK documentation](https://docs.authsignal.com/sdks/server/java).

## Installation

### Requirements

- Java 1.11 or later

### Gradle users

Add this dependency to your project's build file:

```groovy
implementation 'com.authsignal:authsignal-java:0.3.0'
```

### Maven users

Add this dependency to your project's POM:

```xml
<dependency>
  <groupId>com.authsignal</groupId>
  <artifactId>authsignal-java</artifactId>
  <version>0.2.2</version>
</dependency>
```

## Initialization

```java
import com.authsignal.AuthsignalClient;
...

AuthsignalClient client = new AuthsignalClient(secret, baseURL);
```

You can find your tenant secret in the [Authsignal Portal](https://portal.authsignal.com/organisations/tenants/api).

You must specify the correct base URL for your tenant's region.

| Region      | Base URL                         |
| ----------- | -------------------------------- |
| US (Oregon) | https://api.authsignal.com/v1    |
| AU (Sydney) | https://au.api.authsignal.com/v1 |
| EU (Dublin) | https://eu.api.authsignal.com/v1 |

## Usage

For more detailed information on how use this library refer to the [official documentation](https://docs.authsignal.com/sdks/server/java).
