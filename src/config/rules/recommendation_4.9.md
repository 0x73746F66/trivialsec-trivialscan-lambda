There are many directives that you can use with `Content-Security-Policy`. This example below allows scripts from both the current domain (defined by 'self') as well as google-analytics.com.

```
Content-Security-Policy: script-src 'self' https://www.google-analytics.com
```

**Enable in Nginx**

```
add_header Content-Security-Policy: "default-src 'none'; script-src 'self' https://www.google-analytics.com";
```

**Enable in Apache**

```
header set Content-Security-Policy "default-src 'none'; script-src 'self' https://www.google-analytics.com;"
```

**Enable on IIS**

```
<system.webServer>
    ...
    <httpProtocol>
        <customHeaders>
            <add name="Content-Security-Policy" value="default-src 'none'; script-src 'self' https://www.google-analytics.com" />
        </customHeaders>
    </httpProtocol>
    ...
</system.webServer>
```
