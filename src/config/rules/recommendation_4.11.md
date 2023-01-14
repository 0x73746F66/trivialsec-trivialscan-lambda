Here is an example of what the `Strict-Transport-Security` header looks like: You can include the max age, subdomains, and preload.

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

**Enable in Nginx**

```
add_header Strict-Transport-Security "max-age=63072000; includeSubdomains; preload";
```

**Enable in Apache**

```
Header always set Strict-Transport-Security "max-age=63072000; includeSubdomains; preload"
```

**Enable on IIS**

```
<system.webServer>
    ...
    <httpProtocol>
        <customHeaders>
            <add name="Strict-Transport-Security" value="max-age=63072000; includeSubdomains; preload" />
        </customHeaders>
    </httpProtocol>
    ...
</system.webServer>
```
