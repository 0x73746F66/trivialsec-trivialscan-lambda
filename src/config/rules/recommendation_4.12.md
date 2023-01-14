Here is an example of what the `Strict-Transport-Security` header looks like: You can include the max age, subdomains, and preload.

**Enable in Nginx**

```
add_header X-Content-Type-Options "nosniff" always;
```

**Enable in Apache**

```
Header always set X-Content-Type-Options "nosniff"
```

**Enable on IIS**

```
<system.webServer>
    ...
    <httpProtocol>
        <customHeaders>
            <add name="X-Content-Type-Options" value="nosniff" />
        </customHeaders>
    </httpProtocol>
    ...
</system.webServer>
```
