There are many directives that you can use with `Content-Security-Policy` HTTP response header, the following can help prevent clickjacking.
One major benefit to this directive is that it allows you to authorize multiple domains.

**Enable in Nginx**

```
add_header Content-Security-Policy: "frame-ancestors";
```

**Enable in Apache**

```
header set Content-Security-Policy "frame-ancestors;"
```

**Enable on IIS**

```
<system.webServer>
    ...
    <httpProtocol>
        <customHeaders>
            <add name="Content-Security-Policy" value="frame-ancestors" />
        </customHeaders>
    </httpProtocol>
    ...
</system.webServer>
```
