The `Referrer-Policy` controls how much (if any) referrer information the browser should reveal to the web server.

**Enable in Nginx**

```
add_header Referrer-Policy "no-referrer" always;
```

**Enable in Apache**

```
Header always set Referrer-Policy "no-referrer"
```

**Enable on IIS**

```
<system.webServer>
    ...
    <httpProtocol>
        <customHeaders>
            <add name="Referrer-Policy" value="no-referrer" />
        </customHeaders>
    </httpProtocol>
    ...
</system.webServer>
```
