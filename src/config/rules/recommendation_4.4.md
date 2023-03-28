Set the `Feature-Policy` HTTP response header to value `clipboard-read 'none'`.
For the time being, the soon to be deprecated `Permissions-Policy` HTTP response header can still help if set to value `clipboard-read=()`

**Enable in Nginx**

```
add_header Feature-Policy "clipboard-read 'none'" always;
```

**Enable in Apache**

```
Header always set Feature-Policy "clipboard-read 'none'"
```

**Enable on IIS**

```
<system.webServer>
    ...
    <httpProtocol>
        <customHeaders>
            <add name="Feature-Policy" value="clipboard-read 'none'" />
        </customHeaders>
    </httpProtocol>
    ...
</system.webServer>
```
