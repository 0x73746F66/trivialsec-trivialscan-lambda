Set the `Feature-Policy` HTTP response header to value `sync-script 'none'`, `sync-xhr 'none'`, and `document-domain 'none'`.
For the time being, the soon to be deprecated `Permissions-Policy` HTTP response header can still help if set to value `sync-script=()`, `sync-xhr=()`, and `document-domain=()`.

**Enable in Nginx**

```
add_header Feature-Policy "sync-script 'none'; sync-xhr 'none'; document-domain 'none'" always;
```

**Enable in Apache**

```
Header always set Feature-Policy "sync-script 'none'; sync-xhr 'none'; document-domain 'none'"
```

**Enable on IIS**

```
<system.webServer>
    ...
    <httpProtocol>
        <customHeaders>
            <add name="Feature-Policy" value="sync-script 'none'; sync-xhr 'none'; document-domain 'none'" />
        </customHeaders>
    </httpProtocol>
    ...
</system.webServer>
```
