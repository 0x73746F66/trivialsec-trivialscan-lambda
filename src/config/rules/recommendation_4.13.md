The `Feature-Policy` header grants the ability to allow or deny browser features, whether in its own frame or content within an inline frame element `<iframe>`

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
