Set the `Cross-Origin-Opener-Policy` HTTP response header to value `same-origin`.

**Enable in Nginx**

```
add_header Cross-Origin-Opener-Policy: "same-origin";
```

**Enable in Apache**

```
header set Cross-Origin-Opener-Policy "same-origin;"
```

**Enable on IIS**

```
<system.webServer>
    ...
    <httpProtocol>
        <customHeaders>
            <add name="Cross-Origin-Opener-Policy" value="same-origin" />
        </customHeaders>
    </httpProtocol>
    ...
</system.webServer>
```
