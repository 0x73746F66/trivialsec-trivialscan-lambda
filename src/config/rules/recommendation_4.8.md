Set the `Cross-Origin-Resource-Policy` HTTP response header to value `same-origin`.

**Enable in Nginx**

```
add_header Cross-Origin-Resource-Policy: "same-origin";
```

**Enable in Apache**

```
header set Cross-Origin-Resource-Policy "same-origin;"
```

**Enable on IIS**

```
<system.webServer>
    ...
    <httpProtocol>
        <customHeaders>
            <add name="Cross-Origin-Resource-Policy" value="same-origin" />
        </customHeaders>
    </httpProtocol>
    ...
</system.webServer>
```
