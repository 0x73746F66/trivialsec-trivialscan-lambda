Set the `Cross-Origin-Embedder-Policy` HTTP response header to value `require-corp`.

**Enable in Nginx**

```
add_header Cross-Origin-Embedder-Policy: "require-corp";
```

**Enable in Apache**

```
header set Cross-Origin-Embedder-Policy "require-corp;"
```

**Enable on IIS**

```
<system.webServer>
    ...
    <httpProtocol>
        <customHeaders>
            <add name="Cross-Origin-Embedder-Policy" value="require-corp" />
        </customHeaders>
    </httpProtocol>
    ...
</system.webServer>
```
