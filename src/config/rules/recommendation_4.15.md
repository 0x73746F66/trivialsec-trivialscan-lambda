There are many directives that you can use with `Content-Security-Policy`. This example below allows scripts from both the current domain (defined by 'self') as well as google-analytics.com.

```
Content-Security-Policy: block-all-mixed-content
```

Or web sites with large numbers of insecure legacy URLs that need to be rewritten:

```
Content-Security-Policy: upgrade-insecure-requests
```

**Note**: The `upgrade-insecure-requests` directive is evaluated _before_ `block-all-mixed-content`

Alternatively the following granular examples will disallow only insecure HTTP images:

**Enable in Nginx**

```
add_header Content-Security-Policy: "img-src https:";
```

**Enable in Apache**

```
header set Content-Security-Policy "img-src https:;"
```

**Enable on IIS**

```
<system.webServer>
    ...
    <httpProtocol>
        <customHeaders>
            <add name="Content-Security-Policy" value="img-src https:" />
        </customHeaders>
    </httpProtocol>
    ...
</system.webServer>
```
