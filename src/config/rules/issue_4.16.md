The server sent a response header to inform supporting browsers whether or not a browser should be allowed to render a page in a `<frame>`, `<iframe>`, `<embed>` or `<object>`.

Sites can use this to avoid click-jacking attacks, by ensuring that their content is not embedded into other sites.

The added security is provided only if the user accessing the document is using a browser that supports X-Frame-Options.

`X-Frame-Options` works only by setting through the HTTP header.

**Note:** Setting X-Frame-Options inside the [`<meta>`](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/meta) element is useless, `<meta http-equiv="X-Frame-Options" content="deny">` has no effect.

**Note** this feature has no impact where malicious actors have full contorl over client requests to simply ignore server response headers it does not want to process or adhere to.
