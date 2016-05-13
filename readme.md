### Blind XSS detection

The point of this project is to detect a request at endpoint ```/s```.

You can inject something like ```<script src="//<endpoint>"></script>``` into an input and observe it sanitize and prevent that xss, however, an administration panel connected to the same data source may be vulnerable. When the administrator requests the endpoint, you'll be sent an email. There is a limit of one email per 10 minute period to prevent flooding.

 uses AWS Simple Email Service

 requires env vars:

 ```
 XSS_CONTACT_EMAIL
 AWS_ACCESS_KEY_ID
 AWS_SECRET_ACCESS_KEY
 ```