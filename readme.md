### Blind XSS detection

The purpose of this project is to detect a request at endpoint ```/s```.

You can inject something like ```<script src="//<endpoint>"></script>``` into an input and observe it prevent an xss, however, something like an administration panel connected to the same data source may be vulnerable. You'll be sent an email when the endpoint is hit. There is a limit of one email per 10 minute period to prevent flooding.

 uses AWS Simple Email Service

 requires env vars:

 ```
 XSS_CONTACT_EMAIL
 AWS_ACCESS_KEY_ID
 AWS_SECRET_ACCESS_KEY
 ```