### Blind XSS detection

The point of this project is to detect a request at endpoint ```/hackerone/xss```.

You can inject something like ```<script src="///hackerone/xss"></script>``` into an input and observe it sanitize and prevent that xss attack, however, an administration panel connected to the same data source may be vulnerable.
