# Native2Frida
Give It Decompiled IDA Code and get Frida Script for All Functions which have Char as argument or return type as char

Feel free to modify as per as need . May be if you modify for generating hook for all method without any char filtering 
please let me know and send a PR

```sh
javac Native2Frida.java
java Native2Frida Decompiled.c output.js
```

If output file is not provided then code will be printed in console.
