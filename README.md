# JCPABE

#### Notes

This is a heavily modified fork of https://github.com/junwei-wang/cpabe.


#### Dependencies
Download the source of JPBC from [here](http://sourceforge.net/p/jpbc/code/) (JCPABE has only been tested with version 2.0.0).
Install it into your local maven repository using
```sh
$ mvn install
```
(only the sub projects jpbc-plaf, jpbc-api and jpbc-pbc are needed)

It is also recommended to install the PBC wrapper for JPBC to improve the performance (as explained [here](http://gas.dia.unisa.it/projects/jpbc/docs/pbcwrapper.html)). Note: in Ubuntu the GMP dependency package is called libgmp10.


(Optional) If you want to regenerate or modify the parser the parser you need to download the JavaCC binary (6.1.2 was tested) from https://java.net/projects/javacc/downloads/directory/releases
and place the javacc.jar into <repo>/javacc/bin/lib/
Alternatively change line 6 of the build.xml file to point towards JavaCC.
You can then build the parser by running ant.

#### Common Problems (todo)

jpbc-pbc library can not be found/loaded

JNA build error
