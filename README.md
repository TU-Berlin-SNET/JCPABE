# JCPABE

#### Notes

JCPABE is a Java implementation of the Attribute-based encryption scheme found in the paper from [Bethencourt (2007)](http://acsc.cs.utexas.edu/cpabe/).
It started out as a fork of https://github.com/junwei-wang/cpabe but has since been mostly rewritten.

It supports numerical attributes and an experimental form of area attributes.

The main functionality is accessible in the cpabe.Cpabe class.

This is research software and should not be used in application where actual security is required.

#### Dependencies
Download the source of JPBC from [here](http://sourceforge.net/p/jpbc/code/) (JCPABE has only been tested with version 2.0.0).
Install it into your local maven repository using
```sh
$ mvn install
```
(only the sub projects jpbc-plaf, jpbc-api and jpbc-pbc are needed)

It is also recommended to install the PBC wrapper for JPBC to improve the performance (as explained [here](http://gas.dia.unisa.it/projects/jpbc/docs/pbcwrapper.html)). Note: in Ubuntu the GMP dependency package is called libgmp10.


#### Build
To build JCPABE:
```sh
$ ./gradlew build
```

To install it into a local maven repository run:
```sh
$ ./gradlew install
```


#### Common Problems

JPBC-PBC library can not be found or loaded:
Remove the system JNA library or patch JPBC to work with newest JNA.
