# infnoise-openssl
OpenSSL engine for random number generation using the [infnoise TRNG](https://github.com/13-37-org/infnoise "infnoise TRNG").

This engine can be used generate true random data for any operations in OpenSSL which use random bits. This includes RSA and Eliptical Curve key generation, Diffie-Hellman key exchange, DSA and RSA-PSS signature salt generation, etc. It does not just seed the OpenSSL PRNG with data from the infnoise TRNG, but instead provides a steady true random bitstream for cryptographic operations.
## Prerequisites
This engine has been tested on both Mac and Linux (Debian). Please feel free to add support for Windows.
### OpenSSL
This engine requires, of course, engine support from OpenSSL.  You can tell whether you have a version built with this support by checking for /usr/local/lib/engines-*openssl_version*. If installed with your system it may be in /usr/lib instead.  If you do not have it, get a copy from [https//github.com/openssl/openssl](https//github.com/openssl/openssl "https//github.com/openssl/openssl"), buid, and install it.
### libinfnoise

This is the library which does the actual magic.  You can obtain it from [https://github.com/13-37-org/infnoise](https://github.com/13-37-org/infnoise "https://github.com/13-37-org/infnoise"). Build and install both the "install" and "install-lib" targets.
## Building and using infnoise-openssl
Get a copy of this repository, cd into it, and just "make".  Then copy libinfnoise.(dylib|so) to the openssl engines library directory.

Once installed, you need to tell OpenSSL to use the engine.  To this effect you have to specify an environment variable called **OPENSSL_CONF** which contains the path to the **openssl-infnoise.cnf** file (provided in this repo). You can either export this variable, or define it in the openssl command line.  Then try a command along the lines of "**openssl genrsa 4096**" You should see a message indicating that the infnoise engine was loaded, or an error. If you don't get either, retrace the steps above.

**NOTE:** On some systems you may have to run openssl as root (sudo openssl...) to get this to work. There must be a way to set the FTDI USB permissions to not require root access, but so far everything I've tried has failed. If anyone knows how to do this, I'd appreciate if you let me know how.

Thanks to WaywardGeek for infnoise, as well as for his help with libinfnoise.
