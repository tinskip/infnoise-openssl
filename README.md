# infnoise-openssl
OpenSSL engine for random number generation using the **[Infinite Noise TRNG](https://github.com/13-37-org/infnoise "infnoise TRNG").**

This engine can be used generate true random data for any operations in OpenSSL which use random bits. This includes RSA and Eliptical Curve key generation, Diffie-Hellman key exchange, DSA and RSA-PSS signature salt generation, etc. It does not just seed the OpenSSL PRNG with data from the Infinite Noise TRNG, but instead provides a steady true random bitstream for cryptographic operations.

## Prerequisites
This engine has been tested on both Mac and Linux (Debian, Ubuntu 18.04). Please feel free to add support for Windows.

### OpenSSL
This engine requires, of course, engine support from OpenSSL.  You can tell whether you have a version built with this support by checking for the directory /usr/local/lib/engines-*openssl_version*. If installed with your system it may be in /usr/lib instead.  If you do not have it, get a copy from [https//github.com/openssl/openssl](https//github.com/openssl/openssl "https://github.com/openssl/openssl"), build, and install it.

    $ git clone https://github.com/openssl/openssl && cd openssl
    $ ./config && make && sudo make install

### libinfnoise
This is the library which does the actual magic.  You can obtain it from [https://github.com/13-37-org/infnoise](https://github.com/13-37-org/infnoise "https://github.com/13-37-org/infnoise"). Build and install both the "install" and "install-lib" targets.

    $ git clone https://github.com/13-37-org/infnoise && cd infnoise/software
    $ make -f Makefile.linux install-lib

## Building and using infnoise-openssl
Get a copy of this repository, cd into it, and just "make".  Then copy infnoise.(dylib|so) to the openssl engines library directory.

Once installed, you need to tell OpenSSL to use the engine.  To this effect you have to specify an environment variable called **OPENSSL_CONF** which contains the path to the file **[infnoise-openssl.cnf](https://github.com/tinskip/infnoise-openssl/blob/master/infnoise-openssl.cnf "infnoise-openssl.cnf")**. You can either export this variable, or define it in the openssl command line.  Then try a command along the lines of "**openssl genrsa 4096**" You should see a message indicating that the infnoise engine was loaded, or an error. If you don't get either, retrace the steps above.

    $ export OPENSSL_CONF="infnoise-openssl.cnf"

    # To check which engines are loaded
    $ openssl engine

    # Create huge keys very fast:
    $ openssl genrsa 4096

    # Test randomness provided by the TRNG
    $ openssl rand 10000000 | ent

**NOTE:** On some systems you may have to run openssl as root (sudo openssl...) to get this to work. To run without root privileges, add the following:

    SUBSYSTEM=="usb", ATTRS{idVendor}=="0403", ATTRS{idProduct}=="6015", SYMLINK+="infnoise", GROUP="dialout", MODE="0664"
 to `/etc/udev/rules.d/75-infnoise.rules` 

then reload udevd and add your user to the "dialout" group. For this to take effect, you'll need to re-login. If applicable, just reboot your machine after adding the line and assigning the group.

    $ sudo service udev reload
    $ śudo adduser manuel dialout

Thanks to WaywardGeek for the hardware design, as well as Manuel Domke (from 13-37.org electronics) for his work on libinfnoise.
