# Ardclient #

Ardclient is the client for Apple Remote Desktop. It allows the Remote
Desktop application on Mac OS X to administer computers running on Linux or
FreeBSD.

This program is licenced under the GPL-2 licence. See the file LICENCE
for details.

## Download ##

You can download Ardclient here:

> http://ardclient.googlecode.com/files/ardclient-0.1.tar.bz2


## Installation ##

Follow these steps to install Ardclient:

# Unpack
```
    $ tar xvjf ardclient-<version>.tar.bz2
```
# Change directory to the program
```
    $ cd ardclient-<version>
```
# Install with setup.py
```
    $ python setup.py install
```

For more help run 'python setup.py --help'.


## Running ##

---


First edit the configuration file (default is /etc/ardclient/ardclient.conf)
and run:
```
    $ ardclient 
```
Ardclient to get the list of accepted command line parameters, run
```
    $ ardclient --help
```
