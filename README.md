# pysyscomply

Python library for testing a systems compliance like CIS.

TODO


## Introduction

The intent of this library is go provide a lightweight, portable, and
modular tool to run compliance tests on Linux machines.

The basic concept is:

* pycomply is a Python 3.9+ compatible library that can also be used in CLI mode.
* The compliance tests are defined in JSON files and easy to customise for your own tests.
* The generated output is a structured JSON that is easy to process or deliver to a database.
* Informational level output is visible on stdout while the tests are running.
* If needed, the tests, both the runtime and the testbook, can be compiled into a binary to remove OS dependencies and make it harder to tweak tests.

## The "testbooks"

## Reports

## The pythin library


## Works in progress

* Write and share a CIS test subset.
* Add built-in functions to help with recurring tests like service status, and package managers.
