# Finance_Tracker_C
Secure Finance Tracker
======================

This is a secure terminal-based Finance Tracker application written in C.

Features:
---------
- Secure user registration and login using SHA-256 password hashing with salt.
- Income and expense tracking with persistent storage in binary files.
- Clear menu-based UI for finance management.
- Improved error handling and input validation.
- bounds checked I/O, file locking, extensive error checks
- Secure file operations and memory management.


Files:
------
- finance_tracker.c         --> Main program source code
- Makefile                  --> Used to compile the project
- README.txt                --> This file
- Implementation report     --> list of all vulnerabilities and their location

Dependencies:
-------------
- GCC compiler
- OpenSSL library (for SHA-256 hashing)

To Compile:
-----------
    make

To Run:
-------
    ./finance_tracker

To Clean:
---------
    make clean

To Clean All data files and binaries deleted:
---------------------------------------------
    make cleanall

Security Enhancements:
----------------------
- SHA-256 + salt password hashing
- Bounds-checked string operations
- Secure memory and file handling
- Input sanitization
- Simplified and safe output messages



