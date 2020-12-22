# IOCScanner

IOCScanner.py is a program to scan an entire mounted windows image for given yara rules.

The yara rules can be tagged before using the IOCTagger.py.

The overall idea is to tag rules as "red" or "yellow" to determine whether a found IoC is a "hard proof" for malware or just an indicator.
The result is a list of found IoCs and the matched files, which can be further analyzed.
