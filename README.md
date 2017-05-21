# md5check_gui
Script to verify MD5 signature hash that is included with LTFO submissions  
This version has a GUI, updated because to some people the CLI version was too complicated. 

## Features:  
* Performs md5 hash calculation on a submitted archived and compare it to the provided signature file for comparison. 
* Automatically unzip archive
* Generate a signature file with user and timestamp info
* Validate signature file to ensure that the signature file hasn't been tampered. 

## v1.1 GUI Version enhancements
* Process multiple Archive or SIGS files
* When verifying, automatically tells the user if Verification with SIGS file is a success (previously I left it for the user to verify).
* Logging Filter Control
* Will not try to Unzip file unless MD5 check passes
