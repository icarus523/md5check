# md5check_gui
Script to verify MD5 signature hash that is included with LTFO submissions  
This version has a GUI, updated because to some people the CLI version was too complicated. 

## Features:  
* Performs md5 hash calculation on a submitted archived and compare it to the provided signature file for comparison. 
* Automatically unzip archive
* Generate a signature file with user and timestamp info
* Validate signature file to ensure that the signature file hasn't been tampered. 

## v1.1 GUI Version enhancements
* Process multiple Archive submissions
* When verifying, automatically tells the user if Verification with SIGS file is a success (previously I left it for the user to verify).
* Logging Filter Control (doesn't work!)
* Will not try to Unzip file unless MD5 check passes
* Initial Directory will now be based on a config file

## v1.2.1 GUI + Config Version enhancements
* Config file per user
* Select Files, will use last working directory\
* In preparation for Full Auto Processing. 