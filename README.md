# md5check_ltfoprocess
Script to automate all Manual LTFO submission processes  
E.g. Copy Files, Rename Files, Unzip Files, Verify Files, etc. 

## Features:  
* Performs md5 hash calculation on a submitted archived and compare it to the provided signature file for comparison. 
* Automatically unzip archive
* Generate a signature file with user and timestamp info
* Validate signature file to ensure that the signature file hasn't been tampered. 

## v1.2 LTFO Process
* Includes ConfigFile Class to save user preferences
* Includes LTFO XML File Reader Class to review XML submissions
* Has the capability to Move Game Artwork to Network Drive based on user preferences and XML Details (Gamename and GameID)
