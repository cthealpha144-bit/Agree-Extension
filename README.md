Agree? - Safe Browsing Assistant
Scrapes and analyzes live pages for phishing and security risks.

An open-source, client-side browser extension that maps website privacy policies and data practices into a layout styled to look like a nutrition facts label. 
The extension runs completely within the client environment to evaluate privacy risks, tracking behaviors, and cookie protocols upon navigating to a web domain.

Repository Guide

manifest.json - Declares extension metadata, localized configuration permissions, and elevated host API rules.
popup.html - The User Interface
popup.js -  Coordinates the tab-switching event handlers, API request matrices, and class color badge states.
database.js - Stores the static JSON dictionary mapping established web domains to known data practices.
Extension icon.png - pretty self explanatory, it is the icon.

Installation Instructions (For Chromium Based Browsers)

1. Download Source Assets: Select the Code dropdown button at the top right of this repository page and click Download ZIP.
2. Extract Files: Decompress the downloaded folder contents to a directory on your local file system.
3. Open Browser Extensions Manager: Open a Chromium-powered browser tab and open the extensions page.
4. Enable Developer Mode: Ensure developer mode is enabled on your browser.
5. Load Unpacked Code: Select the Load unpacked button located in the upper left corner.
6. Target Target Directory: Select the folder that contains the project assets, ensuring it is where manifest.json resides.


