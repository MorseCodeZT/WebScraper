# WebScraper
This is a project maded by me during my intership period into MalwareBytes.

WHAT IS IT:
  - Zenigata is a Crowler appointed to capture through regular expression all the IOC presents into the web page. 
  The next step consist to saved the datas into a NoSQL MongDB for simplify the research through queries. 
  It was entirely developed in python3 using Requests(for build the request into the web),
  BeautifulSoup4(parsing the HTML structure), Re(used for build the regular expression),  
  Base64(for codify datas before they are shipped into the DB), Pymongo(for create a connection 
  between the host and the DB instance) and Json(conver the report into a json file for MondoDB) .

SOME INFO ABOUT IT:
  - All the functions are described with functionality, input and output field. The targets of Zenigata are "The DFIR Report" which pubbish threath, malware analysis report for Windows, Linux, MacOS, and "LookOut" that talk about threath, a simplex malware analysis report for Android and iOS device.

WHAT IS HES PURPOSE:
  - The objective of Zenigata is to save time for the malware analyst, that need IOCs for their purpose.

REQUIREMENTS:
  - Before run Zenigata you nee to download those library:
    . bs4 -> python.exe -m pip install BeautifulSoup4;
    . requests -> python.exe -m pip install requests;
    . pymongo -> python.exe -m pip install pymongo;

  DEFAULT OPTIONS:
    - MongoDB settings:
      . client will connect to "mongodb://localhost:27017/", if you want to change it check the 61th line of "zenigata.py";
      . DB that contains the two istance of "The DFIR Report" and "LookOut" has the name of "master", so create a DB name with it 
        or change it into the line 64 of "zenigata.py";
      . DB Istances(colletion) are named with "dfir" and "lookout", same thighs, if you want to change it go to 46 of "zenigata.py" and change the keys of the dictionary as the name that you want;
      . If you want to save the reports in local you CAN DO IT!
        Just go to 2438-2446 lines of "dfirScript.py" and "active" those lines. It will saved in the same directory where "zenigata.py" is saved.
        For "lookoutScript.py" go to 1338-1346" and active those lines;
    - Base64 encoding(deactivated):
      . If you prefer to encode the data before the are shipped to the DB, in both scripts, you need to go to the "replacer" function, active all the return that 
        encode the string and deactive all the return that returns the simple string;
        
