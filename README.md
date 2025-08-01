# Zenigata
Crowler for malware analyst.

ABOUT IT:
  - This is a project make by me during my intership period at MalwareBytes.

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
    - client will connect to "mongodb://localhost:27017/", if you want to change it check the 61th line of "zenigata.py";
    - DB that contains the two istance of "The DFIR Report" and "LookOut" has the name of "master", so create a DB name with it  or change it into the line 64 of "zenigata.py";
    - DB Istances(colletion) are named with "dfir" and "lookout", same thighs, if you want to change it go to 46 of "zenigata.py" and change the keys of the dictionary as the name that you want;
    - If you want to save the reports in local you CAN DO IT! Just go to 2438-2446 lines of "dfirScript.py" and "active" those lines. It will saved in the same directory where "zenigata.py" is saved. For "lookoutScript.py" go to 1338-1346" and active those lines;
  - Base64 encoding(deactivated):
    - If you prefer to encode the data before the are shipped to the DB, in both scripts, you need to go to the "replacer" function, active all the return that encode the string and deactive all the return that returns the simple string;
  - Whene the zenigata starts running, it will check if the first report of the current source is already saved on the DB, it will stop. So you need to clear the DB before.

SETUP THE ENVIRONMENTS FOR ZENIGATA:
  - For a correct running of Zenigata you need to setup up MongoDB.
  - First of all download "MongoDB" Compass if you want the GUI version:
  - https://www.mongodb.com/try/download/compass
    
  ![compass](https://github.com/user-attachments/assets/a882bdf8-2d3b-4df8-b067-8012005f4984)


  - Secondth, download "MongoDB Community Server". You need this executable for start the instance on your localhost:
  - https://www.mongodb.com/try/download/community

  ![community](https://github.com/user-attachments/assets/67e45a96-7e5d-439a-bef8-14e01287c8d9)
    
  
  - Thirdth, extract the .zip downloaded, go in "bin" take "mongod.exe" and put it into this path "C:\Program Files\MongoDB\Server\8.0" because it need administator priviledge... If not, you can create this path and put the executable there. THIS IS IMPORTAT!!! For the future, if the version goes ahead(and it will) replace the "8.0" dir of "C:\Program Files\MongoDB\Server\8.0" with the correct one, just the first two digits isn't necessary to write for example "8.0.10".
  - Fourth, start the DB instance into your localhost with "mongod.exe" executable.
  - The fifth STEP in to create your DB, start "MongoDB Compass", near "CONNECTIONS" on the left there's a "+", now make sure that the URI is the SAME of the one in the script "zenigata.py" same thingh for the "name" field. "Save & Connect".
  - Sixth, create a Database with "+" on the right of you instance created. How I saw, the "DB name" and the "collection" name's NEED to be the SAME of the one into the "zenigata.py". DON'T FORGET IT!!!
  
  ![db](https://github.com/user-attachments/assets/7f814324-fad6-46e4-86fc-9333fdae2402)

  - If you have this path you're READY :D

  - I leave the executable of Zenigata that is ready to go but with the default options, if you want the doing some changes you need to re-build the executable with "pyinstaller" for example, or simlpy start the .py scripts <3.
