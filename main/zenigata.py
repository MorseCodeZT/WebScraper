from os import remove, path
from time import time
from dfirScript import zenigata_dfir
from lookoutScript import zenigata_lookout
from pymongo import MongoClient as mc


def query(db, site):
    added_report_links = []

    coll = db[site]

    query = [
        {
            "$match":{
                "about_it":{"$exists":True}
            }
        },
        {
            "$project": {
                "link":{
                    "$filter":{
                        "input":"$about_it",
                        "as":"item", 
                        "cond":{
                            "$regexMatch":{
                                "input":"$$item", 
                                "regex":"link"
                            }
                        }
                    }
                }
            }
        }
    ]

    outputQ = coll.aggregate(query)
    for elm_query in outputQ:
        for key_elm_query, value_elm_query in elm_query.items():
            if key_elm_query == "link":
                added_report_links.append(value_elm_query[0][8:-2])

    return added_report_links

def main():
    for site, link in sources.items():
        source = (site, link)

        if path.exists("errorsLog.txt"):
            remove("errorsLog.txt")

        # main
        print("\n", f"------------------------------| ZENIGATA is RUNNING on {site}!  (^^_) |------------------------------")

        start_script = time()

        # Query per estrarre i link dei report presenti nella collezione corrente
        # Creo una connessione con l'istanza dove risiede il DB
        client = mc("mongodb://localhost:27017/")

        # Creo un collegamento con il DB
        db = client['master']

        added_report_links = query(db, site)

        # estrazione dei dati di dfir
        if site == "dfir":
            # added_report_links = ["https://thedfirreport.com/2025/05/19/another-confluence-bites-the-dust-falling-to-elpaco-team-ransomware/"]

            titles_all = []
            zenigata_dfir(source, titles_all, added_report_links)

            stop_script = time()

            total_time = float(f"{stop_script-start_script:.2f}")

            if total_time > 60:
                minuti = int(f"{total_time//60:.0f}")
                secondi = f"{total_time-(60*minuti):.2f}"
                print(f"\n[+] Tempo impiegato: {minuti} minuti e {secondi} secondi")
            else:
                print(f"\n[+] Tempo impiegato: {stop_script-start_script:.2f} secondi")


        # estrazione dei dati di lookout
        if site == "lookout":
            # added_report_links = ["https://www.lookout.com/threat-intelligence/article/lookout-discovers-new-spyware-by-north-korean-apt37"]
            zenigata_lookout(source, added_report_links)
            stop_script = time()

            total_time = float(f"{stop_script-start_script:.2f}")

            if total_time > 60:
                minuti = int(f"{total_time//60:.0f}")
                secondi = f"{total_time-(60*minuti):.2f}"
                print(f"\n[+] Tempo impiegato: {minuti} minuti e {secondi} secondi")
            else:
                print(f"\n[+] Tempo impiegato: {stop_script-start_script:.2f} secondi")

sources = {'dfir': "https://thedfirreport.com/", 'lookout': "https://www.lookout.com/threat-intelligence"}

print("########################################################################################################\n", "SCAN BOTH THE SOURCES?".center(100, " "))
print("[y](both) or [n](choice your target)".center(100, " "))
choice = input("#- ")

areUIdiot = 0
while choice != "y" and choice != "n":
    if areUIdiot == 1:
        print("Really?!...... -.-\n")
    elif areUIdiot >= 2:
        print("Don't try to bug it..... YOU CAN'T!!! :D")
    elif areUIdiot == 0:
        print("Don't be shrewd!!! >:( \n You just need to read.... Come on it's eazy!)\n")
    choice = input("#- ")
    areUIdiot += 1

if choice == "y":
    main()
    
elif choice == "n":
    print("[*] Which source you want?".center(100, " "))
    print("[dfir] or [lookout]".center(100, " ")) 

    another_choice = input("#- ")
    c = 0
    while another_choice != "dfir" and another_choice != "lookout":
        if c == 0 and areUIdiot >= 1:
            print("It stopped being fun a thousand yars ago...")
        another_choice = input("#- ")

    if another_choice == "dfir":
        source = ("dfir", "https://thedfirreport.com/")
    elif another_choice == "lookout":
        source = ("lookout", "https://www.lookout.com/threat-intelligence")

    if path.exists("errorsLog.txt"):
        remove("errorsLog.txt")

    # main
    print("\n", f"------------------------------| ZENIGATA is RUNNING on {source[0]}!  (^^_) |------------------------------")

    start_script = time()

    # Query per estrarre i link dei report presenti nella collezione corrente
    # Creo una connessione con l'istanza dove risiede il DB
    client = mc("mongodb://localhost:27017/")

    # Creo un collegamento con il DB
    db = client['master']

    added_report_links = query(db, source[0])

    # estrazione dei dati di dfir
    if source[0] == "dfir":
        # added_report_links = ["https://thedfirreport.com/2025/05/19/another-confluence-bites-the-dust-falling-to-elpaco-team-ransomware/"]

        titles_all = []
        zenigata_dfir(source, titles_all, added_report_links)

        stop_script = time()

        total_time = float(f"{stop_script-start_script:.2f}")

        if total_time > 60:
            minuti = int(f"{total_time//60:.0f}")
            secondi = f"{total_time-(60*minuti):.2f}"
            print(f"\n[+] Tempo impiegato: {minuti} minuti e {secondi} secondi")
        else:
            print(f"\n[+] Tempo impiegato: {stop_script-start_script:.2f} secondi")


    # estrazione dei dati di lookout
    if source[0] == "lookout":
        # added_report_links = ["https://www.lookout.com/threat-intelligence/article/lookout-discovers-new-spyware-by-north-korean-apt37"]
        zenigata_lookout(source, added_report_links)
        stop_script = time()

        total_time = float(f"{stop_script-start_script:.2f}")

        if total_time > 60:
            minuti = int(f"{total_time//60:.0f}")
            secondi = f"{total_time-(60*minuti):.2f}"
            print(f"\n[+] Tempo impiegato: {minuti} minuti e {secondi} secondi")
        else:
            print(f"\n[+] Tempo impiegato: {stop_script-start_script:.2f} secondi")

