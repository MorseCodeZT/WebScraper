from requests import get
from bs4 import BeautifulSoup as bs, MarkupResemblesLocatorWarning
from traceback import format_exc
from warnings import filterwarnings
from random import choice, randint
from time import sleep
from re import search, escape, finditer, findall
from os import mkdir, path
from json import dump
from time import time
from pymongo import MongoClient as mc
from base64 import standard_b64encode as b64encode


filterwarnings("ignore", category=MarkupResemblesLocatorWarning)


def id_generator(report):
    '''
        Funzione usata per generare un ID casuale ma con solo le prime due cifre
            che identificano l'anno di pubblicazione del report.

        Input:
            - report(tuple), tupla che contiene la data di pubblicazione;
        Output:
            - report_id(str), stringa che definisce ID univoco del report;
    '''

    num = [0,1,2,3,4,5,6,7,8,9]

    report_id = str(report[1][-2:])
    for x in range(5):
        report_id += str(choice(num))
    
    return report_id

def collection(home_page_main_content, added_report_links):
    '''
        Funzione che colleziona i dati target, restituisce un pacchetto di dati
            in formato "zip";

        input:
            - risposta del server formato BSObj;
            - added_report_links(list), contiene tutti i link dei report estratti dalla query;
        output:
            - zip(titolo, data_pubblicazione, reposity)
            - exit_(bool), se True indica che non ce nulla di nuovo;
    '''

    exit_ = False

    # attributi necessari per filtrare il div contenente la lista dei report
    report_div_attribute = {
        'class':'w-dyn-item',
        'id':'w-node-_9e1b07a6-150b-19ed-92c1-4fa9e7eefedc-0498cf24',
        'role':'listitem'
    }

    # estrazione delle informazioni target dei report dalla struttura HTML
    report_items = home_page_main_content.find_all("div", report_div_attribute)

    # estraggo le informazioni da ogni singolo report
    pubblication_dates = []
    titles = []
    links = []

    for report_item in report_items:
        pubblication_dates.append(report_item.find("div", "text-size-small text-color-grey").text)
        if "https://www.lookout.com" + report_item.find("a", "threats_filter_link-wrap w-inline-block")['href'] in added_report_links:
            exit_ = True
            break
        links.append("https://www.lookout.com" + report_item.find("a", "threats_filter_link-wrap w-inline-block")['href'])
        titles.append(report_item.find("a", "threats_filter_link-wrap w-inline-block").text)
        
    return zip(titles, pubblication_dates, links), exit_

def check_last_page(home_page_soup):
    # verifica di last_page
    if home_page_soup.find("a", "w-pagination-next next threats"):
        new_home_page =  "https://www.lookout.com/threat-intelligence" + home_page_soup.find("a", "w-pagination-next next threats")['href']
        # print(home_page_url)
        return True, new_home_page
    else:
        return False, ""

def osTag_scoring(elm_bs, os_score, key_viewed):
    '''
        Funzione usata per calcolare, tramite parole chiavi, uno score per determinare 
            quale sistema operativo è protagonista del report.
        
            Input: 
                - elm_bs(bs4OBJ), elemento da controllare;
                - os_score(dict), dizionario che tiene conto del punteggio per ogni singolo OS;
                - key_viewed(set), contenitore set per tener conto della keyword trovata, per evitare
                    che una parola chiave venga contata più di una volta;
            Output: 
                - os_score(dict), aggiornamento delle scoring;
                - key_viewed(set), aggiornamento della lista delle parole chiavi controllate;
    '''

    # questo dizionario serve per far si che ,nel testo del report, venga stimato 
    #    di quale OS si sta parlando  
    os_keywords = {
        "windows":[
                    "windows", "powershell", "active directory", "group policy", "registry",
                    "windows defender", "cmd", "ntfs", "task manager", "system32",
                    "wmi", "gpedit", "winlogon", "taskschd", "netsh",
                    "rundll32", "explorer.exe", "winver", "svchost", "windows update",
                    "wsus", ".exe", "dll", "taskkill", "diskpart",
                    "winrm", "administrator account", "windows firewall", "netdom", "control panel",
                    "uac", "trustedinstaller", "psexec", ".ps1", "invoke-", ".sys",
                    ".vbs", ".bat", ".reg", ".cmd" 
                ],
        "linux":[
                    "linux", "bash", "apt", "systemd",
                    "sshd", "cron", "kernel module", "selinux", "journald",
                    "init", "debian", "red hat", "rpm", "pacman", "gnome", "unix"
                    "zypper", "gnome-terminal", "sysctl", "iptables", "grep",
                    "tar", "/etc/passwd", "mount", "crontab", "sudoers",
                    "/var/log", "systemctl", "ufw", "rsync", "runlevel", "elf", ".sh"
                ],
        "mac":[
                    "macos", "spotlight", "finder", "time machine", "launchd",
                    "apple silicon", "brew", "system preferences", "xcode", "darwin",
                    "macbook", "mac mini", "safari", "plist", ".dmg", ".pkg", "macho", "mach-o"
                    "activity monitor", "keychain", "console.app", "icloud", "airplay",
                    "automator", "disk utility", "mission control", "osascript", "applescript",
                    "menu bar", "menubar apps", "thunderbolt", "macports", "/applications", 
                    "/private/tmp", "launchagent", "launchdaemon", "tcc", "xprotect", "dlyb", 
                    "amos", "/volumes", "xattr"
                ],
        "android":[
                    "android", "apk", "play store", "playstore", "adb",
                    "dalvik", "logcat", "manifest.xml",
                    "android sdk", "android studio", "adb shell", "android debug bridge",
                    "android manifest", "androidmanifest", "android.intent.action", "r.java",
                    "minSdkVersion", "targetSdkVersion", "android.hardware.camera", "android.permission",
                    "dex", "dalvkin executable", "sms", "sms messages", "sms message", "call logs", "sms logs", "google play", "apkpure",
                    "google play store", "phone", "phone manager", "mobile devices" , "mobile device", "app stores", 
                    "device contacts", "app", "apps", "mobile apps"
                ]
    }

    if elm_bs != "" and elm_bs != "\n":
        for os, keywords in os_keywords.items():
            for kws in keywords:
                pattern = r"\b" + escape(kws) + r"\b"
                # if kws in str(elm_bs.text).strip().lower() and kws not in key_viewed:
                if search(pattern, elm_bs.lower()) and kws not in key_viewed:
                    # print(f"os: {os} -> {kws}")
                    os_score[os] += 1
                    key_viewed.add(kws)
    return os_score, key_viewed
    ################################################################################################

def extractor(url):
    '''
        Funzione usata per gestire l'estrazione dei dati grezzi e la formattazione in sezioni.

        Input:
            - url(str), url usato per richiedere la risorsa html della pagina da cui estrarre
                le informazioni;
        Output:
            - new_sections(list), lista contenente i dati grezzi formattati;
            - titles(list), lista contenente i titoli con dati della pagina 
    '''

    #--------------------------------------------------------------------------
    # score per gli os;
    os_score = {
        "windows":0,
        "linux":0,
        "mac":0,
        "android":0
    }
    #--------------------------------------------------------------------------

    #--------------------------------------------------------------------------
    # contenitore per evitare che una parola venga contata per più di una volta;
    key_viewed = set()
    #--------------------------------------------------------------------------

    report_request = get(url, headers={"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 Edg/132.0.0.0"})
    report_soup = bs(report_request.content, "html.parser")
    report_main_content = report_soup.find("div", "blog_content-wrapper")
    
    #--------------------------------------------------------------------------
    # lista che conterrà la sezione grezza;
    sections = []
    #--------------------------------------------------------------------------

    for x in report_soup.find("div", "max-width-xlarge").contents:
        if str(x)[:2] == "<h":
            sections.append((int(str(x)[2]),replacer_title(str(x.text).lower().strip())))
            break

    #--------------------------------------------------------------------------
    # lista per raggrupapre i dati;
    data_collection = []
    #--------------------------------------------------------------------------

    #--------------------------------------------------------------------------
    # True:
    #   . quando viene trovato il titolo "citations";
    # False:
    #   . quando precedentemente era True e viene trovato un nuovo titolo;
    citation_section = False
    #--------------------------------------------------------------------------

    #--------------------------------------------------------------------------
    # True:
    #   . quando viene trovato un titolo in tag <strong>;
    # False:
    #   . quando precedentemente era True e viene trovato un nuovo titolo;
    strong_title = False
    #--------------------------------------------------------------------------

    #--------------------------------------------------------------------------
    # True:
    #   . quando viene trovato il titolo "Indicators of Compromise", 
    #       che indica la zona degli ioc;
    # False:
    #   . quando stiamo ancora scorrendo il report;
    ioc = False
    #--------------------------------------------------------------------------

    #--------------------------------------------------------------------------
    # lista che conterrà i titoli da usare come tags
    titles = []
    #--------------------------------------------------------------------------

    for elm in report_main_content.contents:
        # analisi del OS menzionato;
        os_score, key_viewed = osTag_scoring(repr(str(elm)), os_score, key_viewed)
        # print("\n#",elm)
        # se il dato è compresso in un div allora lo scomponiamo per una ricerca approfondita;
        if str(elm)[:4] == "<div":
            # print("\n",elm)
            for elm_deep in elm:
                # print("\n#",elm_deep)
                data_collection, titles, author, citation_section, ioc = extracting(elm_deep, sections, data_collection, titles, citation_section, strong_title, ioc)
        else:
            data_collection, titles, author, citation_section, ioc = extracting(elm, sections, data_collection, titles, citation_section, strong_title, ioc)
    
    # pulizia dai titoli vuoti e dati senza titoli;
    if sections:
        while len(sections) > 0 and type(sections[-1]) == tuple:
            sections.pop()

        while len(sections) > 0 and type(sections[0]) != tuple:
            sections.pop(0)

    sections = emptySec(sections)

    # estrazione dei titoli dal report;
    titles_check = [x[1] for x in sections if type(x) == tuple]
    
    titles = [title for title in titles.copy() if title[1] in titles_check]
    
    # calcolo del OS rilevato
    max_score = 0
    os_detected = ""
    for os, value in os_score.items():
        if value > max_score:
            max_score = value
            os_detected = os

    # aggiunta del tag os in titles;
    titles.append(os_detected)

    # formattazione delle sezione in formato liste [*titolo, [subTitle, [dato]]];
    new_sections = []
    min_num = 10

    stack = []
    new_section = []
    i = 0

    if sections:
        while i < len(sections):
            elm = sections[i]
            
            # print(elm)
            if type(elm) == tuple:
                num, title = elm
                        
                if num < min_num:
                    min_num = num

                node = ["*"+title]
                
                while i+1 < len(sections) and (type(sections[i+1]) == str or (type(sections[i+1] == list) and sections[i+1][0] == "data")):
                    
                    if type(sections[i+1]) == list:
                        
                        node.append(sections[i+1][1:])
                    else:
                        
                        node.append(sections[i+1])
                        
                    i += 1

                while stack and stack[-1][0] > num:
                    stack.pop()

                if not stack:
                    new_section.append(node)
                
                else:
                    prev_num, prev_node = stack[-1]

                    if prev_num == num:
                        if num == min_num:
                            new_section.append(node)
                        else:
                            if len(stack) >= 2:
                                for x in range(len(stack)-2, -1, -1):
                                    candidate_num, candidate_node = stack[x]

                                    if candidate_num < num:
                                        candidate_node.append(node)
                                        break
                    else:
                        prev_node.append(node)
            
            stack.append((num, node))
            i += 1
            
        new_sections.append(new_section)

    else:
        return new_sections, "", author
    
    return new_sections, titles, author

def replacer(elm, noTags):
    '''
        Funzione usata per pulire i dati.

        Input:
            - elm(bs4OBJ), elemento estratto dalla struttura HTML;
            - noTags(bool), valore booleno per permettere o meno l'uso del parsing
                di pulizia degli elementi HTML;
        Outpt:
            - clear_string(str), stringa che corrisponde all'elemento pulito
    '''
    
    clear_string = str(elm)

    if "<br/>" in clear_string:
        clear_string = clear_string.replace("<br/>", "\n")
    if "’" in clear_string:
        clear_string = clear_string.replace("’", "'")
    if "‘" in clear_string:
        clear_string = clear_string.replace("‘", "'")
    if "“" in clear_string:
        clear_string = clear_string.replace("“", "'")
    if "”" in clear_string:
        clear_string = clear_string.replace("”", "'")
    
    if not noTags:
        clear_string = bs(clear_string, "html.parser")    
        clear_string = str(clear_string.text).strip()

    if "https" in clear_string:
        if clear_string[0].isdigit():
            clear_string = clear_string[1:].strip()
            
    if clear_string[-1] == ".":
        clear_string = clear_string[:-1].strip()

    # print(clear_string)

    # return str(b64encode(clear_string.encode()))
    return clear_string
    ###########################################################################

def replacer_title(elm):
    '''
        Funzione usata per pulire i titoli.

        Input:
            - elm(bs4OBJ), elemento estratto dalla struttura HTML;
        Output:
            - clear_title(str), stringa che corrisponde al titolo pulito;
    '''

    clear_title = str(elm)
    # print(clear_title)
    if "’" in clear_title:
        clear_title = clear_title.replace("’", "'")
    if "–" in clear_title:
        clear_title = clear_title.replace("–", "-")
    if '"' in clear_title:
        clear_title = clear_title.replace('"', "'")
    if "\u200d" in clear_title:
        clear_title = clear_title.replace("\u200d", "")

    return clear_title
 ##############################################################################

def extracting(elm, sections, data_collection, titles, citation_section, strong_title, ioc):
    '''
        Funzione usata per estrarre le informazioni dalla struttura HTML.

        Input:
            - elm(bs4OBJ), elemento estratto dalla struttura HTML;
            - sections(list), lista che rappresenta le sezioni di dati grezzi;
            - strong_titles(list), lista che contiene i titoli target incapsulati nei tag <strong>
            - data_collection(list), lista usata per ricomporre tutti i dati target 
                che si trovano all'interno dei tag <pre>. Questo perchè i tag <pre> sono figli 
                dei tag <div> che sono troppo compressi e quindi è necessari scomporre la stringa;
            - citation_section(bool), interruttore per gestire la sezione "citation" quando presente;
            - strong_title(bool), interruttore per gestire i titoli all'interno dei tag <strong>;
            - ico(bool), interruttore per gestire i dati nella parte degli IOC(in fondo alla pagina); 

        Output:
            - data_collection(list), lista aggiornata;
            - citation_section(bool), valore aggiornato;
            - strong_title(bool), valore aggiornato;
            - ioc(bool), valore aggiornato; 
    '''

    #--------------------------------------------------------------------------
    # titoli contenuti in tag <strong>;
    strong_titles = ["files", "c2 domains", "firebase projects", "sha-256", "c2 servers", "sha-1s", 'ip / domainport', "sha1package nametitle", "sha1"]
    #--------------------------------------------------------------------------


    excluded_datas = ["gmail.com", "mail.ru", "and/or", "globally.through", "ssn/ein", "application.In"]
    
    ioc = False

    clear_elm = elm

    author = ""
    
    if "<li>" in str(clear_elm):
        clear_elm = str(clear_elm).replace("<li>", " ")
        clear_elm = bs(clear_elm, "html.parser")
    elif "</li>" in str(clear_elm):
        clear_elm = str(clear_elm).replace("</li>", "\n")
        clear_elm = bs(clear_elm, "html.parser")
    clear_elm = str(clear_elm.text).strip()
    
    # print("\n#",elm)
    if citation_section:
        # print(elm.text)
        if str(elm)[:2] == "<h" or str(elm)[:11] == "<p><strong>":
            citation_section = False

            # se ci sono dati salvati allora li invio alla sezione grezza
            if data_collection:
                if type(data_collection) == list:
                    if len(data_collection) == 1:
                        data_collection = data_collection[0]
                    else:
                        data_collection.insert(0, "data")
                        
                sections.append(data_collection)
                # resetto la data_collection per la prossima section;
                data_collection = []
        else:
            data_collection.append(replacer(elm, False))
        return data_collection, titles, author, citation_section, ioc
    
    if strong_title:
        if str(elm)[:2] == "<h" or str(elm)[:11] == "<p><strong>":
            strong_title = False

    # titoli principali e subTitles contenuti in tag <h*>;
    if str(elm)[:2] == "<h":
        if clear_elm != "" and clear_elm != "\n" and clear_elm != "\u200d":
            # print(elm.text)
            if clear_elm.lower() == "indicators of compromise":
                ioc = True

            # se viene trovato un nuovo titolo o subTitle e data_collection 
            #   contiene dati, allora bisogna spezzare la section;
            if data_collection:
                if type(data_collection) == list:
                    if len(data_collection) == 1:
                        data_collection = data_collection[0]
                    else:
                        data_collection.insert(0, "data")
                # print("\n",clear_elm, data_collection)
                sections.append(data_collection)
                # resetto la data_collection per la prossima section;
                data_collection = []

            # aggiungo il titolo o subTitle;
            
            sections.append((int(str(elm)[2]), replacer_title(clear_elm.lower())))
            titles.append((int(str(elm)[2]), replacer_title(clear_elm.lower())))

    # titoli, subTitles e dati contenuti nei tag <strong>;
    elif str(elm)[:3] == "<p>":
        if clear_elm != "" and clear_elm != "\n" and clear_elm != "\u200d":
            # titoli e subTitles;
            if str(elm)[:11] == "<p><strong>":
                # Avvolte questi magnifici sviluppatori mettono titolo e dati attaccati :)))) DIO PORCO!
                # quindi controllo se qualche strong_title è presente nel titolo per magheggiare e provare 
                # ad estrarre i dati
                # print("\n",elm.text)
                for strong_title in strong_titles:
                    if strong_title in str(elm.text).lower():
                        sections.append((5, strong_title))
                        titles.append((5, strong_title))

                        dato = str(elm.text).lower().replace(strong_title, "").strip()
                        
                        # se è presente questo subTitle con dati
                        #   allora è necessario effettuare delle operazioni di parsing
                        if strong_title == "sha1package nametitle":
                            dato_parsed = qualcosaParser(str(elm.text).replace(strong_title, "").strip())
                            dato_dict = {}
                            # print(dato_parsed)
                            for d in range(len(dato_parsed)):
                                dato_dict[str(d)] = {"Name": dato_parsed[d][0], "Pkg Name": dato_parsed[d][1], "SHA-1": dato_parsed[d][2]}
                            
                            sections.append(["data", dato_dict])
                            return data_collection, titles, author, citation_section, ioc

                        if strong_title == "sha-1s" or strong_title == "sha1":
                            if len(dato) > 40:
                                dato = findall(r'[a-f0-9]{40}', dato)
                        if type(dato) == list:
                            dato.insert(0, "data")
                            
                        sections.append(dato)
                        # print("\n#",str(elm.text).lower().replace(strong_title, "").strip())
                        return data_collection, titles, author, citation_section, ioc

                # attivo la raccolgo delle sorgenti di informazioni;
                if clear_elm.lower() == "citations":
                    citation_section = True
                    
                    if data_collection:
                        if type(data_collection) == list:
                            if len(data_collection) == 1:
                                data_collection = data_collection[0]
                            else:
                                data_collection.insert(0, "data")
                                
                        sections.append(data_collection)
                        # resetto la data_collection per la prossima section;
                        data_collection = []

                    sections.append((5, replacer_title(clear_elm.lower())))
                    titles.append((5, replacer_title(clear_elm.lower())))
                
                elif clear_elm.lower() in strong_titles:
                    
                    strong_title = True
                    # se viene trovato un nuovo titolo o subTitle e data_collection 
                    #   contiene dati, allora bisogna spezzare la section;
                    if data_collection:
                        # print(data_collection)
                        if type(data_collection) == list:
                            if len(data_collection) == 1:
                                data_collection = data_collection[0]
                            else:
                                data_collection.insert(0, "data")
                                
                        sections.append(data_collection)
                        # resetto la data_collection per la prossima section;
                        data_collection = []
                        
                    # aggiungo il titolo o subTitle;
                    sections.append((5, replacer_title(clear_elm.lower())))
                    titles.append((5, replacer_title(clear_elm.lower())))

                else:
                    clear_string = replacer(elm, False)
                    # print("\n#",clear_elm)
                    matches = data_detection(clear_string)
                    if matches:
                        for m in matches:
                            # print(m)
                            if m not in data_collection and m.lower() not in excluded_datas:
                                if m[-1] == ":" or m[-1] == "." or m[-1] == '"' or m[-1] == ",":
                                    m = m[:-1]
                                if m[0] == "(" or m[0] == '"':
                                    m = m[1:]
                                # print(m, rule)
                                # print("\n[+] Controllo la presenza del dato...")
                                check_data_added(m, data_collection)
                                # print("[+] Controllo completato!")

            else:
                # print("\n#",elm.text)
                if str(elm.text).strip().lower().startswith("(download csv file"):
                    sections.append(f"{elm.text}: {elm.find("a")['href']}")
                    
                if strong_title:
                    data_collection.append(replacer(elm, False))
                
                # nel caso in cui un mini-titolo non ha tag <p><strong> ma solo <p>
                #   allora verifico se è nella lista degli strong_titles, se lo è
                #   lo aggiungo alla sezione
                elif not strong_title and clear_elm.lower() in strong_titles:
                    # print(clear_elm)
                    # Se sono presenti dati estratti, li aggiungo alla sezione 
                    if data_collection:
                        if type(data_collection) == list:
                            if len(data_collection) == 1:
                                data_collection = data_collection[0]
                            else:
                                data_collection.insert(0, "data")
                                
                        sections.append(data_collection)
                        # resetto la data_collection per la prossima section;
                        data_collection = []

                    sections.append((5, replacer_title(clear_elm.lower())))
                    titles.append((5, replacer_title(clear_elm.lower())))
                    return data_collection, titles, author, citation_section, ioc

                else:
                    if ioc:
                        data_collection.append(clear_elm)
                    else:
                        clear_string = replacer(elm, False)

                        # print("\n#",clear_elm)
                        matches = data_detection(clear_string)
                        # print("*",matches)

                        matches_sorted = sort_matches(matches)
                        clear_matches_sorted(matches_sorted)
                        # print(matches_sorted)
                        if matches:
                            for m in matches:
                                # print(m)
                                if m.lower() not in excluded_datas:
                                    if m[-1] == ":" or m[-1] == "." or m[-1] == '"' or m[-1] == ",":
                                        m = m[:-1]
                                    if m[0] == "(":
                                        m = m[1:]
                                    # print(m, rule)
                                    # print("\n[+] Controllo la presenza del dato...")
                                    check_data_added(m, data_collection)
                                    # print("[+] Controllo completato!")
                        # print("[+] Controllo regex completato!")
    
    # gestore dei dati in tabelle statiche
    elif str(elm)[:21] == '<div class="w-embed">':
        clone_table(elm, sections)

    # gestione dei dati in tabelle dinamiche
    elif str(elm)[:30] == '<div class="w-embed w-script">':
        script_string = str(elm.find("script").string).strip()
        match_script = search(r'https?://[^\s\'"]+', script_string)
        if match_script:
            source_code = match_script.group()
            # print(source_code)
            request_source_code = get(source_code, headers={"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 Edg/132.0.0.0"})
            soup_source_code = bs(request_source_code.content, "html.parser")
            
            clone_table(soup_source_code, sections)
            
    elif str(elm)[:46] == '<div class="hero_blog_author_list w-dyn-items"':
        author_div = elm.find("div", "hero_blog_author_name-wrapper").contents
        
        deep = False
        if len(author_div) == 1:
            deep = True

        for x in author_div:
            if deep:
                for j in x:
                    if str(j)[:2] == "<h":
                        author = str(j.text).lower().strip()
                        return data_collection, titles, author, citation_section, ioc
            
            if str(x)[:2] == "<h":
                author = str(x.text).lower().strip()
                # print(x)
                return data_collection, titles, author, citation_section, ioc

    else:
        if len(clear_elm) % 4==0:
            if "<br/>" in str(elm):
                clear_elm = bs(str(elm).replace("<br/>", "\n"), "html.parser").text
        # print("\n#", len(clear_elm))
        matches = data_detection(clear_elm)
        # print("*",matches)

        matches_sorted = sort_matches(matches)
        clear_matches_sorted(matches_sorted)
        
        if matches:
            # print(matches)
            for m in matches_sorted:
                # print("\n--------------------------------\n",m)
                if m.lower() not in excluded_datas:
                    if m[-1] == ":" or m[-1] == "." or m[-1] == '"' or m[-1] == ",":
                        m = m[:-1]
                    if m[0] == "(" or m[0] == '"':
                        m = m[1:]
                    # print("\n",m)
                    # print("\n[+] Controllo la presenza del dato...")
                    # print("*", data_collection)
                    check_data_added(m, data_collection)
                    # print(data_collection)
                    # print("[+] Controllo completato!")
        # print("[+] Controllo regex completato!")

    return data_collection, titles, author, citation_section, ioc
    ##########################################################################################

def qualcosaParser(string):
    '''
        Funzione usata per separare un dato che contiene [SHA-1][DOMINIO][NOME_PKG]

        IMPORTANTE: il nome della funzione è protetto da copyright, 
            per usi futuri contattare il Bizzo;

        Input:
            - string(str), stringa compattata da separare;
        Output:
            - master_pkg(list), lista di tuple che contengono i dati in questo formato
                (NOME_PKG, DOMINIO, SHA-1)
    '''

    # print(string)
    # stringa che conterrà i caratteri ad salvare
    string_pkg_reversed = ""

    # contenitore per formare il pkg [NOME_PKG, DOMINIO, SHA-1]
    master_pkg = []

    # interruttore per salvare i dati
    take_char = True

    # Punto in cui è permesso salvare i dati.
    #   Nel momento in cui viene trovato [DOMINIO] e [NOME_PKG] viene calcolata
    #   la posizione dello SHA 
    checkpoint = 0


    # La stringa ha questa sintassi [SHA-1][DOMINIO][NOME_PKG],
    #   il dominio inizia sempre per "com." e il nome_pkg ha sempre uno spazio
    #   tra le due parole con le iniziali maiuscole mentre lo sha ha 40 caratteri.
    #   Intendo operare iterando dal fondo della stringa, trovare l'inizio del dominio
    #   e procedere per 40 caratteri.

    # a ritroso itero all'interno della stringa
    for x in range(len(string)-1, -1, -1):
        # Se la stringa che sto riempendo dal fondo è stata svuotata e l'iteratore
        #  non è al punto iniziale allora evito che i caratteri vengano salvati.
        #  Questo perchè siamo nella zona SHA 
        if string_pkg_reversed == "" and x < len(string)-1:
            take_char = False

        # se l'iteratore ha raggiunto il checkpoint possiamo tornare a salvare i caratteri
        if x == checkpoint:
            take_char = True

        # aggiungo a ritroso i caratteri
        if ".moc" not in string_pkg_reversed:
            # verifico di avere il permesso di salvare i caratteri
            if take_char:
                string_pkg_reversed += string[x]
        
        
        # Se la stringa ".moc"(com. al contrario) è presente nel stringa che contiene
        #   [DOMINIO][NOME_PKG] significa che il prossimo dato sono 40 caratteri di sha
        else:
            # stringa che ricomporrò al contrario
            string_pkg = ""
            for j in range(len(string_pkg_reversed)-1, -1, -1):
                string_pkg += string_pkg_reversed[j]

            # spezzare il dato perchè abbiamo trovato [DOMINIO][NOME_PKG]
            string_pkg_reversed = ""
            current_sha = string[(x+1)-40:x+1]
            checkpoint = (x+1)-41
            
            # separo il DOMINIO dal NOME_PKG
            c = 0
            # print("\n", string_pkg)
            for z in string_pkg:
                if z.isupper():
                    nome_pkg = string_pkg[c:]
                    dominio = string_pkg[:c]
                    break
                c += 1
            # print(nome_pkg)
            master_pkg.append((nome_pkg, dominio, current_sha))
    return master_pkg

def sort_matches(matches):
    '''
        Funzione usata per ordinare una lista con lunghezza degli elementi in modo descrescente.

        Input:
            - matches(list), contiene gli elementi da ordinare;
        Output:
            - matches_sort(list), contiene gli elementi ordinati;
    '''

    matches_sort = []

    for match in matches:
        if not matches_sort:
            # print(f"\naggiungo '{match}' in '{matches}'")
            matches_sort.append(match)
        else:
            # print(f"\nmatches esiste -> {matches}")
            count = 0
            while count <= len(matches)-1:
                # print(f"confronto '{match}' con '{matches[count]}'")
                if len(match) >= len(matches[count]):
                    matches_sort.insert(count, match)
                    break
                
                count += 1
    return matches_sort

def clear_matches_sorted(matches_sorted):
    '''
        Funzione usata per filtrare tutti i dati che vengono contenuti,
            per evitare che più dati provenienti dallo stesso vengano salvati.

        Input:
            - matches_sorted(list), contiene possibili doppioni
    '''

    for x in range(len(matches_sorted)-1,-1,-1):
        add_data = True
        candidate = matches_sorted.pop(x)

        # print("\n*",candidate,"\n",matches_sorted)

        for match in matches_sorted:
            if candidate in match:
                # print("\n", candidate, "in", match)
                add_data = False

        if add_data:
            matches_sorted.append(candidate)

def data_detection(clear_elm):
    '''
        Funzione usata per identificare dati secondo espressioni regolari.

        Input:
            - clear_elm(str), testo da controllare;
        Output:
            - matches(list), contiene i dati rilevati;
    '''

    #--------------------------------------------------------------------------
    # lista di regex per la ricerca di dati;
    # Rileva url, domini ed email con [.] e senza, ip e path
    detection_regex_data = [r"[^\:]+(?:(?:\:)+[^\:]+)+(?:\>)+", r"(?:\<)+[^\:]+(?:(?:\:)+[^\:]+)+", r"c\:(?:\\[^\\]+)+", r"(?:\<[^/]+\>|[^/\s]{3,}+)?(?:/[^/\s,]{3,}+)+",'((?:https|http|hxxps|hxxp)?(?:\\:/)?(?:/[^/\'"”\\s,]{4,})+(?:/[^/\\s,]+)*)', r'\d{1,3}(?:(?:\.|\[\.])\d{1,3}){3}(?:\:\d{3,5})?', '^<script.*</script>$', '(?:[a-zA-Z0-9._%+-])*@[a-zA-Z0-9-]+(?:(?:\\.|\\[\\.])[a-zA-Z0-9-]+)*(?:\\.|\\[\\.])?[a-zA-Z0-9]{2,}\\b', '\\b[a-fA-F0-9]{28,}\\b', r'(?:[a-zA-Z0-9-_]+(?:(?:\[.\])|\[..\]|\.)){1,}[a-zA-Z_]{2,}(?:\:[0-9]+)?(?:\:\:[a-zA-Z\(\)]*)*', '\\b(?:(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.)3(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)(?::\\d(1, 5))?\\b', '\\b\\w+(?:_\\w+)+\\b', '\\b\\w+\\(\\)', '\\b[a-fA-F0-9]{6,}-[a-zA-Z0-9]{1,6}\\b', 'Mozilla\\/[0-9.]+ \\([^)]+\\)(?: [a-zA-Z]+\\/[0-9.]+)+', r"CVE-\d{4}-\d{4,}"]
    #--------------------------------------------------------------------------


    if "’" in clear_elm:
        clear_elm = clear_elm.replace("’", "'")
    if "‘" in clear_elm:
        clear_elm = clear_elm.replace("‘", "'")
    if "“" in clear_elm:
        clear_elm = clear_elm.replace("“", "'")
    if "”" in clear_elm:
        clear_elm = clear_elm.replace("”", "'")

    if clear_elm.startswith("'") and clear_elm.endswith("'"):
        clear_elm = clear_elm[1:-1]
    if clear_elm.startswith('"') and clear_elm.endswith('"'):
        clear_elm = clear_elm[1:-1]


    #--------------------------------------------------------------------------
    # lista per contenere i range dei dati aggiunti
    used_ranges = []
    #--------------------------------------------------------------------------
    #--------------------------------------------------------------------------
    # lista per contenere i dati rilevati
    matches = []
    #--------------------------------------------------------------------------
    
    # print("\n---------------------------------------------------------\n")
    # print(f"\n{clear_elm}")
    for reg in detection_regex_data:
        # print(f"\nUso {reg}")
        for match in finditer(reg, clear_elm):
            # print(f"\nUso {reg}")
            # print(f"Trovato: {match.group()}")
            span = match.span()
            # print(f"Posizione: {span}")
            is_dirty, match_cleared = clearMatch(str(match.group()))

            while is_dirty:
                is_dirty, match_cleared = clearMatch(match_cleared)

            if not used_ranges:
                # print(f"used_ranges vuota...\n  Aggiungo {span} e {match.group()}")
                used_ranges.append(span)
                
                matches.append(match_cleared)
            else:
                add = True
                # print(f"Used_ranges esiste...")
                for range in used_ranges:
                    # print(f"    Estraggo {range} e verifico {span}")
                    if span[0] >= range[0] and span[1] <= range[1]:
                        # print(f"{span} è in {range}")
                        add = False

                if add:
                    # print(f"    Aggiungo {match.group()}")
                    matches.append(match_cleared)
                    used_ranges.append(span)
                else:
                    # print(f"    {span} è presente in {range}")
                    break
    # print("\n",matches)
    return matches

def clearMatch(string):
    '''
        Funzione usata per pulire il dato identificato all'interno del testo.

        Input:
            - string(str), match identificato;
        Output:
            - is_dirty(bool), valore booleano che indica se è stato identificato 
                dello sporco nella stringa;
            - string(str), stringa pulita;
    '''
    # print(f"\nPulisco '{string}'")
    dirty = False

    if string[-1] == "." or string[-1] == "," or string[-1] == "'" or string[-1] == '"':
        string = string[:-1]
        dirty = True

    if string[0] == "'" or string[0] == '"':
        string = string[1:]
        dirty = True

    # print(f"- {string}")
    return dirty, string

def clone_table(elm, sections):
    '''
        Funzione usata per filtrare i dati da una tabella 
            e ricostruirla sotto forma di dizionario.
        
        Input:
            - elm(bs4OBJ), elemento da cui estrarre i dati;
            - sections(list), contenitore dove salvare i dati;
    '''

    # Contatore delle righe della tabella;
    # Inizializzato a -1 per saltare la prima riga che sono i titoli di essa,
    #   quando è maggiore di 0 iniziare a scriverla;
    raw_count = -1
    # Contatore dei dati, quando è maggiore della dimensione della lista dei titoli
    #  allora lo azzero;
    data_count = 0

    # Dizionario che simula la tabella;
    table = {}

    # interruttore per permettere al dato di essere salvato
    save_data = False
    
    table_titles = []

    # spacchetto l'elemento che contiene tutta la struttura della tabella
    for table_elm in str(elm).split("\n"):
        # quando al tabella finisce esco dal ciclo
        if table_elm[:7] == "</tbody":
            break

        table_elm_bs = bs(table_elm, "html.parser")
        # ogni volta che c'è una nuova linea aumento il contatore
        if table_elm[:3] == "<tr":
            raw_count += 1
        # disattivo l'interruttore;
        elif table_elm[:4] == "</tr":
            save_data = False
            continue

        # attivo l'interruttore;
        if raw_count > 0 and not save_data:
            save_data = True
            # Creo la riga;
            for table_title in table_titles:
                if raw_count not in table.keys():
                    table[raw_count] = {table_title:""}
                else:
                    table[raw_count].update({table_title:""})
                    
        # attivo l'interrutore per i titoli
        elif raw_count == 0:
            if table_elm_bs.text != "":
                table_titles.append(table_elm_bs.text)
        
        # se il contatore è maggiore di 0 allora possiamo iniziare a salvare i dati;
        if table_elm[:3] == "<td":
            if save_data:
                # azzero il contatore dei dati per riallinearlo con i titoli
                if data_count > len(table_titles)-1:
                    data_count = 0

                # alimento la tabella
                if str(table_elm_bs.text).strip() != "":
                    table[raw_count][table_titles[data_count]] = replacer(table_elm_bs, False) 
                else:
                    table[raw_count][table_titles[data_count]] = str(table_elm_bs.text) 
                data_count += 1
    sections.append(["data", table])

def check_data_added(dato, data_collection):
    '''
        Funzione usata per verificare se una dato è gia stato aggiunto.

        Input:
            - dato(str), dato da verificare se già aggiunto in precedenza;
        Output:
            - data_collection(list), lista da verificare
    '''
    
    # interruttore per permettere di aggiungere il dato
    add_data = True
    # controllo se almeno un dato è contenuto
    if data_collection:
        count_data_collection = 0
        # print("\n*",dato)
        # print(data_collection)
        for data in data_collection:
            # print("-", data)
            if len(dato) > len(data):
                if data in dato:
                    # print(dato)
                    dato = replacer(dato, True)
                    if dato not in data_collection:
                        # print(f"\n'{dato}' sostituisco '{data}'")
                        data_collection[count_data_collection] = replacer(dato, True)
                    else:
                        # print(f"\n'{dato}' è presente, elmino '{data}'")
                        data_collection.pop(count_data_collection)
                    # data_collection[count_data_collection] = replacer(dato, True)
                    add_data = False
            elif dato in data:
                # print("\n+",dato,"\n-", data)
                add_data = False
                break
            
            elif dato == data:
                add_data = False
                break
            
            count_data_collection += 1

        
        # se l'interruttore è rimasto attivo allora aggiungo il dato
        # print("\n*", dato, add_data)
        if add_data:
            # print("\n*", dato)
            data_collection.append(replacer(dato, True))
    
    # aggiungo il primo dato
    else:
        data_collection.append(replacer(dato, True))

def emptySec(sections):
    '''
        Funzione usata per eliminare le sezioni vuote.

        Input:
            - sections(list), lista che contiene le sezioni di dati formattate ed organizzate
                in una versione grezza(da pulire);
    '''

    sections_copy = sections.copy()

    exit_ = False
    update = 0

    for x in range(len(sections_copy)-1, -1, -1):
        x -= update
        if exit_:
            break
        if -x == len(sections_copy):
            break
        neg_c = x-1
        while type(sections_copy[x]) == tuple:
            if x+1 == len(sections_copy):
                sections_copy.pop()
                update += 1
                x -= 1
                neg_c -= 1
                continue
            if type(sections_copy[neg_c]) == tuple:
                if sections_copy[x][0] <= sections_copy[neg_c][0]:
                    sections_copy.pop(neg_c)
                    update += 1
                    x -= 1
                    neg_c -= 1
                else:
                    break

            else:
                # print(sections_copy[x], sections_copy[neg_c], x, len(sections_copy),"\n----------------------\n", sections_copy,"\n----------------------\n")
                if x+1 > len(sections_copy):
                    sections_copy.pop()
                else:
                    break

            if (neg_c) < 0:
                exit_ = True
                break
    return sections_copy

def build_tree(node):
    '''
        Funzione usata per costruire la struttura ad albero delle sezioni.

        Input:
            - node(list), lista che corrisponde ad una sezione;
        Output:
            - node(list/dict), lista aggiornata;
    '''

    if type(node) == list and len(node) >= 2:
        key, *children = node
        if type(key) == str and key[0] == "*":
            key = key[1:]
            result = []

            for child in children:
                if type(child) == list:
                    # Se il figlio è una lista, potrebbe essere un altro titolo o dati
                    # print("\n----------------\n",child)
                    if len(child) >= 2 and type(child[0]) == str and child[0][0] == "*":
                        # Fratelli, creiamo un dizionario per ciascuno
                        result.append(build_tree(child))

                    else:
                        # Dati sotto il titolo (senza titolo figlio)
                        # print("\n",child)

                        # controllo per evitare che titoli visti come dati vengano aggiunti
                        if len(child) == 1:
                            if type(child[0]) != dict:
                                if child[0][0] == "*":
                                    # print(child)
                                    continue

                        #   controllo necessario per far si che solo i dati listati vengano
                        #   aggiunti con append. I dati in liste annidate devono essere
                        #   aggiunti tramite extend per evitare una lista di troppo
                        if type(child[0]) != list:
                            # print(child)
                            result.append(child)
                            continue

                        # aggiungo il dato
                        result.extend(child)

                elif type(child) == str:
                    # Dati semplici
                    result.append(child)
            return {key : result}
    return node

def build_tree_tags(tag):
    if type(tag) == list and len(tag) >= 2:
        key, *values = tag
        result = []
        
        for val in values:
            result.append(build_tree_tags(val))
        return {key: result}
    
    else:
        return tag[0]

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

def zenigata_lookout(source, added_report_links, page_count=1):
    site = source[0]
    home_page_url = source[1]

    exit_ = False

    # creo una connessione con l'istanza dove risiede il DB
    client = mc("mongodb://localhost:27017/")

    # creo un collegamento con il DB
    db = client['master']

    # creo un collegamento con la collezione
    coll = db[site]
    
    home_page_request = get(home_page_url, headers={"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 Edg/132.0.0.0"})
    home_page_soup = bs(home_page_request.content, "html.parser")

    home_page_div_attributes = {
        'class': 'w-dyn-items',
        'fs-cmsfilter-element': 'list',
        'fs-cmsload-element': 'list',
        'fs-cmsload-mode': 'pagination',
        'fs-cmsload-pageboundary': '1',
        'fs-cmsload-pagesiblings': '1',
        'fs-cmsload-resetix': 'true',
        'fs-cmssort-element': 'list',
        'role': 'list'
    }

    home_page_main_content = home_page_soup.find("div", home_page_div_attributes)

    # contenitore zip(title, date, link)
    print("\n   [*] Estraendo dati dai report...")
    reports_zip, exit_ = collection(home_page_main_content, added_report_links)
    frasiDaBar = ["Altro giorno, altri dati uguali. Zenigata ringrazia per la pazienza <3", "Esperimento #204: risultati identici a ieri. E a ieri l'altro. E a quello prima.", "I dati rimangono... uguali. Ma almeno il caffè era buono.", "Abbiamo escluso un'altra novità. Solo migliaia di informazioni uguali.", "Se ci fosse un dato nuovo dietro l'angolo, io sto girando in tondo da settimane (°°.)", "Ho controllato. Nulla da aggiungere...", "La mia scoperta più recente? Dati uguali..." "Niente di nuovo per oggi :/"]

    if exit_:
        report_count_check = 0
        for x in reports_zip:
            report_count_check += 1
        
            
        if report_count_check == 0:
            print(f"      [-] {frasiDaBar[randint(0, len(frasiDaBar)-1)]}")
            return True
    

    report_count = 1
    time_sleep_value = [1, 2, 3]
    print(f"      [PAGINA {page_count}] Collezionata!")

    for report in reports_zip:
        try:
            sleep(choice(time_sleep_value))
            # print(report[2])

            report_saved = {}
            section_container = []

            report_id = id_generator(report)

            new_sections, titles, author = extractor(report[2])

            report_saved["about_it"] = [f"| title: {replacer_title(report[0])} |", f"| pubblication: {report[1]} |", f"| link: {report[2]} |", f"| author: {author} |", f"| page: {page_count} |", f"| report_id: {report_id} |", f"| report: {report_count} |"]
            section_container.append(report_saved)
            
            #--------------------------------------------------------------
            
            if new_sections:
                if titles:
                    tags = []
                    stack = []
                    tags_dict = []
                    min_num = 10

                    i = 0
                    while i < len(titles):
                        elm = titles[i]
                        if type(elm) != tuple:
                            tags_dict.append(elm)
                            i += 1
                        else:
                            num, title = elm
                            node = [title]

                            if num < min_num:
                                min_num = num

                            while stack and num < stack[-1][0]:
                                stack.pop()

                            if not stack:
                                tags.append(node)
                            else:
                                prev_num, prev_node = stack[-1]

                                if num == prev_num:
                                    if num == min_num:
                                        tags.append(node)
                                    else:
                                        for x in range(len(stack)-2, -1, -1):
                                            candidate_num, candidate_node = stack[x]

                                            if candidate_num < prev_num:
                                                candidate_node.append(node)
                                                break
                                else:
                                    prev_node.append(node)
                            
                            stack.append((num, node))
                            i += 1
                        
                    for tag in tags:
                        tags_dict.append((build_tree_tags(tag)))

                    tags_dict.append(author)
                    section_container.append({"tags":tags_dict})
                try:
                    for section in new_sections[0]:
                        if type(section) == list and len(section) > 1:
                            # print(section)
                            section_container.append(build_tree(section))
                        # print(section_container)

                    # save in local
                    # output_path = path.abspath(__file__)[:len(path.abspath(__file__))-len(path.basename(__file__))]
                    # if not path.exists(output_path+"\\outputZenigata_lookout"):
                    #     mkdir(output_path+"\\outputZenigata_lookout")

                    # if not path.exists(output_path+f"\\outputZenigata_lookout\\page_{page_count}"):
                    #     mkdir(output_path+f"\\outputZenigata_lookout\\page_{page_count}")

                    # with open(output_path+f"\\outputZenigata_lookout\\page_{page_count}\\Report_{report_count}.json", "w", encoding="utf-8") as f:
                    #     dump(section_container, f, indent=4, ensure_ascii=False)
                    
                    # add report to DB
                    report_for_db = {}
                    for item in section_container:
                        report_for_db.update(item)
                    # print("\n",report_for_db)
                    coll.insert_one(report_for_db)
                    print(f"        [REPORT {report_count}] Elaborato e salvato!")

                except (IndexError, TypeError) as e:
                    print(f"        [REPORT {report_count}] Problemi durante la scrittura dei dati!")
                    with open("errorsLog_lookout.txt", "a") as f:
                        f.write(f"----------------------------------------------------------------------------\n[REPORT {report_count}] Problemi durante la scrittura dei dati!\n\n{format_exc()}\n\n{report[2]}\n----------------------------------------------------------------------------\n\n")

            else:
                print(f"        [REPORT {report_count}] Elaborato, ma nessun dato trovato!")
                report_saved["MISTAKE"] = "Nessun dato trovato!"
            
            #--------------------------------------------------------------
            
        #--------------------------------------------------------------
        # tenere attivo in fase di test per elaborare solo il primo report
        #   della home_page indicata;
            # return section_container
        #--------------------------------------------------------------
            report_count += 1
        except IndexError as e:
            print(f"        [REPORT {report_count}] Problemi durante l'elaborazione!")
            with open("errorsLog_lookou.txt", "a") as f:
                f.write(f"----------------------------------------------------------------------------\n[REPORT {report_count}] Problemi durante l'elaborazione!\n\n{format_exc()}\n\n{report[2]}\n----------------------------------------------------------------------------\n\n")
            report_count += 1
    #--------------------------------------------------------------
    # tenere attivo in fase di test per elaborare solo la home_page indicata;
    # return True
    #--------------------------------------------------------------
    if exit_:
        return True
    
    last_page, new_home_page_url = check_last_page(home_page_soup)
    if last_page:
        page_count += 1
        return zenigata_lookout((site, new_home_page_url), added_report_links, page_count)
    else:
        return True

def main_lookout():
    # start_script = time()

    source = ("lookout", "https://www.lookout.com/threat-intelligence")

    client = mc("mongodb://localhost:27017/")
    db = client['master']

    added_report_links = query(db, source[0])

    from os import path, remove
    if path.exists("errorsLog_lookout.txt"):
        remove("errorsLog_lookout.txt")

    zenigata_lookout(source, added_report_links)

    # stop_script = time()

    # total_time = float(f"{stop_script-start_script:.2f}")

    # if total_time > 60:
    #     minuti = int(f"{total_time//60:.0f}")
    #     secondi = f"{total_time-(60*minuti):.2f}"
    #     print(f"\n   [*] Tempo impiegato: {minuti} minuti e {secondi} secondi")
    # else:
    #     print(f"\n   [*] Tempo impiegato: {stop_script-start_script:.2f} secondi")


#####################################################################################################


if __name__ == "__main__":
    main_lookout()