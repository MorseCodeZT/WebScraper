from bs4 import BeautifulSoup as bs, MarkupResemblesLocatorWarning
from requests import get
from re import search, match, escape
from time import sleep
from random import choice, randint
from warnings import filterwarnings
from os import path, remove, mkdir, path
from traceback import format_exc
from base64 import standard_b64encode as b64encode
from json import dump, load
from time import time
from pymongo import MongoClient as mc


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

def collection(soup, added_report_links):
    '''
        Funzione che colleziona i dati target, restituisce un pacchetto di dati
            in formato "zip".
            Nel momento in cui i link vengono estratti, li si controlla uno ad uno
            per verificare se il report è gia stato aggiunto al DB.

        input:
            - risposta del server formato BSObj;
            - added_report_links(list), contiene tutti i link dei report estratti dalla query;
        output:
            - zip(titolo, data_pubblicazione, reposity)
            - exit_(bool), se True indica che non ce nulla di nuovo;
    '''
    
    exit_ = False

    # repository del report
    repos_report_pkg = []
    check = ""
    link_count = 0
    # print(soup.find_all("a", attrs={"rel":"bookmark"}))
    for repo in soup.find_all("a", attrs={"rel":"bookmark"}):
        # print(repo['href'])
        if repo['href'] != check:
            # print(repo['href'])
            if repo['href'] in added_report_links:
                # print(repo['href'])
                exit_ = True
                break
            repos_report_pkg.append(repo['href'])
            link_count += 1
        check = repo['href']
        
    # titolo pulito dalle date e repo
    pattern_date = r"([A-Za-z]+) (\d{1,2}), (\d{4})"
    titoli_report_pkg = []

    title_count = 0
    for titolo in soup.find_all("a", attrs={"rel":"bookmark"}):
        if title_count != link_count:
            if not search(pattern_date, str(titolo)):
                titoli_report_pkg.append(replacer_title(titolo.text))
                title_count += 1
        else:
            break

    # print(titoli_report_pkg)
    
    # pulizia della stringa "titolo" estratta dalla home page che contiene i report
    # count = 0
    # for title in titoli_report_pkg:
    #     titoli_report_pkg[count] = title.text
    #     count += 1

    # date di pubblicazione
    pubblicazioni_report_pkg = []
    date_count = 0
    
    for pubb in soup.find_all("a", attrs={"rel":"bookmark"}): 
        if date_count != link_count:
            if search(pattern_date, str(pubb)):
                pubblicazioni_report_pkg.append(pubb.text)
                date_count += 1
        else:
            break
    
    return list(zip(titoli_report_pkg, pubblicazioni_report_pkg, repos_report_pkg)), exit_

def check_lastPage(soup):
    '''
        Funzione per verificare se è presente un'altra pagina da elaborare,
            restituisci un valore boleano e una stringa vuota se non è presente 
            una pagina successiva altrimenti il suo link.

            input:
                . la risposta del server formato BSObj;
            output:
                . last_page = True/False;
                . link = <LINK>/"" 
    '''

    if not soup.find("a", class_="next page-numbers"):
        # utlima pagina
        return True, ""
    else:
        # ci sono altre pagine
        link = soup.find("a", class_="next page-numbers")
        return False, link["href"]

def title_filter(skip, strong, strong_datas, elm, titles, yaraDataSended, pm, suricata, yaraLinks, sections, sigma, findMitre, findYaraLinks, ioc, untouchables, sigmaDatas, sigmaDataSended):
    strong_titles = ["snort", "references", "mitre att&ck techniques ", "mitre software", "mitre", "yara rules", "yara", "sigma", "suricata", "network", "file"]
    mini_titles = ["DFIR Report Repository", "Sigma Repository", "SIGMA Project Repo", "DFIR Report Repo"]

    # print(elm)
    if str(elm)[:2] == "<h" and str(elm.text).strip() != "":
        # print(elm.text)
        if str(elm)[2].isdigit():
            # print(str(elm.text).lower())
            if str(elm.text).strip() != "\xa0" and str(elm.text).strip() != "" and str(elm.text).strip() != "\n":
                title = replacer_title(str(elm.text).strip().lower())
                
                # print(title)
                if title == "sigma rules":
                    title = "sigma"
                elif title == "yara rules":
                    title = "yara"
                elif title == "suricata rules":
                    title = "suricata"
                # print(title)
                if title == "mitre" or title == "mitre att&ck":
                    title = "mitre"
                    findYaraLinks = False
                    sigma = False
                    suricata = False
                
                if title == "indicators":
                    title = "iocs"

                if title.startswith("http"):
                    sections.append(title)
                    skip = True
                    return skip, strong, strong_datas, yaraDataSended, pm, suricata, sigma, findYaraLinks, findMitre, ioc, untouchables, sigmaDataSended, titles, sigmaDatas, yaraLinks

                    
                    # parte gestita prima di aggiungere un nuovo titolo
                    # if yaraLinks and not yaraDataSended:
                    #     if type(yaraLinks) == list:
                    #         yaraLinks.insert(0, "data")
                    #     sections.append(yaraLinks)

                if title == "sigma":
                    # print("yres")
                    sigma = True

                    # parte gestita prima di aggiungere un nuovo titolo
                    # if yaraLinks and not yaraDataSended:
                    #     # print(yaraLinks)
                    #     sections.append(yaraLinks)
                    #     yaraDataSended = True

                if title == "yara" or findYaraLinks:
                    # print("yara")
                    findYaraLinks = True
                    sigma = False
                    suricata = False
                    
                    # parte gestita prima di aggiungere un nuovo titolo
                    # if not sigmaDataSended:
                    #     # print(sigmaDatas)
                    #     if sigmaDatas:
                    #         # print(sections)
                    #         # print(sigmaDatas)
                    #         if len(sigmaDatas) == 1:
                    #             sections.append(sigmaDatas[0])
                    #             # print(sections)
                    #         else:
                    #             sigmaDatas.insert(0, "data")
                    #             sections.append(sigmaDatas)
                    #         sigmaDataSended = True

                if title == "suricata":
                    suricata = True
                    sigma = False
                if title == "persistence mechanisms":
                    pm = True
                    findMitre = False
                        
                # print(title.lower())
                if title == "iocs" or title == "detections":
                    # print(title)
                    sections.append((1, title))
                    titles.append((1, title))
                    untouchables = True
                    ioc = True
                else:
                    if yaraLinks:
                        if type(yaraLinks) == list:
                            if len(yaraLinks) == 1:
                                yaraLinks = yaraLinks[0]
                                skip = True    
                            else:
                                yaraLinks.insert(0, "data")
                        sections.append(yaraLinks)
                        yaraLinks = []

                    if sigmaDatas:
                        if not sigmaDataSended:
                            if type(sigmaDatas) == list:
                                if len(sigmaDatas) == 1:
                                    sigmaDatas = sigmaDatas[0]
                                else:
                                    sigmaDatas.insert(0, "data")
                            sections.append(sigmaDatas)
                            sigmaDatas = []
                    # print(title)
                    sections.append((int(str(elm)[2]), title))
                    titles.append((int(str(elm)[2]), title))
            strong = False

    elif str(elm)[:3] == "<p>" and str(elm.text).strip() != "":
        # print("\n#",elm)
        for strongT in strong_titles:
            if str(elm.text).strip().lower()[:len(strongT)] == strongT:
                # print(strong_title, str(elm.text).strip()[:len(strong_title)])
                # print(f"\n\n#{str(elm).strip()}")
                # print("\n************\n",elm,"\n************\n")
                strong_title = replacer_title(str(elm.text).strip().lower())
                
                if strong_title == "sigma rules":
                    strong_title = "sigma"
                elif strong_title == "yara rules":
                    strong_title = "yara"
                elif strong_title == "suricata rules":
                    strong_title = "suricata"
                elif strong_title == "mitre atta&ck":
                    strong_title = "mitre"
                elif strong_title == "indicators":
                    strong_title = "iocs"

                if len(strong_title) > 20:
                    if strong_title[:len(strongT)].lower().strip() in strong_titles:
                        strong_title = strong_title[:len(strongT)]
                # print(strong_title)
                if strong_title == "yara":
                    findYaraLinks = True
                    sigma = False

                    if not sigmaDataSended:
                        # print(sigmaDatas)
                        if sigmaDatas:
                            # print(sections)
                            # print(sigmaDatas)
                            if len(sigmaDatas) == 1:
                                sections.append(sigmaDatas)
                            else:
                                sigmaDatas.insert(0, "data")
                                sections.append(sigmaDatas)
                            sigmaDataSended = True
                            sigma = False

                if strong_title == "mitre" or strong_title == "mitre att&ck" or strong_title == "mitre att&ck techniques":
                    findYaraLinks = False
                    sigma = False
                    findMitre = True

                    if not sigmaDataSended:
                        if sigmaDatas:
                            # print(sections)
                            if len(sigmaDatas) == 1:
                                sections.append(sigmaDatas)
                            else:
                                sigmaDatas.insert(0, "data")
                                sections.append(sigmaDatas)


                possible_strong_data = str(elm.text).strip()[len(strong_title):].strip()
                # print(possible_strong_data)
                if possible_strong_data.strip() != "" and len(possible_strong_data.strip()) > 6 and possible_strong_data.lower().strip() not in strong_titles:    
                    # print(possible_strong_data)
                    # print(elm)
                    possible_strong_data = replacer(str(elm).strip(), False)
                    # print(strong_title, possible_strong_data[0].lower())
                    # print(possible_strong_data)
                    if possible_strong_data[0].lower().strip() in strong_titles:
                        possible_strong_data[0] = "data"
                    # print(possible_strong_data)
                    skip = True
                else:
                    possible_strong_data = ""
                # print(possible_strong_data)
                    # print("#",str(elm.text).strip()[len(strong_title):].strip())
                strong = True
                if strong_datas:
                    # print("taglia")
                    # print(strong_datas)
                    if type(strong_datas) == list:
                        strong_datas.insert(0, "data")
                    # print(strong_datas)
                    sections.append(strong_datas)
                    strong_datas = []
                # print(strong_title, elm.text[:len(strong_title)+1])
                # print("\n#",sections)
                # print(strong_title)
                sections.append((4, strong_title))
                titles.append((4, strong_title))
                # print("\n---------------------\n", sections)
                # print(sections)
                if possible_strong_data:
                    # print(sections)
                    # print(possible_strong_data)
                    sections.append(possible_strong_data)
                break
            if ioc:
                if len(str(elm.text).strip()) < 30:
                    mini_title = replacer_title(str(elm.text).strip().lower())
                    # print(mini_title)

                    if mini_title == "sigma rules":
                        mini_title = "sigma"
                    elif mini_title == "yara rules":
                        mini_title = "yara"
                    elif mini_title == "suricata rules":
                        mini_title = "suricata"
                    elif mini_title == "mitre atta&ck":
                        mini_title = "mitre"
                    elif mini_title == "indicators":
                        mini_title = "iocs"
                    
                    if mini_title[-1] == ":":
                        mini_title = mini_title[:-1]

                    if match(r'^(?:.*?[a-zA-Z]){5,}.*:$', mini_title):
                        # print(sections)
                        # print(elm.text)
                        sections.append((4, mini_title))
                        titles.append((4, mini_title))
                        break
                    else:
                        if mini_title in mini_titles:
                            sections.append((4, mini_title))
                            titles.append((4, mini_title))
    return skip, strong, strong_datas, yaraDataSended, pm, suricata, sigma, findYaraLinks, findMitre, ioc, untouchables, sigmaDataSended, titles, sigmaDatas, yaraLinks

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

def file_type(stringa):
    '''
        Funzione usata per verificare se contenuto di una sezione è un file di configurazione o
            script PowerShell.
        
        Input:
            - stringa(str), la stringa da verificare
        Output:
            - True/False(bool), la risposta alla verifica
    '''

    # identificatori
    ps_target = ["get-", "echo", "$", "function", "param", "if", "foreach", "while", "write-output", "get-command", "new-object"]
    general_target = ["[general]", "[database]", "[server]", "[logging]", "[security]", "[settings]", "host =", "port =", "user =", "password =", "enabled =", "timeout =", "log_level =", "server=", "port=", "user=", "pass=", "protocol:", "rulename:", "rulename:", "dns query:","user_agent =", "processguid:", "image:", "processid:", "version:", "name:", "config:", "database:", "host:", "port:", "enabled:", "connection:", "timeout:", "user:", "password:", 'server":', 'type":', '"name":', '"version":', '"publickey":', '"proxytype":', '"useragent":', '"proxyusername":', '"proxy":', '"config":', '"database":', '"host":', '"port":', '"user":', '"password":', '"license":', '"server":', "acceèt-language:"]
    general_regex = [r"\w+\s*=", r'^&[a-z]{2,4};$', r'<\/\w+>', r'<(\w+)\s+(\w+)=', r"\n[\w.-]{4,}\s{3,}-\s+[\w.-]+\n", r"\n.{3,}:\s+[\w\-_]+\n"]
    acurate_regex = [r"\n\s+[\w./\-\\]{4,}:\s+[\w./\-\\]{1,}\s*\n", r"\\\\[^\\]+\\n", r"\net"]
    structure_regex = [r"\+[^\+]*-[^\+]*\+", r"-{9,}", r"\|[^|]*\.[^|]*\|", r"\d{8}(?: [A-Za-z0-9]{2}){10,}"]
    ###############################################################################

    stringa = stringa.lower()
    # print(repr(stringa))
    #---------------------------------------------------------------
    newLine_check = False
    newLine_count = stringa.count("\n")
    # print(newLine_count)
    if newLine_count >= 3:
        newLine_check = True

    hashtag_count = stringa.count("#")

    general_score = 0
    # print("**********************************")
    # print(newLine_count)

    if hashtag_count > 10:
        general_score += 2

    if "<?xml" in stringa and newLine_check:
        general_score += 3
        # print("# <?xml")
    if "\n" in stringa and newLine_check:
        if stringa.startswith("{"):
            general_score += 2
            # print("# {")
        if stringa.endswith("}") and newLine_check:
            general_score += 2
            # print("# }")
    if "{\n" in stringa and newLine_check:
        general_score += 2
        # print("# {\\n")
    if "}\n" in stringa and newLine_check:
        general_score += 2
        # print("# }\\n")
    if "iex" in stringa and newLine_check:
        general_score += 1
        # print("# iex")

    visto = set()
    for target in ps_target:
        if newLine_check:
            for elm in stringa.split():
                # print(elm)
                if elm.strip().startswith(target):
                    # print("*****",elm)
                    if target not in visto:
                        visto.add(target)
                        general_score += 1
                        # print("# ",target)
                    else:
                        continue
    for target in general_target:
        if newLine_check:
            for elm in stringa.split():
                if target in elm:
                    if target not in visto:
                        visto.add(target)
                        general_score += 1
                        # print("# ", target)

    for regex in general_regex:
        # print(repr(stringa))
        # print(newLine_check)
        if search(regex, repr(stringa)) and newLine_check:
            general_score += 1
            # print("##",regex)
    for a_regex in acurate_regex:
        # print(a_regex)
        if search(a_regex, repr(stringa)):
            general_score += 2
            # print("# ",a_regex)
    for s_regex in structure_regex:
        if search(s_regex, repr(stringa)):
            general_score += 1
            # print("#", s_regex)

    c = 0
    target_ = 0
    for x in stringa:
        if x == "\n":
            if stringa[c+1] == "|":
                target_ += 1
        c += 1
    if target_ > 30:
        general_score += 1
        
    # print(general_score)
    if general_score > 1:
        return True
    else:
        return False
  
def replacer(stringa, indicators):
    '''
        Funzione usata per ripulire le stringhe da caratteri speciali, spazi inecessi, la struttura HTML e dividere gli elementi. 
        Procede con quattro passaggi, il primo per sostituire il tag "<br/>" con "\n", il secondo rimuovere i caratteri speciale,
            il terzo per rimuovere spazi in ecessi mentre il quarto divide i dati tramite "\n"

        Input:
            - stringa da pulire;
            - indicators(bool), valore booleano che indica quando siamo nella sezione "indicators".
                Ciò è importante perchè tutti i suoi dati non devono essere divisi;
        Output:
            - Stringa pulita
        Dependece:
            - file_type();
    '''
    # print(stringa, "\n------------------\n")
    # controllore per verificare se la stringa è stata splittata quindi se è una lista
    split_mode = False
    # primo passaggio gestisce il tag "br" sostituendolo con un "\n", se presente
    if "<br/>" in stringa:
        new_stringa = stringa.replace("<br/>", "\n") 
    else:
        new_stringa = stringa
    if "<br>" in new_stringa:
        new_stringa = new_stringa.replace("<br>", "\n")
    if "</p>" in new_stringa:
        new_stringa = new_stringa.replace("</p>", "\n")
    if "</span>" in new_stringa: 
        new_stringa.replace("</span>", "\n")
    # print(new_stringa)
    new_stringa = bs(new_stringa, "html.parser")
    new_stringa = str(new_stringa.text).rstrip()
    # print(new_stringa)
    sepa = True
    
    # print(new_stringa,"\n***************\n", sepa,"\n\n------------------------")
    # secondo passaggio gestisce la pulizia dei caratteri speciali
    if "\t" in new_stringa:
        new_stringa = new_stringa.replace("\t", "")
    if "\r" in new_stringa:
        new_stringa = new_stringa.replace("\r", "")
    if "\xa0" in new_stringa:
        new_stringa = new_stringa.replace("\xa0", " ")
    if "\u200b" in new_stringa:
        new_stringa = new_stringa.replace("\u200b", " ")
    if "\u2013" in new_stringa:
        new_stringa = new_stringa.replace("\u2013", "-")
    if "\u2018" in new_stringa:
        new_stringa = new_stringa.replace("\u2018", "'") 
    if "\\n" in new_stringa:
        new_stringa = new_stringa.replace("\\n", "\n")
    if "\u0070" in new_stringa:
        new_stringa = new_stringa.replace("\u0070", "p")
    if "’" in new_stringa:
        new_stringa = new_stringa.replace("’", "'")
    if "“" in new_stringa:
        new_stringa = new_stringa.replace("“", '"')
    if "”" in new_stringa:
        new_stringa = new_stringa.replace("”", '"')
    while "  " in new_stringa:
        new_stringa = new_stringa.replace("  ", " ")
    
    # Controllore per far si che quando il titolo è indicators, nulla venga 
    #   trattato come un file di configurazione onde evitare fraintendimenti;
    # print(indicators)
    if not indicators:
        if file_type(new_stringa):
            # print(new_stringa, "\n------------------------------------------\n")
            sepa = False
    
    if "[email protected]" in new_stringa:
        new_stringa = new_stringa + " -> check the Indicators Section for the clean data!"
    new_stringa = new_stringa.strip()
    
    if sepa:
        # se è possibile inserisco il segnale di separatore "***"
        if "\n \n" in new_stringa:
            new_stringa = new_stringa.replace("\n \n", "\n\n")
        if "\n\n" in new_stringa:
            new_stringa = new_stringa.replace("\n\n", "\n***\n")

        # terzo passaggio gestisce la divisione degli elementi divisi da "\n"
        if "\n" in new_stringa:
            new_stringa = [elm.lstrip() for elm in new_stringa.split("\n") if elm != "" and elm != "\\\"" and elm != "'"]
            split_mode = True
        # print(new_stringa)
        if split_mode:
            # contenitore per la sezione che deve essere divisa
            clear_string_sepa = []

            # verifico la presenza del segnale di separatore "***"
            if "***" in new_stringa:
                temp = []
                # estraggo ogni elemento della stringa pulita alla ricerca del segnale di separatore "***"
                
                for elm in new_stringa:
                    # fino a quando l'elemento non è uguale a "***", raggruppo i dati
                    if elm != "***":
                        # attivare in fase di test
                        #--------------------------
                        temp.append(elm)
                        #--------------------------
                        # codifico il dato in base64
                        # temp.append(str(b64encode(elm.encode())))
                    # quando trovo il segnale di separatore, spezzo la lista e invio tutto in un punto di raccola(clear_string_sepa)
                    else:
                        if len(temp) == 1:
                            clear_string_sepa.append(temp[0])
                        else:
                            clear_string_sepa.append(temp)
                        temp = []
                # infine aggiungo l'ultima parte rimasta in "temp" perchè il segnale di separatore non si trova mai in fondo alla stringa
                clear_string_sepa.append(temp)

            # se il punto di raccolta ha qualcosa dentro alla la espulgo
            if clear_string_sepa:
                # verifico se una lista contiene solo una stringa,
                #   se così fosse allora gestisco
                c = 0
                for elm in clear_string_sepa:
                    if len(elm) == 1:
                        clear_string_sepa[c] = elm[0]
                    c += 1
                return clear_string_sepa
            # se il punto di raccolta è vuoto restituisco la stringa pulita
            else:
                
                # disattivare in caso di test
                #----------------------------------------------------
                # c = 0
                # for elm in new_stringa:
                #     new_stringa[c] = str(b64encode(elm.encode()))
                #     c += 1
                #----------------------------------------------------
                return new_stringa
        else:
            # attivare in caso di test
            #--------------------------
            return new_stringa
            #--------------------------
            # return str(b64encode(new_stringa.encode()))
    else:
        # attivare in fase di test
        #--------------------------
        # print(new_stringa)
        if "\n" in new_stringa:
            new_stringa = new_stringa.replace("\n", "\\n")
            return new_stringa
        else:    
            return new_stringa
        #--------------------------
        # return str(b64encode(new_stringa.encode()))

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
    if "’" in clear_title or "“" in clear_title or "”" in clear_title:
        clear_title = clear_title.replace("’", "'")
    if "–" in clear_title:
        clear_title = clear_title.replace("–", "-")
    if clear_title[-1] == ":":
        clear_title = clear_title[:-1]
    if "\xa0" in clear_title:
        clear_title = clear_title.replace("\xa0", "")
    if "\u200d" in clear_title:
        clear_title = clear_title.replace("\u200d", "")

    return clear_title

def extractor(datas, glitch, url):
    '''
        Funzione usata per estrarre le informazioni target dal contenuto HTML scaricato.

        Input:
            - datas(list), lista che contiene il contenuto HTML separato tramite tag;
            - glitch(bool), valore booleano per gestire determinati report;
            - url(str), stringa che determina l'url da parsare;
        Output:
            - new_sections(list), lista che contiene le sezioni di dati formattate ed organizzate
                in una versione grezza(da pulire);
       '''

    sections = []

    custom_titles = ""
    extracting_titles = ""
    deep_titles = ""
    ioc_titles = ""

    # report troppo particolare per essere gestito insieme agli altri;
    if url == "https://thedfirreport.com/2021/10/18/icedid-to-xinglocker-ransomware-in-24-hours/":
        # funzione fatta su misura per l'estrazione dei dati del link soprastante;
        os_score, custom_titles = extracting_custom(datas, sections)
        # print("eyo")
        if sections:
            # print(sections)
            while type(sections[-1]) == tuple:
                sections.pop()
                if len(sections) == 0:
                    break

            sections = emptySec(sections)

        max_score = 0
        os_tag = ""
        for os, score in os_score.items():
            if score > max_score:
                max_score = score
                os_tag = os

        # print(f"os: {os_tag}\n{os_score}") 

    # gestione del resto dei report;
    else:

        ioc, os_score, extracting_titles = extracting(datas, sections, glitch)
        if sections:
            # print(sections)
            while type(sections[-1]) == tuple:
                sections.pop()
                if len(sections) == 0:
                    break

            sections = emptySec(sections)
            # print(extracting_titles)
            # print(titles)
        # print(sections)
        # for xx in sections:
        #     print("\n", xx)
        # print("\n\n---------------------------------")

        # print(ioc)
         
        # se non sono stati trovati punti di riferimento che indicavano la sezione
        #    degli IOC allora si dovrà effettuare una ricerca più profonda;
        if not ioc:
            # print("cia")

            # nuova lista che conterrà la sezione ricercata in profondità
            deep_sections = []
            os_tag = ""
            # nuovo valore IOC determinato dalla ricerca approfondita
            ioc, os_score_deep, deep_titles = deep_extracting(datas, deep_sections, glitch)
            
            for os in os_score.keys():
                for os_deep in os_score_deep.keys():
                    if os_deep == os:
                        os_score[os] += os_score_deep[os_deep]

            # print(sections)
            # print(deep_sections)

            # se esiste una sezione data dalla ricerca approfondita ed esiste anche
            #   la sezione principale allora andiamo ad aggiornare la sezione originale
            if deep_sections and sections:
                # print("yes")
                # print(deep_sections)
                # eliminiamo tutti i titoli vuoti in fondo alla sezione data dalla
                #   ricerca approfondita
                while type(deep_sections[-1]) == tuple:
                    deep_sections.pop()
                    if len(deep_sections) == 0:
                        break
                
                # puliamo la deep_sections dai restanti titoli vuoti
                deep_sections = emptySec(deep_sections)

                # se la deep sections contiene più elementi della sezione originale
                #   allora andiamo ad aggiungere i dati non rilevati nella prima ricerca
                if len(deep_sections) > len(sections):
                    c = 0
                    for x in range(len(sections)):
                        if sections[x] == deep_sections[x]:
                            # incremento questo contatore ogni volta che trovo due dati uguali,
                            #   alla fine verrà usato come puntatore per estrarre dati dalla 
                            #   deep sections;
                            c += 1
                            # print(deep_sections[c+1])

                    # eliminiamo i dati doppioni per evitare eccezioni
                    while len(sections) != c:
                        sections.pop()
                    
                    # aggiungo i dati non rilevati nella prima ricerca alla sezione originale
                    for x in deep_sections[c:]:
                        sections.append(x)

            elif deep_sections:
                if not sections:
                    while type(deep_sections[-1]) == tuple:
                        deep_sections.pop()
                        if len(deep_sections) == 0:
                            break
                    deep_sections = emptySec(deep_sections)
                    
                    for x in deep_sections:
                        sections.append(x)
                        
            deep_titles = [title for title in deep_titles if title in deep_sections]
            
        # print(ioc)
        # print(sections)
        if url != "https://thedfirreport.com/2022/01/24/cobalt-strike-a-defenders-guide-part-2/":
            if not ioc:
                # print("eioi")
                ioc_sections, os_score_ioc, ioc_titles = onlyIOC(datas)

                for os in os_score.keys():
                    for os_ioc in os_score_ioc.keys():
                        if os_ioc == os:
                            os_score[os] += os_score_ioc[os_ioc]

                if ioc_sections:
                    while type(ioc_sections[-1]) == tuple:
                            ioc_sections.pop()
                            if len(ioc_sections) == 0:
                                break
                    ioc_sections = emptySec(ioc_sections)

                    if ioc_sections and sections:
                        # print("yes")
                        
                        # print(ioc_sections)
                        # print(sections)
                        c = 0
                        for x in range(len(sections)):
                            if sections[x] == ioc_sections[x]:
                                c += 1
                        if c == 0:
                            for x in ioc_sections:
                                sections.append(x)
                        else:
                            for x in ioc_sections[c+1:]:
                                sections.append(x)

                    else:
                        if not sections and ioc_sections:
                            # print(sections)
                            while type(ioc_sections[-1]) == tuple:
                                ioc_sections.pop()
                                if len(ioc_sections) == 0:
                                    break
                            ioc_sections = emptySec(ioc_sections)

                            for x in ioc_sections:
                                sections.append(x)

    # calcolo del sistema operativo protaonista del report
    max_score = 0
    os_tag = ""
    for os, score in os_score.items():
        if score > max_score:
            max_score = score
            os_tag = os

    # print(f"os: {os_tag}\n{os_score}")    
    # for x in sections:
    #     print("\n",x)
    # print(len(sections), sections_add_count)
    # print(titles)

    titles = ([x[1] for x in sections if type(x) == tuple])
    # print(titles)

    if custom_titles:
        titles = [title for title in custom_titles if title[1] in titles.copy()]

    if extracting_titles:
        titles = [title for title in extracting_titles if title[1] in titles.copy()]
        
    if deep_titles:
        titles = [title for title in deep_titles if title[1] in titles.copy()]

    if ioc_titles:
        titles = [title for title in ioc_titles if title[1] in titles.copy()]

    # print(sections)
    new_sections = []
    min_num = 10
    
    stack = []
    new_section = []
    i = 0
    # for x in sections:
        # print("\n",x)
    if sections:
        while i < len(sections):
            elm = sections[i]
            # print(elm)
            if type(elm) == tuple:
                # print(elm)
                # print(elm)
                num, title = elm
                        
                if num < min_num:
                    min_num = num

                node = ["*"+title]
                # print(sections[i+1])
                while i+1 < len(sections) and (type(sections[i+1]) == str or (type(sections[i+1] == list) and sections[i+1][0] == "data")):
                    # print(f"\n{sections[i+1]} - {type(sections[i+1])}")
                    if type(sections[i+1]) == list:
                        # temp_count = 1

                        # for j in range(len(sections[i+1])-1):
                        # for j in sections[i+1][1:]:
                        #     node.append(j)
                            # temp_count += 1
                        # print(sections[i+1][1:])
                        node.append(sections[i+1][1:])
                    else:
                        # print(sections[i+1])
                        node.append(sections[i+1])
                    # print(node)
                    i += 1

                # aggiungere controllo titoli vuoti
                # if num < stack[-1] and :
                # if stack:
                #     if len(stack[-1][1]) == 1:
                #         print(i)

                while stack and stack[-1][0] > num:
                    stack.pop()

                if not stack:
                    new_section.append(node)
                
                else:
                    prev_num, prev_node = stack[-1]

                    if prev_num == num:
                        # print(f"\ntitle: {title}\nnum: {num}\nprev_num: {prev_num}\nstack: {stack}")
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
            # print(num, node)
            stack.append((num, node))
            i += 1

        # print(new_section)
        new_sections.append(new_section)
    else:
        return sections, "", os_tag

    # print(new_sections)
    # print(new_section, titles)
    return new_sections, titles, os_tag
    #######################################################################################################

def extracting_custom(datas, sections):
    titles = []
    add = False
    sigma = False
    findMitre = False
    mitre_datas = []

    sigmaDatas = []
    pre = []

    # score per gli os
    os_score = {"windows":0,
                "linux":0,
                "mac":0,
                "android":0,
                "ios":0}
    
    # contenitore per evitare che una parola venga contata per più di una volta
    key_viewed = set()
    
    datas_str = ""
    for elm in datas:
        datas_str += str(elm)

    datas = datas_str.split("\n")
    
    c = 0
    
    while c < len(datas):
        # if len(sections) > 2:
        #     break
        elm = datas[c].strip()
        elm_bs = bs(elm, "html.parser")
        # print("\n#",repr(str(elm_bs)))
        # calcolo del os_tag
        os_score, key_viewed = osTag_scoring(repr(str(elm_bs.text)).strip().lower(), os_score, key_viewed)

        max_score = 0
        for os, score in os_score.items():
            if score > max_score:
                max_score = score

        # disattivatore del "findMitre"
        if elm[:43].strip() == "<div class=\"sharedaddy sd-sharing-enabled\">":
            findMitre = False
            mitre_datas.insert(0, "data")
            sections.append(mitre_datas)
            # print(mitre_datas)
            return os_score, titles

        if findMitre:
            if str(elm_bs.text).strip() != "" and str(elm_bs.text).strip() != "\n":
                mitre_datas.append(replacer(elm, True))

        if sigma:
            if elm.strip()[:11] == "<p><strong>":
                sigmaDatas.insert(0, "data")
                sections.append(sigmaDatas)
                sigmaDatas = []
                sigma = False
                pass
            else:
                if "–" in elm_bs.text:
                    sigmaDatas.append(str(elm_bs.text).replace("–", "-"))
                else:
                    sigmaDatas.append(elm_bs.text)
                    
                # print(elm_bs.text, elm_bs.find("a")['href'])
                # print(elm_bs.find("a")['href'])

        if elm.strip()[:2] == "<h" and str(elm_bs.text).strip() != "":
            title = str(elm_bs.text).strip().lower()
            # print(str(elm_bs.text).strip())
            if title == "mitre":
                findMitre = True
            
            if title == "mitre att&ck":
                c += 1
                continue

            sections.append((int(elm[2]), replacer_title(title)))
            titles.append((int(elm[2]), replacer_title(title)))

            
        if elm.strip()[:11] == "<p><strong>":
            # print(str(elm_bs.text).strip().lower())
            # print(sections)
            # print("\n", sections_add_count, len(sections))
            sections.append((4, replacer_title(str(elm_bs.text).strip().lower())))
            titles.append((4, replacer_title(str(elm_bs.text).strip().lower())))
            # print(sections)
            # assorrbire i dati sigma
            if elm_bs.text == "Sigma":
                sigma = True
            

        # dato completo
        if elm[:4].strip() == "<pre" and elm[-6:].strip() == "</pre>":
            # print(elm_bs.text, "\n----------------------------\n")
            if str(elm_bs.text).strip() != "" and str(elm_bs.text).strip() != "\n":
                # print(elm, "\n")
                dato = replacer(elm, False)
                # print(dato)
                if type(dato) == list:
                    dato.insert(0, "data")
                    sections.append(dato)
                else:
                    sections.append(dato)
                
        # chiusura del dato
        elif elm.strip()[:5] == "</pre" or (elm.strip()[:4] != "<pre" and elm.strip()[-6:] == "</pre>"):
            # print("#",elm_bs.text, "\n----------------------------\n")
            if str(elm_bs.text).strip() != "" and str(elm_bs.text).strip() != "\n":
                pre.append(elm)
                # print(pre)

            data_compose = ""
            for d in pre:
                data_compose += d
            # print(data_compose, "\n")
            data_compose = replacer(data_compose, False)
            # print(data_compose,"\n")
            if type(data_compose) == list:
                data_compose.insert(0, "data")
                sections.append(data_compose)
            else:
                sections.append(data_compose)

            add = False
            pre = []
            
        # resto del dato
        if add:
            # print("#", elm_bs.text)
            if str(elm_bs.text).strip() != "" and str(elm_bs.text).strip() != "\n":
                pre.append(elm)

        # inizio del dato
        if elm[:4].strip() == "<pre" and elm[-6:].strip() != "</pre>":
            add = True
            # print("#",elm_bs.text)
            if str(elm_bs.text).strip() != "" and str(elm_bs.text).strip() != "\n":
                pre.append(elm)
        c += 1
           
def extracting(datas, sections, glitch):
    titles = []
    untouchables = False
    sigma = False
    findYaraLinks = False
    yaraDataSended = False
    findMitre = False
    suricata = False
    pm = False
    sigmaDataSended = False
    block = False
    ioc = False
    strong = False
    skip = False

    table_op = False

    sigmaDatas = []
    yaraLinks = []
    strong_datas = []
    strong_titles = ["joesecurity repo:", "dfir public rules repo:", "dfir private rules:", "sigma repo:", "hunting/analysis rules:", "snort", "references", "mitre att&ck techniques ", "mitre software", "mitre", "yara rules", "yara", "sigma", "suricata", "network", "file"]

    # score per gli os
    os_score = {"windows":0,
                "linux":0,
                "mac":0,
                "android":0,
                "ios":0}
    
    # contenitore per evitare che una parola venga contata per più di una volta
    key_viewed = set()
    
    # print(datas)
    for elm in datas:
        # if str(elm)[:3] == "<h3":
        # print("\n#",repr(str(elm.text)))

        os_score, key_viewed = osTag_scoring(repr(str(elm.text)).strip().lower(), os_score, key_viewed)

        if type(elm) != str:
            # gestione delle eccezioni di alcuni report
            if glitch:
                # in un report è presente una tabella da estrarre
                # filtro il titolo che la contiene
                if elm.text == "Common JA3/S":
                    # utilizzo questo interruttore per far si che si attivi
                    # l'aspirapolvere dei dati
                    table_op = True

                # questo div contiene tutta la tabella
                if str(elm)[:56] == "<div class=\"clickup-table-view clickup-table-view_wide\">":
                    # solo se la table_operation è attiva
                    if table_op:
                        # prende tutta la struttura della tabella
                        table = [x for x in repr(str(elm)).split("\\n") if x != "" or x != "\n"]
                        
                        # contatore delle righe della tabella
                        raw_count = 0
                        # tabella convertita in dizionario
                        table_data = {}
                        # interruttore per filtrare solo i tag con i dati all'interno
                        target = False

                        # estraggo ogni elemento della tabella
                        for table_elm in table:
                            elm_bs = bs(table_elm, "html.parser")
                            
                            # filtro il tag di apertura di ciascun riga
                            if table_elm[:13] == "<tr data-row=" and table_elm[:26] != '<tr data-row="row-val640">':
                                # print(elm[14:16])
                                # evito che viene contata la riga dei titoli della tabella
                                if str(table_elm[14:16]) != '1"':
                                    raw_count += 1
                                    # creo la riga 
                                    table_data[str(raw_count)] = {"Hash":"", "Type":"", "Count":0, "C2 Type":""}
                                    # print("\n-----------------\n")

                            # se almeno una riga è stata creata allora alimento 
                            if raw_count > 0:
                                # filtro il tag di apertura delle righe
                                if table_elm[:12] == "<td colspan=":
                                    target = True
                                    # passo al dato successivo che sarà il target
                                    continue

                                if target:
                                    if len(str(elm_bs.text)) > 30:
                                        table_data[str(raw_count)]["Hash"] = str(elm_bs.text)
                                    if str(elm_bs.text) == "JA3" or str(elm_bs.text) == "JA3s":
                                        table_data[str(raw_count)]["Type"] = str(elm_bs.text)
                                    if str(elm_bs.text).isdigit():
                                        table_data[str(raw_count)]["Count"] = int(elm_bs.text)
                                    if len(str(elm_bs.text)) <= 26 and (not str(elm_bs.text).isdigit() and not (str(elm_bs.text) == "JA3" or str(elm_bs.text) == "JA3s")):
                                        table_data[str(raw_count)]["C2 Type"] = str(elm_bs.text)
                                    target = False
                        
                        # disattivo la table_operation
                        table_op = False
                        sections.append(["data",table_data])
                        # print(sections)

            if elm.text == "Internal case # TB23869 PR28513":
                if glitch:
                    return ioc, os_score, titles
            if str(elm.text)[:15] == "Internal case #":
                if strong_datas:
                    if type(strong_datas) == list:
                        strong_datas.insert(0, "data")
                    sections.append(strong_datas)
                return ioc, os_score, titles

            # disattivatore del "findMitre"
            if str(elm)[:43].strip() == "<div class=\"sharedaddy sd-sharing-enabled\">":
                findMitre = False
                return ioc, os_score, titles

            skip, strong, strong_datas, pm, yaraDataSended, suricata, sigma, findYaraLinks, findMitre, ioc, untouchables, sigmaDataSended, titles, sigmaDatas, yaraLinks = title_filter(skip, strong, strong_datas, elm, titles, yaraDataSended, pm, suricata, yaraLinks, sections, sigma, findMitre, findYaraLinks, ioc, untouchables, sigmaDatas, sigmaDataSended)
            
            if skip:
                skip = False
                continue
            
            # print(ioc)
            if ioc:
                # print("\n#",elm.text)
                # print(sigma)
                if strong:
                    # print("#",elm.text)
                    if str(elm).strip()[:4] != "<pre" and str(elm).strip()[:2] != "<h" and str(elm.text).strip() != "":
                        # print("\n#",elm.text)
                        # print(sections)
                        control_count = -1
                        while type(sections[control_count]) != tuple:
                            control_count -= 1
                        # if str(elm.text).strip()[-1] == ":":
                        #     print(elm.text)
                        #     if sections[control_count][1] == str(elm.text).strip()[:-1]:
                        #         continue
                        # else:
                        #     if sections[control_count][1] == str(elm.text).strip():
                        #         continue
                            # print(sections[control_count][1], str(elm.text).strip()[:-1])
                        # print(sections[control_count])
                       
                        if str(elm.text).strip().lower() not in strong_titles and str(elm.text).strip() != "":
                            # print("\n#",sections)
                            # print("\n-----------------------\n",elm.text.strip().lower())
                            strongDatas = replacer(str(elm), True)
                            # print("\n#",strongDatas)
                            if type(strongDatas) == list:
                                # print("\n#",strongDatas)
                                if strongDatas[0].lower() in strong_titles:
                                    strongDatas[0] = "data"
                                else:
                                    strongDatas.insert(0, "data")
                                # print(strongDatas)
                                sections.append(strongDatas)
                            else:
                                # print(strongDatas)
                                sections.append(strongDatas)
                            continue
                    # ricerca dei dati quando strong è attivo
                    find_pre(elm, sections)
                    # if str(elm)[:4].strip() == "<pre":
                    #     if str(elm.text) != "" and str(elm.text) != "\n":
                    #         print("\n#",elm,"\n-------------------------------\n")
                    #         # print(untouchables)
                    #         data = replacer(str(elm).strip(), False)
                    #         # print(data)
                    #         # print("\n#",data)
                    #         if type(data) == list:
                    #             data.insert(0, "data")
                    #             # print(sections)
                    #             sections.append(data)
                    #             # print(data.insert(0, "data"))
                    #         else:
                    #             sections.append(data)
                    continue
                # print(findMitre)
                # attivazione del "findMitre" e disattivazione del "findYaraLinks"
                if str(elm.text).strip().lower() == "mitre att&ck" or str(elm.text).strip().lower() == "mitre" or findMitre:
                    # print(mitre_doing)
                    # if not mitre_doing:
                    #     print(sigmaDatas)
                    findYaraLinks = False
                    findMitre = True
                    sigma = False               
                
                # ricercatore per dati del persistence mechanisms quando non sono nel box <pre
                if pm:
                    if str(elm.text).strip().lower() != "persistence mechanisms": 
                        if str(elm.text).strip() != "" and str(elm.text).strip() != "\n":
                            data = replacer(str(elm), False)
                            if type(data) == list:
                                data.insert(0, "data")
                            sections.append(data)
                            continue

                # ricercatore per dati del mitre quando non sono nel box <pre
                if findMitre:
                    if str(elm.text).strip() != "\n" and str(elm.text).strip() != "" and not strong:
                        # print(elm.text)
                        if str(elm.text).strip().lower() != "mitre" and str(elm.text).strip().lower() != "mitre att&ck":
                            data = replacer(str(elm).strip(), True)
                            # print(data)
                            if type(data) == list:
                                data.insert(0, "data")
                                sections.append(data)
                            else:
                                if data.lower() not in strong_titles:
                                    sections.append(data)
                            continue

                # ricercatore dei dati suricata fuori dal box <pre
                if suricata:
                    if str(elm.text).strip().lower() != "suricata" and str(elm.text).strip().lower() != "suricata:":
                        if str(elm.text).strip() != "\n" and str(elm.text).strip() != "":
                            if str(elm).strip()[:3] == "<p>":
                                data = replacer(str(elm).strip(), False)
                                if type(data) == list:
                                    data.insert(0, "data")
                                sections.append(data)
                                continue
                                

                # ricercatore dei dati yara fuori dal box <pre
                if findYaraLinks:
                    # print("yara")
                    if str(elm.text).strip() != "\n" and str(elm.text).strip() != "":
                        # print("\n#",elm)
                        if str(elm.text).strip() == "YARA Forge":
                            try:
                                # print(elm)
                                sections.append(elm.find("a")['href'])
                                continue
                            except TypeError:
                                pass
                        if str(elm.text).strip()[-1] != ":":
                            if str(elm)[:3].strip() == "<p>":
                                # print("\n#", elm)
                                try:
                                    if str(elm.text).strip() == str(elm.find("a")['href']).strip():
                                        yaraLinks.append(elm.find("a")['href'])
                                    else:
                                        if elm.text == "[email protected]":
                                            yaraLinks.append(f"{str(elm.text).replace("\xa0", " ")}: {elm.find("a")['href']}")
                                        else:
                                            yaraLinks.append(f"{elm.text}: {elm.find("a")['href']}")
                                    # print(yaraLinks)
                                except TypeError:
                                    # print("\n#",elm.text)
                                    # print(yaraLinks)
                                    yaraLinks.append(str(elm.text).strip())
                                    continue
                            else:
                                # print("\n#",elm)
                                if str(elm)[:4] == "<pre":
                                    
                                    dato = replacer(str(elm), False)
                                    # print(dato)
                                    if type(dato) == list:
                                        dato.insert(0, "data")
                                        sections.append(dato)
                                    else:
                                        sections.append(dato)
                                    continue
                                try:
                                    if elm.find("div", "wp-block-embed__wrapper") is not None:
                                        # print(elm)
                                        if str(elm.text).strip() == str(elm.find("a")['href']).strip():
                                            # print(f"{elm.text}: {elm.find("div", "wp-block-embed__wrapper").find("a")['href']}")
                                            yaraLinks.append(elm.find("a")['href'])
                                        else:
                                            # print(str(elm.text).strip()[:5])
                                            if str(elm.text).strip()[:5] == "https":
                                                rule = replacer(str(elm), True)
                                                if type(rule) == list:
                                                    rule.insert(0, "data")
                                                yaraLinks.append(rule)
                                            else:
                                                yaraLinks.append(f"{elm.text}: {elm.find("div", "wp-block-embed__wrapper").find("a")['href']}")
                                    block = True
                                except KeyError:
                                    # print(elm)
                                    if str(elm)[:4] == "<pre":
                                        # print(elm)
                                        sections.append(replacer(str(elm.text).strip(), False))
                                    continue

                                if not block:
                                    # print(elm)
                                    data = (replacer(str(elm).strip(), False))
                                    if type(data) == list:
                                        data.insert(0, "data")
                                        sections.append(data)
                                    else:
                                        sections.append(data)
                                    continue
                        else:
                            # print("\n#", elm.text)
                            # sections.append((4, str(elm.text).strip()[:-1]))        
                            if yaraLinks:
                                if len(yaraLinks) == 1:
                                    sections.append(yaraLinks[0])
                                else:
                                    yaraLinks.insert(0, "data")
                                    sections.append(yaraLinks)
                                # print(sections)
                                yaraLinks = []  
                # print(sigma)
                if sigma:
                    # print("sigma")
                    # print("#",str(elm.text).strip())
                    findYaraLinks = False
                    
                    if str(elm.text).strip() == "Search rules on detection.fyi or sigmasearchengine.com" or str(elm.text).strip() == "Search rules on detection.fyi or sigmasearchengine.com" or str(elm.text).strip() == "Search sigma rules at detection.fyi" or str(elm.text).strip() == "Search sigma rules at detection.fyi":
                        # print(elm)
                        sections.append(replacer(elm.text, True))    
                        continue
                    # print(elm.text)
                    if str(elm.text).strip() == "DFIR Public Rules Repo:" or str(elm.text).strip() == "DFIR Report Public:" or str(elm.text).strip() == "DFIR Private Rules:" or str(elm.text).strip() == "DFIR Report Private:" or str(elm.text).strip() == "Sigma Repo:" or str(elm.text).strip() == "DFIR Report Repository" or str(elm.text).strip() == "DFIR Report Repo" or str(elm.text).strip() == "SIGMA Project Repo" or str(elm.text).strip() == "DFIR Report Public Repo:" or str(elm.text).strip() == "JoeSecurity Repo:":
                        try:
                            # print(elm)
                            sections.append(elm.find("a")['href'])
                            continue
                        except TypeError:
                            pass

                    if str(elm.text).strip() != "\n" and str(elm.text).strip() != "":
                        # print("\n#",str(elm).strip())
                        if str(elm.text).strip().lower() != "sigma":
                            if str(elm).strip()[:4] == "<pre":
                                sigmaData = replacer(str(elm), False)
                                if type(sigmaData) == list:
                                    sigmaData.insert(0, "data")
                                sections.append(sigmaData)
                            else:
                                ##########################################
                                try:
                                    # print(elm)
                                    sigmaData = elm.find_all("a")
                                    sigmaData = [f"{str(sigmaLink.text).strip()}: {sigmaLink['href']}" if sigmaLink.text != sigmaLink['href'] else sigmaLink['href'] for sigmaLink in sigmaData]
                                    
                                    for sigmad in sigmaData:
                                        sigmaDatas.append(sigmad)
                                    # print(sigmaDatas)
                                except KeyError:
                                    sigmaDatas = replacer(str(elm).strip(), False)
                                # print(sigmaDatas)
                            continue
                # ricerca dei dati negli IOC
                find_pre(elm, sections)
                # if str(elm)[:4].strip() == "<pre":
                #     if str(elm.text) != "" and str(elm.text) != "\n":
                #         print("\n#",elm,"\n-------------------------------\n")
                #         # print(untouchables)
                #         data = replacer(str(elm).strip(), False)
                #         # print(data)
                #         # print("\n#",data)
                #         if type(data) == list:
                #             data.insert(0, "data")
                #             # print(sections)
                #             sections.append(data)
                #             # print(data.insert(0, "data"))
                #         else:
                #             sections.append(data)
                continue
            find_pre(elm, sections)
            # if str(elm)[:4].strip() == "<pre":
            #     if str(elm.text) != "" and str(elm.text) != "\n":
            #         print("\n#",elm,"\n-------------------------------\n")
            #         # print(untouchables)
            #         data = replacer(str(elm).strip(), False)
            #         # print("\n-------------------------------\n",data)
            #         # print(sections)
            #         # print("\n#",data)
            #         if type(data) == list:
            #             data.insert(0, "data")
            #             # print(sections)
            #             sections.append(data)
            #             # print(data.insert(0, "data"))
            #         else:
            #             sections.append(data)
            
    # print(sections)
    # print(ioc)
        # print("\n#",sections)
    return ioc, os_score, titles

def deep_extracting(datas, sections, glitch):
    # print("yas")
    yaraLinks = []
    sigmaDatas = []
    pre = []
    strong_titles = ["snort", "references", "mitre att&ck techniques ", "mitre software", "mitre", "yara rules", "yara", "sigma", "suricata", "network", "file"]
    strong_datas = []
    titles = []

    sigmaData = ""

    untouchables = False
    sigma = False
    sigmaDataSended = False
    ioc = False
    findYaraLinks = False
    yaraDataSended = False
    findMitre = False
    suricata = False
    add = False
    skip = False
    strong = False
    pm = False

    # score per gli os
    os_score = {
        "windows":0,
        "linux":0,
        "mac":0,
        "android":0,
        "ios":0
    }
    
    # contenitore per evitare che una parola venga contata per più di una volta
    key_viewed = set()

    datas_str = ""
    for elm in datas:
        datas_str += str(elm)

    datas = datas_str.split("\n")
    # print(datas)
    c = 0
    
    while c < len(datas):
        elm = datas[c].strip()
        elm_bs = bs(elm, "html.parser")
        # print("#",elm)
        # if elm[:2] == "<h":
        #     if str(elm_bs.text).strip() == "Yara Rules":
        #         print("yes")

        os_score, key_viewed = osTag_scoring(repr(str(elm_bs.text)).strip().lower(), os_score, key_viewed)

        #--------------------------------------------------------------------------
        # gestionale IOC
        if str(elm_bs.text).strip()[:15] == "Internal case #":
            ioc = True
            if glitch:
                return ioc, os_score, titles

            if strong_datas:
                if type(strong_datas) == list:
                    strong_datas.insert(0, "data")
                sections.append(strong_datas)
            return ioc, os_score, titles

        # disattivatore del "findMitre"
        if elm[:43].strip() == "<div class=\"sharedaddy sd-sharing-enabled\">":
            findMitre = False
            # print("stop")
            return ioc, os_score, titles
        
        skip, strong, strong_datas, pm, yaraDataSended, suricata, sigma, findYaraLinks, findMitre, ioc, untouchables, sigmaDataSended, titles, sigmaDatas, yaraLinks = title_filter(skip, strong, strong_datas, elm_bs, titles, yaraDataSended, pm, suricata, yaraLinks, sections, sigma, findMitre, findYaraLinks, ioc, untouchables, sigmaDatas, sigmaDataSended)
            
        if skip:
            skip = False
            c += 1
            continue

        if str(elm_bs.text).strip() == "Detections" and len(sections) > 5:
            ioc = True
            
        # print(f"ioc:{ioc}, yara:{findYaraLinks}")
        if ioc:
            # print(strong)
            if strong:
                if str(elm).strip()[:4] != "<pre" and str(elm).strip()[:2] != "<h" and str(elm_bs.text).strip() != "":
                    # print("\n#",elm.text)
                    # print(sections)
                    control_count = -1
                    while type(sections[control_count]) != tuple:
                        control_count -= 1
                    if str(elm_bs.text).strip()[-1] == ":":
                        # print(elm.text)
                        if sections[control_count][1] == str(elm_bs.text).strip()[:-1]:
                            c += 1
                            continue
                    else:
                        if sections[control_count][1] == str(elm_bs.text).strip():
                            c += 1
                            continue
                        # print(sections[control_count][1], str(elm.text).strip()[:-1])
                    # print(sections[control_count])
                    
                    if str(elm_bs.text).strip().lower() not in strong_titles and str(elm_bs.text).strip() != "":
                        # print("\n-----------------------\n",elm)
                        strongDatas = replacer(str(elm), True)
                        # print("\n#",strongDatas)
                        if type(strongDatas) == list:
                            # print("\n#",strongDatas)
                            if strongDatas[0].lower() in strong_titles:
                                strongDatas[0] = "data"
                            else:
                                strongDatas.insert(0, "data")
                            # print(strongDatas)
                            sections.append(strongDatas)
                        else:
                            # print(strongDatas)
                            sections.append(strongDatas)
                        c += 1
                        continue
                # ricerca dei dati quando strong è attivo
                find_pre(elm_bs, sections)
                # if str(elm)[:4].strip() == "<pre":
                #     if str(elm_bs.text) != "" and str(elm_bs.text) != "\n":
                #         # print("\n#",elm,"\n-------------------------------\n")
                #         # print(untouchables)
                #         data = replacer(str(elm).strip(), False)
                #         # print(data)
                #         # print("\n#",data)
                #         if type(data) == list:
                #             data.insert(0, "data")
                #             # print(sections)
                #             sections.append(data)
                #             # print(data.insert(0, "data"))
                #         else:
                #             sections.append(data)
                c += 1
                continue

            if pm:
                if str(elm_bs.text).strip().lower() != "persistence mechanisms": 
                    if str(elm_bs.text).strip() != "" and str(elm_bs.text).strip() != "\n":
                        data = replacer(str(elm), False)
                        if type(data) == list:
                            data.insert(0, "data")
                        sections.append(data)
                        continue

            # ricercatore per dati del mitre quando non sono nel box <pre
            if findMitre:
                if str(elm_bs.text).strip() != "\n" and str(elm_bs.text).strip() != "":
                    if elm_bs.text == "MITRE Software" or elm_bs.text == "Reference":
                        sections.append((3, replacer_title(str(elm_bs.text).strip().lower())))
                        titles.append((3, replacer_title(str(elm_bs.text).strip().lower())))
                        c += 1
                        continue

                    data = replacer(elm.strip(), True)
                    # print(data)
                    if type(data) == list:
                        # print(data)
                        data.insert(0, "data")
                        sections.append(data)
                    else:
                        sections.append(data)
                    c += 1
                    continue

            if suricata:
                if str(elm_bs.text).strip().lower() != "suricata" and str(elm_bs.text).strip().lower() != "suricata:":
                    if str(elm_bs.text).strip() != "\n" and str(elm_bs.text).strip() != "":
                        if str(elm).strip()[:3] == "<p>":
                            data = replacer(str(elm).strip(), False)
                            if type(data) == list:
                                data.insert(0, "data")
                            sections.append(data)
                            continue

            # attivazione del "findMitre" e disattivazione del "findYaraLinks"
            if str(elm_bs.text).strip() == "MITRE ATT&CK" or str(elm_bs.text).strip() == "MITRE":
                findYaraLinks = False
                findMitre = True
                # print("\n\n-----------------------\n\n","mitre")
                sigma = False


            # ricercatore dei dati yara fuori dal box <pre
            # print(findYaraLinks)
            if findYaraLinks:
                # print("#",elm)
                if elm[:3].strip() == "<p>":
                    if str(elm_bs.text).strip() != "\n" and str(elm_bs.text).strip() != "" and str(elm_bs.text).strip() != str(elm_bs.find("a")['href']).strip():
                        try:
                            yaraLinks.append(f"{elm_bs.text}: {elm_bs.find("a")['href']}")
                            c += 1
                            continue
                        except TypeError:
                            yaraLinks.append(replacer(str(elm_bs.text).strip(), False))
                            c += 1
                            continue
                    else:
                        try:
                            yaraLinks.append(elm_bs.find("a")['href']) 
                            c += 1
                            continue
                        except TypeError:
                            yaraLinks.append(replacer(str(elm_bs.text).strip(), False))
                            c += 1
                            continue
                elif elm[:4] == "<div":
                    if str(elm_bs.text).strip() != "\n" and str(elm_bs.text).strip() != "":
                        rules = [x['href'] for x in elm_bs.find("div", "wp-block-embed__wrapper").find_all("a")]
                        # print(rules)
                        if rules:
                            if len(rules) == 1:
                                yaraLinks.append(rules[0])
                            else:
                                yaraLinks.append(rules)
                    # print(elm.find("div", "wp-block-embed__wrapper").find("a")['href'])
                else:
                    # print("#",elm)
                    # dato completo
                    if elm[:4].strip() == "<pre" and elm[-6:].strip() == "</pre>":
                        # print(elm)
                        if str(elm_bs.text).strip() != "" and str(elm_bs.text).strip() != "\n":
                            sections.append(replacer(elm, untouchables))

                    # chiusura del dato
                    elif elm.strip()[:5] == "</pre" or (elm.strip()[:4] != "<pre" and elm.strip()[-6:] == "</pre>"):
                        # print(elm)
                        if str(elm_bs.text).strip() != "" and str(elm_bs.text).strip() != "\n":
                            # print("#", elm)
                            pre.append(elm)
                        # print(pre)
                        data_compose = ""
                        for d in pre:
                            data_compose += d + "\n"
                        data_compose = replacer(data_compose, False)
                        # print(data_compose)
                        # 
                        
                        if type(data_compose) == list:
                            data_compose.insert(0, "data")
                        sections.append(data_compose)

                        add = False
                        pre = []

                    # resto del dato
                    if add:
                        pre.append(elm)
                        # print("#",elm)

                    # inizio del dato
                    if elm[:4].strip() == "<pre" and elm[-6:].strip() != "</pre>":
                        add = True
                        # print("#",elm)
                        if str(elm_bs.text).strip() != "" and str(elm_bs.text).strip() != "\n":
                            pre.append(elm)

                    # print(data)
                    c += 1
                    continue
            # ricercatore dei dati sigma fuori dal box <pre
            if str(elm_bs.text).strip() == "Yara" or str(elm_bs.text).strip() == "YARA" or str(elm_bs.text).strip() == "Yara Rules":
                # print("yess")
                findYaraLinks = True
                sigma = False
                if sigmaDatas:
                    # print(sigmaDatas)
                    if len(sigmaDatas) == 1:
                        sections.append(sigmaDatas)
                    else:
                        sigmaDatas.insert(0, "data")
                        sections.append(sigmaDatas)
                    sigmaDataSended = True
            
            if sigma:
                if str(elm_bs.text).strip() == "Search rules on detection.fyi or sigmasearchengine.com" or str(elm_bs.text).strip() == "Search rules on detection.fyi or sigmasearchengine.com" or str(elm_bs.text).strip() == "Search sigma rules at detection.fyi" or str(elm_bs.text).strip() == "Search sigma rules at detection.fyi":
                    # print(elm)
                    sections.append(replacer(elm_bs.text, True))  
                    c += 1
                    continue
                if str(elm_bs.text).strip() == "DFIR Public Rules Repo:" or str(elm_bs.text).strip() == "DFIR Private Rules:" or str(elm_bs.text).strip() == "Sigma Repo:":
                    try:
                        sections.append(elm_bs.find("a")['href'])
                        c += 1
                        continue
                    except TypeError:
                        c += 1
                        continue
                try:
                    if replacer(elm_bs.text, True) != elm_bs.find("a")['href']:
                        sigmaData = f"{replacer(elm_bs.text, True)}: {elm_bs.find("a")['href']}"
                    else:
                        sigmaData = elm_bs.find("a")['href']
                    # print(elm)
                except:
                    #########################################
                    # dato completo
                    if elm[:4].strip() == "<pre" and elm[-6:].strip() == "</pre>":
                        if str(elm_bs.text).strip() != "" and str(elm_bs.text).strip() != "\n":
                            # print("\n",elm)
                            sigmaData = replacer(elm, untouchables)

                    # chiusura del dato
                    elif elm[:5].strip() == "</pre" or (elm[:4] != "<pre" and elm[-6:].strip() == "</pre>"):
                        if str(elm_bs.text).strip() != "" and str(elm_bs.text).strip() != "\n":
                            pre.append(elm)
                        
                        data_compose = ""
                        for d in pre:
                            data_compose += (d+"\n")
                        sigmaData = replacer(data_compose, False)

                        add = False
                        pre = []

                    # resto del dato
                    if add:
                        pre.append(elm)
                        # print("#",elm)

                    # inizio del dato
                    if elm[:4].strip() == "<pre" and elm[-6:].strip() != "</pre>":
                        add = True
                        # print("#",elm)
                        if str(elm_bs.text).strip() != "" and str(elm_bs.text).strip() != "\n":
                            pre.append(elm)
                        

                    
                if sigmaData and not add:
                    # print(sigmaData)
                    if type(sigmaData) == list:
                        if len(sigmaData) == 1:
                            sections.append(sigmaData[0])
                        else:
                            for sigmaD in sigmaData:
                                sigmaDatas.append(sigmaD)
                            sigmaData.insert(0, "data")
                    sections.append(sigmaData)
                    sigmaDataSended = True
                    c += 1
                    continue
        #--------------------------------------------------------------------------

        ###########################################################################

        #--------------------------------------------------------------------------
        # filtro per dati
        # print(elm)
        # if str(elm_bs.text).strip() != "" and str(elm_bs.text).strip() != "\n":
        # dato completo
        if not findMitre and not findYaraLinks and not sigma:
            if elm[:4].strip() == "<pre" and elm[-6:].strip() == "</pre>":
                if str(elm_bs.text).strip() != "" and str(elm_bs.text).strip() != "\n":
                    # print("\n#",elm_bs)
                    dato = replacer(elm, False)
                    
                    if type(dato) == list:
                        dato.insert(0, "data")
                        sections.append(dato)
                    else:
                        sections.append(dato)

            # chiusura del dato
            elif elm[:5].strip() == "</pre" or (elm[:4] != "<pre" and elm[-6:].strip() == "</pre>"):
                # print("#", elm)
                if str(elm_bs.text).strip() != "" and str(elm_bs.text).strip() != "\n":
                    pre.append(elm)
                data_compose = ""
                for d in pre:
                    data_compose += (d+"\n")
                data_compose = replacer(data_compose, False)
                # print(data_compose)
                if type(data_compose) == list:
                    data_compose.insert(0, "data")
                
                add = False
                sections.append(data_compose)
                pre = []

            # resto del dato
            if add:
                pre.append(elm)
                # print("#",elm)

            # inizio del dato
            if elm[:4].strip() == "<pre" and elm[-6:].strip() != "</pre>":
                add = True
                # print("#",elm)
                if str(elm_bs.text).strip() != "" and str(elm_bs.text).strip() != "\n":
                    pre.append(elm)
                    # data_compose(elm, elm_bs, sections, untouchables, add, pre)
        #--------------------------------------------------------------------------
        c += 1
    return ioc, os_score, titles

def onlyIOC(datas):
    ioc_sections = []
    pre = []
    titles = []

    add = False
    ioc_data = False

    titles_target = ["sigma", "sigma rules", "suricata", "yara", "yara rules", "mitre", "mitre att&ck"]

    # score per gli os
    os_score = {"windows":0,
                "linux":0,
                "mac":0,
                "android":0,
                "ios":0}
    
    # contenitore per evitare che una parola venga contata per più di una volta
    key_viewed = set()

    datas_str = ""
    for elm in datas:
        datas_str += str(elm)

    datas = datas_str.split("\n")
    # print(datas)
    c = 0
    
    while c < len(datas):
        elm = datas[c].strip()
        elm_bs = bs(elm, "html.parser")

        
        os_score, key_viewed = osTag_scoring(repr(str(elm_bs.text)).strip().lower(), os_score, key_viewed)

        if elm[:43].strip() == "<div class=\"sharedaddy sd-sharing-enabled\">":
            break

        if ioc_data:
            if str(elm).strip()[:2] != "<h" and str(elm_bs.text).strip() != "":
                # str(elm_bs.text).strip()
                if elm[:3].strip() == "<p>":
                    try:
                        ioc_sections.append(f"{str(elm_bs.text).replace("\xa0", " ")}: {elm_bs.find("a")['href']}")
                    except TypeError:
                        dato = replacer(elm, False)
                        if type(dato) == list:
                            dato.insert(0, "data")
                            ioc_sections.append(dato)
                        else:
                            ioc_sections.append(dato)

                        c += 1
                        continue
                elif elm[:4] == "<div":
                    # print(elm)
                    rules = [x['href'] for x in elm_bs.find("div", "wp-block-embed__wrapper").find_all("a")]
                    # print(rules)
                    if rules:
                        if len(rules) == 1:
                            ioc_sections.append(rules[0])
                        else:
                            ioc_sections.append(rules)
                    # print(elm.find("div", "wp-block-embed__wrapper").find("a")['href'])
                else:
                    if elm[:4].strip() == "<pre" and elm[-6:].strip() == "</pre>":
                        # print(elm)
                        if str(elm_bs.text).strip() != "" and str(elm_bs.text).strip() != "\n":
                            ioc_sections.append(replacer(elm, False))

                    # chiusura del dato
                    elif elm[:5].strip() == "</pre" or (elm[:4] != "<pre" and elm[-6:].strip() == "</pre>"):
                        if str(elm_bs.text).strip() != "" and str(elm_bs.text).strip() != "\n":
                            pre.append(elm)
                        
                        data_compose = ""
                        for d in pre:
                            data_compose += d
                            # print(data_compose)
                        data_compose = replacer(data_compose, False)
                        
                        if type(data_compose) == list:
                            data_compose.insert(0, "data")
                        ioc_sections.append(data_compose)

                        add = False
                        pre = []

                    # resto del dato
                    # print("qua")
                    if add:
                        pre.append(elm)
                        # print("#",elm)

                    # inizio del dato
                    if elm[:4].strip() == "<pre" and elm[-6:].strip() != "</pre>":
                        add = True
                        # print("#",elm)
                        if str(elm_bs.text).strip() != "" and str(elm_bs.text).strip() != "\n":
                            pre.append(elm)


        if elm[:2].strip() == "<h" and elm[2].isdigit():
            if str(elm_bs.text).strip() != "\xa0" and str(elm_bs.text).strip() != "" and str(elm_bs.text).strip() != "\n":
                ioc_title = str(elm_bs.text).strip().lower()
                if ioc_data:
                    # print(str(elm_bs.text).strip())
                    ioc_title = replacer_title(str(elm_bs.text).strip().lower())
                        
                    if ioc_title == "suricata rules":
                        ioc_title = "suricata"
                    if ioc_title == "sigma rules":
                        ioc_title = "sigma"
                    if ioc_title == "yara rules":
                        ioc_title = "yara"
                    if ioc_title == "indicators":
                        ioc_title = "iocs"

                    ioc_sections.append((int(elm[2]), ioc_title))
                    titles.append((int(elm[2]), ioc_title))
                else:
                    for t in titles_target:
                        if t == ioc_title:
                            if ioc_title == "suricata rules":
                                ioc_title = "suricata"
                            if ioc_title == "sigma rules":
                                ioc_title = "sigma"
                            if ioc_title == "yara rules":
                                ioc_title = "yara"
                            if ioc_title == "indicators":
                                ioc_title = "iocs"

                            ioc_sections.append((int(elm[2]), ioc_title))
                            titles.append((int(elm[2]), ioc_title))
                            ioc_data = True
        c += 1
    return ioc_sections, os_score, titles

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
                    "linux", "bash", "root", "apt", "systemd",
                    "sshd", "cron", "kernel module", "selinux", "journald",
                    "init", "debian", "red hat", "rpm", "pacman", "gnome", "unix"
                    "zypper", "gnome-terminal", "sysctl", "iptables", "grep",
                    "tar", "/etc/passwd", "mount", "crontab", "sudoers",
                    "/var/log", "systemctl", "ufw", "rsync", "runlevel", "elf", ".sh",
                    ".rodata"
                ],
        "mac":[
                    "macos", "spotlight", "finder", "time machine", "launchd",
                    "apple silicon", "brew", "system preferences", "xcode", "darwin",
                    "macbook", "mac mini", "safari", "plist", ".dmg", ".pkg", "macho", "mach-o"
                    "activity monitor", "keychain", "console.app", "icloud", "airplay",
                    "automator", "disk utility", "mission control", "osascript", "applescript",
                    "menu bar", "menubar apps", "thunderbolt", "macports", "/applications", 
                    "/private/tmp", "launchagent", "launchdaemon", "tcc", "xprotect", "dlyb", 
                    "amos", "/volumes", "xattr", "apple events", ".dylib", "codesign", "fat binary",
                    ".rodata", ".app", "/contents/macos", "avfoundation", "xprotect"
                ],
        "android":[
                    "android", "apk", "play store", "adb",
                    "dalvik", "logcat", "manifest.xml",
                    "android sdk", "android studio", "adb shell",
                    "android manifest", "androidmanifest", "android.intent.action", "r.java",
                    "minSdkVersion", "targetSdkVersion", "android.hardware.camera", "android.permission",
                    "dex", "dalvkin executable",
                ],
        "ios":[
                    "app store", "xcodeproj", "swift",
                    "cocoapods", "entitlements", "xcode", "apple developer", "plist.info",
                    "objective-c", "bundle identifier"
                ]
    }

    if elm_bs != "" and elm_bs != "\n":
        for os, keywords in os_keywords.items():
            for kws in keywords:
                pattern = r"\b" + escape(kws) + r"\b"
                # if kws in str(elm_bs.text).strip().lower() and kws not in key_viewed:
                if search(pattern, elm_bs) and kws not in key_viewed:
                    # print(f"os: {os} -> {kws}")
                    os_score[os] += 1
                    key_viewed.add(kws)
    return os_score, key_viewed

def find_pre(elm, sections):
    '''
        Funzione usata per ricercare dati nei tag <pre>;

        Input:
            - elm(bs4OBJ), elemento estratto dalla struttura HTML;
            - sections(list), lista contenente le sezioni(titolo, dati);
    '''

    if str(elm)[:4].strip() == "<pre":
        if str(elm.text) != "" and str(elm.text) != "\n":
            # print("\n#",elm,"\n-------------------------------\n")
            # print(untouchables)
            data = replacer(str(elm).strip(), False)
            # print("\n#",data)
            if type(data) == list:
                data.insert(0, "data")
                # print(sections)
                sections.append(data)
                # print(data.insert(0, "data"))
            else:
                # print("\n#",data)
                sections.append(data)
            # print("\n#",sections)

def data_composing(elm, elm_bs, sections, pre, untouchables, add):
    '''
        Funzione usata per ricomporre i tag <pre nel report in cui la struttura HTML
            viene scomposta;

        Input:
            - elm(str), elemento della struttura HTML estratto;
            - elm_bs(bs4OBJ), elemento della struttura HTML estratto;
            - sections(list), lista che conterrà titoli e dati;
            - pre(list), lista usato per comporre un pre alla volta;
            - untouchables(bool), valore booleano utilizzato per rappresentare se il dato
                fa parte della sezione "IOC";
            - add(bool), valore booleano utilizzato per la composizione del dato;
        Output:
            - add(bool), aggiornamento del valore booleano utilizzato per la composizione del dato;
    '''
    
    # dato completo
    if elm[:4].strip() == "<pre" and elm[-6:].strip() == "</pre>":
        # print(elm)
        if str(elm_bs.text).strip() != "" and str(elm_bs.text).strip() != "\n":
            dato = replacer(elm, untouchables)
            if type(dato) == list:
                dato.insert(0, "data")
                sections.append(dato)
            else:
                sections.append(dato)

    # chiusura del dato
    elif elm[:5].strip() == "</pre" or (elm[:4] != "<pre" and elm[-6:].strip() == "</pre>"):
        if str(elm_bs.text).strip() != "" and str(elm_bs.text).strip() != "\n":
            pre.append(elm)
        
        data_compose = ""
        for d in pre:
            data_compose += (d+"\n ")
        data_compose = replacer(data_compose, False)
        
        if type(data_compose) == list:
            data_compose.insert(0, "data")
        sections.append(data_compose)

        add = False
        pre = []

    # resto del dato
    if add:
        pre.append(elm)
        # print("#",elm)

    # inizio del dato
    if elm[:4].strip() == "<pre" and elm[-6:].strip() != "</pre>":
        add = True
        # print("#",elm)
        if str(elm_bs.text).strip() != "" and str(elm_bs.text).strip() != "\n":
            pre.append(elm)
    
    return add

def build_tree(node):
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

def zenigata_dfir(source, titles_all, added_report_links, page_count=1):
    #---------------------------
    # home_page_response = get(home_page_url, headers={"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 Edg/132.0.0.0"}).text
    # soup = bs(home_page_response, "html.parser")

    # main_content = soup.find("div", class_="entry-content")
    # noise = main_content.contents
    #---------------------------

    # print("\nColleziono...")

    site = source[0]
    home_page_url = source[1]
    
    home_page_response = get(home_page_url, headers={"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 Edg/132.0.0.0"})
    home_page_soup = bs(home_page_response.content, "html.parser")  

    #####################################################
    # DA QUI INIZIARE A MUTARE ZENIGATA PER LOOKOUT
    #####################################################
    print("\n   [*] Estraendo dati dai report...")

    # creo una connessione con l'istanza dove risiede il DB
    client = mc("mongodb://localhost:27017/")

    # creo un collegamento con il DB
    db = client['master']

    # creo un collegamento con la collezione
    coll = db[site]

    reports_zip, exit_ = collection(home_page_soup, added_report_links)
    frasiDaBar = ["Altro giorno, altri dati uguali. Zenigata ringrazia per la pazienza <3", "Esperimento #204: risultati identici a ieri. E a ieri l'altro. E a quello prima.", "I dati rimangono... uguali. Ma almeno il caffè era buono.", "Abbiamo escluso un'altra novità. Solo migliaia di informazioni uguali.", "Se ci fosse un dato nuovo dietro l'angolo, io sto girando in tondo da settimane.", "Ho controllato. Nulla da aggiungere...", "La mia scoperta più recente? Dati uguali..." "Niente di nuovo per oggi :/"]
    
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
            report_response = get(report[2], headers={"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 Edg/132.0.0.0"})
            report_soup = bs(report_response.content, "html.parser")
            main_content = report_soup.find("div", class_="entry-content")
            contents = main_content.contents

            # dizionario che verrà aggiuno ad una lista, dati che verranno scritti nel json
            report_saved = {}
            tags = {}
            section_container = []

            report_id = id_generator(report)

            report_saved["about_it"] = [f"| title: {report[0]} |", f"| pubblication: {report[1]} |", f"| link: {report[2]} |", f"| page: {page_count} |", f"| report_id: {report_id} |", f"| report: {report_count} |"]
            section_container.append(report_saved)

            # print(f"\n--------------------------------------\nlink: {report[2]}")
            if report[2] == "https://thedfirreport.com/2024/04/29/from-icedid-to-dagon-locker-ransomware-in-29-days/" or report[2] == "https://thedfirreport.com/2023/03/06/2022-year-in-review/":
                new_sections, titles, os_tag = extractor(contents, True, report[2])
            else:
                new_sections, titles, os_tag = extractor(contents, False, report[2])
                
            if new_sections:
                if titles:
                    tags = []
                    stack = []
                    min_num = 10

                    i = 0
                    while i < len(titles):
                        elm = titles[i]

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
                        
                    tags_dict = []
                    for tag in tags:
                        tags_dict.append((build_tree_tags(tag)))
                    tags_dict.append(os_tag)
                    section_container.append({"tags":tags_dict})
                # print("\n----------------------------------------------------------------------------")
                try:
                    for section in new_sections[0]:
                        if type(section) == list and len(section) > 1:
                            # print(section)
                            section_container.append(build_tree(section))
                        # print(section_container)

                    # save in local
                    # output_path = path.abspath(__file__)[:len(path.abspath(__file__))-len(path.basename(__file__))]
                    # if not path.exists(output_path+"\\outputZenigata_dfir"):
                    #     mkdir(output_path+"\\outputZenigata_dfir")

                    # if not path.exists(output_path+f"\\outputZenigata_dfir\\page_{page_count}"):
                    #     mkdir(output_path+f"\\outputZenigata_dfir\\page_{page_count}")

                    # with open(output_path+f"\\outputZenigata_dfir\\page_{page_count}\\Report_{report_count}.json", "w", encoding="utf-8") as f:
                    #     dump(section_container, f, indent=4, ensure_ascii=False)
                    
                    ##############################################
                    # add document to db
                    report_for_db = {}
                    for item in section_container:
                        report_for_db.update(item)
                    # print("\n",report_for_db)
                    coll.insert_one(report_for_db)
                    print(f"        [REPORT {report_count}] Elaborato e salvato!")
                    ##############################################

                except (IndexError, TypeError) as e:
                    print(f"        [REPORT {report_count}] Problemi durante la scrittura dei dati!")
                    with open("errorsLog_dfir.txt", "a") as f:
                        f.write(f"----------------------------------------------------------------------------\n[REPORT {report_count}] Problemi durante la scrittura dei dati!\n\n{format_exc()}\n\n{report[2]}\n----------------------------------------------------------------------------\n\n")
            else:
                print(f"        [REPORT {report_count}] Elaborato, ma nessun dato trovato!")
                report_saved["MISTAKE"] = "Nessun dato trovato!"
            report_count += 1
        except (AttributeError, IndexError, UnboundLocalError, ValueError) as e:
            print(f"        [REPORT {report_count}] Issues occurred during processing!")
            with open("errorsLog_dfir.txt", "a") as f:
                f.write(f"----------------------------------------------------------------------------\n[REPORT {report_count}] Problemi durante l'elaborazione!\n\n{format_exc()}\n\n{report[2]}\n----------------------------------------------------------------------------\n\n")
            report_count += 1
        
        # print(titles)
            
        # print(titles)
    # print(titles)
    #----------------------------------------------------------------------------
    # da disattivare in caso di utilizzo con "check_last_page()"
    # return True
    ###############################################
    if exit_:
        return True
    
    last_page, new_link = check_lastPage(home_page_soup)
    # print(last_page, new_link)
    if not last_page:
        page_count += 1
        return zenigata_dfir((site, new_link), titles_all, added_report_links, page_count)
    else:
        return True
    ###############################################
    #----------------------------------------------------------------------------

def main_dfir():
    source = ('dfir',"https://thedfirreport.com/")
    if path.exists("errorsLog_dfir.txt"):
        remove("errorsLog_dfir.txt")

    # main
    print("\n   [*] Elaborando...")
    titles_all = []
    # start_script = time()

    client = mc("mongodb://localhost:27017/")
    db = client['master']

    added_report_links = query(db, source[0])
    zenigata_dfir(source, titles_all, added_report_links)

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
    main_dfir()