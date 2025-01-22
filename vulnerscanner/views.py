from django.contrib.auth.models import User, auth
from django.shortcuts import render, redirect
from django.http import HttpResponse,JsonResponse
from django.contrib import messages
from . models import *
from zapv2 import ZAPv2
import time
import re
import urllib.parse
from urllib.parse import urlsplit as us

# Create your views here.




# ------------------------------ Default Context -------------------------

zap = ZAPv2(apikey=apiKeys)


def newContext():
    try:
        contxt = zap.context.context_list

        if not contxt:

            context_id = zap.context.new_context(contextname="Default Context")
            if context_id:
                # Delete Previous Context 
                ContextData.objects.all().delete()
                # Creating Instance of data ContextData
                conInsert = ContextData()
                conInsert.context_name = "Default Context_{}".format(
                    context_id)
                conInsert.con_number = context_id
                conInsert.save()
                return True

    except:
        print("Please Make Sure You have Added your Context")


newContext()


# ----------------------------- Login -------------------------------------


def login(request):

    if request.method == "POST":
        username = request.POST['username']
        password = request.POST['password']

        user = auth.authenticate(username=username, password=password)

        if user is not None:
            auth.login(request, user)
            return redirect('dashboard')
        else:
            messages.info(request, "Not Valid Credential")
            return redirect('/')

    return render(request, 'vulnerweb/login.html')


# ------------------------------ Dashboard  ---------------------------------


def dashboard(request):

    try:

        high = VulnerData.objects.filter(risk="High").count()
        medium = VulnerData.objects.filter(risk="Medium").count()
        low = VulnerData.objects.filter(risk="Low").count()

        total_domain = ScanData.objects.order_by(
            'domain').values('domain').distinct()
        final_domain = total_domain.count()

        chartt = []
        ids_data = ScanData.objects.all()
        for y in ids_data:

            datafull = data_by_severity(y.id)
            chartt.append(datafull)

        dic = {'high': high, 'medium': medium,
               'low': low, 'final_domain': final_domain, 'chartt': chartt}
        return render(request, 'vulnerweb/dashboard.html', dic)
    except Exception as e:
        return redirect('dashboard')


# ----------------------- Fetch Data by Severity -----------------------------

def data_by_severity(ids):

    dom = ScanData.objects.filter(id=ids)

    for x in dom:
        domain_name = x.domain
        idd = x.id
    full_data = VulnerData.objects.filter(scan_id=ids)

    high = float(full_data.filter(risk="High").count())
    med = float(full_data.filter(risk="Medium").count())
    low = float(full_data.filter(risk="Low").count())
    Informational = float(full_data.filter(risk="Informational").count())

    data = [domain_name, idd, [["High", high], ["Medium", med],
                               ["Low", low], ["Informational", Informational]]]
    return data


# ******************************* All Scan Module *******************************


# ------------------------------ Scan  ---------------------------------

def scan(request):

    scan_alldata = ScanData.objects.all()

    if request.method == "POST":
        if request.POST.get('domain'):

            domain = request.POST.get('domain')
            scanWithUser = request.POST.get('AuthActive')
            if not scanWithUser == None:

                # Scan With User Authetication
                state1 = spiderWithUser(domain)
                if state1 == True:
                    try:
                        # Retrive last Scan Number
                        last_num = ScanData.objects.last()
                        # Retrive Status
                        recent_scan = ScanStatus(apiKeys)
                        # Total Page Crawled
                        total_page = domainTotalPage(
                            recent_scan["id"], apiKeys)

                        # Open Database Instanse
                        scandatabase = ScanData()
                        if last_num == None:
                            scandatabase.scan_num = recent_scan["id"]

                        else:
                            scandatabase.scan_num = last_num.scan_num + 1
                        scandatabase.domain = domain
                        scandatabase.scan_progress = recent_scan["progress"]
                        scandatabase.scan_status = recent_scan["state"]
                        scandatabase.total_urls = total_page
                        # Save Data to Database
                        scandatabase.save()

                        # Retrive Scan_Id for Active Scan Data Insertion
                        last_num_insert = ScanData.objects.last().scan_num
                        activeScan = passivetest(apiKeys, domain)
                        scan_ide = ScanData.objects.get(
                            scan_num=last_num_insert)

                        for track in activeScan:

                            vul = VulnerData()
                            vul.scan_id = scan_ide
                            vul.urls = track["url"]
                            vul.vul_name = track["name"]
                            vul.risk = track["risk"]
                            vul.alert = track["alert"]
                            vul.decryption = track["description"]
                            vul.solution = track["solution"]
                            vul.evidence = track["evidence"]
                            vul.other = track["other"]
                            vul.save()

                        messages.success(request, "Scan Compleated !! ")
                        return redirect("scan")
                        # When Getting Errror
                    except Exception as e:
                        messages.info(
                            request, "error while data insertion :: {}".format(e))
                        redirect("scan")
                else:
                    messages.info(request, "Somthing Went Wrong !! ")
                    return redirect("scan")

            elif scanWithUser == None:

                # Send Domain for Scan
                state = spider(domain, apiKeys)
                if state == True:
                    try:
                        # Retrive last Scan Number
                        last_num = ScanData.objects.last()
                        # Retrive Status
                        recent_scan = ScanStatus(apiKeys)
                        # Total Page Crawled
                        total_page = domainTotalPage(
                            recent_scan["id"], apiKeys)

                        # Open Database Instanse
                        scandatabase = ScanData()
                        if last_num == None:
                            scandatabase.scan_num = recent_scan["id"]

                        else:
                            scandatabase.scan_num = last_num.scan_num + 1

                        scandatabase.domain = domain
                        scandatabase.scan_progress = recent_scan["progress"]
                        scandatabase.scan_status = recent_scan["state"]
                        scandatabase.total_urls = total_page
                        # Save Data to Database
                        scandatabase.save()

                        # Retrive Scan_Id for Active Scan Data Insertion
                        last_num_insert = ScanData.objects.last().scan_num
                        activeScan = passivetest(apiKeys, domain)
                        scan_ide = ScanData.objects.get(
                            scan_num=last_num_insert)
                        

                        for track in activeScan:

                            vul = VulnerData()
                            vul.scan_id = scan_ide
                            vul.urls = track["url"]
                            vul.vul_name = track["name"]
                            vul.risk = track["risk"]
                            vul.alert = track["alert"]
                            vul.decryption = track["description"]
                            vul.solution = track["solution"]
                            vul.evidence = track["evidence"]
                            vul.other = track["other"]
                            vul.save()

                        messages.success(request, "Scan Compleated !! ")
                        return redirect("scan")
                        # When Getting Errror
                    except Exception as e:
                        messages.info(
                            request, "error while data insertion :: {}".format(e))
                        redirect("scan")
                else:
                    messages.info(request, "Somthing Went Wrong !! ")
                    return redirect("scan")

    dic = {'scan_alldata': scan_alldata}
    return render(request, "vulnerweb/scan.html", dic)


# ------------------------------- Delete Data and Alert --------------------------------

def scanDelete(request, pk):

    if pk:

        dltfirst = VulnerData.objects.filter(scan_id=pk)
        dltsecond = ScanData.objects.get(id=pk)

        if not dltfirst:
            if dltsecond:
                dltsecond.delete()
                messages.info(request, "Data Deleted Successfully!!")
                return redirect('scan')
            else:

                messages.info(request, "No Such Data for Delete")
                return redirect('scan')

        elif dltfirst and dltsecond:
            dltfirst.delete()
            dltsecond.delete()
            messages.info(request, "Data Deleted Successfully!!")
            return redirect('scan')

    return redirect('scan')


# ------------------------------------ Vulner View Function --------------------------


def vulnerview(request, pk):

    allvulner = VulnerData.objects.filter(scan_id=pk)

    Low = 0
    Medium = 0
    High = 0
    Info = 0

    for x in allvulner:

        if x.risk == "Low":
            Low += 1
        elif x.risk == "Medium":
            Medium += 1
        elif x.risk == "Informational":
            Info += 1
        elif x.risk == "High":
            High += 1

    dic = {'allvulner': allvulner,
           'Low': Low, 'Medium': Medium, 'High': High, 'Info': Info}

    return render(request, "vulnerweb/vulnerView.html", dic)


# ------------------------------  Start Scanning URLs.  ---------------------------------

# Create global variable

datasend = 0
scantype = ""

def spider(domain, api):

    try:
        
        # The URL of the application to be tested
        target = domain

        # Change to match the API key set in ZAP, or use None if the API key is disabled
        apiKey = api

        # By default ZAP API client will connect to port 8080
        zap = ZAPv2(apikey=apiKey)

        # Use the line below if ZAP is not listening on port 8080, for example, if listening on port 8090
        # zap = ZAPv2(apikey=apiKey, proxies={'http': 'http://127.0.0.1:8090', 'https': 'http://127.0.0.1:8090'})

        print('Spidering target {}'.format(target))
        # The scan returns a scan id to support concurrent scanning
        scanID = zap.spider.scan(target, maxchildren=0, recurse=True)
        
        while int(zap.spider.status(scanID)) < 100:
            # Poll the status until it completes
            print('Spider progress %: {}'.format(zap.spider.status(scanID)))
            # storing status of current running scan 
            realdata = int(zap.spider.status(scanID))
            # Sending data to "sendstatus".
            # sendstatus(request=None, data=realdata)
            global datasend
            global scantype

            datasend = realdata
            scantype = 'Spider'
            time.sleep(3)
            

            
        
        print('Spider has completed!')
        

        return True

    except Exception as e:

        print("Getting Error : {}".format(e))


# ----------------------------- Scan With Authetication And User -----------------------------------


def spiderWithUser(target_url):

    try:

        contexts = ContextData.objects.all()
        for x in contexts:
            context_id = x.con_number

        usrdata = zap.users.users_list(context_id)
        for p in usrdata:
            user_id = p['id']

        scanID = zap.spider.scan_as_user(context_id, user_id,
                                         target_url, maxchildren=0, recurse='true')

        print('Started Scanning with Authentication')
        print(scanID)
        while int(zap.spider.status(scanID)) < 100:
            # Poll the status until it completes
            print('Spider progress %: {}'.format(zap.spider.status(scanID)))
            time.sleep(3)

        print('Spider has completed!')

        return True

    except Exception as e:

        print("Getting Error : {}".format(e))


# -------------------------------------------- Status of All Scan ----------------------------------------------

def ScanStatus(apiKey):

    zap = ZAPv2(apikey=apiKey)
    result = zap.spider.scans
    ind = len(result) - 1
    last_data = result[ind]

    return last_data


# -------------------------------------- Sending Scan Status -----------------------------------------

def sendstatus(request):
    try:
        global datasend
        global scantype
        data1 = {
            'my_data': datasend,
            'type' : scantype,
        }
        # if ajax request with get method only then return the status of current scan.
        return JsonResponse(data1)
    except Exception as e:
        print("Error found in sendStatus function : {}".format(e))

        
        


# --------------------------------------------- Total Link Cwals by Scanner Single Domian ----------------------------


def domainTotalPage(id, apiKey):

    zap = ZAPv2(apikey=apiKey)
    count = 0
    page = zap.spider.results(id)
    for x in page:
        count += 1

    return count


# -------------------------------------------- pasive test Scan ---------------------------------------------


def passivetest(apiky, Target):

    apiKey = apiky
    target = Target
    zap = ZAPv2(apikey=apiKey, proxies={
        'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'})

    # TODO : explore the app (Spider, etc) before using the Passive Scan API, Refer the explore section for details
    while int(zap.pscan.records_to_scan) > 0:
        # Loop until the passive scan has finished
        print('Records to passive scan : ' + zap.pscan.records_to_scan)
        global datasend
        global scantype
        print('------------------', datasend)
        datasend = zap.pscan.records_to_scan
        scantype = 'Passive'
        time.sleep(2)

    print('Passive scan Completed!!')
    datasend = 0
    print('------------------', datasend)
    # Print Passive scan results/alerts
    try:

        alert_target = zap.core.alerts(baseurl=target, start=0, count=5000)
        return alert_target
    except Exception as e:
        print("Error : {}".format(e))

# -------------------------------- End Scan ----------------------------------



# ******************************  All General Setting *****************************

# ---------------------------- Fetching General Setting ---------------------------


def generalsetting(request):

    useragent = generalsettingUpi()

    return render(request, "vulnerweb/generalSetting.html", useragent)


# ----------------------------------- Update General Setting ------------------------

def generalsettingupdate(request):

    zap = ZAPv2(apikey=apiKeys)
    try:
        if request.method == "POST":
            if request.POST.get('http_timeout') or request.POST.get('useragent') or request.POST.get('cookierequest') or request.POST.get('httpstate') or request.POST.get('timeout'):
                timeout_value = request.POST.get('http_timeout')
                useragent = request.POST.get('useragent')
                cookierequest = request.POST.get('cookierequest')
                if cookierequest == None:
                    cookierequest = "false"
                else:
                    cookierequest = "true"

                httpstate = request.POST.get('httpstate')
                if httpstate == None:
                    httpstate = "false"
                else:
                    httpstate = "true"
                timeout = request.POST.get('timeout')

                # print("{} \n{} \n{} \n{} \n{} \n ".format(
                #     timeout_value, useragent, cookierequest, httpstate, timeout))

                # ------------------ Http Timout Api -------------------------

                httptimout = zap.core.set_option_timeout_in_secs(timeout_value)
                defUserAgent = zap.core.set_option_default_user_agent(
                    useragent)
                cookieRequest = zap.core.set_option_single_cookie_request_header(
                    cookierequest)
                httpStateUnable = zap.core.set_option_http_state_enabled(
                    httpstate)
                timeOutSec = zap.core.set_option_timeout_in_secs(timeout)

                if httptimout == "OK" and defUserAgent == "OK" and cookieRequest == "OK" and httpStateUnable == "OK" and timeOutSec == "OK":
                    messages.info(request, "Data Updated Successfully!!")
                    return redirect('generalsetting')
                else:
                    messages.info(
                        request, "Can't Update Data, Please Try Later")

    except:
        pass

 # ----------------------------- generalUPI ------------------------------------


def generalsettingUpi():

    # By default ZAP API client will connect to port 8080
    zap = ZAPv2(apikey=apiKeys)

    # user agent
    defaultUserAgent = zap.core.option_default_user_agent

    # Request Cookies Header

    reqCookHead = zap.core.option_single_cookie_request_header
    if reqCookHead == "false":
        reqCookHead = "disable"
    elif reqCookHead == "true":
        reqCookHead = "checked"

    # Timeout Second
    timeOutSec = zap.core.option_timeout_in_secs

    # Http State
    httpState = zap.core.option_http_state_enabled
    if httpState == "true":
        httpState = 'checked'
    elif httpState == "false":
        httpState = "disable"

    # DNS Timeout
    dnsTime = zap.core.option_dns_ttl_successful_queries

    generalAll = {'defaultUserAgent': defaultUserAgent,
                  'timeOutSec': timeOutSec, 'reqCookHead': reqCookHead, 'httpState': httpState, 'dnsTime': dnsTime}

    return generalAll


# -------------------------------- Fetch Proxy Setting ---------------------

def proxysetting(request):

    return render(request, "vulnerweb/proxySetting.html")


# ------------------------------- Proxy Add ---------------------------------

def proxyadd(request):

    if request.method == "POST":

        if request.POST.get('ip') and request.POST.get('port'):

            try:

                zap = ZAPv2(apikey=apiKeys)
                ip = request.POST.get('ip')
                port = int(request.POST.get('port'))
                print(type(ip))
                print(type(port))

                addProxy = zap.localProxies.add_additional_proxy(
                    address=ip, port=port)

                messages.info(request, "Proxy Added Successfully!!")
                return redirect('proxysetting')

            except:
                messages.info(request, "Can not Add Proxy Please try Later!!")
                return redirect('proxysetting')


def deleteProxy(request):

    if request.method == "POST":

        if request.POST.get('ip') and request.POST.get('port'):

            try:

                zap = ZAPv2(apikey=apiKeys)
                ip = request.POST.get('ip')
                port = request.POST.get('port')

                addProxy = zap.localProxies.remove_additional_proxy(
                    address=ip, port=port)

                messages.info(request, "Proxy Deleted Successfully!!")
                return redirect('proxysetting')

            except:
                messages.info(request, "Can not Add Proxy Please try Later!!")
                return redirect('proxysetting')


# ---------------------------------- Context ----------------------------

def context(request):

    contexts = ContextData.objects.all()
    context_id = 1
    print(contexts)
    for x in contexts:
        context_id = x.con_number
    try:
        AuthAll = zap.authentication.get_authentication_method(context_id)
        logoutData = zap.context.exclude_regexs("Default Context")
        lstt = []

        if AuthAll:
            for o, p in AuthAll.items():
                lstt.append(p)

        pattrn = '={\%(.*?)\%}'
        splitData = re.split(pattrn, lstt[3])
        loginData = lstt[0]
        logoutData = logoutData[0]
        uname = splitData[1]
        passwd = splitData[3]
        authDict = {"login": loginData, 'logout': loginData,
                    'uname': uname, 'passwd': passwd}

    except:
        authDict = {}

    datas = {}
    newdata = []
    forcedata = []
    usr = zap.users.users_list(context_id)
    if usr:
        ab = usr[0]
        for x in usr:
            datas['id'] = x['id']
            datas['name'] = x['name']
            if x['enabled'] == "true":
                datas['enabled'] = "checked"
            else:
                datas['enabled'] = "unchecked"

    newdata.append(datas)

    take = activeContext()
    exclude = excludeContext()

    forceduser = {}

    datta = zap.forcedUser.get_forced_user(context_id)
    usrr = zap.users.get_user_by_id(context_id, datta)
    if usrr:
        ab = usrr[0]
        for x in usr:
            forceduser['name'] = x['name']
            acti = zap.forcedUser.is_forced_user_mode_enabled
            if acti == "true":
                forceduser['enabled'] = "checked"
            else:
                forceduser['enabled'] = "unchecked"

    if forceduser:
        forcedata.append(forceduser)

    checked = list([y, "checked"] for y in take)
    unchecked = list([x, "unchecked"] for x in exclude)

    tot = checked + unchecked

    db = []
    lan = []
    oss = []
    ws = []
    scm = []

    for x in tot:
        try:
            if x[0].split('.')[0] == "Db":
                db.append([x[0].split('.')[1], x[1]])

            elif x[0].split('.')[0] == "Language":

                lan.append([x[0].split('.')[1], x[1]])

            elif x[0].split('.')[0] == "OS":

                oss.append([x[0].split('.')[1], x[1]])

            elif x[0].split('.')[0] == "WS":

                ws.append([x[0].split('.')[1], x[1]])

            elif x[0].split('.')[0] == "SCM":

                scm.append([x[0].split('.')[1], x[1]])

        except:
            pass

    dicto = {'db': db, 'lan': lan, 'oss': oss,
             'ws': ws, 'scm': scm, 'newdata': newdata, 'forcedata': forcedata, 'authDict': authDict}

    return render(request, "vulnerweb/context.html", dicto)


# --------------------- Update Context ---------------------------------


def updateContext(request):

    take = activeContext()
    db = []
    lan = []
    oss = []
    scm = []
    ws = []
    for x in take:
        try:

            if x.rsplit('.')[0] == 'Db':

                db.append(x)

            elif x.rsplit('.')[0] == 'Language':

                lan.append(x)

            elif x.rsplit('.')[0] == 'OS':

                oss.append(x)

            elif x.rsplit('.')[0] == "WS":

                ws.append(x)

            elif x.rsplit('.')[0] == "SCM":

                ws.append(x)

        except:
            pass

    if request.method == "POST":

        zap = ZAPv2(apikey=apiKeys)

        # DB value check and Uncheck

        check_selected_db = request.POST.getlist('Db')
        print(check_selected_db)
        list_difference = [
            item for item in db if item not in check_selected_db]
        print(list_difference)
        if list_difference:
            for x in list_difference:
                exclude = zap.context.exclude_context_technologies(
                    contextname="Default Context", technologynames=x)
                if exclude == "OK":
                    pass
                else:
                    break
        if check_selected_db:
            for x in check_selected_db:
                exclude = zap.context.include_context_technologies(
                    contextname="Default Context", technologynames=x)
                if exclude == "OK":
                    pass
                else:
                    break

        else:
            pass

        # Language Data

        check_selected_lan = request.POST.getlist('Language')

        list_difference_1 = [
            item for item in lan if item not in check_selected_lan]

        if list_difference_1:
            for x in list_difference_1:
                exclude_1 = zap.context.exclude_context_technologies(
                    contextname="Default Context", technologynames=x)
                if exclude_1 == "OK":
                    pass
                else:
                    break
        if check_selected_lan:
            for x in check_selected_lan:
                exclude_1 = zap.context.include_context_technologies(
                    contextname="Default Context", technologynames=x)
                if exclude_1 == "OK":
                    pass
                else:
                    break

        # Operating System

        check_selected_os = request.POST.getlist('OS')

        list_difference_2 = [
            item for item in oss if item not in check_selected_os]

        if list_difference_2:
            for x in list_difference_2:
                exclude_2 = zap.context.exclude_context_technologies(
                    contextname="Default Context", technologynames=x)
                if exclude_2 == "OK":
                    pass
                else:
                    break
        if check_selected_os:
            for x in check_selected_os:
                exclude_2 = zap.context.include_context_technologies(
                    contextname="Default Context", technologynames=x)
                if exclude_2 == "OK":
                    pass
                else:
                    break

        # Web Socket

        check_selected_ws = request.POST.getlist('WS')

        list_difference_3 = [
            item for item in ws if item not in check_selected_ws]

        print(list_difference_3)
        if list_difference_3:
            for x in list_difference_3:
                exclude_3 = zap.context.exclude_context_technologies(
                    contextname="Default Context", technologynames=x)
                if exclude_3 == "OK":
                    pass
                else:
                    break
        if check_selected_ws:
            for x in check_selected_ws:
                exclude_3 = zap.context.include_context_technologies(
                    contextname="Default Context", technologynames=x)
                if exclude_3 == "OK":
                    pass
                else:
                    break

        # Source Code Management

        check_selected_scm = request.POST.getlist('SCM')

        list_difference_4 = [
            item for item in scm if item not in check_selected_scm]

        print(list_difference_4)
        if list_difference_4:
            for x in list_difference_4:
                exclude_4 = zap.context.exclude_context_technologies(
                    contextname="Default Context", technologynames=x)
                if exclude_4 == "OK":
                    pass
                else:
                    break
        if check_selected_scm:
            for x in check_selected_scm:
                exclude_4 = zap.context.include_context_technologies(
                    contextname="Default Context", technologynames=x)
                if exclude_4 == "OK":
                    pass
                else:
                    break

    return redirect('context')


# ---------------------------- Find all Active Context -----------------

def activeContext():

    zap = ZAPv2(apikey=apiKeys)

    contextDetails = zap.context.included_technology_list(
        contextname="Default Context")

    return contextDetails


# ---------------------------- Find all InActive Context -----------------

def excludeContext():

    zap = ZAPv2(apikey=apiKeys)

    contextDetails = zap.context.excluded_technology_list(
        contextname="Default Context")

    return contextDetails


# ---------------------------- Authentications ------------------------------


def authSetting(request):

    contexts = ContextData.objects.all()
    for x in contexts:
        context_id = x.con_number
    if request.method == "POST":
        if request.POST.get('domainname') and request.POST.get('usernameclass') and request.POST.get('passwordclass'):

            # POST DATA
            domain = request.POST.get('domainname')
            exclude_url = request.POST.get('logoutDomain')
            username = request.POST.get('usernameclass')
            pwdclass = request.POST.get('passwordclass')
            loginMsg = request.POST.get('loginmsg')
            logoutMsg = request.POST.get('logoutmsg')
            logoutregex = request.POST.get('anchorlogout')

            try:
                # Base Urls with Star(*)
                base_url = "{0.scheme}://{0.netloc}".format(us(domain))
                include_url = "{}.*".format(base_url)

                # Login Data Passes in Urls
                login_request_data = 'username={%' + \
                    username+'%}&password={%'+pwdclass+'%}'

                # Full Urls Pass to the Scannner
                form_based_config = 'loginUrl=' + domain + \
                    '&loginRequestData=' + \
                    urllib.parse.quote(login_request_data)

                # set_include_in_context
                if include_url and exclude_url:
                    zap.context.include_in_context(
                        "Default Context", include_url)
                    zap.context.exclude_from_context(
                        "Default Context", exclude_url)

                # logged_in_regex
                logged_in_regex = '\Q{}\E'.format(logoutregex)

                zap.authentication.set_logged_in_indicator(
                    context_id, logged_in_regex)

                # set_form_based_auth

                zap.authentication.set_authentication_method(
                    context_id, 'formBasedAuthentication', form_based_config)

                messages.info(request, "Updated Successfully!!")

            except:
                messages.info(request, "Somthing Went Wrong")

    return redirect('context')


# ------------------------ Create User ---------------------------------

def createUser(request):

    contexts = ContextData.objects.all()
    for x in contexts:
        context_id = x.con_number

    if request.method == "POST":
        if request.POST.get('user') and request.POST.get('uname') and request.POST.get('pass'):

            # Variables

            user = request.POST.get('user')
            username = request.POST.get('uname')
            password = request.POST.get('pass')
            active = request.POST.get('active')
            user_id = zap.users.new_user(context_id, user)
            user_auth_config = 'username=' + \
                urllib.parse.quote(username) + '&password=' + \
                urllib.parse.quote(password)
            zap.users.set_authentication_credentials(
                context_id, user_id, user_auth_config)
            if active == None:
                zap.users.set_user_enabled(context_id, user_id, 'false')

            else:
                zap.users.set_user_enabled(context_id, user_id, 'true')

            zap.forcedUser.set_forced_user(context_id, user_id)
            zap.forcedUser.set_forced_user_mode_enabled('true')
            messages.info(request, "User Created Successfully!!")
            return redirect('context')

    return render(request, "vulnerweb/context.html")


# ----------------------------- Delete Context User -----------------------

def deleteuser(request, pk):

    contexts = ContextData.objects.all()
    for x in contexts:
        context_id = x.con_number

    if pk:
        delete = zap.users.remove_user(context_id, pk)
        if delete:
            messages.info(request, "Deleted User Successfully")
            return redirect('context')

        else:
            messages.info(
                request, "Somthing Went Wrong Please Try Again Latter")
            return redirect('context')

    return redirect('context')


# ----------------------------- Context Reset -----------------------------

def resetContext(request):
    try:
        context_name = "Default Context"
        reset = zap.context.remove_context(context_name)
        if reset == "OK":

            newContext()
            messages.info(request, "Context Reset Successfully ")
            return redirect('context')

    except:
        messages.info(request, "Somthing Went Wrong While Resetting Context")
        return redirect('context')


# ------------------------------ Active Forced User --------------------------


def activeForceUser(request):
    zap.forcedUser.set_forced_user_mode_enabled("true")
    messages.info(request, "Forced User Enabled Successfully")
    return redirect("context")


# ------------------------------- Anti CSRF Tokens ---------------------------


def antiCsrf(request):

    try:
        default_com = ['__RequestVerificationToken', 'csrfSecret', 'anoncsrf', 'anticsrf',
                       'authenticity_token', 'csrf_token', 'csrfmiddlewaretoken', 'CSRFToken', '_csrf', '_csrfSecret']
        default_token = []
        user_token = []
        data = zap.acsrf.option_tokens_names
        for x in data:
            if not x == "OWASP_CSRFTOKEN" and x in default_com:
                default_token.append(x)
            elif not x == "OWASP_CSRFTOKEN":
                user_token.append(x)
            else:
                pass

        dic = {'default': default_token, 'usercsrf': user_token}

        return render(request, 'vulnerweb/anticsrf.html', dic)
    except:
        pass


# -------------------------------- Add Csrf Token ------------------


def addcsrf(request):
    try:
        if request.method == "POST":

            if request.POST.get('csrf'):
                strings = request.POST.get('csrf')
                add = zap.acsrf.add_option_token(strings)
                if add == "OK":
                    messages.info(request, "Csrf Token Added Successfully!!")
                    return redirect('anticsrf')

    except:

        messages.info(request, "Somthing Went Wrong")
        return redirect('anticsrf')


# -------------------------------- Delete Csrf Token ------------------


def deletecsrf(request, name):

    try:
        zap.acsrf.remove_option_token(name)
        messages.info(request, "Csrf Token Deleted Successfully!!")
        return redirect('anticsrf')
    except:
        messages.info(request, "Somthing Went Wrong")
        return redirect('anticsrf')


# **************************** End General Setting ****************************


# **************************** Start Passive Scan Setting ***********************

# ------------------------------------ PAssive Scan Rule ---------------------------
def passivescan(request):

    try:
        data = zap.pscan.scanners
        dic = {'data': data}

        return render(request, 'vulnerweb/passivescan.html', dic)
    except:

        return redirect('passivescan')


# --------------------------------- Passive Scan Rule Update -------------------------

def spiderRule(request):

    try:

        maxDept = zap.spider.option_max_depth
        maxConcurrent = zap.spider.option_thread_count
        maxDuration = zap.spider.option_max_duration
        maxChildren = zap.spider.option_max_children
        maxParse = zap.spider.option_max_parse_size_bytes
        referHeader = zap.spider.option_send_referer_header
        if referHeader == "true":
            referHeader1 = "checked"
        else:
            referHeader1 = "unchecked"
        acceptCookies = zap.spider.option_accept_cookies
        if acceptCookies == "true":
            acceptCookies1 = "checked"
        else:
            acceptCookies1 = "unchecked"
        processForm = zap.spider.option_process_form
        if processForm == "true":
            processForm1 = "checked"
        else:
            processForm1 = "unchecked"
        postForm = zap.spider.option_post_form
        if postForm == "true":
            postForm1 = "checked"
        else:
            postForm1 = "unchecked"
        parseComment = zap.spider.option_parse_comments
        if parseComment == "true":
            parseComment1 = "checked"
        else:
            parseComment1 = "unchecked"
        parseRobot = zap.spider.option_parse_robots_txt
        if parseRobot == "true":
            parseRobot1 = "checked"
        else:
            parseRobot1 = "unchecked"
        parseSiteMap = zap.spider.option_parse_sitemap_xml
        if parseSiteMap == "true":
            parseSiteMap1 = "checked"
        else:
            parseSiteMap1 = "unchecked"
        svnEntries = zap.spider.option_parse_svn_entries

        if svnEntries == "true":
            svnEntries1 = "checked"
        else:
            svnEntries1 = "unchecked"

        parseGit = zap.spider.option_parse_git
        if parseGit == "true":
            parseGit1 = "checked"
        else:
            parseGit1 = "unchecked"
        handleO_data = zap.spider.option_handle_o_data_parameters_visited
        if handleO_data == "true":
            handleO_data1 = "checked"
        else:
            handleO_data1 = "unchecked"

        dic = {'maxDept': maxDept, 'maxConcurrent': maxConcurrent,
               'maxDuration': maxDuration, 'maxChildren': maxChildren, 'maxParse': maxParse, 'referHeader1': referHeader1, 'acceptCookies1': acceptCookies1, 'processForm1': processForm1, 'postForm1': postForm1, 'parseComment1': parseComment1, 'parseRobot1': parseRobot1, 'parseSiteMap1': parseSiteMap1, 'svnEntries1': svnEntries1, 'parseGit1': parseGit1, 'handleO_data1': handleO_data1}

        return render(request, 'vulnerweb/spider.html', dic)

    except Exception as e:
        print('Somthing Went Wrong {}'.format(e))
        return redirect('spiderRule')


# ----------------------------------- Update Spider Rules ----------------------

def updatespider(request):

    if request.method == "POST":
        if request.POST.get('maxDept') and request.POST.get('maxConcurrent') and request.POST.get('maxDuration') and request.POST.get('maxChildren') and request.POST.get('maxParse'):

            maxDept = request.POST.get('maxDept')
            maxConcurrent = request.POST.get('maxConcurrent')
            maxDuration = request.POST.get('maxDuration')
            maxChildren = request.POST.get('maxChildren')
            maxParse = request.POST.get('maxParse')
            referHeader = request.POST.get('referHeader')
            acceptCookies = request.POST.get('acceptCookies')
            processForm = request.POST.get('processForm')
            postForm = request.POST.get('postForm')
            parseComment = request.POST.get('parseComment')
            parseRobot = request.POST.get('parseRobot')
            parseSiteMap = request.POST.get('parseSiteMap')
            svnEntries = request.POST.get('svnEntries')
            parseGit = request.POST.get('parseGit')
            handleO_data = request.POST.get('handleO_data')

            # Set Max Depth
            zap.spider.set_option_max_depth(maxDept)
            # Set Max Thread
            zap.spider.set_option_thread_count(maxConcurrent)
            # Set Max Durations
            zap.spider.set_option_max_duration(maxDuration)
            # Set Child Crwal
            zap.spider.set_option_max_children(maxChildren)
            # Set Max Parse
            zap.spider.set_option_max_parse_size_bytes(maxParse)

            if referHeader == None:
                referHeader1 = "false"
                zap.spider.set_option_send_referer_header(referHeader1)

            else:
                referHeader1 = "true"
                zap.spider.set_option_send_referer_header(referHeader1)

            if acceptCookies == None:
                acceptCookies1 = "false"
                zap.spider.set_option_accept_cookies(acceptCookies1)
            else:
                acceptCookies1 = "true"
                zap.spider.set_option_accept_cookies(acceptCookies1)

            if processForm == None:
                processForm1 = "false"
                zap.spider.set_option_process_form(processForm1)
            else:
                processForm1 = "true"
                zap.spider.set_option_process_form(processForm1)

            if postForm == None:
                postForm1 = "false"
                zap.spider.set_option_post_form(postForm1)
            else:
                postForm1 = "true"
                zap.spider.set_option_post_form(postForm1)

            if parseComment == None:
                parseComment1 = "false"
                zap.spider.set_option_parse_comments(parseComment1)
            else:
                parseComment1 = "true"
                zap.spider.set_option_parse_comments(parseComment1)

            if parseRobot == None:
                parseRobot1 = "false"
                zap.spider.set_option_parse_robots_txt(parseRobot1)
            else:
                parseRobot1 = "true"
                zap.spider.set_option_parse_robots_txt(parseRobot1)

            if parseSiteMap == None:
                parseSiteMap1 = "false"
                zap.spider.set_option_parse_sitemap_xml(parseSiteMap1)
            else:
                parseSiteMap1 = "true"
                zap.spider.set_option_parse_sitemap_xml(parseSiteMap1)

            if svnEntries == None:
                svnEntries1 = "false"
                zap.spider.set_option_parse_svn_entries(svnEntries1)
            else:
                svnEntries1 = "true"
                zap.spider.set_option_parse_svn_entries(svnEntries1)

            if parseGit == None:
                parseGit1 = "false"
                zap.spider.set_option_parse_git(parseGit1)
            else:
                parseGit1 = "true"
                zap.spider.set_option_parse_git(parseGit1)

            if handleO_data == None:
                handleO_data1 = "false"
                zap.spider.set_option_handle_o_data_parameters_visited(
                    handleO_data1)
            else:
                handleO_data1 = "true"
                zap.spider.set_option_handle_o_data_parameters_visited(
                    handleO_data1)

            return redirect('spiderRule')

# **************************** End Passive Scan Setting *************************


# **************************** Start Active Scan  *************************


# ---------------------------------- Active Scan Policy -----------------------------

def activescanpolicies(request):

    policy = "Default Policy"

    information = zap.ascan.scanners(policy, 0)
    server = zap.ascan.scanners(policy, 2)
    Miscellaneous = zap.ascan.scanners(policy, 3)
    Injection = zap.ascan.scanners(policy, 4)

    dic = {'information': information, 'server': server,
           'Miscellaneous': Miscellaneous, 'Injection': Injection}
    return render(request, 'vulnerweb/activescanpolicy.html', dic)


# ----------------------------------- Active Scan Setting -----------------------------

def activescansetting(request):

    conScan = zap.ascan.option_host_per_scan
    threadHost = zap.ascan.option_thread_per_host
    maxResultList = zap.ascan.option_max_results_to_list
    maxRuleDuration = zap.ascan.option_max_rule_duration_in_mins
    maxScanDuration = zap.ascan.option_max_scan_duration_in_mins
    delayTime = zap.ascan.option_delay_in_ms
    injectionPlugin = zap.ascan.option_inject_plugin_id_in_header
    if injectionPlugin == "true":
        injectionPlugin = "checked"
    else:
        injectionPlugin = "unchecked"

    Csrf = zap.ascan.option_handle_anti_csrf_tokens
    if Csrf == "true":
        Csrf = "checked"
    else:
        Csrf = "unchecked"
    defaulPolicy = zap.ascan.option_default_policy
    attackPolicy = zap.ascan.option_attack_policy

    try:
        if request.method == "POST":
            if request.POST.get('conScan') and request.POST.get('threadHost') and request.POST.get('maxResultList') and request.POST.get('maxRuleDuration') and request.POST.get('delayTime'):

                conSn = request.POST.get('conScan')
                thread = request.POST.get('threadHost')
                mxresult = request.POST.get('maxResultList')
                mxRule = request.POST.get('maxRuleDuration')
                mxScan = request.POST.get('maxScanDuration')
                delay = request.POST.get('delayTime')
                injection = request.POST.get('inject')
                csrfs = request.POST.get('csrf')

                zap.ascan.set_option_host_per_scan(conSn)
                zap.ascan.set_option_thread_per_host(thread)
                zap.ascan.set_option_max_results_to_list(mxresult)
                zap.ascan.set_option_max_rule_duration_in_mins(mxRule)
                zap.ascan.set_option_max_scan_duration_in_mins(mxScan)
                zap.ascan.set_option_delay_in_ms(delay)
                print(injection)
                if injection == None:
                    status = "false"
                    zap.ascan.set_option_inject_plugin_id_in_header(status)
                else:
                    status = "true"
                    zap.ascan.set_option_inject_plugin_id_in_header(status)

                if csrfs == None:
                    status1 = "false"
                    zap.ascan.set_option_handle_anti_csrf_tokens(status1)

                else:
                    status1 = "true"
                    zap.ascan.set_option_handle_anti_csrf_tokens(status1)

                messages.info(request, "Data Updated Successfully!!")
                return redirect('activescansetting')

    except:
        pass

    dic = {'conScan': conScan, 'threadHost': threadHost, 'maxResultList': maxResultList,
           'maxRuleDuration': maxRuleDuration, 'maxScanDuration': maxScanDuration, 'delayTime': delayTime, 'injectionPlugin': injectionPlugin, 'Csrf': Csrf, 'defaulPolicy': defaulPolicy, 'attackPolicy': attackPolicy}

    return render(request, 'vulnerweb/activescansetting.html', dic)


# ------------------------------------ Passive input ----------------------------------


def activeinput(request):

    # Inject Target Data
    injectTarget = zap.ascan.option_target_params_injectable
    # 1
    if injectTarget == "1":
        injectData = {'queryString': 'checked', 'postData': 'unchecked',
                      'cookies': 'unchecked', 'http': 'unchecked', 'url': 'unchecked'}
    # 2
    elif injectTarget == '2':
        injectData = {'queryString': 'unchecked', 'postData': 'checked',
                      'cookies': 'unchecked', 'http': 'unchecked', 'url': 'unchecked'}

    # 4
    elif injectTarget == '4':
        injectData = {'queryString': 'unchecked', 'postData': 'unchecked',
                      'cookies': 'checked', 'http': 'unchecked', 'url': 'unchecked'}

    # 8
    elif injectTarget == '8':
        injectData = {'queryString': 'unchecked', 'postData': 'unchecked',
                      'cookies': 'unchecked', 'http': 'checked', 'url': 'unchecked'}

    # 16
    elif injectTarget == '16':
        injectData = {'queryString': 'unchecked', 'postData': 'unchecked',
                      'cookies': 'unchecked', 'http': 'unchecked', 'url': 'checked'}

    elif injectTarget == '3':
        injectData = {'queryString': 'checked', 'postData': 'checked',
                      'cookies': 'unchecked', 'http': 'unchecked', 'url': 'unchecked'}

    elif injectTarget == '5':
        injectData = {'queryString': 'checked', 'postData': 'unchecked',
                      'cookies': 'checked', 'http': 'unchecked', 'url': 'unchecked'}

    elif injectTarget == '6':
        injectData = {'queryString': 'unchecked', 'postData': 'checked',
                      'cookies': 'checked', 'http': 'unchecked', 'url': 'unchecked'}

    elif injectTarget == '7':
        injectData = {'queryString': 'checked', 'postData': 'checked',
                      'cookies': 'checked', 'http': 'unchecked', 'url': 'unchecked'}

    elif injectTarget == '9':
        injectData = {'queryString': 'checked', 'postData': 'unchecked',
                      'cookies': 'unchecked', 'http': 'checked', 'url': 'unchecked'}

    elif injectTarget == '10':
        injectData = {'queryString': 'unchecked', 'postData': 'checked',
                      'cookies': 'unchecked', 'http': 'checked', 'url': 'unchecked'}

    elif injectTarget == '11':
        injectData = {'queryString': 'checked', 'postData': 'checked',
                      'cookies': 'unchecked', 'http': 'checked', 'url': 'unchecked'}

    elif injectTarget == '12':
        injectData = {'queryString': 'unchecked', 'postData': 'unchecked',
                      'cookies': 'checked', 'http': 'checked', 'url': 'unchecked'}

    elif injectTarget == '13':
        injectData = {'queryString': 'checked', 'postData': 'unchecked',
                      'cookies': 'checked', 'http': 'checked', 'url': 'unchecked'}

    elif injectTarget == '14':
        injectData = {'queryString': 'unchecked', 'postData': 'checked',
                      'cookies': 'checked', 'http': 'checked', 'url': 'unchecked'}

    elif injectTarget == '15':
        injectData = {'queryString': 'checked', 'postData': 'checked',
                      'cookies': 'checked', 'http': 'checked', 'url': 'unchecked'}

    elif injectTarget == '17':
        injectData = {'queryString': 'checked', 'postData': 'unchecked',
                      'cookies': 'unchecked', 'http': 'unchecked', 'url': 'checked'}

    elif injectTarget == '18':
        injectData = {'queryString': 'unchecked', 'postData': 'checked',
                      'cookies': 'unchecked', 'http': 'unchecked', 'url': 'checked'}

    elif injectTarget == '19':
        injectData = {'queryString': 'checked', 'postData': 'checked',
                      'cookies': 'unchecked', 'http': 'unchecked', 'url': 'checked'}

    elif injectTarget == '20':
        injectData = {'queryString': 'unchecked', 'postData': 'unchecked',
                      'cookies': 'checked', 'http': 'unchecked', 'url': 'checked'}

    elif injectTarget == '21':
        injectData = {'queryString': 'checked', 'postData': 'unchecked',
                      'cookies': 'checked', 'http': 'unchecked', 'url': 'checked'}

    elif injectTarget == '22':
        injectData = {'queryString': 'unchecked', 'postData': 'checked',
                      'cookies': 'checked', 'http': 'unchecked', 'url': 'checked'}

    elif injectTarget == '23':
        injectData = {'queryString': 'checked', 'postData': 'checked',
                      'cookies': 'checked', 'http': 'unchecked', 'url': 'checked'}

    elif injectTarget == '24':
        injectData = {'queryString': 'unchecked', 'postData': 'unchecked',
                      'cookies': 'unchecked', 'http': 'checked', 'url': 'checked'}

    elif injectTarget == '25':
        injectData = {'queryString': 'checked', 'postData': 'unchecked',
                      'cookies': 'unchecked', 'http': 'checked', 'url': 'checked'}

    elif injectTarget == '26':
        injectData = {'queryString': 'unchecked', 'postData': 'checked',
                      'cookies': 'unchecked', 'http': 'checked', 'url': 'checked'}

    elif injectTarget == '27':
        injectData = {'queryString': 'checked', 'postData': 'checked',
                      'cookies': 'unchecked', 'http': 'checked', 'url': 'checked'}

    elif injectTarget == '28':
        injectData = {'queryString': 'unchecked', 'postData': 'unchecked',
                      'cookies': 'checked', 'http': 'checked', 'url': 'checked'}

    elif injectTarget == '29':
        injectData = {'queryString': 'checked', 'postData': 'unchecked',
                      'cookies': 'unchecked', 'http': 'checked', 'url': 'checked'}

    elif injectTarget == '30':
        injectData = {'queryString': 'unchecked', 'postData': 'checked',
                      'cookies': 'checked', 'http': 'checked', 'url': 'checked'}
    elif injectTarget == '31':
        injectData = {'queryString': 'checked', 'postData': 'checked',
                      'cookies': 'checked', 'http': 'checked', 'url': 'checked'}

    # Input Vector Handler

    inputhandler = zap.ascan.option_target_params_enabled_rpc
    if int(inputhandler) > 31:
        newdata = int(inputhandler) - 128 - 32
    else:
        newdata = int(inputhandler)

    if newdata == 1:
        inputhandler1 = {'multidata': 'checked', 'xml': 'unchecked',
                         'json': 'unchecked', 'toolkit': 'unchecked', 'odata': 'unchecked'}
    # 2
    elif newdata == 2:
        inputhandler1 = {'multidata': 'unchecked', 'xml': 'checked',
                         'json': 'unchecked', 'toolkit': 'unchecked', 'odata': 'unchecked'}

    # 4
    elif newdata == 4:
        inputhandler1 = {'multidata': 'unchecked', 'xml': 'unchecked',
                         'json': 'checked', 'toolkit': 'unchecked', 'odata': 'unchecked'}

    # 8
    elif newdata == 8:
        inputhandler1 = {'multidata': 'unchecked', 'xml': 'unchecked',
                         'json': 'unchecked', 'toolkit': 'checked', 'odata': 'unchecked'}

    # 16
    elif newdata == 16:
        inputhandler1 = {'multidata': 'unchecked', 'xml': 'unchecked',
                         'json': 'unchecked', 'toolkit': 'unchecked', 'odata': 'checked'}

    elif newdata == 3:
        inputhandler1 = {'multidata': 'checked', 'xml': 'checked',
                         'json': 'unchecked', 'toolkit': 'unchecked', 'odata': 'unchecked'}

    elif newdata == 5:
        inputhandler1 = {'multidata': 'checked', 'xml': 'unchecked',
                         'json': 'checked', 'toolkit': 'unchecked', 'odata': 'unchecked'}

    elif newdata == 6:
        inputhandler1 = {'multidata': 'unchecked', 'xml': 'checked',
                         'json': 'checked', 'toolkit': 'unchecked', 'odata': 'unchecked'}

    elif newdata == 7:
        inputhandler1 = {'multidata': 'checked', 'xml': 'checked',
                         'json': 'checked', 'toolkit': 'unchecked', 'odata': 'unchecked'}

    elif newdata == 9:
        inputhandler1 = {'multidata': 'checked', 'xml': 'unchecked',
                         'json': 'unchecked', 'toolkit': 'checked', 'odata': 'unchecked'}

    elif newdata == 10:
        inputhandler1 = {'multidata': 'unchecked', 'xml': 'checked',
                         'json': 'unchecked', 'toolkit': 'checked', 'odata': 'unchecked'}

    elif newdata == 11:
        inputhandler1 = {'multidata': 'checked', 'xml': 'checked',
                         'json': 'unchecked', 'toolkit': 'checked', 'odata': 'unchecked'}

    elif newdata == 12:
        inputhandler1 = {'multidata': 'unchecked', 'xml': 'unchecked',
                         'json': 'checked', 'toolkit': 'checked', 'odata': 'unchecked'}

    elif newdata == 13:
        inputhandler1 = {'multidata': 'checked', 'xml': 'unchecked',
                         'json': 'checked', 'toolkit': 'checked', 'odata': 'unchecked'}

    elif newdata == 14:
        inputhandler1 = {'multidata': 'unchecked', 'xml': 'checked',
                         'json': 'checked', 'toolkit': 'checked', 'odata': 'unchecked'}

    elif newdata == 15:
        inputhandler1 = {'multidata': 'checked', 'xml': 'checked',
                         'json': 'checked', 'toolkit': 'checked', 'odata': 'unchecked'}

    elif newdata == 17:
        inputhandler1 = {'multidata': 'checked', 'xml': 'unchecked',
                         'json': 'unchecked', 'toolkit': 'unchecked', 'odata': 'checked'}

    elif newdata == 18:
        inputhandler1 = {'multidata': 'unchecked', 'xml': 'checked',
                         'json': 'unchecked', 'toolkit': 'unchecked', 'odata': 'checked'}

    elif newdata == 19:
        inputhandler1 = {'multidata': 'checked', 'xml': 'checked',
                         'json': 'unchecked', 'toolkit': 'unchecked', 'odata': 'checked'}

    elif newdata == 20:
        inputhandler1 = {'multidata': 'unchecked', 'xml': 'unchecked',
                         'json': 'checked', 'toolkit': 'unchecked', 'odata': 'checked'}

    elif newdata == 21:
        inputhandler1 = {'multidata': 'checked', 'xml': 'unchecked',
                         'json': 'checked', 'toolkit': 'unchecked', 'odata': 'checked'}

    elif newdata == 22:
        inputhandler1 = {'multidata': 'unchecked', 'xml': 'checked',
                         'json': 'checked', 'toolkit': 'unchecked', 'odata': 'checked'}

    elif newdata == 23:
        inputhandler1 = {'multidata': 'checked', 'xml': 'checked',
                         'json': 'checked', 'toolkit': 'unchecked', 'odata': 'checked'}

    elif newdata == 24:
        inputhandler1 = {'multidata': 'unchecked', 'xml': 'unchecked',
                         'json': 'unchecked', 'toolkit': 'checked', 'odata': 'checked'}

    elif newdata == 25:
        inputhandler1 = {'multidata': 'checked', 'xml': 'unchecked',
                         'json': 'unchecked', 'toolkit': 'checked', 'odata': 'checked'}

    elif newdata == 26:
        inputhandler1 = {'multidata': 'unchecked', 'xml': 'checked',
                         'json': 'unchecked', 'toolkit': 'checked', 'odata': 'checked'}

    elif newdata == 27:
        inputhandler1 = {'multidata': 'checked', 'xml': 'checked',
                         'json': 'unchecked', 'toolkit': 'checked', 'odata': 'checked'}

    elif newdata == 28:
        inputhandler1 = {'multidata': 'unchecked', 'xml': 'unchecked',
                         'json': 'checked', 'toolkit': 'checked', 'odata': 'checked'}

    elif newdata == 29:
        inputhandler1 = {'multidata': 'checked', 'xml': 'unchecked',
                         'json': 'unchecked', 'toolkit': 'checked', 'odata': 'checked'}

    elif newdata == 30:
        inputhandler1 = {'multidata': 'unchecked', 'xml': 'checked',
                         'json': 'checked', 'toolkit': 'checked', 'odata': 'checked'}
    elif newdata == 31:
        inputhandler1 = {'multidata': 'checked', 'xml': 'checked',
                         'json': 'checked', 'toolkit': 'checked', 'odata': 'checked'}

    excludesend = []
    userexclude = []
    defaultexclude = ['(?i)ASP.NET_SessionId', '(?i)ASPSESSIONID.*', '(?i)PHPSESSID', '(?i)SITESERVER', '(?i)sessid', '__VIEWSTATE',
                      '__EVENTVALIDATION', '__EVENTTARGET', '__EVENTARGUMENT', 'javax.faces.ViewState', '(?i)jsessionid', 'cfid', 'cftoken']
    excludedata = zap.ascan.option_excluded_param_list
    for x in excludedata:
        if x['parameter'] in defaultexclude:
            excludesend.append(
                {'name': x['parameter'], 'id': x['idx'], 'url': x['url'], 'location': x['type']['name']})
        else:
            userexclude.append(
                {'name': x['parameter'], 'id': x['idx'], 'url': x['url'], 'location': x['type']['name']})

    dic = {'excludesend': excludesend, 'injectData': injectData,
           'inputhandler1': inputhandler1, 'userexclude': userexclude}

    return render(request, "vulnerweb/activeinput.html", dic)


# **************************** End Active Scan Setting *************************


# ----------------------------- Update Injectable Target ----------------------

def updateinjectable(request):

    # ------- POST DATA -----------

    if request.method == "POST":
        insertData = 0

        queryString = request.POST.get('queryString')
        if queryString == None:
            pass
        else:
            insertData += 1

        postData = request.POST.get('postData')
        if postData == None:
            pass
        else:
            insertData += 2

        cookies = request.POST.get('cookies')
        if cookies == None:
            pass
        else:
            insertData += 4

        http = request.POST.get('http')
        if http == None:
            pass
        else:
            insertData += 8

        url = request.POST.get('url')
        if url == None:
            pass
        else:
            insertData += 16

        if insertData:
            zap.ascan.set_option_target_params_injectable(insertData)
            messages.info(request, "Updated Successfully!!")
            return redirect('activeinput')
        else:
            messages.info(request, "Somthing Went Wrong")
            return redirect('activeinput')

# ----------------------------- Update Injectable Target ----------------------


def updateInput(request):

    # ------- POST DATA -----------

    if request.method == "POST":
        insertData = 0

        queryString = request.POST.get('multidata')
        if queryString == None:
            pass
        else:
            insertData += 1

        postData = request.POST.get('xml')
        if postData == None:
            pass
        else:
            insertData += 2

        cookies = request.POST.get('json')
        if cookies == None:
            pass
        else:
            insertData += 4

        http = request.POST.get('toolkit')
        if http == None:
            pass
        else:
            insertData += 8

        url = request.POST.get('odata')
        if url == None:
            pass
        else:
            insertData += 16

        if insertData:
            zap.ascan.set_option_target_params_enabled_rpc(insertData)
            messages.info(request, "Updated Successfully!!")
            return redirect('activeinput')
        else:
            messages.info(request, "Somthing Went Wrong")
            return redirect('activeinput')


def addexclude(request):

    if request.method == "POST":
        if request.POST.get('name') and request.POST.get('url') and request.POST.get('location'):
            name = request.POST.get('name')
            url = request.POST.get('url')
            location = request.POST.get('location')
            print(name, url, location)
            final = zap.ascan.add_excluded_param(name, location, url)
            if final:
                messages.info(request, "Data Added Successfully!!")
                return redirect('activeinput')
            else:
                messages.info(request, "Somthing Went Wrong")
                return redirect('activeinput')


# --------------------------------- Delete Exclude ------------------------------

def deleteeclude(request, pk):

    zap.ascan.remove_excluded_param(pk)
    messages.info(request, "Deleeted Successfully")
    return redirect('activeinput')


# ====================================== License ====================================

def license(request):
    from datetime import date
    # Count total Domain Scanned(for License Perpose)
    scantotal = ScanData.objects.order_by(
        'domain').values('domain').distinct().count()
    today = date.today()
    d4 = today.strftime("%d-%b-%Y")
    dic = {'date': d4, 'hosts': scantotal}
    return render(request, 'vulnerweb/license.html', dic)


# --------------------------------- Logout -----------------------------------

def logout(request):

    auth.logout(request)
    return redirect('/')
