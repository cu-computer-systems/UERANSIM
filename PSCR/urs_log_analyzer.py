#!/usr/bin/env python3
"""urs_log_analyzer.py"""

import sys
import json
from collections import OrderedDict


procedure_list = [
    'sendInitialRegistrationRequest', 
    'receiveAuthenticationRequest', 
    'sendAuthenticationResponse', 
    'receiveSecurityModeCommand', 
    'sendSecurityModeComplete', 
    'receiveInitialContextSetupRequest(+RegistrationAccept)', 
    'sendInitialContextSetupResponse', 
    'sendRegistrationComplete', 
    'sendPDUSessionEstablishmentRequest',
    'receivePDUSessionResourceSetupRequest(+EstablishmentAccept)',
    'sendPDUSessionResourceSetupResponse',
    'receiveConfigurationUpdateCommand',
    'sendConfigurationUpdateComplete',
    'sendContextReleaseRequest', 
    'receiveContextReleaseCommand', 
    'sendContextReleaseComplete'
]
proc_duration_by_name_dict = OrderedDict()


def init_ue_info(ue_info_by_imsi_dict, first_imsi, ue_num):
    for i in range(0, ue_num):
        ue_imsi = first_imsi + i
        ue_info_by_imsi_dict[ue_imsi] = {
            'ueid': 0, 
            'uetoken': 0, 
            'gnbtoken': 0, 
            'sendInitialRegistrationRequest': {'start': 0, 'end': 0, 'duration': 0}, 
            'receiveAuthenticationRequest': {'start': 0, 'end': 0, 'duration': 0}, 
            'sendAuthenticationResponse': {'start': 0, 'end': 0, 'duration': 0}, 
            'receiveSecurityModeCommand': {'start': 0, 'end': 0, 'duration': 0}, 
            'sendSecurityModeComplete': {'start': 0, 'end': 0, 'duration': 0}, 
            'receiveInitialContextSetupRequest(+RegistrationAccept)': {'start': 0, 'end': 0, 'duration': 0},
            'sendInitialContextSetupResponse': {'start': 0, 'end': 0, 'duration': 0}, 
            'sendRegistrationComplete': {'start': 0, 'end': 0, 'duration': 0},  
            'sendPDUSessionEstablishmentRequest': {'start': 0, 'end': 0, 'duration': 0},  
            'receivePDUSessionResourceSetupRequest(+EstablishmentAccept)': {'start': 0, 'end': 0, 'duration': 0},  
            'sendPDUSessionResourceSetupResponse': {'start': 0, 'end': 0, 'duration': 0}, 
            'receiveConfigurationUpdateCommand': {'start': 0, 'end': 0, 'duration': 0}, 
            'sendConfigurationUpdateComplete': {'start': 0, 'end': 0, 'duration': 0}, 
            'sendContextReleaseRequest': {'start': 0, 'end': 0, 'duration': 0}, 
            'receiveContextReleaseCommand': {'start': 0, 'end': 0, 'duration': 0}, 
            'sendContextReleaseComplete': {'start': 0, 'end': 0, 'duration': 0}
        }

    for procedure in procedure_list:
        proc_duration_by_name_dict[procedure] = {'time_list': [], 'avg': 0.0}
    
    # https://www.geeksforgeeks.org/python-initializing-dictionary-with-empty-lists/
    # proc_duration_by_name_dict = dict.fromkeys(procedure_list, [])
    
    # proc_duration_by_name_dict = {procedure: [] for procedure in procedure_list}
    # print (proc_duration_by_name_dict)

    return ue_info_by_imsi_dict


def exit_with_format_error(items):
    print("ERROR: Unexpected Format!", items)
    sys.exit(1)


def main():
    first_imsi = 901700000000001
    ue_num = 1
    log_filename = "urs-all.log"

    ue_info_by_imsi_dict = {}
    imsi_by_ueid_dict = {}

    ue_start_time = ''
    ue_end_time = ''
    ue_duration = ''

    if (len(sys.argv) == 4):
        first_imsi = int(sys.argv[1])
        ue_num = int(sys.argv[2])
        log_filename = sys.argv[3]
    elif (len(sys.argv) > 1) and (len(sys.argv) != 4) :
        print ("Usage:", sys.argv[0], "<first_imsi> <number of UEs> <log file>")
        sys.exit(1)
    print ("Input:", first_imsi, ue_num, log_filename)

    try:
        with open(log_filename, 'r', encoding='iso-8859-15') as log_file:
            lines = log_file.readlines()
    except OSError as err:
        print("ERROR: File Open Failed!", err)
        sys.exit(1)

    ue_info_by_imsi_dict = init_ue_info(ue_info_by_imsi_dict, first_imsi, ue_num)
    # Initialize DB for 2000 UEs
    # ue_info_by_imsi_dict = init_ue_info(ue_info_by_imsi_dict, first_imsi, 2000)

    # print (ue_info_by_imsi_dict)

    for line in lines:
        info = line.split('JK###')
        if (len(info) != 2):
            continue
        
        ue_imsi = 0
        items = info[-1].split()
        # print (items)
        # To get gnbToken and ueToken
        # JK### RlsUeEntity_sendSetupComplete @ue gnbToken: 3312879965910294896 ueToken: 864116952956684276 START: 1616817174960.644043
        if items[0] == 'RlsUeEntity_sendSetupComplete':
            if ue_num > 1:
                ue_imsi = int(info[0].split('[')[2].split('|rls]')[0])
            else:
                ue_imsi = first_imsi
            # print (items)
            ue_info_by_imsi_dict[ue_imsi]['gnbtoken'] = items[3]
            ue_info_by_imsi_dict[ue_imsi]['uetoken'] = items[5]
            ue_start_time = items[7]
        # To Associate ueId and ueToken
        # JK### RlsGnbEntity_onReceive @gNB ueId: 3 ueToken: 864116952956684276
        elif items[0] == 'RlsGnbEntity_onReceive':
            ueid = 0
            uetoken = 0
            if items[2] != 'ueId:':
                print ("ERROR: ueId NOT Found!")
                exit_with_format_error(items)
            else:
                ueid = items[3]

            if items[4] != 'ueToken:':
                print ("ERROR: ueToken NOT Found!")
                exit_with_format_error(items)
            else:
                uetoken = items[5]

            if ue_num > 1:
                ue_imsi_found = False
                for key_imsi, value_ue_info in ue_info_by_imsi_dict.items():
                    if value_ue_info['uetoken'] == uetoken:
                        ue_imsi = key_imsi
                        ue_imsi_found = True
                        break
                if ue_imsi_found == False:
                    print (ueid, ue_imsi, uetoken)
                    print ("ERROR: Failed to search ue_imsi with ueToken from ue_info_by_imsi_dict!")
                    sys.exit(1)
            else:
                ue_imsi = first_imsi
            ue_info_by_imsi_dict[ue_imsi]['ueid'] = ueid
            imsi_by_ueid_dict[ueid] = ue_imsi

        else:
            """
            # Exception
            # // m_logger->info("JK### receiveMmMessage receiveConfigurationUpdate IMSI: %s END: %.3f",
            if items[0] == 'receiveMmMessage':
                ue_imsi = items[3]
                time_type = items[4]
                time_value = items[5]
                items[0] = 'receiveConfigurationUpdate'
                items[1] = '@ue'
                items[2] = 'IMSI:'
                items[3] = ue_imsi
                items[4] = time_type
                items[5] = time_value
            # Exception2 no @ue
            # JK### receiveConfigurationUpdate IMSI: 901700000000001 END: 1616775599632.687
            if items[0] == 'receiveConfigurationUpdate':
                ue_imsi = items[2]
                time_type = items[3]
                time_value = items[4]
                items[0] = 'receiveConfigurationUpdate'
                items[1] = '@ue'
                items[2] = 'IMSI:'
                items[3] = ue_imsi
                items[4] = time_type
                items.append(time_value)
            # To get UE's IMSI
            # JK### sendInitialRegistrationRequest @ue IMSI: 901700000000001 START: 1616872241581.620
            if (items[0] == 'sendInitialRegistrationRequest') and (items[2] == 'IMSI:'):
                # print (items)
                ue_imsi = items[3]
            """

            # To get UE's ue_end_time until the sendPDUSessionResourceSetupResponse (END) 
            # JK### sendPDUSessionResourceSetupResponse @gNB ueId: 3 END: 1616823085003.179
            if (items[0] == 'sendPDUSessionResourceSetupResponse') and (items[4] == 'END:'):
                # print (items)
                ue_end_time = items[5]
                ue_duration = "{0:.3f}".format(float(ue_end_time) - float(ue_start_time))

            if items[0] in procedure_list:
                # print (items)
                procedure = items[0]
                if items[1] == '@ue':
                    ue_imsi = int(items[3])
                    if items[4] == 'START:':
                        ue_info_by_imsi_dict[ue_imsi][procedure]['start'] = items[5]
                    elif items[4] == 'END:':
                        ue_info_by_imsi_dict[ue_imsi][procedure]['end'] = items[5]
                    else:
                        print ("ERROR: START/END NOT Found!")
                        exit_with_format_error(items)
                elif items[1] == '@gNB':
                    if items[2] != 'ueId:':
                        print ("ERROR: ueId NOT Found!")
                        exit_with_format_error(items)
                    else:
                        ueid = items[3]

                    if ue_num > 1:
                        ue_imsi = imsi_by_ueid_dict[ueid]
                    else:
                        ue_imsi = first_imsi

                    if items[4] == 'START:':
                        ue_info_by_imsi_dict[ue_imsi][procedure]['start'] = items[5]
                    elif items[4] == 'END:':
                        ue_info_by_imsi_dict[ue_imsi][procedure]['end'] = items[5]
                    else:
                        print ("ERROR: START/END NOT Found!")
                        exit_with_format_error(items)
                else:
                    print ("ERROR: @ue/gNB NOT Found!")
                    exit_with_format_error(items)
            else:
                print ("Unknown Procedure!")
                exit_with_format_error(items)

    for key_imsi, value_ue_info in ue_info_by_imsi_dict.items():
        # print (key_imsi)
        for key, value in value_ue_info.items():
            if key in procedure_list:
                # if key == 'receivePDUSessionResourceSetupResponse':
                #     print (value["start"], value["end"], value["end"])

                if (value["start"] == 0) or (value["end"] == 0):
                    continue

                duration = "{0:.3f}".format(float(value["end"]) - float(value["start"]))
                value["duration"] = str(duration)
                proc_duration_by_name_dict[key]['time_list'].append(value["duration"])
                # print (proc_duration_by_name_dict[key])
                # print(key)
                # print(str(duration))

        # print (key_imsi)
        # print (json.dumps(value_ue_info, indent=4))
    print ('UE#:', ue_num)
    # print ('ue_start_time', ue_start_time, 'ue_end_time', ue_end_time, 'ue_duration', ue_duration)        
    print ('ue_duration:', ue_duration)
    for procedure in procedure_list:
        # print (procedure, proc_duration_by_name_dict[procedure])

        count = len(proc_duration_by_name_dict[procedure]['time_list'])
        sum = 0
        for duration in proc_duration_by_name_dict[procedure]['time_list']:
            if float(duration) == 0:
                count = count - 1
            sum = sum + float(duration)
        
        if (count != ue_num) or (count == 0):
            print ("\nERROR: Data Count is not the same as ue_num:", procedure, count, '\n')
        if (count > 0):
            avg = sum / count
        else: 
            avg = 0

        proc_duration_by_name_dict[procedure]['avg'] = "{0:.3f}".format(avg)
        print (procedure, proc_duration_by_name_dict[procedure]['avg'])

        # print (procedure, proc_duration_by_name_dict[procedure]['time_list'])
        # print (procedure, proc_duration_by_name_dict[procedure])
        

if __name__ == "__main__":
    # execute only if run as a script
    main()